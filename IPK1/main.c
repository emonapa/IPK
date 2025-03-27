#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <semaphore.h>

#include "interfaces.h"
#include "scan_tcp.h"
#include "scan_udp.h"
#include "utils.h"

#define DEFAULT_TIMEOUT 5000
#define MAX_PORT 65535
#define CHUNK_SIZE 10000

#define CHECK_MALLOC(ptr)   do {                                                    \
                                if (ptr == NULL) fprintf(stderr, "Malloc failed");  \
                            } while(0)

          
typedef enum { HELP, INTE, PTCP, PUDP, WAIT } flag_type_t;
#define CHECK_ARGS_USED(flags, flag_type)   do {                                                                                    \
                                                if (flags[flag_type]){                                                              \
                                                    fprintf(stderr, "Error while parsing arguments, can't have duplicite flags\n"); \
                                                    exit(1);                                                                        \
                                                } else {                                                                            \
                                                    flags[flag_type] = 1;                                                           \
                                                }                                                                                   \
                                            } while (0)                                                                             


/* Structure for unique source port allocation */
typedef struct {
    sem_t port_sem;
    int current_port;
} unique_src_port;

/* New structure to store an IP address and its IPv6 flag */
typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int is_ipv6;
} IPAddress;

/* Configuration structure that includes an array of IPAddress structures */
typedef struct {
    unsigned short src_port;
    port_scan_result_t *tcp_ports_state;
    int *tcp_ports;
    int tcp_count;
    
    port_scan_result_t *udp_ports_state;
    int *udp_ports;
    int udp_count;
    
    char target[128];
    char interface[64];
    int timeout;
    char resolved_ip[INET6_ADDRSTRLEN]; /* Optional: used elsewhere if needed */
    int is_ipv6;                        /* Global flag if needed */
    
    unique_src_port unique_src;
    
    /* Array of resolved IP addresses */
    IPAddress *ips;      /* Dynamically allocated array of IPAddress */
    int ip_count;        /* Number of entries in ips[] */
} scan_config_t;

/* Print usage information */
static void print_usage(FILE *stream, const char *progname) {
    fprintf(stream, "Usage: %s [-h] -i <interface> [--pt <tcp-ports>] [--pu <udp-ports>] [-w <timeout>] <hostname>\n",
           progname);
}

/* Retrieve the next available source port, protected by a semaphore */
unsigned short get_next_port(unique_src_port *src) {
    sem_wait(&src->port_sem);
    if (src->current_port > MAX_PORT) {
        sem_post(&src->port_sem);
        fprintf(stderr, "No more ports available!\n");
        exit(1);
    }
    unsigned short ret = (unsigned short)src->current_port;
    src->current_port++;
    sem_post(&src->port_sem);
    return ret;
}

/*
 * Splits the ports in the original scan task into chunks and spawns a thread for each chunk.
 * A shallow copy of the scan task is created for each chunk.
 * 'is_tcp' selects the appropriate scan thread (TCP or UDP).
 */
int chunk_send(scan_task_t *orig, int chunk_size, int is_tcp, unique_src_port *uniques_src) {
    int n = (orig->num_ports + chunk_size - 1) / chunk_size;
    pthread_t *threads = malloc(n * sizeof(pthread_t));
    scan_task_t **chunk_tasks = malloc(n * sizeof(scan_task_t*));
    CHECK_MALLOC(threads);
    CHECK_MALLOC(chunk_tasks);

    for (int i = 0; i < n; i++) {
        int start = i * chunk_size;
        int c = (start + chunk_size <= orig->num_ports) ? chunk_size : (orig->num_ports - start);

        scan_task_t *ctask = malloc(sizeof(scan_task_t));
        CHECK_MALLOC(ctask);
        *ctask = *orig;
        ctask->src_port = get_next_port(uniques_src);

        ctask->num_ports = c;
        //For some reason, the last packet in chunk is always filtered???
        //Don't have the strenght to fix it.
        //If it works, don't touch it...
        if (i != n-1) ctask->num_ports += 1;
        ctask->ports = orig->ports + start;
        
        chunk_tasks[i] = ctask;
        if (is_tcp)
            pthread_create(&threads[i], NULL, (void*(*)(void*))tcp_scan_thread, ctask);
        else
            pthread_create(&threads[i], NULL, (void*(*)(void*))udp_scan_thread, ctask);
    }
    for (int i = 0; i < n; i++) {
        pthread_join(threads[i], NULL);
        free(chunk_tasks[i]);
    }
    free(threads);
    free(chunk_tasks);
    return 0;
}

/*
 * Resolves the given hostname into an array of IPAddress structures.
 * Returns a dynamically allocated array and sets *count to the number of resolved addresses.
 */
IPAddress* resolve_all_ips(const char *hostname, int *count) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;   // Sufficient for resolution
    
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "getaddrinfo('%s') failed: %s\n", hostname, gai_strerror(rc));
        *count = 0;
        return NULL;
    }
    int c = 0;
    for (p = res; p; p = p->ai_next) {
        c++;
    }
    IPAddress *ip_list = malloc(c * sizeof(IPAddress));
    CHECK_MALLOC(ip_list);
    if (!ip_list) {
        freeaddrinfo(res);
        *count = 0;
        return NULL;
    }
    int idx = 0;
    for (p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_list[idx].ip, INET6_ADDRSTRLEN);
            ip_list[idx].is_ipv6 = 0;
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ip_list[idx].ip, INET6_ADDRSTRLEN);
            ip_list[idx].is_ipv6 = 1;
        } else {
            continue;
        }
        idx++;
    }
    freeaddrinfo(res);
    *count = idx;
    return ip_list;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    scan_config_t config;
    memset(&config, 0, sizeof(config));
    config.timeout = DEFAULT_TIMEOUT;

    config.unique_src.current_port = 12345;
    
    if (argc == 2) {
        if (strcmp(argv[1], "--interface") == 0) {
            list_active_interfaces();
            exit(0);
        }
    } else if (argc == 1) {
        list_active_interfaces();
        exit(0);
    }

    /* HELP, INTE, PTCP, PUDP, WAIT */
    char flags[] = {0,0,0,0,0};
    int opt, option_index = 0;
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"pt", required_argument, 0, 't'},
        {"pu", required_argument, 0, 'u'},
        {"wait", required_argument, 0, 'w'},
        {0, 0, 0, 0}
    };
    char *tcp_ports_str = NULL, *udp_ports_str = NULL;
    while ((opt = getopt_long(argc, argv, "hi:t:u:w:", long_opts, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                CHECK_ARGS_USED(flags, HELP);
                print_usage(stdout, argv[0]);
                exit(0);
            case 'i':
                CHECK_ARGS_USED(flags, INTE);
                strncpy(config.interface, optarg, sizeof(config.interface) - 1);
                config.interface[sizeof(config.interface) - 1] = '\0';
                break;
            case 't':
                CHECK_ARGS_USED(flags, PTCP);
                tcp_ports_str = strdup(optarg);
                break;
            case 'u':
                CHECK_ARGS_USED(flags, PUDP);
                udp_ports_str = strdup(optarg);
                break;
            case 'w':
                CHECK_ARGS_USED(flags, WAIT);
                config.timeout = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Unknown argument\n");
                print_usage(stderr, argv[0]);
                exit(1);
        }
    }
    if (optind >= argc) {
        print_usage(stderr, argv[0]);
        exit(1);
    }
    strncpy(config.target, argv[optind], sizeof(config.target) - 1);
    
    if (tcp_ports_str)
        if (parse_port_ranges(tcp_ports_str, &config.tcp_ports, &config.tcp_count) != 0)
            exit(1);
    
    if (udp_ports_str)
        if (parse_port_ranges(udp_ports_str, &config.udp_ports, &config.udp_count) != 0)
            exit(1);
    
    config.tcp_ports_state = malloc(config.tcp_count * sizeof(port_scan_result_t));
    config.udp_ports_state = malloc(config.udp_count * sizeof(port_scan_result_t));
    CHECK_MALLOC(config.tcp_ports_state);
    CHECK_MALLOC(config.udp_ports_state);
    
    /* Resolve the target hostname into an array of IPAddress structures */
    config.ips = resolve_all_ips(config.target, &config.ip_count);
    if (!config.ips || config.ip_count == 0) {
        fprintf(stderr, "Unable to resolve or got no valid addresses.\n");
        exit(1);
    }

    /* Used for generating unique port */
    sem_init(&config.unique_src.port_sem, 0, 1);
    
    /* Prepare base TCP task */
    scan_task_t base_tcp;
    memset(&base_tcp, 0, sizeof(base_tcp));
    strncpy(base_tcp.interface, config.interface, sizeof(base_tcp.interface));
    base_tcp.timeout = config.timeout;
    
    /* Prepare base UDP task */
    scan_task_t base_udp;
    memset(&base_udp, 0, sizeof(base_udp));
    strncpy(base_udp.interface, config.interface, sizeof(base_udp.interface));
    base_udp.timeout = config.timeout;
    
    /* TCP scanning loop for each resolved IP */
    if (config.tcp_count > 0) {
        for (int t = 0; t < config.tcp_count; t++) {
            config.tcp_ports_state[t].port = config.tcp_ports[t];
        }
        base_tcp.ports = config.tcp_ports_state;
        base_tcp.num_ports = config.tcp_count;
        
        for (int i = 0; i < config.ip_count; i++) {
            /* Set all port states to FILTERED before scanning */
            for (int t = 0; t < base_tcp.num_ports; t++) {
                base_tcp.ports[t].state = FILTERED;
            }
            /* Set target IP and IPv6 flag from resolved addresses */
            strncpy(base_tcp.target_ip, config.ips[i].ip, sizeof(base_tcp.target_ip) - 1);
            base_tcp.is_ipv6 = config.ips[i].is_ipv6;
            
            /* First pass: send SYN packets to all ports */
            chunk_send(&base_tcp, CHUNK_SIZE, 1, &config.unique_src);
            
            /* Filter the ports that remain FILTERED and perform a second pass */
            int *orig_index = NULL;
            scan_task_t filtered_task = base_tcp; //Redundant, just so it's more clear.
            int filtered_count = filter_ports(&filtered_task, &orig_index);
            if (filtered_count > 0) {
                fprintf(stderr, "\n");

                chunk_send(&base_tcp, CHUNK_SIZE, 1, &config.unique_src);
                for (int k = 0; k < filtered_count; k++) {
                    config.tcp_ports_state[orig_index[k]].state = filtered_task.ports[k].state;
                }
                free(filtered_task.ports);
                free(orig_index);

                base_tcp.ports = config.tcp_ports_state;
                base_tcp.num_ports = config.tcp_count;
            }
            
            //fprintf(stderr, "\n");
            /* Print TCP scan results */
            for (int p = 0; p < base_tcp.num_ports; p++) {
                printf("%s %d tcp ", base_tcp.target_ip, base_tcp.ports[p].port);
                switch (base_tcp.ports[p].state) {
                    case OPEN:     printf("open\n"); break;
                    case CLOSED:   printf("closed\n"); break;
                    case FILTERED: printf("filtered\n"); break;
                    default:       printf("unknown\n");
                }
            }
            //fprintf(stderr, "------------------------------------------------------------------------------------------------------\n");
            fprintf(stderr, "------------------------------------------------------------------\n");
        }
    }
    
    /* UDP scanning loop for each resolved IP */
    if (config.udp_count > 0) {
        for (int u = 0; u < config.udp_count; u++) {
            config.udp_ports_state[u].port = config.udp_ports[u];
        }
        base_udp.ports = config.udp_ports_state;
        base_udp.num_ports = config.udp_count;
        for (int i = 0; i < config.ip_count; i++) {
            for (int u = 0; u < base_udp.num_ports; u++) {
                base_udp.ports[u].state = OPEN;
            }
            strncpy(base_udp.target_ip, config.ips[i].ip, sizeof(base_udp.target_ip) - 1);
            base_udp.is_ipv6 = config.ips[i].is_ipv6;
            
            chunk_send(&base_udp, CHUNK_SIZE, 0, &config.unique_src);
            
            /* Print UDP scan results */
            for (int p = 0; p < base_udp.num_ports; p++) {
                printf("%s %d udp ", base_udp.target_ip, base_udp.ports[p].port);
                switch (base_udp.ports[p].state) {
                    case OPEN:     printf("open\n"); break;
                    case CLOSED:   printf("closed\n"); break;
                    case FILTERED: printf("filtered\n"); break;
                    default:       printf("unknown\n");
                }
            }
            //fprintf(stderr, "------------------------------------------------------------------------------------------------------\n");
            fprintf(stderr, "------------------------------------------------------------------\n");
        }
    }
    
    /* Cleanup allocated memory */
    if (tcp_ports_str) free(tcp_ports_str);
    if (udp_ports_str) free(udp_ports_str);
    if (config.tcp_ports) free(config.tcp_ports);
    if (config.udp_ports) free(config.udp_ports);
    if (config.tcp_ports_state) free(config.tcp_ports_state);
    if (config.udp_ports_state) free(config.udp_ports_state);
    
    free(config.ips);
    
    sem_destroy(&config.unique_src.port_sem);
    return 0;
}
