#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

#include "interfaces.h"
#include "scan_tcp.h"
#include "scan_udp.h"
#include "utils.h"

#define DEFAULT_TIMEOUT 1000
#define MAX_PORT 65535
#define CHUNK_SIZE 1000

typedef struct {
    sem_t port_sem;
    int current_port;
} unique_src_port;

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
    char resolved_ip[INET6_ADDRSTRLEN];
    int is_ipv6;
    unique_src_port unique_src;
} scan_config_t;

static void print_usage(const char *progname) {
    printf("Usage: %s [-h] -i <interface> [--pt <tcp-ports>] [--pu <udp-ports>] [-w <timeout>] <hostname>\n",
           progname);
}

extern int filter_ports(scan_task_t *task, int **orig_index);

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

int chunk_send(scan_task_t *orig, int chunk_size, int is_tcp, unique_src_port uniques_src) {
    int n = (orig->num_ports + chunk_size - 1) / chunk_size;
    pthread_t *threads = malloc(n * sizeof(pthread_t));
    scan_task_t **chunk_tasks = malloc(n * sizeof(scan_task_t*));
    for (int i = 0; i < n; i++) {
        int start = i * chunk_size;
        int c = (start + chunk_size <= orig->num_ports) ? chunk_size : (orig->num_ports - start);
        scan_task_t *ctask = malloc(sizeof(scan_task_t));
        *ctask = *orig;
        ctask->src_port = get_next_port(&uniques_src);
        ctask->num_ports = c;
        ctask->ports = orig->ports + start;
        chunk_tasks[i] = ctask;
        if (is_tcp) pthread_create(&threads[i], NULL, (void*(*)(void*))tcp_scan_thread, ctask);
        else        pthread_create(&threads[i], NULL, (void*(*)(void*))udp_scan_thread, ctask);
    }
    for (int i = 0; i < n; i++) {
        pthread_join(threads[i], NULL);
        free(chunk_tasks[i]);
    }
    free(threads);
    free(chunk_tasks);
    return 0;
}

char **resolve_all_ips(const char *h, int *cnt, int *is6) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    int r = getaddrinfo(h, NULL, &hints, &res);
    if (r != 0 || !res) return NULL;
    int c = 0;
    for (p = res; p; p = p->ai_next) c++;
    char **ret = malloc(c * sizeof(char*));
    int idx = 0;
    *is6 = 0;
    for (p = res; p; p = p->ai_next) {
        ret[idx] = malloc(INET6_ADDRSTRLEN);
        if (p->ai_family == AF_INET) {
            *is6 = 0;
            struct sockaddr_in *sa = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ret[idx], INET6_ADDRSTRLEN);
        } else if (p->ai_family == AF_INET6) {
            *is6 = 1;
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)p->ai_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ret[idx], INET6_ADDRSTRLEN);
        }
        idx++;
    }
    freeaddrinfo(res);
    *cnt = c;
    return ret;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    scan_config_t config;
    memset(&config, 0, sizeof(config));
    config.timeout = DEFAULT_TIMEOUT;

    /* Inicializace semaforu a počátečního portu */
    sem_init(&config.unique_src.port_sem, 0, 1); // semafor pro sdílený zdroj
    config.unique_src.current_port = 1025;       // Třeba začneme od 1025

    int opt, option_index = 0;
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"pt", required_argument, 0, 't'},
        {"pu", required_argument, 0, 'u'},
        {"wait", required_argument, 0, 'w'},
        {0,0,0,0}
    };
    char *tcp_ports_str = NULL, *udp_ports_str = NULL;
    while ((opt = getopt_long(argc, argv, "h:i:t:u:w:", long_opts, &option_index)) != -1) {
        switch(opt) {
            case 'h': print_usage(argv[0]); exit(0);
            case 'i':
                if (!optarg || !strlen(optarg)) {
                    list_active_interfaces();
                    exit(0);
                }
                strncpy(config.interface, optarg, sizeof(config.interface)-1);
                break;
            case 't': tcp_ports_str = strdup(optarg); break;
            case 'u': udp_ports_str = strdup(optarg); break;
            case 'w': config.timeout = atoi(optarg); break;
            default: print_usage(argv[0]); exit(1);
        }
    }
    if (optind >= argc) { print_usage(argv[0]); exit(1); }

    strncpy(config.target, argv[optind], sizeof(config.target)-1);
    if (tcp_ports_str) {
        if (parse_port_ranges(tcp_ports_str, &config.tcp_ports, &config.tcp_count) != 0) exit(1);
    }
    if (udp_ports_str) {
        if (parse_port_ranges(udp_ports_str, &config.udp_ports, &config.udp_count) != 0) exit(1);
    }
    config.tcp_ports_state = malloc(config.tcp_count * sizeof(port_scan_result_t)); //Valid for malloc(0)
    config.udp_ports_state = malloc(config.udp_count * sizeof(port_scan_result_t)); //Valid for malloc(0)

    int ip_count=0, resolved_ipv6=0;
    char **ip_list = resolve_all_ips(config.target, &ip_count, &resolved_ipv6);
    if (!ip_list) exit(1);

    scan_task_t base_task;
    memset(&base_task, 0, sizeof(base_task));
    strncpy(base_task.interface, config.interface, sizeof(base_task.interface)-1);
    base_task.timeout = config.timeout;
    base_task.num_ports = config.tcp_count;

    if (config.tcp_count > 0) {
        base_task.ports = config.tcp_ports_state;
        base_task.num_ports = config.tcp_count;
        for (int p=0; p<config.tcp_count; p++) {
            base_task.ports[p].port = config.tcp_ports[p];
            base_task.ports[p].state = FILTERED;
        }

        for (int i=0; i<ip_count; i++) {
            strncpy(base_task.target_ip, ip_list[i], sizeof(base_task.target_ip)-1);
            printf("IP ADRESA WTF:____%s\n", base_task.target_ip);
            base_task.is_ipv6 = resolved_ipv6;

            chunk_send(&base_task, CHUNK_SIZE, 1, config.unique_src);
            int *orig_index = NULL;
            //Redundant, just so it's not that confusing
            scan_task_t filtered_task = base_task;
            //filter_ports already creates new array for ports and the right ports count
            int filtered_count = filter_ports(&filtered_task, &orig_index);
            if (filtered_count > 0) {
                chunk_send(&base_task, CHUNK_SIZE, 1, config.unique_src);
                for (int k=0; k<filtered_count; k++) {
                    config.tcp_ports_state[orig_index[k]].state = filtered_task.ports[k].state;
                }
                base_task.ports = config.tcp_ports_state;
                base_task.num_ports = config.tcp_count;
            } else {
            }
            if (orig_index) free(orig_index);

            for (int p=0; p<base_task.num_ports; p++) {
                printf("%s %d tcp ", base_task.target_ip, base_task.ports[p].port);
                switch (base_task.ports[p].state) {
                    case OPEN:     printf("open\n"); break;
                    case CLOSED:   printf("closed\n"); break;
                    case FILTERED: printf("filtered\n"); break;
                    default:       printf("unknown\n");
                }
            }

        }
    }

    if (config.udp_count > 0) {
        base_task.ports = config.udp_ports_state;
        base_task.num_ports = config.udp_count;
        for (int p=0; p<config.udp_count; p++) {
            base_task.ports[p].port = config.udp_ports[p];
            base_task.ports[p].state = FILTERED;
        }

        for (int i=0; i<ip_count; i++) {
            base_task.is_ipv6 = resolved_ipv6;
            strncpy(base_task.target_ip, ip_list[i], sizeof(base_task.target_ip)-1);
            printf("SALINA\n");
            chunk_send(&base_task, CHUNK_SIZE, 0, config.unique_src);
        }

        for (int p=0; p<base_task.num_ports; p++) {
            printf("%s %d udp ", base_task.target_ip, base_task.ports[p].port);
            switch (base_task.ports[p].state) {
                case OPEN:     printf("open\n"); break;
                case CLOSED:   printf("closed\n"); break;
                case FILTERED: printf("(open|filtered)\n"); break;
                default:       printf("unknown\n");
            }
        }
    }

    if (tcp_ports_str) free(tcp_ports_str);
    if (udp_ports_str) free(udp_ports_str);
    if (config.tcp_ports) free(config.tcp_ports);
    if (config.udp_ports) free(config.udp_ports);
    for (int i=0; i<ip_count; i++) {
        free(ip_list[i]);
    }
    free(ip_list);
    free(base_task.ports);


    return 0;
}
