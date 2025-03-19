#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "interfaces.h"
#include "scan_tcp.h"
#include "scan_udp.h"
#include "utils.h"

#define DEFAULT_TIMEOUT 1000
#define SRC_PORT 12345

typedef struct {
    unsigned short src_port;
    int *tcp_ports;
    int tcp_count;
    int *udp_ports;
    int udp_count;
    char target[128];
    char interface[64];
    int timeout;
    char resolved_ip[INET6_ADDRSTRLEN];
    int is_ipv6;
} scan_config_t;

static void print_usage(const char *progname) {
    printf("Usage: %s {-h} [-i interface] [--pt port-ranges] [--pu port-ranges] {-w timeout} [hostname|ip-adresa]\n", progname);
}

static int resolve_target(const char *hostname, char *out_ip, size_t out_size, int *is_ipv6) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "getaddrinfo failed for '%s': %s\n", hostname, gai_strerror(rc));
        return -1;
    }
    if (res->ai_family == AF_INET) {
        *is_ipv6 = 0;
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, out_ip, out_size);
    } else if (res->ai_family == AF_INET6) {
        *is_ipv6 = 1;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &sa6->sin6_addr, out_ip, out_size);
    } else {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char *argv[]) {
    scan_config_t config;
    memset(&config, 0, sizeof(config));
    config.timeout = DEFAULT_TIMEOUT;
    config.src_port = SRC_PORT;
    
    int opt, option_index = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"pt", required_argument, 0, 't'},
        {"pu", required_argument, 0, 'u'},
        {"wait", required_argument, 0, 'w'},
        {0, 0, 0, 0}
    };
    
    char *tcp_ports_str = NULL;
    char *udp_ports_str = NULL;
    
    while ((opt = getopt_long(argc, argv, "hi:t:u:w:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'i':
                strncpy(config.interface, optarg, sizeof(config.interface) - 1);
                config.interface[sizeof(config.interface) - 1] = '\0';
                break;
            case 't':
                tcp_ports_str = strdup(optarg);
                break;
            case 'u':
                udp_ports_str = strdup(optarg);
                break;
            case 'w':
                config.timeout = atoi(optarg);
                break;
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
    
    if (optind < argc) {
        strncpy(config.target, argv[optind], sizeof(config.target) - 1);
        config.target[sizeof(config.target) - 1] = '\0';
    } else {
        fprintf(stderr, "Error: Target address is required.\n");
        print_usage(argv[0]);
        exit(1);
    }
    
    if (strlen(config.interface) == 0) {
        list_active_interfaces();
        exit(0);
    }
    
    if (tcp_ports_str) {
        if (parse_port_ranges(tcp_ports_str, &config.tcp_ports, &config.tcp_count) != 0) {
            fprintf(stderr, "Error parsing TCP ports.\n");
            exit(1);
        }
    }
    if (udp_ports_str) {
        if (parse_port_ranges(udp_ports_str, &config.udp_ports, &config.udp_count) != 0) {
            fprintf(stderr, "Error parsing UDP ports.\n");
            exit(1);
        }
    }
    
    if (resolve_target(config.target, config.resolved_ip, sizeof(config.resolved_ip),
                       &config.is_ipv6) < 0) {
        fprintf(stderr, "Unable to resolve target '%s' to IP address.\n", config.target);
        exit(1);
    }
    
    /* Vytvoříme jeden jediný TCP úkol (task) se seznamem portů */
    tcp_scan_task_t tcp_task;
    memset(&tcp_task, 0, sizeof(tcp_scan_task_t));
    tcp_task.src_port = config.src_port;
    strncpy(tcp_task.target_ip, config.resolved_ip, sizeof(tcp_task.target_ip) - 1);
    tcp_task.target_ip[sizeof(tcp_task.target_ip) - 1] = '\0';
    tcp_task.timeout = config.timeout;
    strncpy(tcp_task.interface, config.interface, sizeof(tcp_task.interface) - 1);
    tcp_task.interface[sizeof(tcp_task.interface) - 1] = '\0';
    tcp_task.is_ipv6 = config.is_ipv6;
    /* Inicializace výsledku jako "unknown" (může se nepoužívat, jelikož výsledek se ukládá do pole) */
    strcpy(tcp_task.result, "unknown");
    
    /* Vytvoříme pole pro porty, které chceme skenovat. Stav výchozí je nastaven na FILTERED. */
    tcp_task.num_ports = config.tcp_count;
    tcp_task.ports = malloc(config.tcp_count * sizeof(port_scan_result_t));
    if (!tcp_task.ports) {
        perror("malloc");
        exit(1);
    }
    for (int i = 0; i < config.tcp_count; i++) {
        tcp_task.ports[i].port = config.tcp_ports[i];
        tcp_task.ports[i].state = FILTERED;
    }
    
    /* Spustíme skenovací vlákno pro TCP - pouze jeden task */
    pthread_t tcp_thread;
    if (pthread_create(&tcp_thread, NULL, tcp_scan_thread, &tcp_task) != 0) {
        perror("pthread_create");
        exit(1);
    }
    pthread_join(tcp_thread, NULL);
    
    /* Vytiskneme výsledky skenování pro každý port */
    for (int i = 0; i < config.tcp_count; i++) {
        printf("%s %d tcp ", config.target, tcp_task.ports[i].port);
        switch (tcp_task.ports[i].state) {
            case OPEN:
                printf("open\n");
                break;
            case CLOSED:
                printf("closed\n");
                break;
            case FILTERED:
                printf("filtered\n");
                break;
            default:
                printf("unknown\n");
        }
    }
    
    /* Uvolníme dynamicky alokovanou paměť */
    free(tcp_task.ports);
    if (tcp_ports_str) free(tcp_ports_str);
    if (udp_ports_str) free(udp_ports_str);
    if (config.tcp_ports) free(config.tcp_ports);
    if (config.udp_ports) free(config.udp_ports);
    
    return 0;
}
