#ifndef SCAN_TCP_H
#define SCAN_TCP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <limits.h>


typedef enum { OPEN, CLOSED, FILTERED } port_state_t;
  
typedef struct {
    int port;
    port_state_t state;
} port_scan_result_t;

typedef struct {
    int src_port;
    char target_ip[64];
    int timeout;          // timeout v milisekundách
    char interface[64];
    int is_ipv6;          // 0 = IPv4, 1 = IPv6
    char result[32];      // není primárně využitý, výsledky se ukládají do pole ports
    int num_ports;        // počet portů k odeslání
    port_scan_result_t *ports; // pole struktur s výsledky pro každý port
} tcp_scan_task_t;

// Vláknová funkce, která provede TCP SYN scan konkrétního portu
void *tcp_scan_thread(void *arg);

#endif
