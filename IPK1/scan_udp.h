#ifndef SCAN_UDP_H
#define SCAN_UDP_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

// Struktura uchovávající parametry pro UDP scan úlohu
typedef struct {
    unsigned short src_port;
    char target_ip[INET6_ADDRSTRLEN];  // cílová IP (IPv4 nebo IPv6)
    int port;                          // port ke skenování
    int timeout;                       // timeout v milisekundách
    char interface[64];                // jméno síťového rozhraní
    char result[16];                   // výsledek ("open", "closed" nebo "error")
    int is_ipv6;
} udp_scan_task_t;

// Vláknová funkce, která provede UDP scan konkrétního portu
void *udp_scan_thread(void *arg);

#endif
