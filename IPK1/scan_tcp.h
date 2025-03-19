#ifndef SCAN_TCP_H
#define SCAN_TCP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <limits.h>
#include <semaphore.h>


typedef enum { OPEN, CLOSED, FILTERED } port_state_t;
  
typedef struct {
    int port;
    port_state_t state;
} port_scan_result_t;

typedef struct {
    int src_port;
    char target_ip[64];
    char interface[64];
    int num_ports;
    port_scan_result_t *ports;   // Každý prvek obsahuje: int port; int state; (OPEN, CLOSED, FILTERED)
    int timeout;                 // Timeout v ms
    int packets_received;        // Počáteční hodnota 0
    pthread_mutex_t packets_mutex;  // Mutex pro chránění packets_received
    int is_ipv6;                 // 0 = IPv4, 1 = IPv6
    sem_t *main_sem;             // Ukazatel na hlavní semafor (předáme jej do callbacku)
} tcp_scan_task_t;

// Vláknová funkce, která provede TCP SYN scan konkrétního portu
void *tcp_scan_thread(void *arg);

#endif
