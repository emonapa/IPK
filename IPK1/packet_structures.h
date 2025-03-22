#ifndef PACKET_STRUCTURES_H
#define PACKET_STRUCTURES_H

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
    pthread_mutex_t packets_mutex;  // Mutex pro chranu packets_received
    int is_ipv6;                 // 0 = IPv4, 1 = IPv6
    sem_t *main_sem;             // Ukazatel na hlavní semafor (předáme jej do callbacku)
} scan_task_t;

#endif
