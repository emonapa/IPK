#ifndef PACKET_STRUCTURES_H
#define PACKET_STRUCTURES_H

#include <semaphore.h>

typedef enum { OPEN, CLOSED, FILTERED } port_state_t;
  
typedef struct {
    uint16_t port;
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
    int is_ipv6;                 // 0 = IPv4, 1 = IPv6
} scan_task_t;

/* Callback used by pcap_loop */
typedef struct {
    pcap_t *pcap_handle;
    scan_task_t *task;
    sem_t *main_sem;
    pthread_mutex_t *packets_mutex;
    int dlt;
} capture_user_data_t;

#endif
