#ifndef SCAN_UDP_H
#define SCAN_UDP_H

#include <pthread.h>
#include <pcap.h>
#include "l4_scan_types.h"

typedef struct {
    pcap_t *pcap_handle;
    scan_task_t *task;
    sem_t *main_sem;
    pthread_mutex_t *packets_mutex;
} udp_capture_user_data_t;

/* 
 * Internal UDP scanning helper functions.
 * (Static functions are limited to this translation unit.)
 */
pcap_t *create_pcap_handle_udp(const char *interface, char *errbuf);
void *send_udp_packets(void *arg);
void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void *capture_udp_packets(void *arg);

/* 
 * Public thread function to perform the complete UDP scan.
 */
void *udp_scan_thread(void *arg);

#endif /* SCAN_UDP_H */
