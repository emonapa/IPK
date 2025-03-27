#ifndef SCAN_TCP_H
#define SCAN_TCP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <limits.h>
#include <semaphore.h>
#include <pcap.h>
#include "l4_scan_types.h"

#define PACKET_SIZE 4096


/* Structure holding one outgoing packet's info */
typedef struct {
    scan_task_t *task;
    char packet[PACKET_SIZE];
    int packet_len;
    int target_port;
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    int send_id; // optional debug
} send_packet_params_t;

/* 
 * Internal helper functions used only within the TCP scanning module.
 * They are declared as static to restrict their scope to the translation unit.
 */
void send_packet(send_packet_params_t *params);
void *send_packets(void *arg);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void *capture_packets(void *arg);
pcap_t *create_pcap_handle(const char *iface, char errbuf[]);

/* 
 * Public thread function for performing a TCP SYN scan on the target ports.
 */
void *tcp_scan_thread(void *arg);

#endif /* SCAN_TCP_H */
