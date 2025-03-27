#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <time.h>
#include <errno.h>

#include "utils.h"
#include "scan_tcp.h"

#define PARSE_PORT_CLEANUP(p, str)  do {                            \
                                        free(p);                    \
                                        free(str);                  \
                                        return -1;                  \
                                    } while(0)           

/* 
 * filter_ports: keep only ports with state=FILTERED. 
 * Updates 'task->ports' and 'task->num_ports' so that only the FILTERED remain.
 * Also sets '*tcp_task_copy_i' to an array of original indices.
 */
int filter_ports(scan_task_t *task, int *tcp_task_copy_i[]) {
    int count = 0;
    for (int i = 0; i < task->num_ports; i++) {
        if (task->ports[i].state == FILTERED) count++;
    }
    if (count == 0) return 0;

    port_scan_result_t *new_ports = malloc(count * sizeof(port_scan_result_t));
    int *new_copy_i = malloc(count * sizeof(int));
    if (!new_ports || !new_copy_i) {
        perror("malloc");
        return -1;
    }
    int j = 0;
    for (int i = 0; i < task->num_ports; i++) {
        if (task->ports[i].state == FILTERED) {
            new_ports[j] = task->ports[i];
            new_copy_i[j] = i;
            j++;
        }
    }
    *tcp_task_copy_i = new_copy_i;
    task->ports = new_ports;
    task->num_ports = count;
    return count;
}

/* 16-bit Internet checksum over 'len' bytes. */
unsigned short compute_checksum(const unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        unsigned short tmp = 0;
        *(unsigned char*)(&tmp) = *(unsigned char*)buf;
        sum += tmp;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

/* TCP checksum for IPv4, building pseudo-header with iphdr + tcphdr. */
unsigned short tcp_checksum_ipv4(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    int tcp_len = sizeof(struct tcphdr);
    psh.src_addr     = iph->saddr;
    psh.dst_addr     = iph->daddr;
    psh.placeholder  = 0;
    psh.protocol     = IPPROTO_TCP;
    psh.tcp_length   = htons(tcp_len);

    int psize = sizeof(psh) + tcp_len;
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        perror("malloc tcp_checksum_ipv4");
        return 0;
    }

    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, tcp_len);

    unsigned short checksum = compute_checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return checksum;
}

/* 
 * TCP checksum for IPv6. We pass in ip6h (with ip6_src/dst),
 * the tcp header, and the length of tcp. This constructs an IPv6 pseudo-header
 * (src/dst + length + next_header), appends the tcphdr, then 1's complement sum. 
 */
unsigned short tcp_checksum_ipv6(const struct ip6_hdr *ip6h,
                                 const struct tcphdr *tcph,
                                 int tcph_len)
{
    struct pseudo_header_ipv6 {
        unsigned char  src_addr[16];
        unsigned char  dst_addr[16];
        unsigned int   tcp_length;
        unsigned char  zeros[3];
        unsigned char  next_header;
    } psh6;

    memset(&psh6, 0, sizeof(psh6));
    memcpy(psh6.src_addr, &ip6h->ip6_src, 16);
    memcpy(psh6.dst_addr, &ip6h->ip6_dst, 16);
    psh6.tcp_length  = htonl(tcph_len);
    psh6.next_header = IPPROTO_TCP;

    int psize = sizeof(psh6) + tcph_len;
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        perror("malloc tcp_checksum_ipv6");
        return 0;
    }

    memcpy(pseudogram, &psh6, sizeof(psh6));
    memcpy(pseudogram + sizeof(psh6), tcph, tcph_len);

    unsigned short checksum = compute_checksum((unsigned short*)pseudogram, psize);
    free(pseudogram);
    return checksum;
}


int parse_port_ranges(const char *port_str, int **ports, int *count) {
    char *str = strdup(port_str);
    if (!str) {
        fprintf(stderr, "Memory allocation error\n");
        return -1;
    }
    int capacity = 10;
    int *p = malloc(capacity * sizeof(int));
    if (!p) {
        fprintf(stderr, "Memory allocation error\n");
        free(str);
        return -1;
    }
    int cnt = 0;
    char *token = strtok(str, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            char *endptr;
            errno = 0;
            long start = strtol(token, &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                fprintf(stderr, "Invalid port number: %s\n", token);
                PARSE_PORT_CLEANUP(p, str);
            }
            errno = 0;
            long end = strtol(dash + 1, &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                fprintf(stderr, "Invalid port number: %s\n", dash + 1);
                PARSE_PORT_CLEANUP(p, str);
            }
            if (start > end) {
                fprintf(stderr, "Invalid port range: %ld-%ld\n", start, end);
                PARSE_PORT_CLEANUP(p, str);
            }
            if (start < 0 || end > 65535) {
                fprintf(stderr, "Port numbers out of range: %ld-%ld\n", start, end);
                PARSE_PORT_CLEANUP(p, str);
            }
            for (long i = start; i <= end; i++) {
                if (cnt >= capacity) {
                    capacity *= 2;
                    int *tmp = realloc(p, capacity * sizeof(int));
                    if (!tmp) {
                        fprintf(stderr, "Memory allocation error\n");
                        PARSE_PORT_CLEANUP(p, str);
                    }
                    p = tmp;
                }
                p[cnt++] = (int)i;
            }
        } else {
            char *endptr;
            errno = 0;
            long port = strtol(token, &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                fprintf(stderr, "Invalid port number: %s\n", token);
                PARSE_PORT_CLEANUP(p, str);
            }
            if (port < 0 || port > 65535) {
                fprintf(stderr, "Port number out of range: %ld\n", port);
                PARSE_PORT_CLEANUP(p, str);
            }
            if (cnt >= capacity) {
                capacity *= 2;
                int *tmp = realloc(p, capacity * sizeof(int));
                if (!tmp) {
                    fprintf(stderr, "Memory allocation error\n");
                    PARSE_PORT_CLEANUP(p, str);
                }
                p = tmp;
            }
            p[cnt++] = (int)port;
        }
        token = strtok(NULL, ",");
    }
    free(str);
    *ports = p;
    *count = cnt;
    return 0;
}


/* Debug print of IPv4/ TCP headers. */
void debug_print_ipv4(const unsigned char *packet, int len) {
    if (len < (int)sizeof(struct iphdr)) {
        printf("[DEBUG] Packet too short for IPv4 header.\n");
        return;
    }
    struct iphdr *ip_hdr = (struct iphdr *)(packet + 14); // typical offset if there's an Ethernet
    int ip_hdr_len = ip_hdr->ihl * 4;
    printf("[DEBUG] IP Header:\n");
    printf("  Version: %d\n", ip_hdr->version);
    printf("  IHL: %d (%d bytes)\n", ip_hdr->ihl, ip_hdr_len);
    printf("  Total Length: %d\n", ntohs(ip_hdr->tot_len));
    printf("  Protocol: %d\n", ip_hdr->protocol);
    struct in_addr saddr, daddr;
    saddr.s_addr = ip_hdr->saddr;
    daddr.s_addr = ip_hdr->daddr;
    printf("  Source: %s\n", inet_ntoa(saddr));
    printf("  Destination: %s\n", inet_ntoa(daddr));

    if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) {
        printf("[DEBUG] Packet too short for TCP header.\n");
        return;
    }
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr_len);
    printf("[DEBUG] TCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcp_hdr->source));
    printf("  Dest Port: %d\n", ntohs(tcp_hdr->dest));
    printf("  Sequence Num: %u\n", ntohl(tcp_hdr->seq));
    printf("  Flags: SYN=%d, ACK=%d, RST=%d, FIN=%d\n",
           tcp_hdr->syn, tcp_hdr->ack, tcp_hdr->rst, tcp_hdr->fin);
}

/* Print packet in hex for debugging. */
void print_packet_hex(const unsigned char *packet, int len) {
    printf("[DEBUG] Packet length: %d bytes\n", len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i+1)%16 == 0) printf("\n");
    }
    printf("\n");
}

