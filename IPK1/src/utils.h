#ifndef UTILS_H
#define UTILS_H

#include <netinet/ip.h>    // for struct iphdr
#include <netinet/ip6.h>   // for struct ip6_hdr
#include <netinet/tcp.h>   // for struct tcphdr
#include "scan_tcp.h"      // for scan_task_t, port_scan_result_t, etc.

/* Generic 16-bit checksum over a buffer of 'len' bytes. */
unsigned short compute_checksum(const unsigned short *buf, int len);

/* TCP checksum for IPv4, using an IP pseudo-header. */
unsigned short tcp_checksum_ipv4(struct iphdr *iph, struct tcphdr *tcph);

/* TCP checksum for IPv6, given a full ip6_hdr plus the TCP header & length. */
unsigned short tcp_checksum_ipv6(const struct ip6_hdr *ip6h,
                                 const struct tcphdr *tcph,
                                 int tcph_len);

/*
 * The function that filters out ports with state != FILTERED.
 * 'task' is updated so that only the filtered ports remain in task->ports.
 * 'orig_index' is set to an array that maps from the new array's index
 * to the original index.
 */
int filter_ports(scan_task_t *task, int *orig_index[]);

/* Parse comma-separated port ranges (e.g. "80,443,1000-1010"). */
int parse_port_ranges(const char *port_str, int **ports, int *count);

/* Debug functions for printing IPv4/TCP headers, etc. */
void debug_print_ipv4(const unsigned char *packet, int len);
void print_packet_hex(const unsigned char *packet, int len);

#endif
