#ifndef UTILS_H
#define UTILS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "packet_structures.h"

// Funkce pro výpočet kontrolního součtu (checksum)
unsigned short compute_checksum(unsigned short *ptr, int nbytes);

// Funkce pro výpočet TCP kontrolního součtu pro IPv4, využívá pseudohlavičku
unsigned short tcp_checksum_ipv4(struct iphdr *iph, struct tcphdr *tcph);

// Funkce pro výpočet TCP kontrolního součtu pro IPv6; pseudohlavička se sestavuje z řetězcových adres
unsigned short tcp_checksum_ipv6(const char *src, const char *dst, struct tcphdr *tcph, int tcph_len);

// Funkce pro parsování řetězce s porty (např. "22,80,443" nebo "1-100")
int parse_port_ranges(const char *port_str, int **ports, int *count);


void debug_print_ipv4(const u_char *packet, int len);
void print_packet_hex(const u_char *packet, int len);
int filter_ports(scan_task_t *task, int *tcp_task_copy_i[]);
int random2000(void);

#endif
