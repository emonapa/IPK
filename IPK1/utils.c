#include "utils.h"
#include "scan_tcp.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

// Příklad funkce, která filtruje pole portů, ponechá jen ty s hodnotou stavu FILTERED (2)
int filter_ports(scan_task_t *task, int *tcp_task_copy_i[]) {
    printf("TADY SNAD JO NE\n");
    int count = 0;
    // Nejprve spočítáme, kolik portů má stav FILTERED
    for (int i = 0; i < task->num_ports; i++) {
        if (task->ports[i].state == FILTERED) {
            count++;
        }
    }

    if (count != 0){
        // Alokujeme nové pole s přesnou velikostí
        port_scan_result_t *new_ports = malloc(count * sizeof(port_scan_result_t));
        int *new_copy_i = malloc(count * sizeof(int));
        if (!new_ports || !new_copy_i) {
            perror("malloc");
            return -1;
        }
        int j = 0;
        // Zkopírujeme pouze porty, které mají stav FILTERED
        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].state == FILTERED) {
                new_ports[j] = task->ports[i];
                new_copy_i[j] = i;
                j++;
            }
        }
        // Uvolníme původní pole a aktualizujeme task
        *tcp_task_copy_i = new_copy_i;
        task->ports = new_ports;
        task->num_ports = count;
    }
    return count;
}


// Výpočet kontrolního součtu podle standardního algoritmu
unsigned short compute_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    
    return answer;
}

// Výpočet TCP kontrolního součtu pro IPv4 pomocí pseudohlavičky
unsigned short tcp_checksum_ipv4(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;
    
    int tcp_len = sizeof(struct tcphdr);
    psh.src_addr = iph->saddr;
    psh.dst_addr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);
    
    int psize = sizeof(psh) + tcp_len;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, tcp_len);
    
    unsigned short checksum = compute_checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return checksum;
}

// Výpočet TCP kontrolního součtu pro IPv6; sestavuje pseudohlavičku z textových IP adres
unsigned short tcp_checksum_ipv6(const char *src, const char *dst, struct tcphdr *tcph, int tcph_len) {
    struct pseudo_header_ipv6 {
        unsigned char src_addr[16];
        unsigned char dst_addr[16];
        unsigned int tcp_length;
        unsigned char zeros[3];
        unsigned char next_header;
    } psh6;
    
    memset(&psh6, 0, sizeof(psh6));
    inet_pton(AF_INET6, src, psh6.src_addr);
    inet_pton(AF_INET6, dst, psh6.dst_addr);
    psh6.tcp_length = htonl(tcph_len);
    psh6.next_header = IPPROTO_TCP;
    
    int psize = sizeof(psh6) + tcph_len;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh6, sizeof(psh6));
    memcpy(pseudogram + sizeof(psh6), tcph, tcph_len);
    
    unsigned short checksum = compute_checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    return checksum;
}

// Funkce pro parsování řetězce s porty, podporuje čárkou oddělené hodnoty i rozsahy (např. "80,443" nebo "1000-1010")
int parse_port_ranges(const char *port_str, int **ports, int *count) {
    char *str = strdup(port_str);
    if (!str)
        return -1;
    int capacity = 10;
    int *p = malloc(capacity * sizeof(int));
    int cnt = 0;
    
    char *token = strtok(str, ",");
    while (token != NULL) {
        char *dash = strchr(token, '-');
        if (dash) {
            // Rozsah portů
            *dash = '\0';
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int i = start; i <= end; i++) {
                if (cnt >= capacity) {
                    capacity *= 2;
                    p = realloc(p, capacity * sizeof(int));
                }
                p[cnt++] = i;
            }
        } else {
            int port = atoi(token);
            if (cnt >= capacity) {
                capacity *= 2;
                p = realloc(p, capacity * sizeof(int));
            }
            p[cnt++] = port;
        }
        token = strtok(NULL, ",");
    }
    free(str);
    *ports = p;
    *count = cnt;
    return 0;
}

// Debugovací funkce pro tisk IP a TCP hlaviček (IPv4)
void debug_print_ipv4(const u_char *packet, int len) {
    if (len < sizeof(struct iphdr)) {
        printf("[DEBUG] Paket je příliš krátký pro IP hlavičku.\n");
        return;
    }
    struct iphdr *ip_hdr = (struct iphdr *)(packet + 14);
    int ip_hdr_len = ip_hdr->ihl * 4;
    printf("[DEBUG] IP Header:\n");
    printf("  Version: %d\n", ip_hdr->version);
    printf("  IHL: %d (%d bajtů)\n", ip_hdr->ihl, ip_hdr_len);
    printf("  Total Length: %d\n", ntohs(ip_hdr->tot_len));
    printf("  Protocol: %d\n", ip_hdr->protocol);
    printf("  Source: %s\n", inet_ntoa(*(struct in_addr *)&ip_hdr->saddr));
    printf("  Destination: %s\n", inet_ntoa(*(struct in_addr *)&ip_hdr->daddr));

    if (len < ip_hdr_len + sizeof(struct tcphdr)) {
        printf("[DEBUG] Paket je příliš krátký pro TCP hlavičku po IP hlavičce.\n");
        return;
    }
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_hdr_len);
    printf("[DEBUG] TCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcp_hdr->source));
    printf("  Destination Port: %d\n", ntohs(tcp_hdr->dest));
    printf("  Sequence Number: %u\n", ntohl(tcp_hdr->seq));
    printf("  Flags: SYN=%d, ACK=%d, RST=%d, FIN=%d, PSH=%d, URG=%d\n",
           tcp_hdr->syn, tcp_hdr->ack, tcp_hdr->rst, tcp_hdr->fin, tcp_hdr->psh, tcp_hdr->urg);
}


// Debugovací výpis celého paketu v hex formátu
void print_packet_hex(const u_char *packet, int len) {
    printf("[DEBUG] Celková délka paketu: %d bajtů\n", len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}



int random2000(void) {
    srand(time(NULL));  // Inicializace generátoru náhodných čísel
    int random_number = rand() % 1001;  // Vygeneruje číslo od 0 do 2000 včetně
    return random_number;
}