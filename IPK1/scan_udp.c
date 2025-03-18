#include "scan_udp.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

/*
 * Vláknová funkce provádějící UDP scan.
 * Postup:
 *  - Vytvoří se UDP socket pro odeslání (a ICMP socket – raw) pro příjem chybové odpovědi.
 *  - Pošle se prázdný UDP paket na daný port.
 *  - Pomocí poll() se čeká na ICMP odpověď.
 *  - U IPv4, pokud obdržíme ICMP zprávu typu 3, kódu 3 (port unreachable), znamená to, že port je "closed".
 *  - Pokud nedojde odpověď, port je označen jako "open" (podle zadání).
 */
void *udp_scan_thread(void *arg) {
    udp_scan_task_t *task = (udp_scan_task_t *) arg;
    int is_ipv6 = (strchr(task->target_ip, ':') != NULL);
    int sock_udp, sock_icmp;
    
    // Vytvoření UDP socketu a raw socketu pro příjem ICMP zpráv
    if (!is_ipv6) {
        sock_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else {
        sock_udp = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        sock_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (sock_udp < 0 || sock_icmp < 0) {
        perror("socket");
        strcpy(task->result, "error");
        pthread_exit(NULL);
    }
    
    // Nastavení cílové adresy pro UDP paket
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    if (!is_ipv6) {
        struct sockaddr_in *dest = (struct sockaddr_in *)&dest_addr;
        dest->sin_family = AF_INET;
        dest->sin_port = htons(task->port);
        dest->sin_addr.s_addr = inet_addr(task->target_ip);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *dest6 = (struct sockaddr_in6 *)&dest_addr;
        dest6->sin6_family = AF_INET6;
        dest6->sin6_port = htons(task->port);
        inet_pton(AF_INET6, task->target_ip, &dest6->sin6_addr);
        addr_len = sizeof(struct sockaddr_in6);
    }
    
    // Odeslání UDP paketu (i prázdný paket stačí)
    char dummy = 0;
    if (sendto(sock_udp, &dummy, sizeof(dummy), 0,
               (struct sockaddr *)&dest_addr, addr_len) < 0) {
        perror("sendto");
        strcpy(task->result, "error");
        close(sock_udp);
        close(sock_icmp);
        pthread_exit(NULL);
    }
    
    // Čekání na ICMP zprávu pomocí poll()
    struct pollfd pfd;
    pfd.fd = sock_icmp;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, task->timeout);
    if (ret > 0) {
        char buf[1024];
        ssize_t len = recv(sock_icmp, buf, sizeof(buf), 0);
        if (len > 0) {
            if (!is_ipv6) {
                // U IPv4 očekáváme IP hlavičku a ICMP hlavičku
                struct iphdr *iph = (struct iphdr *) buf;
                int ip_header_len = iph->ihl * 4;
                if ((long unsigned int)len < ip_header_len + sizeof(struct icmphdr))
                    strcpy(task->result, "open");
                else {
                    struct icmphdr *icmph = (struct icmphdr *)(buf + ip_header_len);
                    // ICMP typ 3, kód 3 znamená "port unreachable" → port zavřený
                    if (icmph->type == 3 && icmph->code == 3)
                        strcpy(task->result, "closed");
                    else
                        strcpy(task->result, "open");
                }
            } else {
                // U IPv6 – zjednodušeně předpokládáme, že pokud obdržíme ICMPv6 error (typ 1, kód 4),
                // port je zavřený
                struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;
                if (icmp6->icmp6_type == 1 && icmp6->icmp6_code == 4)
                    strcpy(task->result, "closed");
                else
                    strcpy(task->result, "open");
            }
        } else {
            strcpy(task->result, "open");
        }
    } else if (ret == 0) {
        // Pokud nedojde odpověď, podle zadání je port označen jako "open"
        strcpy(task->result, "open");
    } else {
        perror("poll");
        strcpy(task->result, "error");
    }
    
    close(sock_udp);
    close(sock_icmp);
    pthread_exit(NULL);
}
