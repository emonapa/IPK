#include "scan_tcp.h"
#include "utils.h"
#include "interfaces.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <sys/select.h>
#include <poll.h>
#include <semaphore.h>

#define PACKET_SIZE 4096

/* Struktura předávaná do vlákna pro odeslání jednoho SYN paketu */
typedef struct {
    tcp_scan_task_t *task;
    char packet[PACKET_SIZE];
    int packet_len;
    int target_port;  // cílový port, který se dosadí do TCP hlavičky
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    //sem_t *send_sem;  // ukazatel na semafor pro synchronizaci odeslání
    int send_sem;  // ukazatel na semafor pro synchronizaci odeslání
} send_packet_params_t;

int randomPP = 1;

/* Vlákno, které odešle jeden SYN paket.
   Před odesláním doplní cílový port, přepočítá checksum a odešle paket přes raw socket.
   Na konci zavolá sem_post, aby signalizovalo dokončení odeslání. */
void *send_packet_thread(void *arg) {
    send_packet_params_t *params = (send_packet_params_t *)arg;
    tcp_scan_task_t *task = params->task;
    if (params->send_sem % 2 == 1){
        sleep((4+params->send_sem) % 4);
        //printf("Port %d was sleeping for %d seconds\n", params->target_port, (4+params->send_sem) % 15);
    }
    randomPP += 1;
    int sock_send = -1;

    if (!task->is_ipv6) {
        sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock_send < 0) {
            perror("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)");
            pthread_exit((void*)"error");
        }
        int on = 1;
        if (setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt(IP_HDRINCL)");
            close(sock_send);
            pthread_exit((void*)"error");
        }
    } else {
        sock_send = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock_send < 0) {
            perror("socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)");
            pthread_exit((void*)"error");
        }
    }
    if (strlen(task->interface) > 0) {
        if (setsockopt(sock_send, SOL_SOCKET, SO_BINDTODEVICE,
                       task->interface, strlen(task->interface) + 1) < 0) {
            perror("setsockopt(SO_BINDTODEVICE)");
            close(sock_send);
            pthread_exit((void*)"error");
        }
    }

    /* Dosadíme cílový port do TCP hlavičky a přepočítáme checksum */
    if (!task->is_ipv6) {
        struct tcphdr *tcph = (struct tcphdr *)(params->packet + sizeof(struct iphdr));
        tcph->dest = htons(params->target_port);
        tcph->check = 0;
        tcph->check = tcp_checksum_ipv4((struct iphdr *)params->packet, tcph);
        ((struct sockaddr_in *)&params->dest_addr)->sin_port = htons(params->target_port);
    } else {
        struct tcphdr *tcph = (struct tcphdr *)params->packet;
        tcph->dest = htons(params->target_port);
        tcph->check = 0;
        tcph->check = tcp_checksum_ipv6(task->interface, task->target_ip, tcph, sizeof(struct tcphdr));
        ((struct sockaddr_in6 *)&params->dest_addr)->sin6_port = htons(params->target_port);
    }

    //printf("[SEND THREAD] Sending SYN packet to port %d...\n", params->target_port);
    if (sendto(sock_send, params->packet, params->packet_len, 0,
               (struct sockaddr *)&params->dest_addr, params->addr_len) < 0) {
        perror("sendto");
        close(sock_send);
        pthread_exit((void*)"error");
    }
    //printf("[SEND THREAD] Packet sent to port %d.\n", params->target_port);
    close(sock_send);

    /* Signalizujeme, že tento paket byl odeslán */
    //sem_post(params->send_sem);
    pthread_exit(NULL);
}

/* Hlavní vlákno skenování:
   1. Připraví "template" paketu (pro IPv4: IP + TCP, pro IPv6: pouze TCP).
   2. Sestaví BPF filtr podle cílové IP, zdrojového portu a odesílaných portů.
   3. Spustí vlákna pro odeslání SYN paketů na všechny zadané porty.
   4. Pomocí semaforu počká, dokud nejsou všechny pakety odeslány.
   5. Centrálně v cyklu pomocí poll() a neblokujícího pcap sbírá odpovědi.
   6. Odpovědi analyzuje – pokud přijdou SYN/ACK, port vyhodnotí jako OPEN, pokud RST, jako CLOSED.
   7. Po uplynutí timeoutu (nebo dříve, pokud dorazí odpovědi ke všem portům) pro porty bez odpovědi zůstane stav FILTERED.
*/
void *tcp_scan_thread(void *arg) {
    tcp_scan_task_t *task = (tcp_scan_task_t *) arg;

    /* 1. Příprava template paketu a adresy */
    char packet_template[PACKET_SIZE];
    memset(packet_template, 0, sizeof(packet_template));
    int packet_len = 0;
    struct sockaddr_storage dest_addr_template;
    memset(&dest_addr_template, 0, sizeof(dest_addr_template));

    if (!task->is_ipv6) {
        struct iphdr *iph = (struct iphdr *) packet_template;
        struct tcphdr *tcph = (struct tcphdr *)(packet_template + sizeof(struct iphdr));
        packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(packet_len);
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;

        char src_ip[INET_ADDRSTRLEN] = "0.0.0.0";
        if (get_interface_address(task->interface, AF_INET, src_ip, sizeof(src_ip)) < 0) {
            fprintf(stderr, "get_interface_address failed\n");
            pthread_exit((void*)"error");
        }
        iph->saddr = inet_addr(src_ip);
        iph->daddr = inet_addr(task->target_ip);
        iph->check = 0;
        iph->check = compute_checksum((unsigned short*)iph, sizeof(struct iphdr));

        tcph->source = htons(task->src_port);
        tcph->dest = 0; // dosadí se později
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        struct sockaddr_in *dst4 = (struct sockaddr_in *)&dest_addr_template;
        dst4->sin_family = AF_INET;
        dst4->sin_port = 0; // dosadí se později
        dst4->sin_addr.s_addr = inet_addr(task->target_ip);
    } else {
        /* IPv6: sestavíme pouze TCP hlavičku */
        struct tcphdr *tcph = (struct tcphdr *) packet_template;
        packet_len = sizeof(struct tcphdr);

        tcph->source = htons(task->src_port);
        tcph->dest = 0; // dosadí se později
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dest_addr_template;
        dst6->sin6_family = AF_INET6;
        dst6->sin6_port = 0; // dosadí se později
        inet_pton(AF_INET6, task->target_ip, &dst6->sin6_addr);
    }

    /* 2. Sestavení BPF filtru – zachytává odpovědi z cílové IP, se zdrojovým portem naší stanice
       a odpovědi ze zdrojových portů odpovídajících odeslaným SYN paketům. */
    char filter_exp[256];
    if (!task->is_ipv6) {
        snprintf(filter_exp, sizeof(filter_exp),
                "tcp and src host %s and dst port %d",
                task->target_ip, task->src_port);
    } else {
        snprintf(filter_exp, sizeof(filter_exp),
                "ip6 and tcp and src host %s and dst port %d",
                task->target_ip, task->src_port);
    }
    printf("[DEBUG] BPF filter: %s\n", filter_exp);


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live(task->interface, BUFSIZ, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pthread_exit((void*)"error");
    }
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap_handle));
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    pcap_freecode(&fp);

    if (pcap_setnonblock(pcap_handle, 1, errbuf) < 0) {
        fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }

    /* Inicializace semaforu pro synchronizaci odeslání paketů.
       Počet čekání = počet portů, které skenujeme. */
    //sem_t send_sem;
    //if (sem_init(&send_sem, 0, 0) != 0) {
    //    perror("sem_init");
    //    pcap_close(pcap_handle);
    //    pthread_exit((void*)"error");
    //}

    /* 3. Odeslání SYN paketů – pro každý port vytvoříme vlákno, které odešle svůj paket */
    pthread_t *send_tids = malloc(task->num_ports * sizeof(pthread_t));
    send_packet_params_t *send_params = malloc(task->num_ports * sizeof(send_packet_params_t));
    if (!send_tids || !send_params) {
        perror("malloc");
        pcap_close(pcap_handle);
        //sem_destroy(&send_sem);
        pthread_exit((void*)"error");
    }
    for (int i = 0; i < task->num_ports; i++) {
        send_params[i].task = task;
        send_params[i].packet_len = packet_len;
        memcpy(send_params[i].packet, packet_template, packet_len);
        send_params[i].target_port = task->ports[i].port;
        memcpy(&send_params[i].dest_addr, &dest_addr_template, sizeof(dest_addr_template));
        if (!task->is_ipv6) {
            ((struct sockaddr_in *)&send_params[i].dest_addr)->sin_port = htons(task->ports[i].port);
            send_params[i].addr_len = sizeof(struct sockaddr_in);
        } else {
            ((struct sockaddr_in6 *)&send_params[i].dest_addr)->sin6_port = htons(task->ports[i].port);
            send_params[i].addr_len = sizeof(struct sockaddr_in6);
        }
        //send_params[i].send_sem = &send_sem;  // předáme ukazatel na semafor
        send_params[i].send_sem = i;
        if (pthread_create(&send_tids[i], NULL, send_packet_thread, &send_params[i]) != 0) {
            perror("pthread_create");
        }
    }

    /* Čekáme, dokud všechny vlákna neodesílají své pakety */
    //for (int i = 0; i < task->num_ports; i++) {
    //    sem_wait(&send_sem);
    //}
    //printf("[DEBUG] Všechny SYN pakety byly odeslány.\n");

    /* Ještě joinneme vlákna, abychom se ujistili, že skončila */


    //sem_destroy(&send_sem);
    

    /* 4. Centrální smyčka pro příjem odpovědí.
       Používáme poll() s dynamickým timeoutem a v neblokujícím režimu voláme pcap_next_ex().
       Jakmile jsou všechny odpovědi obdrženy nebo uplyne timeout, cyklus končí. */
    int received = 0;
    int done = 0;
    int pcap_fd = pcap_get_selectable_fd(pcap_handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "pcap_get_selectable_fd returned -1\n");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }

    struct timespec begin_time, now;
    clock_gettime(CLOCK_MONOTONIC, &begin_time);

    while (!done) {
        printf("_______________________________________________________________________\n");
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - begin_time.tv_sec) * 1000 +
                        (now.tv_nsec - begin_time.tv_nsec) / 1000000;

        if (elapsed_ms >= task->timeout) 
            break;

        long remaining_ms = task->timeout - elapsed_ms;
        
        struct pcap_stat stats;
        if (pcap_stats(pcap_handle, &stats) == 0) {
            printf("[DEBUG] pcap_stats: received=%u, dropped=%u, if_dropped=%u\n",
                stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
        } else {
            fprintf(stderr, "[DEBUG] pcap_stats failed: %s\n", pcap_geterr(pcap_handle));
        }
        
        printf("Elapsed: %ld ms\n", elapsed_ms);
        printf("Remaining: %ld ms\n", remaining_ms);
        
        struct pollfd pfd;
        pfd.fd = pcap_fd;
        pfd.events = POLLIN;
        int poll_ret = poll(&pfd, 1, remaining_ms);

        if (poll_ret > 0) {
            struct pcap_pkthdr *header;
            const u_char *pcap_packet;
            while (pcap_next_ex(pcap_handle, &header, &pcap_packet) == 1) {
                //printf("Zpracovavam paket...\n");
                // Případně zde zavolejte svou funkci pro tisk/případné zpracování paketu
                // debug_print_ipv4(pcap_packet, header->len);
                int eth_offset = 14; // předpokládáme Ethernet header (14 bajtů)
                if (!task->is_ipv6) {
                    struct iphdr *rip = (struct iphdr *)(pcap_packet + eth_offset);
                    int ip_hdr_len = rip->ihl * 4;
                    struct tcphdr *rtcp = (struct tcphdr *)(pcap_packet + eth_offset + ip_hdr_len);
                    int resp_port = ntohs(rtcp->source);
                    for (int i = 0; i < task->num_ports; i++) {
                        if (task->ports[i].port == resp_port) {
                            if (rtcp->syn && rtcp->ack)
                                task->ports[i].state = OPEN;
                            else if (rtcp->rst)
                                task->ports[i].state = CLOSED;
                            received++;
                            break;
                        }
                    }
                } else {
                    int ip6_hdr_len = sizeof(struct ip6_hdr);
                    struct tcphdr *rtcp = (struct tcphdr *)(pcap_packet + eth_offset + ip6_hdr_len);
                    int resp_port = ntohs(rtcp->source);
                    for (int i = 0; i < task->num_ports; i++) {
                        if (task->ports[i].port == resp_port) {
                            if (rtcp->syn && rtcp->ack)
                                task->ports[i].state = OPEN;
                            else if (rtcp->rst)
                                task->ports[i].state = CLOSED;
                            received++;
                            break;
                        }
                    }
                }
                if (received >= task->num_ports) {
                    done = 1;
                    break;
                }
            }
        } else if (poll_ret == 0) {
            printf("___________________Poll timeout____________________\n");
            printf("Poll - Elapsed: %ld ms\n", elapsed_ms);
            printf("Poll - Remaining: %ld ms\n", remaining_ms);
            break;
        } else {
            perror("poll");
            break;
        }
    }

    //printf("SPIM\n");
    for (int i = 0; i < task->num_ports; i++) {
        pthread_join(send_tids[i], NULL);
    }
    free(send_tids);
    free(send_params);
    //printf("DOSPANO\n");

    pcap_close(pcap_handle);
    pthread_exit(NULL);
}