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
#include <poll.h>
#include <semaphore.h>
#include <time.h>
#include <pthread.h>

#define PACKET_SIZE 4096

/* 
  Předpokládejme, že tcp_scan_task_t obsahuje alespoň:
    int src_port;
    char target_ip[64];
    char interface[64];
    int num_ports;
    port_scan_result_t *ports;   // Každý prvek obsahuje: int port; int state; (OPEN, CLOSED, FILTERED)
    int timeout;                 // Timeout v ms
    int packets_received;        // Počáteční hodnota 0
    pthread_mutex_t packets_mutex;  // Mutex pro chránění packets_received
    int is_ipv6;                 // 0 = IPv4, 1 = IPv6
    sem_t *main_sem;             // Ukazatel na hlavní semafor (předáme jej do callbacku)
*/

/* Struktura pro odeslání jednoho SYN paketu */
typedef struct {
    tcp_scan_task_t *task;
    char packet[PACKET_SIZE];
    int packet_len;
    int target_port; // Cílový port, který se doplní do TCP hlavičky
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    int send_id;     // Pro debug (volitelné)
} send_packet_params_t;

/* ==================== ODESÍLÁNÍ PAKETŮ ==================== */
/* Funkce, která odešle jeden SYN paket (volána sekvenčně). */
void send_packet(send_packet_params_t *params) {
    tcp_scan_task_t *task = params->task;
    int sock_send = -1;
    if (!task->is_ipv6) {
        sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock_send < 0) {
            perror("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)");
            return;
        }
        int on = 1;
        if (setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt(IP_HDRINCL)");
            close(sock_send);
            return;
        }
    } else {
        sock_send = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock_send < 0) {
            perror("socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)");
            return;
        }
    }
    if (strlen(task->interface) > 0) {
        if (setsockopt(sock_send, SOL_SOCKET, SO_BINDTODEVICE,
                       task->interface, strlen(task->interface) + 1) < 0) {
            perror("setsockopt(SO_BINDTODEVICE)");
            close(sock_send);
            return;
        }
    }
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
    //printf("[DEBUG] SENDUJU!\n");
    if (sendto(sock_send, params->packet, params->packet_len, 0,
               (struct sockaddr *)&params->dest_addr, params->addr_len) < 0) {
        perror("sendto");
    }
    close(sock_send);
}

/* Funkce, která odešle všechny SYN pakety sekvenčně v jednom vlákně. */
void *send_packets(void *arg) {
    tcp_scan_task_t *task = (tcp_scan_task_t *)arg;
    char packet_template[PACKET_SIZE];
    memset(packet_template, 0, sizeof(packet_template));
    int packet_len = 0;
    struct sockaddr_storage dest_addr_template;
    memset(&dest_addr_template, 0, sizeof(dest_addr_template));
    
    if (!task->is_ipv6) {
        struct iphdr *iph = (struct iphdr *)packet_template;
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
        tcph->dest = 0; // bude dosazeno v odeslání
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        struct sockaddr_in *dst4 = (struct sockaddr_in *)&dest_addr_template;
        dst4->sin_family = AF_INET;
        dst4->sin_port = 0; // bude dosazeno v odeslání
        dst4->sin_addr.s_addr = inet_addr(task->target_ip);
    } else {
        struct tcphdr *tcph = (struct tcphdr *)packet_template;
        packet_len = sizeof(struct tcphdr);
        tcph->source = htons(task->src_port);
        tcph->dest = 0; // bude dosazeno v odeslání
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dest_addr_template;
        dst6->sin6_family = AF_INET6;
        dst6->sin6_port = 0;
        inet_pton(AF_INET6, task->target_ip, &dst6->sin6_addr);
    }
    
    for (int i = 0; i < task->num_ports; i++) {
        send_packet_params_t params;
        params.task = task;
        params.packet_len = packet_len;
        memcpy(params.packet, packet_template, packet_len);
        params.target_port = task->ports[i].port;
        memcpy(&params.dest_addr, &dest_addr_template, sizeof(dest_addr_template));
        if (!task->is_ipv6) {
            ((struct sockaddr_in *)&params.dest_addr)->sin_port = htons(task->ports[i].port);
            params.addr_len = sizeof(struct sockaddr_in);
        } else {
            ((struct sockaddr_in6 *)&params.dest_addr)->sin6_port = htons(task->ports[i].port);
            params.addr_len = sizeof(struct sockaddr_in6);
        }
        send_packet(&params);
    }
    //printf("[DEBUG] exit send packtes.\n");
    pthread_exit(NULL);
}

/* ==================== PŘÍJEM PAKETŮ ==================== */

/* Struktura pro předání uživatelských dat do callbacku pcap_loop(). */
typedef struct {
    pcap_t *pcap_handle;
    tcp_scan_task_t *task;
    sem_t *main_sem; // Hlavní semafor, který bude uvolněn, když obdržíme všechny odpovědi.
    pthread_mutex_t *packets_mutex; // Ukazatel na mutex pro ochranu packets_received.
} capture_user_data_t;

/* Callback funkce pro pcap_loop().
   Zpracovává paket, aktualizuje počet přijatých paketů pod ochranou mutexu
   a pokud počet dosahne task->num_ports, uvolní hlavní semafor. */
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    //printf("[DEBUG] Prijal jsem packet\n");
    capture_user_data_t *cap_data = (capture_user_data_t *)user;
    tcp_scan_task_t *task = cap_data->task;
    int eth_offset = 14; // předpokládáme Ethernet header
    int resp_port = 0;
    if (!task->is_ipv6) {
        struct iphdr *iph = (struct iphdr *)(packet + eth_offset);
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(packet + eth_offset + ip_hdr_len);
        resp_port = ntohs(tcph->source);
        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == resp_port) {
                if (tcph->syn && tcph->ack)
                    task->ports[i].state = OPEN;
                else if (tcph->rst)
                    task->ports[i].state = CLOSED;
                break;
            }
        }
    } else {
        int ip6_hdr_len = sizeof(struct ip6_hdr);
        struct tcphdr *tcph = (struct tcphdr *)(packet + eth_offset + ip6_hdr_len);
        resp_port = ntohs(tcph->source);
        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == resp_port) {
                if (tcph->syn && tcph->ack)
                    task->ports[i].state = OPEN;
                else if (tcph->rst)
                    task->ports[i].state = CLOSED;
                break;
            }
        }
    }
}

/* Vlákno pro příjem paketů pomocí pcap_loop(). */
void *capture_packets(void *arg) {
    capture_user_data_t *cap_data = (capture_user_data_t *)arg;
    printf("Pocet portu na prozkoumani: %d\n", cap_data->task->num_ports);
    int ret = pcap_loop(cap_data->pcap_handle, cap_data->task->num_ports, packet_handler, (u_char *)cap_data);
    printf("[DEBUG] PCAP_LOOP SKONCIL\n");
    if (ret == PCAP_ERROR)
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cap_data->pcap_handle));
    else if (ret == PCAP_ERROR_BREAK)
        printf("pcap_loop terminated by pcap_breakloop()\n");
    else if (ret == 0)
        sem_post(cap_data->main_sem);
    printf("[DEBUG] exit captue s pcap_loopem()\n");
    pthread_exit(NULL);
}

/* ==================== HLAVNÍ SKENOVACÍ VLÁKNO ==================== */
void *tcp_scan_thread(void *arg) {
    tcp_scan_task_t *task = (tcp_scan_task_t *)arg;
    
    /* Inicializace mutexu pro počet přijatých paketů */
    pthread_mutex_t packets_mutex;
    pthread_mutex_init(&packets_mutex, NULL);
    task->packets_received = 0;
    
    /* 1. Vytvoříme pcap handle s filtrem, bez interního read timeoutu (timeout=0) */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live(task->interface, BUFSIZ, 1, 1, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pthread_exit((void*)"error");
    }
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
    
    /* 2. Vytvoříme hlavní semafor pro čekání na všechny odpovědi. */
    sem_t main_sem;
    sem_init(&main_sem, 0, 0);
    
    /* 3. Spustíme vlákno pro příjem paketů pomocí pcap_loop(). */
    capture_user_data_t cap_data;
    cap_data.pcap_handle = pcap_handle;
    cap_data.task = task;
    cap_data.main_sem = &main_sem;
    cap_data.packets_mutex = &packets_mutex;
    pthread_t tid_capture;
    if (pthread_create(&tid_capture, NULL, capture_packets, &cap_data) != 0) {
        perror("pthread_create capture_packets");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    //sleep(3);

    /* 4. Spustíme vlákno, které odešle všechny SYN pakety sekvenčně. */
    pthread_t tid_send;
    if (pthread_create(&tid_send, NULL, send_packets, task) != 0) {
        perror("pthread_create send_packets");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    
    /* 5. Hlavní vlákno čeká pomocí sem_timedwait() na hlavní semafor.
       Nastavíme absolutní čas, do kdy čekat: aktuální čas + task->timeout ms. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += task->timeout / 1000;
    ts.tv_nsec += task->timeout * 1000;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
    }
    printf("Cas: %ld s, %ld ns\n", ts.tv_sec, ts.tv_nsec);


    int sem_ret = sem_timedwait(&main_sem, &ts);
    if (sem_ret != 0) {
        perror("sem_timedwait main_sem");
    } else {
        printf("[DEBUG] Všechny odpovědi byly přijaty.\n");
    }

    
    /* 6. Ukončíme pcap_loop() zavoláním pcap_breakloop() */
    pcap_breakloop(pcap_handle);
    //printf("[DEBUG] BREAKLOOP\n");

    pthread_join(tid_send, NULL);
    //printf("[DEBUG] TID_SEND joinuty\n");
    pthread_join(tid_capture, NULL);
    //printf("[DEBUG] Vsechny thready spojene!\n");



    /* Vyčteme zbývající pakety z pcap bufferu (pokud nějaké jsou) */
    struct pcap_pkthdr *header;
    const u_char *pcap_packet;
    while (pcap_next_ex(pcap_handle, &header, &pcap_packet) == 1) {
        packet_handler((u_char *)&cap_data, header, pcap_packet);
    }
    //printf("[DEBUG] Docetl jsem packety z bufferu!\n");

    pcap_close(pcap_handle);
    sem_destroy(&main_sem);
    pthread_mutex_destroy(&packets_mutex);
    pthread_exit(NULL);
}
