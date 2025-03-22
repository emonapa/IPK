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


/* Struktura pro odeslání jednoho SYN paketu */
typedef struct {
    scan_task_t *task;
    char packet[PACKET_SIZE];
    int packet_len;
    int target_port; // Cílový port, který se doplní do TCP hlavičky
    struct sockaddr_storage dest_addr;
    socklen_t addr_len;
    int send_id;     // Pro debug (volitelné)
} send_packet_params_t;

/* ==================== ODESÍLÁNÍ PAKETŮ ==================== */
void send_packet(send_packet_params_t *params) {
    scan_task_t *task = params->task;
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

    if (sendto(sock_send, params->packet, params->packet_len, 0,
               (struct sockaddr *)&params->dest_addr, params->addr_len) < 0) {
        perror("sendto");
    }
    close(sock_send);
}

void *send_packets(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
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
        tcph->dest = 0; // bude dosazeno při každém odeslání
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = sizeof(struct tcphdr) / 4;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        struct sockaddr_in *dst4 = (struct sockaddr_in *)&dest_addr_template;
        dst4->sin_family = AF_INET;
        dst4->sin_port = 0;
        dst4->sin_addr.s_addr = inet_addr(task->target_ip);

    } else {
        struct tcphdr *tcph = (struct tcphdr *)packet_template;
        packet_len = sizeof(struct tcphdr);

        tcph->source = htons(task->src_port);
        tcph->dest = 0; // dosadíme při odeslání
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
    pthread_exit(NULL);
}

/* ==================== PŘÍJEM PAKETŮ (PCAP) ==================== */
typedef struct {
    pcap_t *pcap_handle;
    scan_task_t *task;
    sem_t *main_sem;
    pthread_mutex_t *packets_mutex; 
} capture_user_data_t;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header; // aby nebylo varování, pokud ho nevyužíváte
    capture_user_data_t *cap_data = (capture_user_data_t *)user;
    scan_task_t *task = cap_data->task;

    int eth_offset = 14; // Ethernet header (za předpokladu, že tam opravdu je)
    int resp_port = 0;

    if (!task->is_ipv6) {
        struct iphdr *iph = (struct iphdr *)(packet + eth_offset);
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(packet + eth_offset + ip_hdr_len);
        resp_port = ntohs(tcph->source);

        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == resp_port) {
                if (tcph->syn && tcph->ack) {
                    task->ports[i].state = OPEN;
                }
                else if (tcph->rst) {
                    task->ports[i].state = CLOSED;
                }
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

    pthread_mutex_lock(cap_data->packets_mutex);
    task->packets_received++;

    // Když dosáhneme počtu num_ports, končíme
    if (task->packets_received >= task->num_ports) {
        pcap_breakloop(cap_data->pcap_handle);
        sem_post(cap_data->main_sem);
    }
    pthread_mutex_unlock(cap_data->packets_mutex);
}

void *capture_packets(void *arg) {
    capture_user_data_t *cap_data = (capture_user_data_t *)arg;
    printf("Pocet portu na prozkoumani: %d\n", cap_data->task->num_ports);

    // Spustíme pcap_loop => blokuje, dokud nepřijde pcap_breakloop()
    int ret = pcap_loop(cap_data->pcap_handle, -1, packet_handler, (u_char *)cap_data);
    printf("[DEBUG] PCAP_LOOP SKONCIL\n");

    if (ret == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cap_data->pcap_handle));
    } else if (ret == PCAP_ERROR_BREAK) {
        printf("pcap_loop terminated by pcap_breakloop()\n");
    }

    printf("[DEBUG] exit captue s pcap_loopem()\n");
    pthread_exit(NULL);
}

/* Vytvoření a aktivace pcap handle s daným rozhraním. */
pcap_t *create_pcap_handle(char interface[], char errbuf[]) {
    pcap_t *pcap_handle = pcap_create(interface, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        pthread_exit((void*)"error");
    }

    // Snapshot délka
    if (pcap_set_snaplen(pcap_handle, BUFSIZ) != 0) {
        fprintf(stderr, "pcap_set_snaplen failed\n");
        pthread_exit((void*)"error");
    }

    // Promiskuitní režim
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        pthread_exit((void*)"error");
    }

    // Read timeout (ms) – pro blokující čtení v pcap_loop
    if (pcap_set_timeout(pcap_handle, 50) != 0) {
        fprintf(stderr, "pcap_set_timeout failed\n");
        pthread_exit((void*)"error");
    }

    //// Nastavíme velikost bufferu např. 15 MB
    //int desired_buffer_size = 1 * 1024 * 1024;
    //if (pcap_set_buffer_size(pcap_handle, desired_buffer_size) < 0) {
    //    fprintf(stderr, "pcap_set_buffer_size failed: %s\n", pcap_geterr(pcap_handle));
    //    pthread_exit((void*)"error");
    //}

    // Aktivace
    if (pcap_activate(pcap_handle) < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(pcap_handle));
        pthread_exit((void*)"error");
    }

    return pcap_handle;
}

/* ==================== HLAVNÍ SKENOVACÍ VLÁKNO ==================== */
void *tcp_scan_thread(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
    
    // Inicializace mutexu pro počítání přijatých paketů
    pthread_mutex_t packets_mutex;
    pthread_mutex_init(&packets_mutex, NULL);
    task->packets_received = 0;
    
    // 1. Vytvoříme pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = create_pcap_handle(task->interface, errbuf);

    // 2. Aplikujeme BPF filtr
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

    // 3. Hlavní semafor
    sem_t main_sem;
    sem_init(&main_sem, 0, 0);
    
    // 4. Spustíme vlákno pro příjem paketů (pcap_loop)
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

    // 5. Spustíme vlákno, které odešle SYN pakety sekvenčně
    pthread_t tid_send;
    if (pthread_create(&tid_send, NULL, send_packets, task) != 0) {
        perror("pthread_create send_packets");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }

    // 6. Čekáme na semafor s timeoutem
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Přičteme timeout (ms) do ts
    ts.tv_sec += task->timeout / 1000;                        // celé vteřiny
    ts.tv_nsec += (task->timeout % 1000) * 1000000L;          // zbytek do ns

    // Normalizace, pokud jsme přesáhli 1 s v nanosekundách
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    printf("Cekam do: %ld s, %ld ns\n", ts.tv_sec, ts.tv_nsec);

    int sem_ret = sem_timedwait(&main_sem, &ts);
    //sleep(1);
    if (sem_ret != 0) {
        // Timeout vypršel => breakloop
        pcap_breakloop(pcap_handle);
        printf("[DEBUG] Vypršel čas semaforu - ruším pcap_loop\n");
    } else {
        printf("[DEBUG] Všechny odpovědi byly přijaty.\n");
    }

    // 7. Připojení vláken
    pthread_join(tid_send, NULL);
    printf("[DEBUG] TID_SEND joinuty\n");
    pthread_join(tid_capture, NULL);
    printf("[DEBUG] Vsechny thready spojene!\n");

    // 8. Výpis statistik
    struct pcap_stat stats;
    if (pcap_stats(pcap_handle, &stats) < 0) {
        fprintf(stderr, "pcap_stats error: %s\n", pcap_geterr(pcap_handle));
    } else {
        printf("=== PCAP STATS ===\n");
        printf("Zachyceno  : %u\n", stats.ps_recv);
        printf("Dropnuto OS: %u\n", stats.ps_drop);
        printf("Dropnuto IF: %u\n", stats.ps_ifdrop);
    }

    // 9. Zavření pcap a úklid
    pcap_close(pcap_handle);
    sem_destroy(&main_sem);
    pthread_mutex_destroy(&packets_mutex);

    pthread_exit(NULL);
    return 0;
}
