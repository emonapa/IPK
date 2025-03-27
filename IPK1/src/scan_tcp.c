/*
  Simple TCP raw-scan program with IPv4/IPv6 support.
  The key update is to properly build the IPv6 header for the outgoing raw packets,
  so that sendto() won't fail with "Invalid argument".
*/

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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <semaphore.h>
#include <time.h>


/* Build and send the packet (IPv4 or IPv6) */
void send_packet(send_packet_params_t *params) {
    scan_task_t *task = params->task;
    int sock_send;

    /* Create raw socket, choose IPv4 or IPv6 domain. */
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

    /* Optionally bind to a specific interface */
    if (strlen(task->interface) > 0) {
        if (setsockopt(sock_send, SOL_SOCKET, SO_BINDTODEVICE,
                       task->interface, strlen(task->interface) + 1) < 0)
        {
            perror("setsockopt(SO_BINDTODEVICE)");
            close(sock_send);
            return;
        }
    }

    /* Adjust ports/checksum for either IPv4 or IPv6 */
    if (!task->is_ipv6) {
        /* There's already an IPv4 header, then TCP. We finalize the TCP dest port & checksum. */
        struct iphdr *iph = (struct iphdr *)params->packet;
        struct tcphdr *tcph = (struct tcphdr *)(params->packet + sizeof(struct iphdr));
        tcph->dest = htons(params->target_port);
        tcph->check = 0;
        tcph->check = tcp_checksum_ipv4(iph, tcph);
        ((struct sockaddr_in *)&params->dest_addr)->sin_port = htons(params->target_port);
    } else {
        /* We have an IPv6 header + TCP header. We fix the TCP destination port and recalc. */
        struct ip6_hdr *ip6h = (struct ip6_hdr *)params->packet;
        struct tcphdr *tcph   = (struct tcphdr *)(params->packet + sizeof(struct ip6_hdr));
        tcph->dest = htons(params->target_port);
        tcph->check = 0;
        tcph->check = tcp_checksum_ipv6(ip6h, tcph, sizeof(struct tcphdr));
        ((struct sockaddr_in6 *)&params->dest_addr)->sin6_port = htons(params->target_port);
    }

    /* Actually send out the raw packet */
    if (sendto(sock_send, params->packet, params->packet_len, 0,
               (struct sockaddr *)&params->dest_addr, params->addr_len) < 0) {
        perror("sendto");
    }

    close(sock_send);
}

/* Build the IPv4 or IPv6 template, then send each port's packet in a loop */
void *send_packets(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
    char packet_template[PACKET_SIZE];
    memset(packet_template, 0, sizeof(packet_template));

    struct sockaddr_storage dest_addr_template;
    memset(&dest_addr_template, 0, sizeof(dest_addr_template));

    int packet_len = 0;

    /* If IPv4, build IP + TCP; if IPv6, build IPv6 hdr + TCP. */
    if (!task->is_ipv6) {
        struct iphdr  *iph = (struct iphdr *)packet_template;
        struct tcphdr *tcph = (struct tcphdr *)(packet_template + sizeof(struct iphdr));
        packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = htons(packet_len);
        iph->id       = htons(54321);
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;

        /* Source IP from interface */
        char src_ip[INET_ADDRSTRLEN] = "0.0.0.0";
        if (get_interface_address(task->interface, AF_INET, src_ip, sizeof(src_ip)) < 0) {
            fprintf(stderr, "get_interface_address failed\n");
            pthread_exit(NULL);
        }
        iph->saddr = inet_addr(src_ip);
        iph->daddr = inet_addr(task->target_ip);

        iph->check = 0;
        iph->check = compute_checksum((unsigned short*)iph, sizeof(struct iphdr));

        tcph->source  = htons(task->src_port);
        tcph->dest    = 0;  /* filled later */
        tcph->seq     = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff    = sizeof(struct tcphdr)/4;
        tcph->syn     = 1;
        tcph->window  = htons(5840);

        struct sockaddr_in *dst4 = (struct sockaddr_in *)&dest_addr_template;
        dst4->sin_family = AF_INET;
        dst4->sin_port   = 0;
        dst4->sin_addr.s_addr = inet_addr(task->target_ip);

    } else {
        // IPv6: sestavíme kompletní IPv6 hlavičku + TCP hlavičku
        char src_ip6[INET6_ADDRSTRLEN] = "::";
        if (get_interface_address(task->interface, AF_INET6, src_ip6, sizeof(src_ip6)) < 0) {
            fprintf(stderr, "get_interface_address for IPv6 failed\n");
            pthread_exit(NULL);
        }

        struct ip6_hdr *ip6h = (struct ip6_hdr *)packet_template;
        memset(ip6h, 0, sizeof(struct ip6_hdr));
        ip6h->ip6_flow = htonl(6 << 28);           // verze 6, flow=0
        ip6h->ip6_plen = htons(sizeof(struct tcphdr)); // payload = TCP header
        ip6h->ip6_nxt  = IPPROTO_TCP;
        ip6h->ip6_hops = 64;
        inet_pton(AF_INET6, src_ip6, &ip6h->ip6_src);
        inet_pton(AF_INET6, task->target_ip, &ip6h->ip6_dst);

        // TCP hlavička následuje za IPv6 hlavičkou
        struct tcphdr *tcph = (struct tcphdr *)(packet_template + sizeof(struct ip6_hdr));
        memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source  = htons(task->src_port);
        tcph->dest    = 0;  /* bude doplněno později */
        tcph->seq     = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff    = sizeof(struct tcphdr) / 4;
        tcph->syn     = 1;
        tcph->window  = htons(5840);

        packet_len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);

        struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dest_addr_template;
        dst6->sin6_family = AF_INET6;
        dst6->sin6_port   = 0;
        inet_pton(AF_INET6, task->target_ip, &dst6->sin6_addr);
    }

    /* For each port, finalize the packet (dest port, checksum) and send it */
    for (int i = 0; i < task->num_ports; i++) {
        send_packet_params_t params;
        memset(&params, 0, sizeof(params));

        params.task        = task;
        params.packet_len  = packet_len;
        params.target_port = task->ports[i].port;

        memcpy(params.packet, packet_template, packet_len);
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



/* This handler checks the TCP packet, identifies port from the source field,
   then updates port state in task->ports. */
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header;
    capture_user_data_t *cap_data = (capture_user_data_t *)user;
    scan_task_t *task = cap_data->task;

    int eth_offset;
    switch (cap_data->dlt) {
        case DLT_EN10MB: eth_offset = 14; break;
        case DLT_NULL:eth_offset = 4; break;
        case DLT_RAW: eth_offset = 0; break;
        default: eth_offset = 14; break;
    }

    if (!task->is_ipv6) {
        struct iphdr  *iph = (struct iphdr *)(packet + eth_offset);
        int ip_hdr_len     = iph->ihl * 4;
        struct tcphdr *tcph= (struct tcphdr *)(packet + eth_offset + ip_hdr_len);
        int resp_port      = ntohs(tcph->source);

        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == resp_port) {
                if (tcph->syn && tcph->ack) {
                    task->ports[i].state = OPEN;
                } else if (tcph->rst) {
                    task->ports[i].state = CLOSED;
                }
                pthread_mutex_lock(cap_data->packets_mutex);
                task->packets_received++;
                if (task->packets_received >= task->num_ports) {
                    pcap_breakloop(cap_data->pcap_handle);
                    sem_post(cap_data->main_sem);
                }
                pthread_mutex_unlock(cap_data->packets_mutex);
                break;
            }
        }
    } else {
        /* IPv6: skip the ip6_hdr, then parse TCP header */
        int ip6_len       = sizeof(struct ip6_hdr);
        struct tcphdr *tcph= (struct tcphdr *)(packet + eth_offset + ip6_len);
        int resp_port     = ntohs(tcph->source);

        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == resp_port) {
                if (tcph->syn && tcph->ack)
                    task->ports[i].state = OPEN;
                else if (tcph->rst)
                    task->ports[i].state = CLOSED;

                pthread_mutex_lock(cap_data->packets_mutex);
                task->packets_received++;
                if (task->packets_received >= task->num_ports) {
                    pcap_breakloop(cap_data->pcap_handle);
                    sem_post(cap_data->main_sem);
                }
                pthread_mutex_unlock(cap_data->packets_mutex);
                break;
            }
        }
    }
}

/* Capturing thread */
void *capture_packets(void *arg) {
    capture_user_data_t *cap_data = (capture_user_data_t *)arg;
    //fprintf(stderr, "[TCP] Number of target ports: %d\n", cap_data->task->num_ports);

    /* pcap_loop() blocks until pcap_breakloop() or we have processed enough packets. */
    int ret = pcap_loop(cap_data->pcap_handle, -1, packet_handler, (u_char *)cap_data);
    if (ret == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cap_data->pcap_handle));
    }   
    pthread_exit(NULL);
}

/* Create and activate a pcap handle on a given interface */
pcap_t *create_pcap_handle(const char *iface, char errbuf[]) {
    pcap_t *pcap_handle = pcap_create(iface, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        pcap_close(pcap_handle); 
        pthread_exit(NULL);
    }
    if (pcap_set_snaplen(pcap_handle, BUFSIZ) != 0) {
        fprintf(stderr, "pcap_set_snaplen failed\n");
        pcap_close(pcap_handle); 
        pthread_exit(NULL);
    }
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        pcap_close(pcap_handle); 
        pthread_exit(NULL);
    }
    if (pcap_set_timeout(pcap_handle, 50) != 0) {
        fprintf(stderr, "pcap_set_timeout failed\n");
        pcap_close(pcap_handle); 
        pthread_exit(NULL);
    }
    if (pcap_activate(pcap_handle) < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle); 
        pthread_exit(NULL);
    }
    return pcap_handle;
}

/* This is the main scanning thread for TCP. It configures pcap with a BPF filter,
   then spawns two threads: one for capturing packets (pcap_loop), one for sending SYN. */
void *tcp_scan_thread(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
    task->packets_received = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = create_pcap_handle(task->interface, errbuf);

    /* Build a BPF filter (IPv4 or IPv6) */
    char filter_exp[256];
    if (!task->is_ipv6) {
        snprintf(filter_exp, sizeof(filter_exp),
                 "tcp and src host %s and dst port %d", task->target_ip, task->src_port);
    } else {
        snprintf(filter_exp, sizeof(filter_exp),
                 "ip6 and tcp and src host %s and dst port %d", task->target_ip, task->src_port);
    }
    //fprintf(stderr, "[TCP] BPF filter: %s\n", filter_exp);

    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pthread_exit(NULL);
    }
    if (pcap_setfilter(pcap_handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap_handle));
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        pthread_exit(NULL);
    }
    pcap_freecode(&fp);

    pthread_mutex_t packets_mutex;
    pthread_mutex_init(&packets_mutex, NULL);
    
    sem_t main_sem;
    sem_init(&main_sem, 0, 0);

    capture_user_data_t cap_data;
    cap_data.pcap_handle   = pcap_handle;
    cap_data.task          = task;
    cap_data.main_sem      = &main_sem;
    cap_data.packets_mutex = &packets_mutex;
    cap_data.dlt           = pcap_datalink(pcap_handle);


    pthread_t tid_capture;
    if (pthread_create(&tid_capture, NULL, capture_packets, &cap_data) != 0) {
        perror("pthread_create capture");
        pcap_close(pcap_handle);
        pthread_exit(NULL);
    }

    pthread_t tid_send;
    if (pthread_create(&tid_send, NULL, send_packets, task) != 0) {
        perror("pthread_create send");
        pcap_close(pcap_handle);
        pthread_exit(NULL);
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += task->timeout / 1000;
    ts.tv_nsec += (task->timeout % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec ++;
        ts.tv_nsec -= 1000000000L;
    }

    int ret = sem_timedwait(&main_sem, &ts);
    if (ret != 0) {
        pcap_breakloop(pcap_handle);
        fprintf(stdout, "[TCP] Timed out, break pcap_loop\n");
    } else {
        fprintf(stderr, "[TCP] All responses arrived (or all ports are CLOSED)\n");
    }

    pthread_join(tid_send, NULL);
    pthread_join(tid_capture, NULL);

    struct pcap_stat stats;
    if (pcap_stats(pcap_handle, &stats) == 0) {
        fprintf(stderr, "[STATS] Captured: %u, Dropped(OS): %u, Dropped(IF): %u\n",
               stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    }
    fprintf(stderr, "[STATS] num of ports: %d, src port: %d\n", task->num_ports, task->src_port);
    
    pcap_close(pcap_handle);
    sem_destroy(&main_sem);
    pthread_mutex_destroy(&packets_mutex);

    pthread_exit(NULL);
}
