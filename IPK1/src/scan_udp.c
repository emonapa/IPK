#include "scan_udp.h"
#include "utils.h"       // e.g. get_interface_address()
#include "interfaces.h"  // e.g. list_active_interfaces()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>    
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <semaphore.h>
#include <ifaddrs.h>
#include <time.h>
#include <net/if.h> 

/* Create and activate a pcap handle for UDP scanning */
pcap_t *create_pcap_handle_udp(const char *interface, char *errbuf) {
    pcap_t *pcap_handle = pcap_create(interface, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        pcap_close(pcap_handle); 
        pthread_exit((void*)"error");
    }
    if (pcap_set_snaplen(pcap_handle, BUFSIZ) != 0) {
        fprintf(stderr, "pcap_set_snaplen failed\n");
        pcap_close(pcap_handle); 
        pthread_exit((void*)"error");
    }
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        pcap_close(pcap_handle); 
        pthread_exit((void*)"error");
    }
    if (pcap_set_timeout(pcap_handle, 50) != 0) {
        fprintf(stderr, "pcap_set_timeout failed\n");
        pcap_close(pcap_handle); 
        pthread_exit((void*)"error");
    }
    if (pcap_activate(pcap_handle) < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle); 
        pthread_exit((void*)"error");
    }
    return pcap_handle;
}

/*
 * send_udp_packets:
 * This function sends UDP packets to every destination port specified in the scan task.
 * It creates a UDP socket (IPv4 or IPv6 depending on the task), binds to a source port if provided,
 * optionally binds to a specific interface, and then sends a predefined UDP message to each target port.
 */
void *send_udp_packets(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
    int domain = task->is_ipv6 ? AF_INET6 : AF_INET;
    int sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[UDP] socket SOCK_DGRAM");
        pthread_exit((void*)"error");
    }

    if (task->src_port > 0) {
        char src_ip[INET6_ADDRSTRLEN] = {0};
        if (!task->is_ipv6) { // IPv4
            if (get_interface_address(task->interface, AF_INET, src_ip, sizeof(src_ip)) < 0) {
                fprintf(stderr, "get_interface_address for IPv4 failed\n");
                close(sockfd);
                pthread_exit((void*)"error");
            }
            struct sockaddr_in bind_addr4;
            memset(&bind_addr4, 0, sizeof(bind_addr4));
            bind_addr4.sin_family = AF_INET;
            bind_addr4.sin_port   = htons(task->src_port);
            inet_pton(AF_INET, src_ip, &bind_addr4.sin_addr);
            if (bind(sockfd, (struct sockaddr*)&bind_addr4, sizeof(bind_addr4)) < 0) {
                perror("[UDP] bind IPv4");
                close(sockfd);
                pthread_exit((void*)"error");
            }
        } else { // IPv6
            /* Get IPv6 source address from the interface */
            if (get_interface_address(task->interface, AF_INET6, src_ip, sizeof(src_ip)) < 0) {
                fprintf(stderr, "get_interface_address for IPv6 failed\n");
                close(sockfd);
                pthread_exit((void*)"error");
            }
            
            /* Set up sockaddr_in6 structure */
            struct sockaddr_in6 bind_addr6;
            memset(&bind_addr6, 0, sizeof(bind_addr6));
            bind_addr6.sin6_family = AF_INET6;
            bind_addr6.sin6_port   = htons(task->src_port);
            inet_pton(AF_INET6, src_ip, &bind_addr6.sin6_addr);

            /* If it's a link-local address, then set sin6_scope_id */
            if (strncmp(src_ip, "fe80", 4) == 0) {
                bind_addr6.sin6_scope_id = if_nametoindex(task->interface);
            }

            if (bind(sockfd, (struct sockaddr*)&bind_addr6, sizeof(bind_addr6)) < 0) {
                perror("[UDP] bind IPv6");
                close(sockfd);
                pthread_exit((void*)"error");
            }
        }
    }

    /* Optionally bind to a specific interface */
    if (strlen(task->interface) > 0) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                       task->interface, strlen(task->interface) + 1) < 0) {
            perror("[UDP] setsockopt(SO_BINDTODEVICE)");
            close(sockfd);
            pthread_exit((void*)"error");
        }
    }

    /* Send a message to every destination port */
    const char *msg = "Hiii UDP :3";
    for (int i = 0; i < task->num_ports; i++) {
        int dst_port = task->ports[i].port;
        if (!task->is_ipv6) {
            struct sockaddr_in dst4;
            memset(&dst4, 0, sizeof(dst4));
            dst4.sin_family = AF_INET;
            dst4.sin_port   = htons(dst_port);
            inet_pton(AF_INET, task->target_ip, &dst4.sin_addr);
            ssize_t sent = sendto(sockfd, msg, strlen(msg), 0,
                                  (struct sockaddr*)&dst4, sizeof(dst4));
            if (sent < 0)
                perror("[UDP] sendto IPv4");
        } else {
            struct sockaddr_in6 dst6;
            memset(&dst6, 0, sizeof(dst6));
            dst6.sin6_family = AF_INET6;
            dst6.sin6_port   = htons(dst_port);
            inet_pton(AF_INET6, task->target_ip, &dst6.sin6_addr);
            /* If the destination address is link-local, set sin6_scope_id as well */
            if (strncmp(task->target_ip, "fe80", 4) == 0) {
                dst6.sin6_scope_id = if_nametoindex(task->interface);
            }
            ssize_t sent = sendto(sockfd, msg, strlen(msg), 0,
                                  (struct sockaddr*)&dst6, sizeof(dst6));
            if (sent < 0)
                perror("[UDP] sendto IPv6");
        }
    }
    close(sockfd);
    pthread_exit(NULL);
}

/*
 * udp_packet_handler:
 * Callback for pcap_loop to process received ICMP (or ICMPv6) packets.
 * This function examines the incoming packet, determines if it contains an ICMP message
 * indicating an unreachable UDP port, and updates the scan task state accordingly.
 */
void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
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

    const u_char *ip_payload = packet + eth_offset;
    unsigned char ver = (ip_payload[0] >> 4);

    if (ver == 4) {
        const struct ip *iph = (const struct ip *)ip_payload;
        int ip_hdr_len = iph->ip_hl * 4;
        if (iph->ip_p != IPPROTO_ICMP) return;

        const struct icmphdr *icmp4 = (const struct icmphdr *)(ip_payload + ip_hdr_len);
        if (icmp4->type != ICMP_UNREACH) return;

        const unsigned char *orig_data = (const unsigned char *)icmp4 + 8;
        const struct ip *orig_iph = (const struct ip *)orig_data;
        if (orig_iph->ip_p != IPPROTO_UDP) return;

        int orig_ip_len = orig_iph->ip_hl * 4;
        const struct udphdr *orig_udph = (const struct udphdr *)(orig_data + orig_ip_len);
        int port_closed = ntohs(orig_udph->uh_dport);
        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == port_closed) {
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
    } else if (ver == 6) {
        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip_payload;
        if (ip6h->ip6_nxt != IPPROTO_ICMPV6) return;

        const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)(ip6h + 1);
        if (icmp6->icmp6_type != ICMP6_DST_UNREACH) return;

        const unsigned char *orig_data = (const unsigned char *)icmp6 + 8;
        const struct ip6_hdr *orig_ip6 = (const struct ip6_hdr *)orig_data;
        if (orig_ip6->ip6_nxt != IPPROTO_UDP) return;

        const struct udphdr *orig_udph = (const struct udphdr *)(orig_ip6 + 1);
        int port_closed = ntohs(orig_udph->uh_dport);
        for (int i = 0; i < task->num_ports; i++) {
            if (task->ports[i].port == port_closed) {
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

/*
 * capture_udp_packets:
 * Thread function for capturing UDP ICMP responses.
 * It runs a pcap_loop to capture ICMP/ICMPv6 packets and processes them using udp_packet_handler.
 */
void *capture_udp_packets(void *arg) {
    // once again, use capture_user_data_t instead of udp_capture_user_data_t
    capture_user_data_t *cap_data = (capture_user_data_t *)arg;
    fprintf(stderr, "[UDP] Number of target ports: %d\n", cap_data->task->num_ports);
    int ret = pcap_loop(cap_data->pcap_handle, -1, udp_packet_handler, (u_char *)cap_data);
    if (ret == PCAP_ERROR)
        fprintf(stderr, "[UDP] pcap_loop error: %s\n", pcap_geterr(cap_data->pcap_handle));

    pthread_exit(NULL);
}

/*
 * udp_scan_thread:
 * Main UDP scan thread that sets up the pcap handle with appropriate filters,
 * spawns both the capture and send threads, and waits for responses with a timeout.
 * It then cleans up and prints pcap statistics.
 */
void *udp_scan_thread(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = create_pcap_handle_udp(task->interface, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "[UDP] create_pcap_handle_udp failed: %s\n", errbuf);
        pthread_exit((void*)"error");
    }

    /* Set BPF filter to capture ICMP and ICMPv6 messages */
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "icmp or icmp6");
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "[UDP] pcap_compile: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    if (pcap_setfilter(pcap_handle, &fp) < 0) {
        fprintf(stderr, "[UDP] pcap_setfilter: %s\n", pcap_geterr(pcap_handle));
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }
    pcap_freecode(&fp);

    pthread_mutex_t packets_mutex;
    pthread_mutex_init(&packets_mutex, NULL);

    /* Initialize semaphore and spawn capture thread */
    sem_t main_sem;
    sem_init(&main_sem, 0, 0);

    /* Create UDP capture handle */
    capture_user_data_t cap_data;
    cap_data.pcap_handle   = pcap_handle;
    cap_data.task          = task;
    cap_data.main_sem      = &main_sem;
    cap_data.packets_mutex = &packets_mutex;
    cap_data.dlt           = pcap_datalink(pcap_handle);

    pthread_t tid_capture;
    if (pthread_create(&tid_capture, NULL, capture_udp_packets, &cap_data) != 0) {
        perror("[UDP] pthread_create capture");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }

    /* Spawn the UDP send thread */
    pthread_t tid_send;
    if (pthread_create(&tid_send, NULL, send_udp_packets, task) != 0) {
        perror("[UDP] pthread_create send");
        pcap_close(pcap_handle);
        pthread_exit((void*)"error");
    }

    /* Wait for responses with timeout */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += task->timeout / 1000;
    ts.tv_nsec += (task->timeout % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    if (sem_timedwait(&main_sem, &ts) != 0) {
        pcap_breakloop(pcap_handle);
        fprintf(stderr, "[UDP] Timed out, break pcap_loop\n");
    } else {
        fprintf(stderr, "[UDP] All responses arrived (or all ports are CLOSED)\n");
    }

    pthread_join(tid_send, NULL);
    pthread_join(tid_capture, NULL);

    /* Print pcap statistics */
    struct pcap_stat stats;
    if (pcap_stats(pcap_handle, &stats) == 0) {
        fprintf(stderr, "[UDP] Pcap stats: captured=%u, dropped=%u, ifdropped=%u\n",
               stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    }
    
    pcap_close(pcap_handle);
    sem_destroy(&main_sem);
    pthread_mutex_destroy(&packets_mutex);

    return NULL;
}
