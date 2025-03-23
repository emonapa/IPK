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
#include <time.h>

/* Create and activate a pcap handle for UDP scanning */
pcap_t *create_pcap_handle_udp(const char *interface, char *errbuf) {
    pcap_t *pcap_handle = pcap_create(interface, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        pthread_exit((void*)"error");
    }
    if (pcap_set_snaplen(pcap_handle, BUFSIZ) != 0) {
        fprintf(stderr, "pcap_set_snaplen failed\n");
        pthread_exit((void*)"error");
    }
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        pthread_exit((void*)"error");
    }
    if (pcap_set_timeout(pcap_handle, 50) != 0) {
        fprintf(stderr, "pcap_set_timeout failed\n");
        pthread_exit((void*)"error");
    }
    if (pcap_activate(pcap_handle) < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(pcap_handle));
        pthread_exit((void*)"error");
    }
    return pcap_handle;
}

/* UDP packet sending function */
void *send_udp_packets(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;
    int domain = task->is_ipv6 ? AF_INET6 : AF_INET;
    int sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[UDP] socket SOCK_DGRAM");
        pthread_exit((void*)"error");
    }

    /* Optionally bind to a specified source port */
    if (task->src_port > 0) {
        char src_ip[INET6_ADDRSTRLEN] = {0};
        if (!task->is_ipv6) {
            get_interface_address(task->interface, AF_INET, src_ip, sizeof(src_ip));
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
        } else {
            get_interface_address(task->interface, AF_INET6, src_ip, sizeof(src_ip));
            struct sockaddr_in6 bind_addr6;
            memset(&bind_addr6, 0, sizeof(bind_addr6));
            bind_addr6.sin6_family = AF_INET6;
            bind_addr6.sin6_port   = htons(task->src_port);
            inet_pton(AF_INET6, src_ip, &bind_addr6.sin6_addr);
            /* For link-local addresses, you may need to set sin6_scope_id here */
            if (bind(sockfd, (struct sockaddr*)&bind_addr6, sizeof(bind_addr6)) < 0) {
                perror("[UDP] bind IPv6");
                close(sockfd);
                pthread_exit((void*)"error");
            }
        }
    }

    /* Optionally bind the socket to a specific interface */
    if (strlen(task->interface) > 0) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                       task->interface, strlen(task->interface) + 1) < 0) {
            perror("[UDP] setsockopt(SO_BINDTODEVICE)");
            close(sockfd);
            pthread_exit((void*)"error");
        }
    }

    /* Prepare a simple message and send it to each target port */
    const char *msg = "Hello from UDP socket!";
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
            ssize_t sent = sendto(sockfd, msg, strlen(msg), 0,
                                  (struct sockaddr*)&dst6, sizeof(dst6));
            if (sent < 0)
                perror("[UDP] sendto IPv6");
        }
    }
    close(sockfd);
    pthread_exit(NULL);
}

/* Callback for pcap_loop: process received ICMP (or ICMPv6) packets */
void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header;
    udp_capture_user_data_t *cap_data = (udp_capture_user_data_t *)user;
    scan_task_t *task = cap_data->task;
    int eth_offset = 14;
    const u_char *ip_payload = packet + eth_offset;
    unsigned char ver = (ip_payload[0] >> 4);

    if (ver == 4) {
        const struct ip *iph = (struct ip *)ip_payload;
        int ip_hdr_len = iph->ip_hl * 4;
        if (iph->ip_p == IPPROTO_ICMP) {
            const struct icmphdr *icmp4 = (const struct icmphdr *)(ip_payload + ip_hdr_len);
            if (icmp4->type == ICMP_UNREACH) {
                const unsigned char *orig_data = (const unsigned char *)icmp4 + 8;
                const struct ip *orig_iph = (const struct ip *)orig_data;
                if (orig_iph->ip_p == IPPROTO_UDP) {
                    int orig_ip_len = orig_iph->ip_hl * 4;
                    const struct udphdr *orig_udph = (const struct udphdr *)(orig_data + orig_ip_len);
                    int port_closed = ntohs(orig_udph->uh_dport);
                    for (int i = 0; i < task->num_ports; i++) {
                        if (task->ports[i].port == port_closed) {
                            if (task->ports[i].state == FILTERED) {
                                task->ports[i].state = CLOSED;
                                pthread_mutex_lock(cap_data->packets_mutex);
                                task->packets_received++;
                                if (task->packets_received >= task->num_ports) {
                                    pcap_breakloop(cap_data->pcap_handle);
                                    sem_post(cap_data->main_sem);
                                }
                                pthread_mutex_unlock(cap_data->packets_mutex);
                            }
                            break;
                        }
                    }
                }
            }
        }
    } else if (ver == 6) {
        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip_payload;
        if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
            const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)(ip6h + 1);
            if (icmp6->icmp6_type == ICMP6_DST_UNREACH) {
                const unsigned char *orig_data = (const unsigned char *)icmp6 + 8;
                const struct ip6_hdr *orig_ip6 = (const struct ip6_hdr *)orig_data;
                if (orig_ip6->ip6_nxt == IPPROTO_UDP) {
                    const struct udphdr *orig_udph = (const struct udphdr *)(orig_ip6 + 1);
                    int port_closed = ntohs(orig_udph->uh_dport);
                    for (int i = 0; i < task->num_ports; i++) {
                        if (task->ports[i].port == port_closed) {
                            if (task->ports[i].state == FILTERED) {
                                task->ports[i].state = CLOSED;
                                pthread_mutex_lock(cap_data->packets_mutex);
                                task->packets_received++;
                                if (task->packets_received >= task->num_ports) {
                                    pcap_breakloop(cap_data->pcap_handle);
                                    sem_post(cap_data->main_sem);
                                }
                                pthread_mutex_unlock(cap_data->packets_mutex);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

/* Capture thread for UDP ICMP responses */
void *capture_udp_packets(void *arg) {
    udp_capture_user_data_t *cap_data = (udp_capture_user_data_t *)arg;
    printf("[UDP] Number of target ports: %d\n", cap_data->task->num_ports);
    int ret = pcap_loop(cap_data->pcap_handle, -1, udp_packet_handler, (u_char *)cap_data);
    printf("[UDP] pcap_loop ended, ret=%d\n", ret);
    if (ret == PCAP_ERROR)
        fprintf(stderr, "[UDP] pcap_loop error: %s\n", pcap_geterr(cap_data->pcap_handle));
    else if (ret == PCAP_ERROR_BREAK)
        printf("[UDP] pcap_loop terminated by pcap_breakloop()\n");
    pthread_exit(NULL);
}

/* Main UDP scan thread: sets up pcap, spawns capture and send threads, and waits for responses */
void *udp_scan_thread(void *arg) {
    scan_task_t *task = (scan_task_t *)arg;

    pthread_mutex_init(&task->packets_mutex, NULL);
    task->packets_received = 0;

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

    /* Initialize semaphore and spawn capture thread */
    sem_t main_sem;
    sem_init(&main_sem, 0, 0);
    udp_capture_user_data_t cap_data;
    cap_data.pcap_handle   = pcap_handle;
    cap_data.task          = task;
    cap_data.main_sem      = &main_sem;
    cap_data.packets_mutex = &task->packets_mutex;

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
    printf("[UDP] Waiting until: %ld s, %ld ns\n", ts.tv_sec, ts.tv_nsec);

    if (sem_timedwait(&main_sem, &ts) != 0) {
        pcap_breakloop(pcap_handle);
        printf("[UDP] Timeout => pcap_breakloop\n");
    } else {
        printf("[UDP] All responses arrived (or all ports are CLOSED)\n");
    }

    pthread_join(tid_send, NULL);
    pthread_join(tid_capture, NULL);

    /* Print pcap statistics */
    struct pcap_stat stats;
    if (pcap_stats(pcap_handle, &stats) == 0) {
        printf("[UDP] Pcap stats: captured=%u, dropped=%u, ifdropped=%u\n",
               stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    }
    pcap_close(pcap_handle);
    sem_destroy(&main_sem);
    pthread_mutex_destroy(&task->packets_mutex);

    return NULL;
}
