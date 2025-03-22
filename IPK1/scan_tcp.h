#ifndef SCAN_TCP_H
#define SCAN_TCP_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <limits.h>
#include <semaphore.h>
#include "packet_structures.h"

// Vláknová funkce, která provede TCP SYN scan konkrétního portu
void *tcp_scan_thread(void *arg);

#endif
