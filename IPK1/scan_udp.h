#ifndef SCAN_UDP_H
#define SCAN_UDP_H

#include <pthread.h>

#include "packet_structures.h"



// Vlákno, které provede celý UDP sken
void *udp_scan_thread(void *arg);

#endif
