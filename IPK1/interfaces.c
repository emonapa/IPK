#include "interfaces.h"
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>

// Funkce pro vypsání všech aktivních síťových rozhraní (IPv4 i IPv6)
void list_active_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    char addr[INET6_ADDRSTRLEN];
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    printf("Aktivní rozhraní:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            void *in_addr;
            if (family == AF_INET)
                in_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            else
                in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            inet_ntop(family, in_addr, addr, sizeof(addr));
            printf("%s: %s\n", ifa->ifa_name, addr);
        }
    }
    freeifaddrs(ifaddr);
}

// Funkce získá IP adresu pro zadané rozhraní (podle rodiny protokolu)
int get_interface_address(const char *iface, int family, char *addr, size_t addr_len) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (strcmp(ifa->ifa_name, iface) != 0)
            continue;
        if (ifa->ifa_addr->sa_family == family) {
            void *in_addr;
            if (family == AF_INET)
                in_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            else
                in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            inet_ntop(family, in_addr, addr, addr_len);
            found = 1;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}
