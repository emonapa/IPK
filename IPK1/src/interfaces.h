#include <stdio.h>

#ifndef INTERFACES_H
#define INTERFACES_H

// The function is used to list active interfaces and obtain the IP address of the specified interface.
void list_active_interfaces();
int get_interface_address(const char *iface, int family, char *addr, size_t addr_len);

#endif
