#include <stdio.h>

#ifndef INTERFACES_H
#define INTERFACES_H

// Deklarace funkcí pro práci s aktivními síťovými rozhraními.
// Funkce slouží k vypsání seznamu aktivních rozhraní a k získání IP adresy zadaného rozhraní.

void list_active_interfaces();
int get_interface_address(const char *iface, int family, char *addr, size_t addr_len);

#endif
