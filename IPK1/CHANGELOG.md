# CHANGELOG

## [v1.0.0] – 10. dubna 2025

### Implementovaná funkcionalita
- **TCP skenování** pomocí raw socketů (IPv4 i IPv6).
- **UDP skenování** pomocí soketů typu SOCK_DGRAM a odchytávání ICMP/ICMPv6 „port unreachable“ pro uzavřené porty.
- **Paralelní chunking** (rozdělování) portů ve funkci `chunk_send()`, což umožňuje rychlejší skenování většího množství portů.
- **Link-local** podpora pro IPv6 (nastavování scope_id).
- **Dvojité skenování** u portů, které se v prvním průchodu označí jako `FILTERED` (platí pro TCP). Druhý pokus eliminuje falešné `FILTERED` porty, jež se ukážou jako open/closed.

### Známá omezení
1. **Velké množství portů**  
   - Při skenování velmi rozsáhlých rozsahů se poslední porty někdy nechovají korektně (zůstávají `filtered`). Zatím to řeší drobný trik v `chunk_send()` (podmínka `if (i != n-1) ctask->num_ports += 1;`) a zvětšení proměnné `CHUNK_SIZE`. Dále se hledá skutečná příčina.  

2. **IPv6 raw TCP na portech > 255**  
   - Odesílání raw TCP/IPv6 paketů selže, pokud je cílový port vyšší než 255. Příčina momentálně není jasná; v praxi to omezuje IPv6 sken na porty `1–255`.  

