import subprocess
import re
import xml.etree.ElementTree as ET
import pytest

ipv6_global_interface = "wlp0s20f3"

# Pomocná funkce pro spuštění příkazu a vrácení (stdout, stderr, returncode)
def run_command(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return result.stdout, result.stderr, result.returncode

# Spustí ipk-l4-scan s danými argumenty
def run_ipk_scan(args):
    cmd = ["./ipk-l4-scan"] + args
    stdout, stderr, rc = run_command(cmd)
    return stdout, stderr, rc

# Parsuje výstup nmap ve formátu XML a vrací slovník {port: state}
def parse_nmap_xml(xml_output):
    ports = {}
    root = ET.fromstring(xml_output)
    for host in root.findall('host'):
        ports_elem = host.find('ports')
        if ports_elem is None:
            continue
        for port in ports_elem.findall('port'):
            portid = int(port.attrib['portid'])
            state = port.find('state').attrib['state']
            ports[portid] = state.upper()
    return ports

# Spustí nmap pro daný protokol, port(y) a cíl, volitelně přes rozhraní
def run_nmap_scan(protocol, ports, target, interface=None):
    if protocol.lower() == "tcp":
        scan_type = "-sS"
    elif protocol.lower() == "udp":
        scan_type = "-sU"
    else:
        raise ValueError("Unknown protocol: " + protocol)
    port_arg = "-p" + ports  # např. "22", "22,80" nebo "20-25"

    if ':' in target:
        cmd = ["nmap", scan_type, "-6", port_arg, target, "-oX", "-"]
    else:
        cmd = ["nmap", scan_type, port_arg, target, "-oX", "-"]

    if interface:
        cmd.extend(["-e", interface])
    print(f"CMD: {cmd}")
    stdout, stderr, rc = run_command(cmd)
    if rc != 0:
        raise Exception("nmap failed: " + stderr)
    return parse_nmap_xml(stdout)

# Parsuje výstup ipk-l4-scan, očekává řádky: "IP port protocol state"
def parse_ipk_output(output):
    ports = {}
    # Očekáváme formát: "127.0.0.1 22 tcp open"
    pattern = re.compile(r"(\S+)\s+(\d+)\s+(\w+)\s+(\w+)", re.IGNORECASE)
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            port = int(m.group(2))
            state = m.group(4).upper()
            ports[port] = state
    return ports

# ----- Testy ----- #

# 1. Test nápovědy
def test_help_message():
    stdout, stderr, rc = run_ipk_scan(["-h"])
    assert rc == 0
    assert "Usage:" in stdout or "usage:" in stdout.lower()

# 2. TCP – jeden port (22) na localhost, s interface
def test_tcp_single_port_localhost():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 3. TCP – více portů (22,80)
def test_tcp_multiple_ports_localhost():
    target = "localhost"
    ports = "22,80"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in [22, 80]:
        assert ipk_results.get(p) == nmap_results.get(p)

# 4. TCP – rozsah portů (20-25)
def test_tcp_port_range_localhost():
    target = "localhost"
    ports = "20-25"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in range(20, 26):
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 5. UDP – jeden port (53) na localhost
def test_udp_single_port_localhost():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 6. UDP – více portů (53,67)
def test_udp_multiple_ports_localhost():
    target = "localhost"
    ports = "53,67"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")
    for p in [53, 67]:
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 7. UDP – rozsah portů (50-60)
def test_udp_port_range_localhost():
    target = "localhost"
    ports = "50-60"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")
    for p in range(50, 61):
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 8. TCP – scan s volbou rozhraní (-i lo)
def test_tcp_with_interface():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 9. UDP – scan s volbou rozhraní (-i lo)
def test_udp_with_interface():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 10. TCP – scan pomocí hostname vs. IP adresy (localhost vs 127.0.0.1)
def test_tcp_ipv4_hostname_vs_ip():
    port = "22"
    stdout1, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", "localhost"])
    stdout2, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", "127.0.0.1"])
    res1 = parse_ipk_output(stdout1)
    res2 = parse_ipk_output(stdout2)
    assert res1.get(22) == res2.get(22)

# 11. TCP – scan s krátkým timeoutem
def test_tcp_timeout_parameter():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "500", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 12. Neplatný rozsah portů – očekáváme chybové hlášení
def test_invalid_port_range():
    target = "localhost"
    _, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "abc", "-w", "1000", target])
    assert rc != 0
    assert "error" in stderr.lower() or "invalid" in stderr.lower()

# 13. Chybějící povinné argumenty (např. chybějící target) – očekáváme chybový návrat
def test_missing_required_argument():
    _, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "22", "-w", "1000"])
    assert rc != 0
    assert "usage" in stderr.lower() or "error" in stderr.lower()

# 14. Použití dlouhé volby pro interface (--interface)
def test_long_option_interface():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["--interface", "lo", "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 15. Použití dlouhé volby pro TCP (--pt)
def test_long_option_tcp():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "--pt", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 16. Použití dlouhé volby pro UDP (--pu)
def test_long_option_udp():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "--pu", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 17. TCP – IPv6 loopback (target ::1)
def test_tcp_ipv6_loopback():
    target = "::1"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 18. UDP – IPv6 loopback (target ::1)
def test_udp_ipv6_loopback():
    target = "::1"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 19. TCP – test s explicitní IPv4 adresou (127.0.0.1)
def test_tcp_explicit_ipv4():
    target = "127.0.0.1"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 20. UDP – test s explicitní IPv4 adresou (127.0.0.1)
def test_udp_explicit_ipv4():
    target = "127.0.0.1"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 21. Big comprehensive test – kombinovaný rozsah portů, interface, TCP i UDP
def test_big_comprehensive():
    target = "localhost"
    tcp_ports = "20-30"
    udp_ports = "50-60"
    stdout_tcp, _, _ = run_ipk_scan(["-i", "lo", "-t", tcp_ports, "-w", "1500", target])
    ipk_tcp = parse_ipk_output(stdout_tcp)
    nmap_tcp = run_nmap_scan("tcp", tcp_ports, target, interface="lo")
    stdout_udp, _, _ = run_ipk_scan(["-i", "lo", "-u", udp_ports, "-w", "1500", target])
    ipk_udp = parse_ipk_output(stdout_udp)
    nmap_udp = run_nmap_scan("udp", udp_ports, target, interface="lo")
    
    for p in range(20, 31):
        ipk_state = ipk_tcp.get(p, "CLOSED")
        nmap_state = nmap_tcp.get(p, "CLOSED")
        assert ipk_state == nmap_state, f"TCP port {p}: ipk={ipk_state}, nmap={nmap_state}"
    for p in range(50, 61):
        ipk_state = ipk_udp.get(p, "CLOSED")
        nmap_state = nmap_udp.get(p, "CLOSED")
        assert ipk_state == nmap_state, f"UDP port {p}: ipk={ipk_state}, nmap={nmap_state}"

# 22. Použití dlouhé volby pro timeout (--wait)
def test_long_option_wait():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "--wait", "1500", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 23. Kombinovaný sken – současně TCP i UDP (dvě volby)
def test_combined_protocols():
    target = "localhost"
    # Skenujeme TCP port 80 a UDP port 53 současně
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", "80", "-u", "53", "-w", "1000", target])
    results = parse_ipk_output(stdout)
    nmap_tcp = run_nmap_scan("tcp", "80", target, interface="lo")
    nmap_udp = run_nmap_scan("udp", "53", target, interface="lo")
    # Očekáváme dva řádky, každý s příslušným protokolem
    assert results.get(80) == nmap_tcp.get(80)
    assert results.get(53) == nmap_udp.get(53)

# 24. Test pořadí argumentů – různá pořadí parametrů
def test_arguments_order():
    target = "localhost"
    port = "22"
    # Přeházejeme pořadí argumentů
    stdout, _, _ = run_ipk_scan(["-w", "1000", "-t", port, "-i", "lo", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 25. Test s neexistujícím cílem – očekáváme, že žádné skeny neproběhnou
def test_nonexistent_target():
    target = "nonexistent.domain.local"
    stdout, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "22", "-w", "1000", target])
    # Předpokládáme, že program vypíše chybovou hlášku
    assert rc != 0 or "error" in stderr.lower()

# 26. Test portů zadaných jako čárkami (22,23,24)
def test_comma_separated_ports():
    target = "localhost"
    ports = "22,23,24"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in [22, 23, 24]:
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 27. TCP – scan s globální IPv6 adresou (pokud je dostupná)
def test_tcp_ipv6_global():
    target = "2001:67c:1220:809::93e5:917"
    port = "80"
    stdout, _, _ = run_ipk_scan(["-i", ipv6_global_interface, "-t", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface=ipv6_global_interface)
    assert ipk_results.get(80) == nmap_results.get(80)

# 28. UDP – scan s globální IPv6 adresou (pokud je dostupná)
def test_udp_ipv6_global():
    target = "2001:67c:1220:809::93e5:917"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", ipv6_global_interface, "-u", port, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface=ipv6_global_interface)
    assert ipk_results.get(53) == nmap_results.get(53)

# 29. Test s volbou rozhraní zadanou jako poslední argument
def test_interface_last_argument():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-t", port, "-w", "1000", target, "-i", "lo"])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 30. Kombinovaný sken s více portovými rozsahy pro TCP i UDP
def test_combined_port_ranges():
    target = "localhost"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", "80,8080,443", "-u", "53,67,123", "-w", "1500", target])
    results = parse_ipk_output(stdout)
    nmap_tcp = run_nmap_scan("tcp", "80,8080,443", target, interface="lo")
    nmap_udp = run_nmap_scan("udp", "53,67,123", target, interface="lo")
    for p in [80, 8080, 443]:
        assert results.get(p, "CLOSED") == nmap_tcp.get(p, "CLOSED")
    for p in [53, 67, 123]:
        assert results.get(p, "CLOSED") == nmap_udp.get(p, "CLOSED")
