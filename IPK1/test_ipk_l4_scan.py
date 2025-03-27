import subprocess
import re
import xml.etree.ElementTree as ET
import pytest

ipv6_global_interface = "tun0"

# Helper function to run a command and return (stdout, stderr, return code)
def run_command(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return result.stdout, result.stderr, result.returncode

# Runs ipk-l4-scan with the given arguments
def run_ipk_scan(args):
    cmd = ["./ipk-l4-scan"] + args
    stdout, stderr, rc = run_command(cmd)
    return stdout, stderr, rc

# Parses the nmap output in XML format and returns a dictionary {port: state}
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

# Runs nmap for the given protocol, port(s), and target, optionally via an interface
def run_nmap_scan(protocol, ports, target, interface=None):
    if protocol.lower() == "tcp":
        scan_type = "-sS"
    elif protocol.lower() == "udp":
        scan_type = "-sU"
    else:
        raise ValueError("Unknown protocol: " + protocol)
    port_arg = "-p" + ports  # e.g., "22", "22,80" or "1-20000"

    if ':' in target:  # IPv6
        cmd = ["nmap", scan_type, "-6", port_arg, target, "-oX", "-"]
    else:  # IPv4
        cmd = ["nmap", scan_type, port_arg, target, "-oX", "-"]

    if interface:
        cmd.extend(["-e", interface])
    print(f"CMD: {cmd}")
    stdout, stderr, rc = run_command(cmd)
    if rc != 0:
        raise Exception("nmap failed: " + stderr)
    return parse_nmap_xml(stdout)

# Parses the output of ipk-l4-scan, expecting lines in the format: "IP port protocol state"
def parse_ipk_output(output):
    ports = {}
    # We expect the format: "127.0.0.1 22 tcp open"
    pattern = re.compile(r"(\S+)\s+(\d+)\s+(\w+)\s+(\w+)", re.IGNORECASE)
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            port = int(m.group(2))
            state = m.group(4).upper()
            ports[port] = state
    return ports

# ----- Tests ----- #

# 1. Help message test
def test_help_message():
    stdout, stderr, rc = run_ipk_scan(["-h"])
    assert rc == 0
    assert "Usage:" in stdout or "usage:" in stdout.lower()

# 2. TCP – single port (22) on localhost, with interface
def test_tcp_single_port_localhost():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 3. TCP – multiple ports (22,80)
def test_tcp_multiple_ports_localhost():
    target = "localhost"
    ports = "22,80"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in [22, 80]:
        assert ipk_results.get(p) == nmap_results.get(p)

# 4. TCP – port range (20-25)
def test_tcp_port_range_localhost():
    target = "localhost"
    ports = "20-25"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in range(20, 26):
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 5. UDP – single port (53) on localhost
def test_udp_single_port_localhost():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 6. UDP – multiple ports (53,67)
def test_udp_multiple_ports_localhost():
    target = "localhost"
    ports = "53,67"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")
    for p in [53, 67]:
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 7. UDP – port range (50-60)
def test_udp_port_range_localhost():
    target = "localhost"
    ports = "50-60"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")
    for p in range(50, 61):
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 8. TCP – scan with interface option (-i lo)
def test_tcp_with_interface():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 9. UDP – scan with interface option (-i lo)
def test_udp_with_interface():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 10. TCP – scan using hostname vs IP address (localhost vs 127.0.0.1)
def test_tcp_ipv4_hostname_vs_ip():
    port = "22"
    stdout1, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", "localhost"])
    stdout2, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", "127.0.0.1"])
    res1 = parse_ipk_output(stdout1)
    res2 = parse_ipk_output(stdout2)
    assert res1.get(22) == res2.get(22)

# 11. TCP – scan with a short timeout
def test_tcp_timeout_parameter():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "500", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 12. Invalid port range – expect an error message
def test_invalid_port_range():
    target = "localhost"
    _, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "abc", "-w", "100", target])
    assert rc != 0
    assert "error" in stderr.lower() or "invalid" in stderr.lower()

# 13. Missing required arguments (e.g., missing target) – expect an error return
def test_missing_required_argument():
    _, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "22", "-w", "100"])
    assert rc != 0
    assert "usage" in stderr.lower() or "error" in stderr.lower()

# 14. Using long option for interface (--interface)
def test_long_option_interface():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["--interface", "lo", "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 15. Using long option for TCP (--pt)
def test_long_option_tcp():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "--pt", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 16. Using long option for UDP (--pu)
def test_long_option_udp():
    target = "localhost"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "--pu", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 17. TCP – IPv6 loopback (target ::1)
def test_tcp_ipv6_loopback():
    target = "::1"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 18. UDP – IPv6 loopback (target ::1)
def test_udp_ipv6_loopback():
    target = "::1"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 19. TCP – test with explicit IPv4 address (127.0.0.1)
def test_tcp_explicit_ipv4():
    target = "127.0.0.1"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 20. UDP – test with explicit IPv4 address (127.0.0.1)
def test_udp_explicit_ipv4():
    target = "127.0.0.1"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface="lo")
    assert ipk_results.get(53) == nmap_results.get(53)

# 21. Big comprehensive test – combined port range, interface, TCP and UDP
def test_big_comprehensive():
    target = "localhost"
    tcp_ports = "20-30"
    udp_ports = "50-60"
    stdout_tcp, _, _ = run_ipk_scan(["-i", "lo", "-t", tcp_ports, "-w", "150", target])
    ipk_tcp = parse_ipk_output(stdout_tcp)
    nmap_tcp = run_nmap_scan("tcp", tcp_ports, target, interface="lo")
    stdout_udp, _, _ = run_ipk_scan(["-i", "lo", "-u", udp_ports, "-w", "150", target])
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

# 22. Using long option for timeout (--wait)
def test_long_option_wait():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", port, "--wait", "150", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 23. Combined scan – TCP and UDP simultaneously (two options)
def test_combined_protocols():
    target = "localhost"
    # Scanning TCP port 80 and UDP port 53 simultaneously
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", "80", "-u", "53", "-w", "100", target])
    results = parse_ipk_output(stdout)
    nmap_tcp = run_nmap_scan("tcp", "80", target, interface="lo")
    nmap_udp = run_nmap_scan("udp", "53", target, interface="lo")
    # We expect two lines, each with the corresponding protocol
    assert results.get(80) == nmap_tcp.get(80)
    assert results.get(53) == nmap_udp.get(53)

# 24. Test argument order – various parameter orders
def test_arguments_order():
    target = "localhost"
    port = "22"
    # Shuffling the order of arguments
    stdout, _, _ = run_ipk_scan(["-w", "100", "-t", port, "-i", "lo", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 25. Test with a non-existent target – expect that no scans will occur
def test_nonexistent_target():
    target = "nonexistent.domain.local"
    stdout, stderr, rc = run_ipk_scan(["-i", "lo", "-t", "22", "-w", "100", target])
    # We expect the program to output an error message
    assert rc != 0 or "error" in stderr.lower()

# 26. Test ports provided as comma-separated values (22,23,24)
def test_comma_separated_ports():
    target = "localhost"
    ports = "22,23,24"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    for p in [22, 23, 24]:
        assert ipk_results.get(p, "CLOSED") == nmap_results.get(p, "CLOSED")

# 27. TCP – scan with a global IPv6 address (if available)
def test_tcp_ipv6_global():
    target = "2001:67c:1220:809::93e5:917"
    port = "80"
    stdout, _, _ = run_ipk_scan(["-i", ipv6_global_interface, "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface=ipv6_global_interface)
    assert ipk_results.get(80) == nmap_results.get(80)

# 28. UDP – scan with a global IPv6 address (if available)
def test_udp_ipv6_global():
    target = "2001:67c:1220:809::93e5:917"
    port = "53"
    stdout, _, _ = run_ipk_scan(["-i", ipv6_global_interface, "-u", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("udp", port, target, interface=ipv6_global_interface)
    assert ipk_results.get(53) == nmap_results.get(53)

# 29. Test with the interface option specified as the last argument
def test_interface_last_argument():
    target = "localhost"
    port = "22"
    stdout, _, _ = run_ipk_scan(["-t", port, "-w", "100", target, "-i", "lo"])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(22) == nmap_results.get(22)

# 30. Combined scan with multiple port ranges for TCP and UDP
def test_combined_port_ranges():
    target = "localhost"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", "80,8080,443", "-u", "53,67,123", "-w", "150", target])
    results = parse_ipk_output(stdout)
    nmap_tcp = run_nmap_scan("tcp", "80,8080,443", target, interface="lo")
    nmap_udp = run_nmap_scan("udp", "53,67,123", target, interface="lo")
    for p in [80, 8080, 443]:
        assert results.get(p, "CLOSED") == nmap_tcp.get(p, "CLOSED")
    for p in [53, 67, 123]:
        assert results.get(p, "CLOSED") == nmap_udp.get(p, "CLOSED")

# --------------------
# New tests (large number of ports)
# --------------------

# 31. TCP IPv4 – high number of ports 1-20000 on localhost
def test_tcp_high_ports_ipv4_localhost():
    target = "localhost"
    ports = "1-20000"
    # Using -i lo, -t, -w 1000
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    # For verification with nmap (note the time consumption):
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    # Here you could verify only a rough match – e.g., port 22, 80, etc.:
    for check_port in [22, 80, 443]:
        assert ipk_results.get(check_port, "CLOSED") == nmap_results.get(check_port, "CLOSED")

# 32. TCP IPv6 – only 255 ports (1-255) on ::1
def test_tcp_high_ports_ipv6_loopback():
    target = "::1"
    ports = "1-255"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-t", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    # Verification with nmap -6
    nmap_results = run_nmap_scan("tcp", ports, target, interface="lo")
    # For example, we compare port 22 and 80, if they are within [1..255]
    for check_port in [22, 80]:
        assert ipk_results.get(check_port, "CLOSED") == nmap_results.get(check_port, "CLOSED")

# 33. UDP IPv4 – high number of ports 1-20000 on localhost
def test_udp_high_ports_ipv4_localhost():
    target = "localhost"
    ports = "1-20000"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    # Compare with nmap:
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")

    # Again, we can check selected ports:
    for check_port in [53, 67, 5353]:
        ipk_state = ipk_results.get(check_port, "CLOSED")

        # Normalize nmap's UDP result: "OPEN|FILTERED" => "OPEN"
        nmap_state = nmap_results.get(check_port, "CLOSED")
        if nmap_state == "OPEN|FILTERED":
            nmap_state = "OPEN"

        assert ipk_state == nmap_state, f"UDP IPv4 port {check_port}: ipk={ipk_state}, nmap={nmap_state}"

# 34. UDP IPv6 – only 255 ports (1-255) on ::1
def test_udp_high_ports_ipv6_loopback():
    target = "::1"
    ports = "1-255"
    stdout, _, _ = run_ipk_scan(["-i", "lo", "-u", ports, "-w", "1000", target])
    ipk_results = parse_ipk_output(stdout)
    # nmap
    nmap_results = run_nmap_scan("udp", ports, target, interface="lo")

    # Control test:
    for check_port in [53, 123]:
        ipk_state = ipk_results.get(check_port, "CLOSED")

        # Normalize nmap's UDP result: "OPEN|FILTERED" => "OPEN"
        nmap_state = nmap_results.get(check_port, "CLOSED")
        if nmap_state == "OPEN|FILTERED":
            nmap_state = "OPEN"

        assert ipk_state == nmap_state, f"UDP IPv6 port {check_port}: ipk={ipk_state}, nmap={nmap_state}"

# 35. TCP IPv6 – port greater than 255
def test_tcp_ipv6_abowe255():
    target = "::1"
    port = "256"
    stdout, _, _ = run_ipk_scan(["-i", ipv6_global_interface, "-t", port, "-w", "100", target])
    ipk_results = parse_ipk_output(stdout)
    nmap_results = run_nmap_scan("tcp", port, target, interface="lo")
    assert ipk_results.get(256) == nmap_results.get(256)
        
