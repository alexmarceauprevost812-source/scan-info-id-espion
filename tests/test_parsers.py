import marceau as m

ARP_SCAN = """Interface: wlan0, type: EN10MB, MAC: 11:22:33:44:55:66, IPv4: 192.168.1.42
Starting arp-scan 1.10.0 with 256 hosts
192.168.1.1\taa:bb:cc:00:00:01\tTP-LINK TECHNOLOGIES CO.,LTD.
192.168.1.20\tAA:BB:CC:00:00:02\tSamsung Electronics Co.,Ltd
192.168.1.30\taa:bb:cc:00:00:03\t(Unknown)

3 packets received by filter, 0 packets dropped by kernel
"""

NMAP_PING = """Starting Nmap 7.94
Nmap scan report for routeur.lan (192.168.1.1)
Host is up (0.0030s latency).
MAC Address: AA:BB:CC:00:00:01 (TP-Link)
Nmap scan report for 192.168.1.20
Host is up (0.050s latency).
MAC Address: AA:BB:CC:00:00:02 (Samsung Electronics)
Nmap scan report for 192.168.1.42
Host is up.
Nmap done: 256 IP addresses (3 hosts up)
"""

PORT_SCAN = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6 (protocol 2.0)
23/tcp   open  telnet  BusyBox telnetd
80/tcp   open  http    lighttpd
Device type: general purpose
Running: Linux 4.X|5.X
OS details: Linux 4.15 - 5.8
"""

IP_ROUTE = """default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.42 metric 600
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42 metric 600
"""

DHCP = """| broadcast-dhcp-discover:
|   Response 1 of 2:
|     Server Identifier: 192.168.1.1
|   Response 2 of 2:
|     Server Identifier: 192.168.1.66
|     Server Identifier: 192.168.1.1
"""


def test_parse_arp_scan():
    d = m.parse_arp_scan(ARP_SCAN)
    assert [x["ip"] for x in d] == ["192.168.1.1", "192.168.1.20", "192.168.1.30"]
    assert d[1]["mac"] == "aa:bb:cc:00:00:02"  # toujours en minuscules
    assert d[0]["vendor"].startswith("TP-LINK")


def test_parse_arp_scan_vide():
    assert m.parse_arp_scan("") == []
    assert m.parse_arp_scan(None) == []


def test_parse_nmap_ping_ignore_hote_sans_mac():
    d = m.parse_nmap_ping(NMAP_PING)
    assert d == [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "vendor": "TP-Link"},
        {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02", "vendor": "Samsung Electronics"},
    ]


def test_parse_ip_route():
    assert m.parse_ip_route(IP_ROUTE) == ("192.168.1.0/24", "192.168.1.1")
    assert m.parse_ip_route("") == (None, None)


def test_parse_port_scan_et_ports_a_risque():
    r = m.parse_port_scan(PORT_SCAN)
    assert [p["port"] for p in r["ports"]] == ["22", "23", "80"]
    assert r["os"] == "Linux 4.X|5.X"  # « Running: » prioritaire sur « OS details: »
    assert r["device_type"] == "general purpose"
    assert m.risky_ports_of(r["ports"]) == ["23/telnet"]


def test_parse_cves_dedoublonne():
    txt = "VULNERABLE CVE-2017-0144 ... CVE-2017-0144 ... CVE-2021-44228"
    assert m.parse_cves(txt) == ["CVE-2017-0144", "CVE-2021-44228"]
    assert m.parse_cves(None) == []


def test_parse_dhcp_servers():
    assert m.parse_dhcp_servers(DHCP) == ["192.168.1.1", "192.168.1.66"]


def test_parse_nmcli_wifi():
    out = "  :Voisin:WPA2\n*:MaMaison:WPA3\n"
    assert m.parse_nmcli_wifi(out) == {"ssid": "MaMaison", "security": "WPA3"}
    assert m.parse_nmcli_wifi("*:CafeGratuit:\n")["security"].startswith("Ouvert")
    assert m.parse_nmcli_wifi("") is None


def test_run_retire_sudo_si_root(monkeypatch):
    vu = {}
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    monkeypatch.setattr(m.subprocess, "run", lambda cmd, **k: vu.setdefault("cmd", cmd))
    from conftest import REAL_RUN
    REAL_RUN(["sudo", "arp-scan", "--localnet"])
    assert vu["cmd"] == ["arp-scan", "--localnet"]
