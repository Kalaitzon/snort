"""
Synthesis of a controlled, time-stamped dataset for the Hybrid IDS.

Produces:
  - pcaps/lab_traffic.pcap : synthetic but realistic traffic (TCP/ICMP)
  - logs/event_log.csv     : timeline (ground truth) of each scenario

IMPORTANT (design choice):
The labels do NOT come from the traffic features, but exclusively from the
time interval and the attacker's identity (timeline). This avoids circular
labeling / data leakage and keeps the metrics honest.

Topology:
  HOME_NET     = 10.0.0.0/24
    - server  (HTTP victim) : 10.0.0.10 : port 8080
    - client  (legitimate)  : 10.0.0.50
  EXTERNAL_NET = !HOME_NET
    - attacker              : 192.168.56.20
    - external_client       : 203.0.113.7 (legitimate external access)
"""

import os
import csv
import random
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

# Fixed random seed -> deterministic, reproducible generation.
SEED = 1337
random.seed(SEED)

# Topology addresses
SERVER = "10.0.0.10"
CLIENT = "10.0.0.50"
EXT_CLIENT = "203.0.113.7"
ATTACKER = "192.168.56.20"
PORT = 8080

# Output paths relative to the project root (portable, independent of the cwd).
# The script lives in <root>/traffic_generation/, so the root is two folders up.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_OUT = os.path.join(BASE, "pcaps", "lab_traffic.pcap")
LOG_OUT = os.path.join(BASE, "logs", "event_log.csv")

packets = []          # list of (timestamp, scapy_packet)
events = []           # list of dicts for event_log.csv

# ---------------------------------------------------------------------------
# Helper functions for building packets
# ---------------------------------------------------------------------------

def _eph_port():
    # Random ephemeral source port (as in real connections)
    return random.randint(1024, 65535)

def tcp_pkt(t, src, dst, sport, dport, flags, payload_len=0):
    # A TCP packet with the given flags. payload_len adds "weight".
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_len > 0:
        p = p / Raw(load=b"x" * payload_len)
    return (t, p)

def icmp_pkt(t, src, dst, payload_len=0):
    # ICMP echo request (type 8) -> the pings
    p = IP(src=src, dst=dst) / ICMP(type=8, code=0)
    if payload_len > 0:
        p = p / Raw(load=b"p" * payload_len)
    return (t, p)

def udp_pkt(t, src, dst, sport, dport, payload_len=0):
    # Helper for UDP (not used in the current scenario, but available)
    p = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload_len > 0:
        p = p / Raw(load=b"u" * payload_len)
    return (t, p)

def http_flow(t, client_ip, server_ip, dport, req_len=120, resp_len=400, n_resp=2):
    """Full legitimate HTTP flow: three-way handshake (SYN, SYN-ACK, ACK), GET request
    (PSH), responses (PSH) and close (FIN). Realistically renders a normal
    browser-server connection."""
    sp = _eph_port()
    out = []
    out.append(tcp_pkt(t + 0.000, client_ip, server_ip, sp, dport, "S"))    # SYN
    out.append(tcp_pkt(t + 0.001, server_ip, client_ip, dport, sp, "SA"))   # SYN-ACK
    out.append(tcp_pkt(t + 0.002, client_ip, server_ip, sp, dport, "A"))    # ACK
    out.append(tcp_pkt(t + 0.003, client_ip, server_ip, sp, dport, "PA", req_len))  # GET
    for i in range(n_resp):
        out.append(tcp_pkt(t + 0.010 + i * 0.004, server_ip, client_ip, dport, sp, "PA", resp_len))
    out.append(tcp_pkt(t + 0.030, client_ip, server_ip, sp, dport, "FA"))   # FIN
    out.append(tcp_pkt(t + 0.031, server_ip, client_ip, dport, sp, "FA"))
    out.append(tcp_pkt(t + 0.032, client_ip, server_ip, sp, dport, "A"))
    return out

# ---------------------------------------------------------------------------
# 1) BENIGN baseline (continuous throughout the whole duration)
# ---------------------------------------------------------------------------

DURATION = 1800.0   # 30 minutes of simulated time

def gen_benign():
    """Legitimate traffic: random HTTP browsing + periodic ICMP pings (monitoring).
    It also includes occasional 'heavy' (but legitimate) bursts, so that a
    realistic false-positive risk is created and the problem is not
    trivially separable."""
    t = 0.0
    while t < DURATION:
        # Normal page visit from an internal (more often) or external client
        client = random.choice([CLIENT, CLIENT, CLIENT, EXT_CLIENT])
        packets.extend(http_flow(t, client, SERVER, PORT,
                                 req_len=random.randint(80, 200),
                                 resp_len=random.randint(200, 800),
                                 n_resp=random.randint(1, 3)))

        # Occasional legitimate "heavy" burst (e.g. a page with many assets)
        if random.random() < 0.04:
            base = t + 0.05
            for _ in range(random.randint(6, 10)):
                packets.extend(http_flow(base, client, SERVER, PORT,
                                         req_len=120, resp_len=600, n_resp=2))
                base += random.uniform(0.02, 0.08)

        # Periodic ICMP ping monitoring from an internal host (INSIDE HOME_NET,
        # which is why it does not trigger the Snort rule for external ICMP)
        if random.random() < 0.10:
            packets.append(icmp_pkt(t + 0.04, CLIENT, SERVER, payload_len=56))

        t += random.uniform(0.6, 1.8)   # gap until the next visit

# ---------------------------------------------------------------------------
# 2) ATTACK scenarios (repeated, at known time intervals)
#    All attacks come from the ATTACKER (outside HOME_NET).
# ---------------------------------------------------------------------------

def log_event(attack_type, start, end, desc):
    # Record one attack episode in the ground truth (event_log.csv)
    events.append({
        "attack_type": attack_type,
        "start_time": round(start, 3),
        "end_time": round(end, 3),
        "description": desc,
    })

def syn_scan(start):
    """SYN scan: many SYNs from the attacker to many ports (reconnaissance/recon).
    Burst of ~3s. The server replies RST on closed ports."""
    t = start
    n = 0
    for port in random.sample(range(1, 9000), 250):
        packets.append(tcp_pkt(t, ATTACKER, SERVER, _eph_port(), port, "S"))
        if random.random() < 0.8:
            packets.append(tcp_pkt(t + 0.0005, SERVER, ATTACKER, port, _eph_port(), "RA"))
        t += 0.012
        n += 1
    log_event("SYN_SCAN", start, t, f"{n} SYN packets to many ports")

def icmp_flood(start):
    """ICMP flood: high-frequency echo requests from the attacker (outside HOME_NET)."""
    t = start
    n = 0
    while t < start + 3.0:
        packets.append(icmp_pkt(t, ATTACKER, SERVER, payload_len=random.randint(56, 1000)))
        t += 0.006
        n += 1
    log_event("ICMP_FLOOD", start, t, f"{n} ICMP echo requests (flood)")

def conn_flood(start):
    """TCP connection flood/burst: many fast full connections (resource exhaustion)."""
    t = start
    n = 0
    while t < start + 3.0:
        packets.extend(http_flow(t, ATTACKER, SERVER, PORT, req_len=60, resp_len=120, n_resp=1))
        t += 0.04
        n += 1
    log_event("CONN_FLOOD", start, t, f"{n} rapid TCP connections (burst)")

# Suspicious URIs used by the application-layer attacks
SUSPICIOUS = ["/phpmyadmin/", "/admin", "/cmd.php?x=id", "/../../../etc/passwd",
              "/shell.php", "/.git/config", "/wp-admin/", "/?file=../../etc/shadow"]

def http_probe(start):
    """HTTP probe: suspicious requests + User-Agent 'sqlmap' (moderate rate).
    The content (sqlmap / phpmyadmin) is caught by Snort with a content match."""
    t = start
    n = 0
    while t < start + 4.0:
        path = random.choice(SUSPICIOUS)
        payload = (f"GET {path} HTTP/1.1\r\nHost: {SERVER}:{PORT}\r\n"
                   f"User-Agent: sqlmap/1.5\r\nConnection: close\r\n\r\n").encode()
        sp = _eph_port()
        packets.append(tcp_pkt(t, ATTACKER, SERVER, sp, PORT, "S"))
        packets.append(tcp_pkt(t + 0.001, SERVER, ATTACKER, PORT, sp, "SA"))
        packets.append(tcp_pkt(t + 0.002, ATTACKER, SERVER, sp, PORT, "A"))
        # The packet with the full HTTP request (contains the signature)
        packets.append((t + 0.003, IP(src=ATTACKER, dst=SERVER) /
                        TCP(sport=sp, dport=PORT, flags="PA") / Raw(load=payload)))
        packets.append(tcp_pkt(t + 0.010, SERVER, ATTACKER, PORT, sp, "PA", 300))
        packets.append(tcp_pkt(t + 0.020, ATTACKER, SERVER, sp, PORT, "FA"))
        t += random.uniform(0.20, 0.35)
        n += 1
    log_event("HTTP_ATTACK", start, t, f"{n} suspicious HTTP requests (sqlmap UA)")

def stealth_web_probe(start):
    """Stealth web probe: INDIVIDUAL suspicious requests (phpmyadmin / sqlmap UA), one
    every ~4s, so that each falls into a separate quiet window with a volume ~ benign.
    Snort catches it with a content match, while RF (which sees the aggregate volume)
    misses it. Source of the "Snort-advantage" case studies."""
    t = start
    n = 0
    while t < start + 70.0:
        path = random.choice(["/phpmyadmin/", "/phpmyadmin/index.php"])
        payload = (f"GET {path} HTTP/1.1\r\nHost: {SERVER}:{PORT}\r\n"
                   f"User-Agent: sqlmap/1.5\r\nConnection: close\r\n\r\n").encode()
        sp = _eph_port()
        packets.append(tcp_pkt(t, ATTACKER, SERVER, sp, PORT, "S"))
        packets.append(tcp_pkt(t + 0.001, SERVER, ATTACKER, PORT, sp, "SA"))
        packets.append(tcp_pkt(t + 0.002, ATTACKER, SERVER, sp, PORT, "A"))
        packets.append((t + 0.003, IP(src=ATTACKER, dst=SERVER) /
                        TCP(sport=sp, dport=PORT, flags="PA") / Raw(load=payload)))
        packets.append(tcp_pkt(t + 0.010, SERVER, ATTACKER, PORT, sp, "PA", 300))
        packets.append(tcp_pkt(t + 0.020, ATTACKER, SERVER, sp, PORT, "FA"))
        n += 1
        t += random.uniform(3.5, 5.0)   # large gaps -> one request per quiet window
    log_event("STEALTH_WEB", start, t, f"{n} stealthy single web probes")

def slow_attack(start):
    """Low-and-slow SQLi: sparse flow, low rate per window, intentionally below
    Snort's thresholds. The request breaks into small pieces with delays, so that
    no packet contains the whole signature. Spread over ~120s."""
    t = start
    n = 0
    while t < start + 120.0:
        sp = _eph_port()
        packets.append(tcp_pkt(t, ATTACKER, SERVER, sp, PORT, "S"))
        packets.append(tcp_pkt(t + 0.05, SERVER, ATTACKER, PORT, sp, "SA"))
        packets.append(tcp_pkt(t + 0.10, ATTACKER, SERVER, sp, PORT, "A"))
        # Each piece of the request in a separate packet, 0.4s apart (stealth)
        for j, chunk in enumerate([b"GET /?id=1", b" UNION", b" SELECT", b" version()--",
                                    b" HTTP/1.1\r\nHost: x\r\n\r\n"]):
            packets.append((t + 0.2 + j * 0.4,
                            IP(src=ATTACKER, dst=SERVER) /
                            TCP(sport=sp, dport=PORT, flags="PA") / Raw(load=chunk)))
        packets.append(tcp_pkt(t + 3.0, ATTACKER, SERVER, sp, PORT, "FA"))
        n += 1
        t += random.uniform(8.0, 14.0)   # large gaps between requests
    log_event("SLOW_ATTACK", start, t, f"{n} low-and-slow SQLi attempts")

# ---------------------------------------------------------------------------
# Orchestration: benign baseline + the attacks at known points of the timeline
# ---------------------------------------------------------------------------

def main():
    gen_benign()

    # Each attack is repeated at different points, with a small random offset
    for s in [150, 600, 1100, 1500]:
        syn_scan(s + random.uniform(0, 5))
    for s in [300, 800, 1300]:
        icmp_flood(s + random.uniform(0, 5))
    for s in [450, 950, 1600]:
        conn_flood(s + random.uniform(0, 5))
    for s in [250, 700, 1200, 1650]:
        http_probe(s + random.uniform(0, 5))
    # Two low-and-slow campaigns (the "hard" scenario for Snort)
    slow_attack(380)
    slow_attack(1000)
    # Two stealth web probe campaigns (the "hard" scenario for ML)
    stealth_web_probe(550)
    stealth_web_probe(1400)

    # Sort all packets by time and assign an absolute timestamp.
    # base_ts is fixed, so that the pcap is deterministic.
    packets.sort(key=lambda x: x[0])
    base_ts = 1716500000.0
    out = []
    for (t, p) in packets:
        p.time = base_ts + t
        out.append(p)

    # Create the output folders if they do not exist, and write
    os.makedirs(os.path.dirname(PCAP_OUT), exist_ok=True)
    os.makedirs(os.path.dirname(LOG_OUT), exist_ok=True)
    wrpcap(PCAP_OUT, out)

    events.sort(key=lambda e: e["start_time"])
    with open(LOG_OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["attack_type", "start_time", "end_time", "description"])
        w.writeheader()
        for e in events:
            w.writerow(e)

    print(f"[OK] Packets: {len(out)}")
    print(f"[OK] Events : {len(events)}")
    print(f"[OK] pcap   : {PCAP_OUT}")
    print(f"[OK] log    : {LOG_OUT}")

if __name__ == "__main__":
    main()
