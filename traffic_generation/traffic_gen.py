
"""
Live traffic generator (for reproduction in a real lab).

HONESTY NOTE: The results in the report are produced by `build_dataset.py`,
which synthesizes the same pcap reproducibly on any machine.
This script exists so that the same traffic can be produced LIVE in a set-up
lab (server + Snort in live capture) to confirm the method. The labeling
here too comes from event_log.csv (timestamps), not from the features.

Topology (see TESTBED_DESIGN.md):
  server (victim) : 10.0.0.10 : 8080         (HOME_NET 10.0.0.0/24)
  attacker        : 192.168.56.20            (EXTERNAL_NET)
Configured via the environment variables TARGET_IP / TARGET_PORT.

Requirements: scapy (SYN/ICMP), root privileges for raw packets.
  sudo python3 traffic_gen.py
"""

import os
import csv
import time
import random
import socket

# The target is set via env vars (default: the victim server of the topology)
TARGET_IP = os.environ.get("TARGET_IP", "10.0.0.10")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8080"))
# The ground truth is written to logs/event_log.csv (relative to the script)
LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "event_log.csv")

# Suspicious URIs for the application-layer attacks
SUSPICIOUS = ["/phpmyadmin/", "/admin", "/cmd.php?x=id", "/../../../etc/passwd",
              "/shell.php", "/.git/config", "/wp-admin/", "/?file=../../etc/shadow"]


def log_event(atype, start, end, desc):
    # Record an attack episode in event_log.csv (writes the header only the first time)
    os.makedirs(os.path.dirname(os.path.abspath(LOG)), exist_ok=True)
    new = not os.path.exists(LOG)
    with open(LOG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["attack_type", "start_time", "end_time", "description"])
        w.writerow([atype, round(start, 3), round(end, 3), desc])
    print(f"[LOG] {atype}: {desc}")


def http_get(path="/", ua="Mozilla/5.0"):
    # A single HTTP GET request to the target. The ua sets the User-Agent
    # (e.g. 'sqlmap' for the attacks). Returns True/False depending on success.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        req = (f"GET {path} HTTP/1.1\r\nHost: {TARGET_IP}:{TARGET_PORT}\r\n"
               f"User-Agent: {ua}\r\nConnection: close\r\n\r\n").encode()
        s.send(req); s.close()
        return True
    except Exception:
        return False


def benign(duration=60):
    # Legitimate traffic: normal GETs at a sparse, random rate
    print("[*] BENIGN traffic")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/"); n += 1
        time.sleep(random.uniform(0.6, 1.8))
    log_event("BENIGN", t0, time.time(), f"{n} normal HTTP requests")


def syn_scan(duration=3):
    # SYN scan: SYN packets to many ports (recon). Requires scapy + root.
    print("[*] SYN scan")
    from scapy.all import IP, TCP, send
    t0 = time.time(); n = 0
    for port in random.sample(range(1, 9000), 250):
        send(IP(dst=TARGET_IP) / TCP(dport=port, flags="S"), verbose=0)
        n += 1; time.sleep(0.012)
    log_event("SYN_SCAN", t0, time.time(), f"{n} SYN packets to many ports")


def icmp_flood(duration=3):
    # ICMP flood: high-frequency echo requests. Requires scapy + root.
    print("[*] ICMP flood")
    from scapy.all import IP, ICMP, send
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        send(IP(dst=TARGET_IP) / ICMP(), verbose=0); n += 1; time.sleep(0.006)
    log_event("ICMP_FLOOD", t0, time.time(), f"{n} ICMP echo requests (flood)")


def conn_flood(duration=3):
    # Connection flood: many fast full connections
    print("[*] TCP connection flood")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/"); n += 1; time.sleep(0.04)
    log_event("CONN_FLOOD", t0, time.time(), f"{n} rapid TCP connections")


def http_probe(duration=4):
    # HTTP probe: suspicious requests with a sqlmap User-Agent (moderate rate)
    print("[*] HTTP probe")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get(random.choice(SUSPICIOUS), ua="sqlmap/1.5"); n += 1
        time.sleep(random.uniform(0.20, 0.35))
    log_event("HTTP_ATTACK", t0, time.time(), f"{n} suspicious HTTP requests")


def stealth_web(duration=70):
    # Stealth web probe: individual suspicious requests, sparse (look legitimate)
    print("[*] Stealth web probe (individual suspicious requests)")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/phpmyadmin/", ua="sqlmap/1.5"); n += 1
        time.sleep(random.uniform(3.5, 5.0))
    log_event("STEALTH_WEB", t0, time.time(), f"{n} stealthy single web probes")


def slow_attack(duration=120):
    # Low-and-slow SQLi: the request in small pieces with delays (stealth)
    print("[*] Low-and-slow SQLi")
    t0 = time.time(); n = 0
    parts = [b"GET /?id=1", b" UNION", b" SELECT", b" version()--", b" HTTP/1.1\r\n\r\n"]
    while time.time() - t0 < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
            s.connect((TARGET_IP, TARGET_PORT))
            for p in parts:
                try:
                    s.send(p); time.sleep(0.4)   # 0.4s between each piece
                except (BrokenPipeError, ConnectionResetError):
                    break
            s.close()
        except Exception:
            pass
        n += 1; time.sleep(random.uniform(8, 14))   # large gaps between requests
    log_event("SLOW_ATTACK", t0, time.time(), f"{n} low-and-slow SQLi attempts")


def main():
    print("=" * 60)
    print("Hybrid IDS lab - live traffic generator")
    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print("=" * 60)
    time.sleep(2)
    # Simplified order: baseline and then the attacks with small gaps between
    benign(60)
    syn_scan(); time.sleep(3)
    http_probe(); time.sleep(3)
    icmp_flood(); time.sleep(3)
    conn_flood(); time.sleep(3)
    stealth_web(); time.sleep(3)
    slow_attack()
    benign(30)
    print("[+] DONE - see logs/event_log.csv")


if __name__ == "__main__":
    main()
