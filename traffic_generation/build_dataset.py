# Ioannis Kalaitzidis, MTE25012

"""
Synthesis ελεγχομενου, χρονοσφραγισμενου dataset για το Hybrid IDS.

Παραγει:
  - pcaps/lab_traffic.pcap : συνθετικη αλλα ρεαλιστικη κινηση (TCP/ICMP)
  - logs/event_log.csv     : χρονοδιαγραμμα (ground truth) καθε σεναριου

ΣΗΜΑΝΤΙΚΟ (σχεδιαστικη επιλογη):
Τα labels ΔΕΝ προερχονται απο τα χαρακτηριστικα (features) της κινησης, αλλα
αποκλειστικα απο το χρονικο διαστημα και την ταυτοτητα του επιτιθεμενου (timeline).
Ετσι αποφευγεται το circular labeling / data leakage και οι μετρικες ειναι τιμιες.

Τοπολογια:
  HOME_NET     = 10.0.0.0/24
    - server  (θυμα HTTP) : 10.0.0.10 : port 8080
    - client  (νομιμος)   : 10.0.0.50
  EXTERNAL_NET = !HOME_NET
    - attacker            : 192.168.56.20
    - external_client     : 203.0.113.7 (νομιμη εξωτερικη προσβαση)
"""

import os
import csv
import random
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

# Σταθερος σπορος τυχαιοτητας -> ντετερμινιστικη, επαναληψιμη παραγωγη.
SEED = 1337
random.seed(SEED)

# Διευθυνσεις της τοπολογιας
SERVER = "10.0.0.10"
CLIENT = "10.0.0.50"
EXT_CLIENT = "203.0.113.7"
ATTACKER = "192.168.56.20"
PORT = 8080

# Διαδρομες εξοδου σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd).
# Το script βρισκεται σε <ριζα>/traffic_generation/, αρα η ριζα ειναι δυο φακελους πανω.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_OUT = os.path.join(BASE, "pcaps", "lab_traffic.pcap")
LOG_OUT = os.path.join(BASE, "logs", "event_log.csv")

packets = []          # λιστα απο (timestamp, scapy_packet)
events = []           # λιστα απο dict για το event_log.csv

# ---------------------------------------------------------------------------
# Βοηθητικες συναρτησεις δομησης πακετων
# ---------------------------------------------------------------------------

def _eph_port():
    # Τυχαια ephemeral θυρα πηγης (οπως σε πραγματικες συνδεσεις)
    return random.randint(1024, 65535)

def tcp_pkt(t, src, dst, sport, dport, flags, payload_len=0):
    # Ενα TCP πακετο με τις δοσμενες σημαιες. Το payload_len προσθετει "βαρος".
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_len > 0:
        p = p / Raw(load=b"x" * payload_len)
    return (t, p)

def icmp_pkt(t, src, dst, payload_len=0):
    # ICMP echo request (type 8) -> τα ping
    p = IP(src=src, dst=dst) / ICMP(type=8, code=0)
    if payload_len > 0:
        p = p / Raw(load=b"p" * payload_len)
    return (t, p)

def udp_pkt(t, src, dst, sport, dport, payload_len=0):
    # Βοηθητικη για UDP (δεν χρησιμοποιειται στο τρεχον σεναριο, αλλα διαθεσιμη)
    p = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload_len > 0:
        p = p / Raw(load=b"u" * payload_len)
    return (t, p)

def http_flow(t, client_ip, server_ip, dport, req_len=120, resp_len=400, n_resp=2):
    """Πληρης νομιμη HTTP ροη: three-way handshake (SYN, SYN-ACK, ACK), αιτημα GET
    (PSH), απαντησεις (PSH) και κλεισιμο (FIN). Αποδιδει ρεαλιστικα μια κανονικη
    συνδεση browser-server."""
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
# 1) BENIGN baseline (συνεχης καθ' ολη τη διαρκεια)
# ---------------------------------------------------------------------------

DURATION = 1800.0   # 30 λεπτα προσομοιωμενου χρονου

def gen_benign():
    """Νομιμη κινηση: τυχαια HTTP browsing + περιοδικα ICMP pings (monitoring).
    Περιλαμβανει και περιστασιακες 'βαριες' (αλλα νομιμες) ριπες, ωστε να
    δημιουργειται ρεαλιστικος κινδυνος false positive και το προβλημα να μην
    ειναι τετριμμενα διαχωρισιμο."""
    t = 0.0
    while t < DURATION:
        # Κανονικη επισκεψη σελιδας απο εσωτερικο (πιο συχνα) ή εξωτερικο πελατη
        client = random.choice([CLIENT, CLIENT, CLIENT, EXT_CLIENT])
        packets.extend(http_flow(t, client, SERVER, PORT,
                                 req_len=random.randint(80, 200),
                                 resp_len=random.randint(200, 800),
                                 n_resp=random.randint(1, 3)))

        # Περιστασιακη νομιμη "βαρια" ριπη (π.χ. σελιδα με πολλα assets)
        if random.random() < 0.04:
            base = t + 0.05
            for _ in range(random.randint(6, 10)):
                packets.extend(http_flow(base, client, SERVER, PORT,
                                         req_len=120, resp_len=600, n_resp=2))
                base += random.uniform(0.02, 0.08)

        # Περιοδικο ICMP ping monitoring απο εσωτερικο host (ΕΝΤΟΣ HOME_NET,
        # γι' αυτο δεν πυροδοτει τον κανονα του Snort για external ICMP)
        if random.random() < 0.10:
            packets.append(icmp_pkt(t + 0.04, CLIENT, SERVER, payload_len=56))

        t += random.uniform(0.6, 1.8)   # κενο μεχρι την επομενη επισκεψη

# ---------------------------------------------------------------------------
# 2) ATTACK σεναρια (επαναλαμβανομενα, με γνωστα χρονικα διαστηματα)
#    Ολες οι επιθεσεις προερχονται απο τον ATTACKER (εκτος HOME_NET).
# ---------------------------------------------------------------------------

def log_event(attack_type, start, end, desc):
    # Καταγραφη ενος επεισοδιου επιθεσης στο ground truth (event_log.csv)
    events.append({
        "attack_type": attack_type,
        "start_time": round(start, 3),
        "end_time": round(end, 3),
        "description": desc,
    })

def syn_scan(start):
    """SYN scan: πολλα SYN απο τον attacker σε πολλες θυρες (αναγνωριση/recon).
    Ριπη ~3s. Ο server απανταει RST στις κλειστες θυρες."""
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
    """ICMP flood: echo requests υψηλης συχνοτητας απο τον attacker (εκτος HOME_NET)."""
    t = start
    n = 0
    while t < start + 3.0:
        packets.append(icmp_pkt(t, ATTACKER, SERVER, payload_len=random.randint(56, 1000)))
        t += 0.006
        n += 1
    log_event("ICMP_FLOOD", start, t, f"{n} ICMP echo requests (flood)")

def conn_flood(start):
    """TCP connection flood/burst: πολλες ταχειες πληρεις συνδεσεις (εξαντληση πορων)."""
    t = start
    n = 0
    while t < start + 3.0:
        packets.extend(http_flow(t, ATTACKER, SERVER, PORT, req_len=60, resp_len=120, n_resp=1))
        t += 0.04
        n += 1
    log_event("CONN_FLOOD", start, t, f"{n} rapid TCP connections (burst)")

# Υποπτα URIs που χρησιμοποιουν οι επιθεσεις εφαρμογης
SUSPICIOUS = ["/phpmyadmin/", "/admin", "/cmd.php?x=id", "/../../../etc/passwd",
              "/shell.php", "/.git/config", "/wp-admin/", "/?file=../../etc/shadow"]

def http_probe(start):
    """HTTP probe: υποπτα αιτηματα + User-Agent 'sqlmap' (μετριος ρυθμος).
    Το περιεχομενο (sqlmap / phpmyadmin) το πιανει ο Snort με content match."""
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
        # Το πακετο με το πληρες HTTP αιτημα (περιεχει την υπογραφη)
        packets.append((t + 0.003, IP(src=ATTACKER, dst=SERVER) /
                        TCP(sport=sp, dport=PORT, flags="PA") / Raw(load=payload)))
        packets.append(tcp_pkt(t + 0.010, SERVER, ATTACKER, PORT, sp, "PA", 300))
        packets.append(tcp_pkt(t + 0.020, ATTACKER, SERVER, sp, PORT, "FA"))
        t += random.uniform(0.20, 0.35)
        n += 1
    log_event("HTTP_ATTACK", start, t, f"{n} suspicious HTTP requests (sqlmap UA)")

def stealth_web_probe(start):
    """Stealth web probe: ΜΕΜΟΝΩΜΕΝΑ υποπτα αιτηματα (phpmyadmin / sqlmap UA), ενα
    καθε ~4s, ωστε καθε ενα να πεφτει σε ξεχωριστο ησυχο παραθυρο με ογκο ~ benign.
    Ο Snort το πιανει με content match, ενω το RF (που βλεπει aggregate ογκο) το
    χανει. Πηγη των "Snort-advantage" case studies."""
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
        t += random.uniform(3.5, 5.0)   # μεγαλα κενα -> ενα αιτημα ανα ησυχο παραθυρο
    log_event("STEALTH_WEB", start, t, f"{n} stealthy single web probes")

def slow_attack(start):
    """Low-and-slow SQLi: αραιη ροη, χαμηλος ρυθμος ανα παραθυρο, σκοπιμα κατω απο
    τα κατωφλια του Snort. Το αιτημα σπαει σε μικρα κομματια με καθυστερησεις, ωστε
    κανενα πακετο να μην περιεχει ολοκληρη την υπογραφη. Απλωνεται σε ~120s."""
    t = start
    n = 0
    while t < start + 120.0:
        sp = _eph_port()
        packets.append(tcp_pkt(t, ATTACKER, SERVER, sp, PORT, "S"))
        packets.append(tcp_pkt(t + 0.05, SERVER, ATTACKER, PORT, sp, "SA"))
        packets.append(tcp_pkt(t + 0.10, ATTACKER, SERVER, sp, PORT, "A"))
        # Καθε κομματι του αιτηματος σε ξεχωριστο πακετο, με 0.4s αναμεσα (stealth)
        for j, chunk in enumerate([b"GET /?id=1", b" UNION", b" SELECT", b" version()--",
                                    b" HTTP/1.1\r\nHost: x\r\n\r\n"]):
            packets.append((t + 0.2 + j * 0.4,
                            IP(src=ATTACKER, dst=SERVER) /
                            TCP(sport=sp, dport=PORT, flags="PA") / Raw(load=chunk)))
        packets.append(tcp_pkt(t + 3.0, ATTACKER, SERVER, sp, PORT, "FA"))
        n += 1
        t += random.uniform(8.0, 14.0)   # μεγαλα κενα μεταξυ αιτηματων
    log_event("SLOW_ATTACK", start, t, f"{n} low-and-slow SQLi attempts")

# ---------------------------------------------------------------------------
# Ενορχηστρωση: benign baseline + οι επιθεσεις σε γνωστα σημεια του timeline
# ---------------------------------------------------------------------------

def main():
    gen_benign()

    # Καθε επιθεση επαναλαμβανεται σε διαφορετικα σημεια, με μικρη τυχαια μετατοπιση
    for s in [150, 600, 1100, 1500]:
        syn_scan(s + random.uniform(0, 5))
    for s in [300, 800, 1300]:
        icmp_flood(s + random.uniform(0, 5))
    for s in [450, 950, 1600]:
        conn_flood(s + random.uniform(0, 5))
    for s in [250, 700, 1200, 1650]:
        http_probe(s + random.uniform(0, 5))
    # Δυο εκστρατειες low-and-slow (το "δυσκολο" σεναριο για τον Snort)
    slow_attack(380)
    slow_attack(1000)
    # Δυο εκστρατειες stealth web probe (το "δυσκολο" σεναριο για το ML)
    stealth_web_probe(550)
    stealth_web_probe(1400)

    # Ταξινομηση ολων των πακετων κατα χρονο και αποδοση απολυτης χρονοσφραγιδας.
    # Η base_ts ειναι σταθερη, ωστε το pcap να ειναι ντετερμινιστικο.
    packets.sort(key=lambda x: x[0])
    base_ts = 1716500000.0
    out = []
    for (t, p) in packets:
        p.time = base_ts + t
        out.append(p)

    # Δημιουργια φακελων εξοδου αν δεν υπαρχουν, και εγγραφη
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
