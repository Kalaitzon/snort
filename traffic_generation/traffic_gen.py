# Ioannis Kalaitzidis, MTE25012

"""
Live traffic generator (για αναπαραγωγη σε πραγματικο εργαστηριο).

ΣΗΜΕΙΩΣΗ ΤΙΜΙΟΤΗΤΑΣ: Τα αποτελεσματα της αναφορας παραγονται απο το 
`build_dataset.py`, το οποιο συνθετει το ιδιο pcap αναπαραγωγιμα σε καθε μηχανημα.
Το παρον script υπαρχει ωστε η ιδια κινηση να μπορει να παραχθει ΖΩΝΤΑΝΑ σε στημενο
lab (server + Snort σε live capture) και να επιβεβαιωθει η μεθοδος. Η επισημανση
(labeling) γινεται και εδω απο το event_log.csv (χρονοσφραγιδες), οχι απο τα features.

Τοπολογια (δες TESTBED_DESIGN.md):
  server (θυμα)  : 10.0.0.10 : 8080         (HOME_NET 10.0.0.0/24)
  attacker       : 192.168.56.20            (EXTERNAL_NET)
Ρυθμιζεται μεσω μεταβλητων περιβαλλοντος TARGET_IP / TARGET_PORT.

Απαιτησεις: scapy (SYN/ICMP), δικαιωματα root για raw packets.
  sudo python3 traffic_gen.py
"""

import os
import csv
import time
import random
import socket

# Ο στοχος οριζεται με env vars (default: ο server-θυμα της τοπολογιας)
TARGET_IP = os.environ.get("TARGET_IP", "10.0.0.10")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8080"))
# Το ground truth γραφεται στο logs/event_log.csv (σχετικα με το script)
LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "event_log.csv")

# Υποπτα URIs για τις επιθεσεις επιπεδου εφαρμογης
SUSPICIOUS = ["/phpmyadmin/", "/admin", "/cmd.php?x=id", "/../../../etc/passwd",
              "/shell.php", "/.git/config", "/wp-admin/", "/?file=../../etc/shadow"]


def log_event(atype, start, end, desc):
    # Καταγραφη επεισοδιου στο event_log.csv (γραφει header μονο την πρωτη φορα)
    os.makedirs(os.path.dirname(os.path.abspath(LOG)), exist_ok=True)
    new = not os.path.exists(LOG)
    with open(LOG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["attack_type", "start_time", "end_time", "description"])
        w.writerow([atype, round(start, 3), round(end, 3), desc])
    print(f"[LOG] {atype}: {desc}")


def http_get(path="/", ua="Mozilla/5.0"):
    # Ενα HTTP GET αιτημα προς τον στοχο. Το ua καθοριζει το User-Agent
    # (π.χ. 'sqlmap' για τις επιθεσεις). Επιστρεφει True/False αναλογα με την επιτυχια.
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
    # Νομιμη κινηση: κανονικα GET σε αραιο, τυχαιο ρυθμο
    print("[*] BENIGN traffic")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/"); n += 1
        time.sleep(random.uniform(0.6, 1.8))
    log_event("BENIGN", t0, time.time(), f"{n} normal HTTP requests")


def syn_scan(duration=3):
    # SYN scan: SYN πακετα σε πολλες θυρες (recon). Απαιτει scapy + root.
    print("[*] SYN scan")
    from scapy.all import IP, TCP, send
    t0 = time.time(); n = 0
    for port in random.sample(range(1, 9000), 250):
        send(IP(dst=TARGET_IP) / TCP(dport=port, flags="S"), verbose=0)
        n += 1; time.sleep(0.012)
    log_event("SYN_SCAN", t0, time.time(), f"{n} SYN packets to many ports")


def icmp_flood(duration=3):
    # ICMP flood: echo requests υψηλης συχνοτητας. Απαιτει scapy + root.
    print("[*] ICMP flood")
    from scapy.all import IP, ICMP, send
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        send(IP(dst=TARGET_IP) / ICMP(), verbose=0); n += 1; time.sleep(0.006)
    log_event("ICMP_FLOOD", t0, time.time(), f"{n} ICMP echo requests (flood)")


def conn_flood(duration=3):
    # Connection flood: πολλες γρηγορες πληρεις συνδεσεις
    print("[*] TCP connection flood")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/"); n += 1; time.sleep(0.04)
    log_event("CONN_FLOOD", t0, time.time(), f"{n} rapid TCP connections")


def http_probe(duration=4):
    # HTTP probe: υποπτα αιτηματα με User-Agent sqlmap (μετριος ρυθμος)
    print("[*] HTTP probe")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get(random.choice(SUSPICIOUS), ua="sqlmap/1.5"); n += 1
        time.sleep(random.uniform(0.20, 0.35))
    log_event("HTTP_ATTACK", t0, time.time(), f"{n} suspicious HTTP requests")


def stealth_web(duration=70):
    # Stealth web probe: μεμονωμενα υποπτα αιτηματα, αραια (μοιαζουν με νομιμα)
    print("[*] Stealth web probe (μεμονωμενα υποπτα αιτηματα)")
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        http_get("/phpmyadmin/", ua="sqlmap/1.5"); n += 1
        time.sleep(random.uniform(3.5, 5.0))
    log_event("STEALTH_WEB", t0, time.time(), f"{n} stealthy single web probes")


def slow_attack(duration=120):
    # Low-and-slow SQLi: το αιτημα σε μικρα κομματια με καθυστερησεις (stealth)
    print("[*] Low-and-slow SQLi")
    t0 = time.time(); n = 0
    parts = [b"GET /?id=1", b" UNION", b" SELECT", b" version()--", b" HTTP/1.1\r\n\r\n"]
    while time.time() - t0 < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
            s.connect((TARGET_IP, TARGET_PORT))
            for p in parts:
                try:
                    s.send(p); time.sleep(0.4)   # 0.4s αναμεσα σε καθε κομματι
                except (BrokenPipeError, ConnectionResetError):
                    break
            s.close()
        except Exception:
            pass
        n += 1; time.sleep(random.uniform(8, 14))   # μεγαλα κενα μεταξυ αιτηματων
    log_event("SLOW_ATTACK", t0, time.time(), f"{n} low-and-slow SQLi attempts")


def main():
    print("=" * 60)
    print("Hybrid IDS lab - live traffic generator")
    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print("=" * 60)
    time.sleep(2)
    # Απλοποιημενη σειρα: baseline και μετα οι επιθεσεις με μικρα κενα αναμεσα
    benign(60)
    syn_scan(); time.sleep(3)
    http_probe(); time.sleep(3)
    icmp_flood(); time.sleep(3)
    conn_flood(); time.sleep(3)
    stealth_web(); time.sleep(3)
    slow_attack()
    benign(30)
    print("[+] DONE - δες logs/event_log.csv")


if __name__ == "__main__":
    main()
