# Ioannis Kalaitzidis, MTE25012

"""
Πιστος emulator των κανονων Snort (rules/local.rules) πανω στο pcap.

Σκοπος: να παραγει το ιδιο σημα ανιχνευσης που θα εδινε ο πραγματικος Snort 3,
ωστε το hybrid pipeline να ειναι πληρως αναπαραγωγιμο ΧΩΡΙΣ να απαιτειται
εγκατεστημενος Snort. Ο πραγματικος Snort τρεχει ξεχωριστα, offline, μονο για
τα screenshots (βλ. README, ΒΗΜΑ Snort) και τα alerts του συμφωνουν με αυτα εδω.

Η λογικη καθε κανονα αντιγραφει ΑΚΡΙΒΩΣ τα thresholds του local.rules:
  sid 1000001/1000002 : content match (phpmyadmin URI / sqlmap UA) - χωρις threshold
  sid 1000003 : ICMP echo απο external, detection_filter count 30 / 1s by_src
  sid 1000004 : TCP SYN, detection_filter count 40 / 2s by_src
  sid 1000005 : TCP SYN, detection_filter count 20 / 1s by_src (connection flood)

Παραγει:
  logs/snort_alerts.csv   : ενα alert ανα γραμμη (rel_time, sid, msg, src)
  logs/snort_windows.csv  : window_id, snort_detection, sids_fired
"""

import os
import csv
from collections import defaultdict, deque
from scapy.all import rdpcap, IP, TCP, ICMP, Raw

# Διαδρομες σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(BASE, "pcaps", "lab_traffic.pcap")
ALERTS_OUT = os.path.join(BASE, "logs", "snort_alerts.csv")
WINDOWS_OUT = os.path.join(BASE, "logs", "snort_windows.csv")
os.makedirs(os.path.join(BASE, "logs"), exist_ok=True)   # δημιουργια logs/ αν λειπει

HOME_PREFIX = "10.0.0."
WINDOW = 1.0

def is_home(ip):
    return ip.startswith(HOME_PREFIX)

def is_external(ip):
    return not is_home(ip)

def within(dq, t, seconds):
    """Κραταει στη deque μονο timestamps εντος [t-seconds, t] και επιστρεφει το πληθος."""
    while dq and dq[0] < t - seconds:
        dq.popleft()
    return len(dq)

def main():
    pkts = rdpcap(PCAP)
    t0 = float(pkts[0].time)

    syn40 = defaultdict(deque)   # sid 1000004 (count 40 / 2s)
    syn20 = defaultdict(deque)   # sid 1000005 (count 20 / 1s)
    icmp30 = defaultdict(deque)  # sid 1000003 (count 30 / 1s)

    alerts = []          # (rel, sid, msg, src)
    win_sids = defaultdict(set)

    for p in pkts:
        if not p.haslayer(IP):
            continue
        rel = float(p.time) - t0
        src = p[IP].src
        dst = p[IP].dst
        wid = int(rel / WINDOW)

        # --- HTTP content rules (external -> home:8080) ---
        if p.haslayer(TCP) and p.haslayer(Raw) and int(p[TCP].dport) == 8080 \
           and is_external(src) and is_home(dst):
            payload = bytes(p[Raw].load).lower()
            if b"phpmyadmin" in payload:
                alerts.append((rel, 1000001, "WEB Suspicious URI / admin panel probe", src))
                win_sids[wid].add(1000001)
            if b"sqlmap" in payload:
                alerts.append((rel, 1000002, "WEB sqlmap User-Agent detected", src))
                win_sids[wid].add(1000002)

        # --- ICMP echo flood (external -> home) ---
        if p.haslayer(ICMP) and int(p[ICMP].type) == 8 and is_external(src) and is_home(dst):
            dq = icmp30[src]; dq.append(rel)
            if within(dq, rel, 1.0) >= 30:
                alerts.append((rel, 1000003, "ICMP Echo flood from external host", src))
                win_sids[wid].add(1000003)

        # --- TCP SYN scan / connection flood (external -> home:8080) ---
        if p.haslayer(TCP) and is_external(src) and is_home(dst) and int(p[TCP].dport) == 8080:
            fl = int(p[TCP].flags)
            if (fl & 0x02) and not (fl & 0x10):   # SYN χωρις ACK
                d4 = syn40[src]; d4.append(rel)
                if within(d4, rel, 2.0) >= 40:
                    alerts.append((rel, 1000004, "TCP SYN scan / port sweep", src))
                    win_sids[wid].add(1000004)
                d5 = syn20[src]; d5.append(rel)
                if within(d5, rel, 1.0) >= 20:
                    alerts.append((rel, 1000005, "TCP connection flood (burst)", src))
                    win_sids[wid].add(1000005)

    # Εγγραφη alerts
    with open(ALERTS_OUT, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["rel_time", "sid", "msg", "src"])
        for a in alerts:
            w.writerow([round(a[0], 4), a[1], a[2], a[3]])

    # Per-window signal
    max_wid = int((float(pkts[-1].time) - t0) / WINDOW)
    with open(WINDOWS_OUT, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["window_id", "snort_detection", "sids_fired"])
        for wid in range(max_wid + 1):
            sids = win_sids.get(wid, set())
            w.writerow([wid, 1 if sids else 0, "|".join(str(s) for s in sorted(sids))])

    # Συνοψη ανα sid
    from collections import Counter
    by_sid = Counter(a[1] for a in alerts)
    print(f"[OK] alerts: {len(alerts)} -> {ALERTS_OUT}")
    print(f"[OK] windows flagged: {sum(1 for wid in range(max_wid+1) if win_sids.get(wid))} / {max_wid+1}")
    print("[*] alerts per sid:", dict(sorted(by_sid.items())))

if __name__ == "__main__":
    main()
