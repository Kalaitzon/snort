# Ioannis Kalaitzidis, MTE25012

"""
Εξαγωγη χαρακτηριστικων ανα χρονικο παραθυρο (1 sec) απο το pcap.

Κρισιμη διαφορα απο τον ευκολο/λανθασμενο τροπο:
Το label καθε παραθυρου ΔΕΝ υπολογιζεται απο τα features (αυτο θα ηταν
data leakage), αλλα απο το event_log.csv (ground truth βασει χρονου) και την
ταυτοτητα του επιτιθεμενου. Ετσι οι μετρικες ειναι τιμιες.

Τα features επιλεγονται ωστε να ειναι σχετικα με τις κατηγοριες επιθεσεων:
  - ογκος/ρυθμος (packet_count, byte_count, mean_pkt_size)
  - σημαιες TCP (syn/fin/rst/ack/psh) -> scan, flood, burst
  - icmp_count -> ICMP flood
  - udp_count  -> udp probes
  - unique_dst_ports, unique_src -> port scan / spread
  - syn_to_synack_ratio -> half-open / scan
  - iat_mean, iat_std -> ρυθμος/κανονικοτητα (χρησιμο για low-and-slow)
  - new_connections -> connection flood
"""

import os
import csv
import numpy as np
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Διαδρομες σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_FILE = os.path.join(BASE, "pcaps", "lab_traffic.pcap")
EVENT_LOG = os.path.join(BASE, "logs", "event_log.csv")
OUTPUT = os.path.join(BASE, "ml_detector", "features.csv")
WINDOW = 1.0                    # μεγεθος παραθυρου σε δευτερολεπτα

HOME_NET_PREFIX = "10.0.0."     # HOME_NET = 10.0.0.0/24
ATTACKER = "192.168.56.20"      # ground truth: γνωστος επιτιθεμενος στο κλειστο lab


def load_intervals():
    """Φορτωνει τα χρονικα διαστηματα των επιθεσεων απο το event_log.
    Επιστρεφει λιστα απο (start_time, end_time, attack_type) σε relative seconds."""
    intervals = []
    with open(EVENT_LOG) as f:
        for row in csv.DictReader(f):
            intervals.append((float(row["start_time"]), float(row["end_time"]),
                              row["attack_type"]))
    return intervals


def label_for(rel_t, intervals):
    """Βρισκει σε ποιον τυπο επιθεσης ανηκει μια χρονικη στιγμη rel_t (αν ανηκει).
    Χρησιμοποιειται μονο για να αποδοθει ο ΤΥΠΟΣ σε ενα attack πακετο, οχι το label."""
    for (s, e, atype) in intervals:
        if s <= rel_t <= e:
            return 1, atype
    return 0, "BENIGN"


def main():
    print("[*] Loading pcap...")
    pkts = rdpcap(PCAP_FILE)
    print(f"[*] {len(pkts)} packets")
    t0 = float(pkts[0].time)     # χρονος αναφορας: το πρωτο πακετο = στιγμη 0

    intervals = load_intervals()

    # Καθε παραθυρο (κλειδι = window_id) συγκεντρωνει αθροιστικα μεγεθη.
    # Χρησιμοποιουμε defaultdict ωστε να δημιουργειται αυτοματα καθε νεο παραθυρο.
    windows = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "syn": 0, "synack": 0, "fin": 0, "rst": 0,
        "ack": 0, "psh": 0, "icmp": 0, "udp": 0,
        "src": set(), "dst_ports": set(), "new_conn": 0,
        "times": [], "attack_ticks": 0, "type_votes": defaultdict(int),
    })

    # ---- 1ο περασμα: κατανομη καθε πακετου στο παραθυρο του και συγκεντρωση ----
    for p in pkts:
        if not p.haslayer(IP):
            continue
        rel = float(p.time) - t0          # χρονος του πακετου σχετικα με την αρχη
        wid = int(rel / WINDOW)           # σε ποιο παραθυρο 1s ανηκει
        w = windows[wid]
        w["packets"] += 1
        w["bytes"] += len(p)
        w["src"].add(p[IP].src)           # μοναδικες πηγες (spread)
        w["times"].append(rel)            # για τον υπολογισμο των ενδιαμεσων χρονων

        if p.haslayer(TCP):
            tcp = p[TCP]
            w["dst_ports"].add(int(tcp.dport))   # μοναδικες θυρες προορισμου (scan)
            fl = int(tcp.flags)
            # Αναγνωση των σημαιων TCP μεσω bitmask:
            # 0x02=SYN, 0x10=ACK, 0x01=FIN, 0x04=RST, 0x08=PSH
            syn = bool(fl & 0x02); ack = bool(fl & 0x10)
            if syn and ack:
                w["synack"] += 1          # SYN-ACK: απαντηση του server
            elif syn:
                w["syn"] += 1             # καθαρο SYN: νεα αιτηση συνδεσης
                w["new_conn"] += 1        # -> μετρητης νεων συνδεσεων (conn flood)
            if fl & 0x01:
                w["fin"] += 1
            if fl & 0x04:
                w["rst"] += 1
            if ack:
                w["ack"] += 1
            if fl & 0x08:
                w["psh"] += 1             # PSH: μεταφορα δεδομενων (αιτηματα/απαντησεις)
        elif p.haslayer(ICMP):
            w["icmp"] += 1
        elif p.haslayer(UDP):
            w["udp"] += 1

        # GROUND TRUTH (βασει ταυτοτητας): αν το πακετο αφορα τον επιτιθεμενο,
        # το παραθυρο "ψηφιζει" ως attack, και σημειωνεται ο τυπος απο το χρονοδιαγραμμα.
        is_atk_pkt = (p[IP].src == ATTACKER or p[IP].dst == ATTACKER)
        if is_atk_pkt:
            w["attack_ticks"] += 1
            _, atype = label_for(rel, intervals)
            w["type_votes"][atype] += 1

    print(f"[*] {len(windows)} windows")

    # ---- 2ο περασμα: υπολογισμος των τελικων χαρακτηριστικων ανα παραθυρο ----
    rows = []
    for wid in sorted(windows):
        w = windows[wid]
        # Ενδιαμεσοι χρονοι αφιξης (inter-arrival times): δειχνουν τον ρυθμο.
        # Χαμηλη/σταθερη τιμη = ριπη, υψηλη/ακανονιστη = αραιη κινηση (low-and-slow).
        times = sorted(w["times"])
        if len(times) > 1:
            iats = np.diff(times)
            iat_mean = float(np.mean(iats)); iat_std = float(np.std(iats))
        else:
            iat_mean = WINDOW; iat_std = 0.0
        pkt = w["packets"]
        syn_ratio = w["syn"] / max(w["synack"], 1)   # πολλα SYN χωρις SYN-ACK -> scan
        mean_size = w["bytes"] / max(pkt, 1)

        # Label: attack αν το παραθυρο περιεχει εστω 1 πακετο του επιτιθεμενου
        # (ground truth βασει ταυτοτητας, ανεξαρτητο απο τα aggregate features).
        # Ο τυπος επιθεσης = ο πιο συχνος τυπος μεταξυ των attack πακετων του παραθυρου.
        is_attack = 1 if w["attack_ticks"] >= 1 else 0
        if is_attack and w["type_votes"]:
            atype = max(w["type_votes"].items(), key=lambda kv: kv[1])[0]
        else:
            atype = "BENIGN"

        rows.append({
            "window_id": wid,
            "packet_count": pkt,
            "byte_count": w["bytes"],
            "mean_pkt_size": round(mean_size, 2),
            "syn_count": w["syn"],
            "synack_count": w["synack"],
            "fin_count": w["fin"],
            "rst_count": w["rst"],
            "ack_count": w["ack"],
            "psh_count": w["psh"],
            "icmp_count": w["icmp"],
            "udp_count": w["udp"],
            "unique_src": len(w["src"]),
            "unique_dst_ports": len(w["dst_ports"]),
            "new_connections": w["new_conn"],
            "syn_to_synack_ratio": round(syn_ratio, 3),
            "iat_mean": round(iat_mean, 4),
            "iat_std": round(iat_std, 4),
            "attack_type": atype,          # μονο για αναλυση/case studies, ΟΧΙ feature
            "is_attack": is_attack,        # το label (target)
        })

    # Εγγραφη του πινακα χαρακτηριστικων
    fields = list(rows[0].keys())
    with open(OUTPUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    n_attack = sum(r["is_attack"] for r in rows)
    print(f"[OK] features -> {OUTPUT}")
    print(f"[*] windows: {len(rows)} | attack: {n_attack} | benign: {len(rows) - n_attack}")
    from collections import Counter
    print("[*] attack-type breakdown:",
          dict(Counter(r["attack_type"] for r in rows if r["is_attack"])))


if __name__ == "__main__":
    main()
