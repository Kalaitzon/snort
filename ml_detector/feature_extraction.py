"""
Feature extraction per time window (1 sec) from the pcap.

Crucial difference from the easy/wrong way:
The label of each window is NOT computed from the features (that would be
data leakage), but from event_log.csv (time-based ground truth) and the
attacker's identity. This keeps the metrics honest.

The features are chosen so as to relate to the attack categories:
  - volume/rate (packet_count, byte_count, mean_pkt_size)
  - TCP flags (syn/fin/rst/ack/psh) -> scan, flood, burst
  - icmp_count -> ICMP flood
  - udp_count  -> udp probes
  - unique_dst_ports, unique_src -> port scan / spread
  - syn_to_synack_ratio -> half-open / scan
  - iat_mean, iat_std -> rate/regularity (useful for low-and-slow)
  - new_connections -> connection flood
"""

import os
import csv
import numpy as np
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Paths relative to the project root (portable, independent of the cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_FILE = os.path.join(BASE, "pcaps", "lab_traffic.pcap")
EVENT_LOG = os.path.join(BASE, "logs", "event_log.csv")
OUTPUT = os.path.join(BASE, "ml_detector", "features.csv")
WINDOW = 1.0                    # window size in seconds

HOME_NET_PREFIX = "10.0.0."     # HOME_NET = 10.0.0.0/24
ATTACKER = "192.168.56.20"      # ground truth: known attacker in the closed lab


def load_intervals():
    """Loads the attack time intervals from event_log.
    Returns a list of (start_time, end_time, attack_type) in relative seconds."""
    intervals = []
    with open(EVENT_LOG) as f:
        for row in csv.DictReader(f):
            intervals.append((float(row["start_time"]), float(row["end_time"]),
                              row["attack_type"]))
    return intervals


def label_for(rel_t, intervals):
    """Finds which attack type a time instant rel_t belongs to (if any).
    Used only to assign the TYPE to an attack packet, not the label."""
    for (s, e, atype) in intervals:
        if s <= rel_t <= e:
            return 1, atype
    return 0, "BENIGN"


def main():
    print("[*] Loading pcap...")
    pkts = rdpcap(PCAP_FILE)
    print(f"[*] {len(pkts)} packets")
    t0 = float(pkts[0].time)     # reference time: the first packet = instant 0

    intervals = load_intervals()

    # Each window (key = window_id) accumulates aggregate quantities.
    # We use a defaultdict so that each new window is created automatically.
    windows = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "syn": 0, "synack": 0, "fin": 0, "rst": 0,
        "ack": 0, "psh": 0, "icmp": 0, "udp": 0,
        "src": set(), "dst_ports": set(), "new_conn": 0,
        "times": [], "attack_ticks": 0, "type_votes": defaultdict(int),
    })

    # ---- 1st pass: assign each packet to its window and accumulate ----
    for p in pkts:
        if not p.haslayer(IP):
            continue
        rel = float(p.time) - t0          # time of the packet relative to the start
        wid = int(rel / WINDOW)           # which 1s window it belongs to
        w = windows[wid]
        w["packets"] += 1
        w["bytes"] += len(p)
        w["src"].add(p[IP].src)           # unique sources (spread)
        w["times"].append(rel)            # for computing the inter-arrival times

        if p.haslayer(TCP):
            tcp = p[TCP]
            w["dst_ports"].add(int(tcp.dport))   # unique destination ports (scan)
            fl = int(tcp.flags)
            # Read the TCP flags via bitmask:
            # 0x02=SYN, 0x10=ACK, 0x01=FIN, 0x04=RST, 0x08=PSH
            syn = bool(fl & 0x02); ack = bool(fl & 0x10)
            if syn and ack:
                w["synack"] += 1          # SYN-ACK: the server's reply
            elif syn:
                w["syn"] += 1             # plain SYN: new connection request
                w["new_conn"] += 1        # -> counter of new connections (conn flood)
            if fl & 0x01:
                w["fin"] += 1
            if fl & 0x04:
                w["rst"] += 1
            if ack:
                w["ack"] += 1
            if fl & 0x08:
                w["psh"] += 1             # PSH: data transfer (requests/responses)
        elif p.haslayer(ICMP):
            w["icmp"] += 1
        elif p.haslayer(UDP):
            w["udp"] += 1

        # GROUND TRUTH (identity-based): if the packet concerns the attacker,
        # the window "votes" as attack, and the type is noted from the timeline.
        is_atk_pkt = (p[IP].src == ATTACKER or p[IP].dst == ATTACKER)
        if is_atk_pkt:
            w["attack_ticks"] += 1
            _, atype = label_for(rel, intervals)
            w["type_votes"][atype] += 1

    print(f"[*] {len(windows)} windows")

    # ---- 2nd pass: compute the final features per window ----
    rows = []
    for wid in sorted(windows):
        w = windows[wid]
        # Inter-arrival times: they show the rate.
        # Low/steady value = burst, high/irregular = sparse traffic (low-and-slow).
        times = sorted(w["times"])
        if len(times) > 1:
            iats = np.diff(times)
            iat_mean = float(np.mean(iats)); iat_std = float(np.std(iats))
        else:
            iat_mean = WINDOW; iat_std = 0.0
        pkt = w["packets"]
        syn_ratio = w["syn"] / max(w["synack"], 1)   # many SYN without SYN-ACK -> scan
        mean_size = w["bytes"] / max(pkt, 1)

        # Label: attack if the window contains at least 1 packet from the attacker
        # (identity-based ground truth, independent of the aggregate features).
        # The attack type = the most frequent type among the window's attack packets.
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
            "attack_type": atype,          # only for analysis/case studies, NOT a feature
            "is_attack": is_attack,        # the label (target)
        })

    # Write the feature table
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
