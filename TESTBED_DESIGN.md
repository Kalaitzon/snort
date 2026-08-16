# Testbed Design - Hybrid IDS (Snort + ML)

## 1. Topology

The testbed uses two distinct networks, so that the HOME_NET / EXTERNAL_NET
separation is meaningful (and not artificial, as in a localhost-only scenario, where the
rule "ICMP from outside HOME_NET" would make no sense).

```
        EXTERNAL_NET  (!10.0.0.0/24)                HOME_NET  (10.0.0.0/24)
  +--------------------------------+          +------------------------------+
  |  attacker   192.168.56.20      |          |  server (victim) 10.0.0.10:8080 |
  |  (SYN scan, ICMP flood,        | =======> |  client (legitimate) 10.0.0.50 |
  |   conn flood, HTTP probe,      |   Snort  |                              |
  |   stealth web, low-and-slow)   |   IDS    |  ext_client 203.0.113.7      |
  +--------------------------------+          +------------------------------+
                                    Snort monitors all the traffic
                                    to/from HOME_NET (offline pcap)
```

- **HOME_NET** = `10.0.0.0/24`, contains the victim server (`10.0.0.10:8080`) and a legitimate internal client (`10.0.0.50`).
- **EXTERNAL_NET** = `!10.0.0.0/24`, includes the attacker (`192.168.56.20`) and a legitimate external client (`203.0.113.7`).
- **Target service**: HTTP server on port `8080`.

## 2. Capture point and method

The analysis is done **offline** over a single pcap (`pcaps/lab_traffic.pcap`), which
contains all the legitimate and malicious traffic with timestamps. Snort runs in
pcap-read mode (`snort -r`), avoiding race conditions and the dependencies of a live
capture. The same pcap also feeds the ML pipeline, so that signature and anomaly
detection are evaluated on exactly the same data.

## 3. Ground truth and labeling

Crucial design principle (lecture 4 - avoiding data leakage): the label of each time
window does **not** derive from the traffic features, but from an independent
ground truth:

1. Each attack runs in a known time interval, recorded in `logs/event_log.csv`.
2. The attacker has a known identity (`192.168.56.20`).
3. A 1s window is labeled as attack if it contains at least one packet from the attacker.

This way, the labels are completely independent of the aggregate features (packet_count,
syn_count, etc.) given to the models, and circularity is avoided.

## 4. Dataset

- Total packets: 24,110 (TCP 22,456, ICMP 1,654), duration ~1,799s (~30 minutes).
- Time windows (1s): 1,484, of which 174 attack and 1,310 benign (~11.7% realistic class imbalance).
- Attack episodes (event_log): 18, across 6 types.

| Attack type | Episodes | Attack windows |
|---|---|---|
| SYN_SCAN | 4 | 8 |
| ICMP_FLOOD | 3 | 12 |
| CONN_FLOOD | 3 | 8 |
| HTTP_ATTACK | 4 | 19 |
| STEALTH_WEB | 2 | 38 |
| SLOW_ATTACK | 2 | 89 |

## 5. Reproducibility

Deterministic reproduction (identical pcap on every machine):

```bash
bash run_all.sh
```

Live reproduction in a set-up lab (optional, to confirm the method):

```bash
# server (victim)
python traffic_generation/web_server.py
# Snort in live capture (or offline over the pcap, see SNORT_GUIDE.md)
# attacker
sudo python traffic_generation/traffic_gen.py
```
