# Hybrid IDS (Snort + Machine Learning)

A reproducible **hybrid Intrusion Detection System** that combines signature-based
detection (**Snort**) with machine-learning anomaly detection (**Random Forest,
Logistic Regression, Isolation Forest**), fuses the two into a single risk-based
decision layer with explicit conflict handling, and evaluates everything **honestly**
on a realistic, time-stamped dataset of 1,484 one-second windows.

## Core design principle (honesty / no data leakage)

Window labels come from **independent ground truth** (attack timestamps in
`event_log.csv` and the attacker's identity), **not** from the traffic features
themselves. This avoids circular labeling and makes the metrics real
(e.g. Hybrid F1 = 0.926, not an artificial 1.0).

## Repository structure

```
.
├── traffic_generation/
│   ├── build_dataset.py      # deterministic pcap + event_log synthesis (tasks 1,2)
│   ├── traffic_gen.py        # live generator for a real lab (reproducibility)
│   └── web_server.py         # simple victim server for live mode
├── ml_detector/
│   ├── feature_extraction.py # per-window features + labels from event_log (tasks 2,4)
│   ├── snort_emulator.py     # faithful emulator of the Snort rules (task 3)
│   ├── train_model.py        # RF + LogReg + Isolation Forest, held-out split (task 4)
│   ├── hybrid_fusion.py      # fusion + risk levels + conflict handling (task 5)
│   ├── evaluation.py         # metrics, confusion, PR curves, case studies (task 6)
│   ├── *.csv, *.json, *.pkl  # generated artifacts
├── rules/
│   ├── local.rules           # 5 valid Snort 3 rules (task 3)
│   ├── snort.lua             # Snort 3 config for offline analysis
│   ├── rules_kali.rules      # rules that ran on real Snort 3.12 (Kali)
│   └── snort_kali.lua        # config that ran on real Snort 3.12 (Kali)
├── logs/
│   ├── event_log.csv         # ground truth: attack timeline
│   ├── snort_alerts.csv      # per-packet alerts (from the emulator)
│   ├── snort_windows.csv     # per-window Snort signal
│   └── alert_fast.txt        # alerts from the REAL Snort 3.12 (Kali)
├── pcaps/
│   └── lab_traffic.pcap      # the single traffic dataset
├── screenshots/              # real Snort execution screenshots (task 3)
├── README.md
├── SNORT_GUIDE.md            # how to run the real Snort on Kali (screenshots)
├── TESTBED_DESIGN.md         # topology, labeling, dataset (task 1)
├── CASE_STUDIES.md           # 3 signature-vs-anomaly disagreement cases (task 6)
├── requirements.txt
└── run_all.sh                # runs the whole pipeline in order
```

## Requirements

Python 3.10+. Install dependencies:

```bash
pip install -r requirements.txt
```

The ML pipeline runs **without** an installed Snort (it uses a faithful emulator).
The real Snort is only needed to produce the alert screenshots and runs on Kali
Linux with Snort 3, offline over the pcap (see `SNORT_GUIDE.md`).

## How to run

Whole pipeline with one command (on Windows, run the steps individually with `python`):

```bash
bash run_all.sh
```

Or step by step:

```bash
python traffic_generation/build_dataset.py     # -> pcaps/lab_traffic.pcap, logs/event_log.csv
python ml_detector/feature_extraction.py       # -> ml_detector/features.csv
python ml_detector/snort_emulator.py           # -> logs/snort_alerts.csv, snort_windows.csv
python ml_detector/train_model.py              # -> predictions.csv, ml_metrics.json, models
python ml_detector/hybrid_fusion.py            # -> hybrid_results.csv, conflicts.json
python ml_detector/evaluation.py               # -> figures/, evaluation.json
```

Real Snort (offline, for the screenshots) on Kali Linux with Snort 3.12:

```bash
sudo apt update && sudo apt install -y snort
snort -c rules/snort_kali.lua -R rules/rules_kali.rules \
      -r pcaps/lab_traffic.pcap -A alert_fast -l logs -k none
```

## What the system does (task by task)

- **Task 1 - Testbed and threat model.** Two-network topology
  (HOME_NET 10.0.0.0/24 with a victim HTTP server on port 8080, EXTERNAL_NET with an
  attacker), an explicit threat model, and time-based ground truth. See `TESTBED_DESIGN.md`.
- **Task 2 - Traffic generation and labeling.** Benign traffic plus six attack
  families (SYN scan, ICMP flood, connection flood, HTTP probe, stealth web probe,
  low-and-slow SQLi), aggregated into 1,484 one-second windows (~11.7% attack).
- **Task 3 - Snort rules.** Five custom Snort 3 rules (suspicious URI, sqlmap
  User-Agent, external ICMP flood, SYN scan, connection flood), verified with a faithful
  emulator and with **real Snort 3.12.2 on Kali** (see `SNORT_GUIDE.md` and `screenshots/`).
- **Task 4 - Features and ML models.** 17 per-window features and three models
  (Random Forest, Logistic Regression, Isolation Forest) trained with a clean, stratified
  70/30 held-out split (RF F1 = 0.916).
- **Task 5 - Hybrid fusion.** A risk score (0.55·RF + 0.30·Snort + 0.15·IF), LOW/MEDIUM/HIGH
  severity levels, and explicit conflict rules (signature override, anomaly watch, stealth).
- **Task 6 - Evaluation.** Precision/recall/F1/FPR, confusion matrices, precision-recall
  curves (emphasized due to class imbalance), an alert timeline, and three real
  disagreement case studies. Hybrid F1 = 0.926, beating each single method. See `CASE_STUDIES.md`.
- **Task 7 - Evasion and critical assessment.** Three evasion techniques, which detector
  each fools, false-positive reduction, and honest limits against zero-day attacks.

### Optional extensions

- **Supervised vs unsupervised learning:** quantifies the precision/labeling trade-off
  between RF/LogReg and Isolation Forest.
- **Feedback loop:** automatically tunes the decision threshold to keep the false-positive
  rate under a chosen budget (lands at 0.41, FPR 0.010, F1 0.923).

## Key results (held-out test set)

| Method | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Snort-only | 1.000 | 0.346 | 0.514 | 0.000 |
| ML-only (Random Forest) | 0.891 | 0.942 | 0.916 | 0.015 |
| **Hybrid** | 0.893 | 0.962 | **0.926** | 0.015 |

The two layers are complementary: the ML layer catches 98 windows Snort misses
(low-and-slow, scan onset), while Snort catches a stealth probe the ML layer reads
as benign.

## Note on reproducibility

Traffic synthesis and model training use a fixed random seed (1337), so every run
produces identical results. All analysis is performed offline over a single pcap.
