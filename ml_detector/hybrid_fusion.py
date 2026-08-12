# Ioannis Kalaitzidis, MTE25012

"""
Hybrid fusion: συνδυασμος signature-based (Snort) και anomaly/supervised (ML).

Σηματα εισοδου ανα παραθυρο:
  - snort_detection : 1 αν πυροδοτηθηκε καποιος κανονας Snort (signature)
  - rf_score        : πιθανοτητα επιθεσης απο Random Forest (supervised)
  - if_score        : κανονικοποιημενο anomaly score απο Isolation Forest

Βαθμολογια κινδυνου (risk score) και επιπεδα:
  risk = 0.55*rf_score + 0.30*snort_detection + 0.15*if_score
  LOW    : risk < 0.40
  MEDIUM : 0.40 <= risk < 0.70
  HIGH   : risk >= 0.70
  Τελικη αποφαση hybrid = alert αν risk >= 0.40 (>= MEDIUM).

Ρητος χειρισμος διαφωνιων (conflict handling):
  C1 signature override : αν Snort=1 αλλα το ML ειναι χαμηλο, το matched signature
       ειναι ντετερμινιστικο IOC -> ανεβαζουμε το risk σε τουλαχιστον 0.70 (HIGH).
  C2 anomaly-only watch : αν Snort=0 ΚΑΙ RF=0 αλλα το IF ειναι πολυ ανωμαλο
       (if_score>0.85), σημανε τουλαχιστον MEDIUM watch (χαμηλοτερη βεβαιοτητα).
  C3 stealth (ML-driven): αν RF=1 αλλα Snort=0, εμπιστευσου το ML - εδω πιανεται
       το low-and-slow που ο Snort ειναι τυφλος (content split, κατω απο thresholds).
"""

import os
import json
import pandas as pd

# Διαδρομες σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRED = os.path.join(BASE, "ml_detector", "predictions.csv")
SNORT_WIN = os.path.join(BASE, "logs", "snort_windows.csv")
OUT = os.path.join(BASE, "ml_detector", "hybrid_results.csv")
CONFLICTS_OUT = os.path.join(BASE, "ml_detector", "conflicts.json")

W_RF, W_SNORT, W_IF = 0.55, 0.30, 0.15
T_MED, T_HIGH = 0.40, 0.70


def main():
    df = pd.read_csv(PRED)
    sn = pd.read_csv(SNORT_WIN)[["window_id", "snort_detection"]]
    df = df.merge(sn, on="window_id", how="left")
    df["snort_detection"] = df["snort_detection"].fillna(0).astype(int)

    base = W_RF * df["rf_score"] + W_SNORT * df["snort_detection"] + W_IF * df["if_score"]
    df["risk_raw"] = base.round(4)

    risk = base.copy()
    # C1 signature override
    c1 = (df["snort_detection"] == 1) & (risk < T_HIGH)
    risk[c1] = T_HIGH
    # C2 anomaly-only watch
    c2 = (df["snort_detection"] == 0) & (df["rf_pred"] == 0) & (df["if_score"] > 0.85) & (risk < T_MED)
    risk[c2] = T_MED
    df["risk_score"] = risk.round(4)

    df["risk_level"] = "LOW"
    df.loc[df["risk_score"] >= T_MED, "risk_level"] = "MEDIUM"
    df.loc[df["risk_score"] >= T_HIGH, "risk_level"] = "HIGH"

    # Αποφασεις ανα μεθοδο (για συγκριση)
    df["snort_only"] = df["snort_detection"]
    df["ml_only"] = df["rf_pred"]
    # Δυαδικη αποφαση hybrid = ενωση των δυο high-precision detectors (signature OR
    # supervised): ο καθενας καλυπτει το τυφλο σημειο του αλλου. Το Isolation Forest
    # δεν κανει auto-alert (θα ριχνε την precision) - συνεισφερει μονο στη βαθμιδα
    # σοβαροτητας (risk_level) ως "anomaly watch".
    df["hybrid"] = ((df["snort_detection"] == 1) | (df["rf_pred"] == 1)).astype(int)

    df.to_csv(OUT, index=False)

    # Καταγραφη περιπτωσεων διαφωνιας (για case studies / συζητηση)
    conflicts = {
        "snort_catches_ml_misses": int(((df.snort_only == 1) & (df.ml_only == 0) & (df.is_attack == 1)).sum()),
        "ml_catches_snort_misses": int(((df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 1)).sum()),
        "snort_fp_ml_clean": int(((df.snort_only == 1) & (df.ml_only == 0) & (df.is_attack == 0)).sum()),
        "ml_fp_snort_clean": int(((df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 0)).sum()),
        "c1_signature_override": int(c1.sum()),
        "c2_anomaly_watch": int(c2.sum()),
    }
    with open(CONFLICTS_OUT, "w") as f:
        json.dump(conflicts, f, indent=2)

    print("[*] risk level distribution:")
    print(df["risk_level"].value_counts().to_dict())
    print("\n[*] detections (full timeline):")
    for m in ("snort_only", "ml_only", "hybrid"):
        print(f"  {m:10s} flagged={int(df[m].sum()):4d}  of {len(df)}")
    print("\n[*] conflicts:", conflicts)
    print(f"[OK] -> {OUT}")


if __name__ == "__main__":
    main()
