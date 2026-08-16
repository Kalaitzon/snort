"""
Hybrid fusion: combination of signature-based (Snort) and anomaly/supervised (ML).

Input signals per window:
  - snort_detection : 1 if some Snort rule fired (signature)
  - rf_score        : attack probability from Random Forest (supervised)
  - if_score        : normalized anomaly score from Isolation Forest

Risk score and levels:
  risk = 0.55*rf_score + 0.30*snort_detection + 0.15*if_score
  LOW    : risk < 0.40
  MEDIUM : 0.40 <= risk < 0.70
  HIGH   : risk >= 0.70
  Final hybrid decision = alert if risk >= 0.40 (>= MEDIUM).

Explicit conflict handling:
  C1 signature override : if Snort=1 but the ML is low, the matched signature
       is a deterministic IOC -> we raise risk to at least 0.70 (HIGH).
  C2 anomaly-only watch : if Snort=0 AND RF=0 but IF is very anomalous
       (if_score>0.85), signal at least a MEDIUM watch (lower certainty).
  C3 stealth (ML-driven): if RF=1 but Snort=0, trust the ML - this is where
       the low-and-slow is caught, where Snort is blind (content split, below thresholds).
"""

import os
import json
import pandas as pd

# Paths relative to the project root (portable, independent of the cwd)
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

    # Decisions per method (for comparison)
    df["snort_only"] = df["snort_detection"]
    df["ml_only"] = df["rf_pred"]
    # Binary hybrid decision = union of the two high-precision detectors (signature OR
    # supervised): each covers the other's blind spot. Isolation Forest does not
    # auto-alert (it would hurt precision) - it only contributes to the severity
    # level (risk_level) as an "anomaly watch".
    df["hybrid"] = ((df["snort_detection"] == 1) | (df["rf_pred"] == 1)).astype(int)

    df.to_csv(OUT, index=False)

    # Record the disagreement cases (for case studies / discussion)
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
