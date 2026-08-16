"""
Evaluation and comparison of Snort-only / ML-only / Hybrid + optional extensions.

Produces (all with REAL numbers from the runs):
  figures/fig1_metrics_comparison.png : P/R/F1/FPR per method (test set)
  figures/fig2_confusion_matrices.png : confusion matrices Snort/ML/Hybrid
  figures/fig3_pr_curves.png          : Precision-Recall (emphasized due to imbalance)
  figures/fig4_alert_timeline.png     : alert volume per method over time
  figures/fig5_feedback_loop.png      : optional - auto-tuning the threshold from FPs
  ml_detector/evaluation.json         : all the metrics + case studies

All the head-to-head metrics are computed on the HELD-OUT test set (in_test==1),
so that the ML comparison is honest (without having seen the data during training).
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # headless backend (writes directly to files)
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             precision_recall_curve, average_precision_score)

# Paths relative to the project root (portable, independent of the cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HYBRID = os.path.join(BASE, "ml_detector", "hybrid_results.csv")
FIG = os.path.join(BASE, "figures")
OUT = os.path.join(BASE, "ml_detector", "evaluation.json")
os.makedirs(FIG, exist_ok=True)   # create figures/ if missing


def block(y, p):
    """Computes the basic metrics of a binary classifier for the predictions p
    against the truth y: TP/FP/FN/TN, precision, recall, F1, FPR."""
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    fpr = fp / max(fp + tn, 1)    # fraction of legitimate windows flagged wrongly
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
            "precision": round(float(pr), 3), "recall": round(float(rc), 3),
            "f1": round(float(f1), 3), "fpr": round(float(fpr), 3)}


def main():
    df = pd.read_csv(HYBRID)
    # Keep ONLY the test-set windows for an honest comparison (in_test==1).
    te = df[df["in_test"] == 1].copy()
    y = te["is_attack"].values    # the truth (ground truth) on the test set

    # The binary decision of each method per window, all on the same data.
    methods = {
        "Snort-only": te["snort_only"].values,
        "ML-only (RF)": te["ml_only"].values,
        "LogReg": te["lr_pred"].values,
        "IsolationForest": te["if_pred"].values,
        "Hybrid": te["hybrid"].values,
    }
    results = {name: block(y, p) for name, p in methods.items()}

    print("[*] TEST-SET comparison:")
    for n, m in results.items():
        print(f"  {n:16s} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} FPR={m['fpr']:.3f}  (TP{m['tp']} FP{m['fp']} FN{m['fn']})")

    # ---- Fig 1: bar chart with P/R/F1/FPR per method ----
    labels = list(methods.keys())
    metrics_names = ["precision", "recall", "f1", "fpr"]
    x = np.arange(len(labels)); w = 0.2   # w = width of each bar
    plt.figure(figsize=(10, 5))
    for i, mn in enumerate(metrics_names):
        plt.bar(x + i * w, [results[l][mn] for l in labels], w, label=mn.upper())
    plt.xticks(x + 1.5 * w, labels, rotation=15)
    plt.ylabel("score"); plt.ylim(0, 1.05)
    plt.title("Comparison of detection methods (held-out test set)")
    plt.legend(); plt.grid(axis="y", alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig1_metrics_comparison.png", dpi=130); plt.close()

    # ---- Fig 2: confusion matrices for the 3 main methods ----
    # (each matrix: rows=actual, columns=predicted)
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, name in zip(axes, ["Snort-only", "ML-only (RF)", "Hybrid"]):
        cm = confusion_matrix(y, methods[name], labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for (r, c), v in np.ndenumerate(cm):   # write the numbers inside the cells
            ax.text(c, r, int(v), ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black", fontsize=12)
        ax.set_title(name); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Benign", "Attack"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Benign", "Attack"])
    plt.tight_layout(); plt.savefig(f"{FIG}/fig2_confusion_matrices.png", dpi=130); plt.close()

    # ---- Fig 3: Precision-Recall curves ----
    # Due to the class imbalance, PR curves are more informative than ROC.
    # AP = average precision (area under the curve).
    plt.figure(figsize=(7, 6))
    for score_col, name in [("rf_score", "RF"), ("if_score", "IsolationForest"),
                            ("risk_score", "Hybrid risk")]:
        pr, rc, _ = precision_recall_curve(y, te[score_col].values)
        ap = average_precision_score(y, te[score_col].values)
        plt.plot(rc, pr, label=f"{name} (AP={ap:.3f})")
    base = y.mean()   # baseline = attack ratio (random classifier)
    plt.hlines(base, 0, 1, colors="gray", linestyles="--", label=f"baseline ({base:.3f})")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Precision-Recall curves (held-out test set)")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig3_pr_curves.png", dpi=130); plt.close()

    # ---- Fig 4: alert volume over time (the whole time series, not just the test) ----
    # Each method at a different height, so that the points where it fires are visible.
    full = df.sort_values("window_id")
    plt.figure(figsize=(12, 4))
    plt.plot(full["window_id"], full["is_attack"] * 1.0, color="black", lw=0.8,
             label="ground truth", alpha=0.6)
    plt.scatter(full[full.snort_only == 1]["window_id"],
                [1.10] * int(full.snort_only.sum()), s=8, label="Snort", color="tab:red")
    plt.scatter(full[full.ml_only == 1]["window_id"],
                [1.20] * int(full.ml_only.sum()), s=8, label="ML (RF)", color="tab:blue")
    plt.scatter(full[full.hybrid == 1]["window_id"],
                [1.30] * int(full.hybrid.sum()), s=8, label="Hybrid", color="tab:green")
    plt.yticks([0, 1, 1.10, 1.20, 1.30],
               ["benign", "attack", "Snort", "ML", "Hybrid"])
    plt.xlabel("window_id (1s windows)"); plt.title("Alert volume per method over time")
    plt.legend(loc="center right"); plt.tight_layout()
    plt.savefig(f"{FIG}/fig4_alert_timeline.png", dpi=130); plt.close()

    # ---- Case studies: real windows where the detectors disagree ----
    def sample(cond, n=3):
        # Returns the first n windows that satisfy the condition, with useful fields.
        sub = df[cond]
        cols = ["window_id", "attack_type", "packet_count", "syn_count", "psh_count",
                "icmp_count", "unique_dst_ports", "iat_mean",
                "snort_only", "ml_only", "rf_score", "if_score", "risk_level"]
        return sub[cols].head(n).to_dict("records")

    case_studies = {
        # ML catches, Snort misses (e.g. low-and-slow, start of scan)
        "ml_catches_snort_misses": sample(
            (df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 1)),
        # Snort catches, ML misses (e.g. stealth web probe via content match)
        "snort_catches_ml_misses": sample(
            (df.snort_only == 1) & (df.ml_only == 0) & (df.is_attack == 1)),
        # ML false positive while Snort stays clean
        "ml_false_positive_snort_clean": sample(
            (df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 0)),
    }

    # ---- Optional: feedback loop (auto-tuning the threshold from the FPs) ----
    # Goal: keep the FPR below a budget, by adjusting the threshold
    # above which the hybrid risk_score is considered an alert.
    fp_budget = 0.02
    thresholds = np.linspace(0.2, 0.9, 71)   # we try 71 thresholds in [0.2, 0.9]
    chosen = None; sweep = []
    for t in thresholds:
        pred = (te["risk_score"].values >= t).astype(int)
        b = block(y, pred); sweep.append((float(t), b["fpr"], b["recall"], b["f1"]))
        # We keep the first (lowest) threshold that brings the FPR within budget.
        if b["fpr"] <= fp_budget and chosen is None:
            chosen = (float(t), b)
    if chosen is None:   # safety: if none satisfies the budget
        chosen = (0.4, block(y, (te["risk_score"].values >= 0.4).astype(int)))

    # Chart of the sweep: FPR / Recall / F1 as a function of the threshold
    sw = np.array(sweep)
    plt.figure(figsize=(8, 5))
    plt.plot(sw[:, 0], sw[:, 1], label="FPR")
    plt.plot(sw[:, 0], sw[:, 2], label="Recall")
    plt.plot(sw[:, 0], sw[:, 3], label="F1")
    plt.axhline(fp_budget, color="red", ls="--", alpha=0.6, label=f"FP budget={fp_budget}")
    plt.axvline(chosen[0], color="green", ls="--", alpha=0.6,
                label=f"chosen t={chosen[0]:.2f}")
    plt.xlabel("hybrid risk threshold"); plt.ylabel("value")
    plt.title("Feedback loop: auto-tuning the threshold under a false-positive budget")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig5_feedback_loop.png", dpi=130); plt.close()

    # ---- Collect all the results into a single json (for the report) ----
    out = {
        "test_set_size": int(len(te)),
        "test_attacks": int(y.sum()),
        "comparison": results,
        "alert_volume_full_timeline": {
            "snort_only": int(df.snort_only.sum()),
            "ml_only": int(df.ml_only.sum()),
            "hybrid": int(df.hybrid.sum()),
            "total_windows": int(len(df)),
        },
        "case_studies": case_studies,
        "feedback_loop": {"fp_budget": fp_budget,
                          "chosen_threshold": chosen[0], "metrics_at_threshold": chosen[1]},
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"\n[*] feedback loop: chosen threshold={chosen[0]:.2f} -> "
          f"FPR={chosen[1]['fpr']:.3f} Recall={chosen[1]['recall']:.3f} F1={chosen[1]['f1']:.3f}")
    print(f"[OK] figures -> {FIG}/  | metrics -> {OUT}")


if __name__ == "__main__":
    main()
