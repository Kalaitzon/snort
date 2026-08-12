# Ioannis Kalaitzidis, MTE25012

"""
Αξιολογηση και συγκριση Snort-only / ML-only / Hybrid + προαιρετικα.

Παραγει (ολα με ΠΡΑΓΜΑΤΙΚΑ νουμερα απο τις εκτελεσεις):
  figures/fig1_metrics_comparison.png : P/R/F1/FPR ανα μεθοδο (test set)
  figures/fig2_confusion_matrices.png : confusion matrices Snort/ML/Hybrid
  figures/fig3_pr_curves.png          : Precision-Recall (εμφαση λογω imbalance)
  figures/fig4_alert_timeline.png     : ογκος alert ανα μεθοδο στον χρονο
  figures/fig5_feedback_loop.png      : προαιρετικο - auto-tuning κατωφλιου απο FPs
  ml_detector/evaluation.json         : ολες οι μετρικες + case studies

Ολες οι head-to-head μετρικες υπολογιζονται στο HELD-OUT test set (in_test==1),
ωστε η συγκριση ML να ειναι τιμια (χωρις να εχει δει τα δεδομενα στην εκπαιδευση).
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # backend χωρις οθονη (γραφει κατευθειαν σε αρχεια)
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             precision_recall_curve, average_precision_score)

# Διαδρομες σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HYBRID = os.path.join(BASE, "ml_detector", "hybrid_results.csv")
FIG = os.path.join(BASE, "figures")
OUT = os.path.join(BASE, "ml_detector", "evaluation.json")
os.makedirs(FIG, exist_ok=True)   # δημιουργια figures/ αν λειπει


def block(y, p):
    """Υπολογιζει τις βασικες μετρικες ενος δυαδικου ταξινομητη για τις
    προβλεψεις p εναντι της αληθειας y: TP/FP/FN/TN, precision, recall, F1, FPR."""
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    fpr = fp / max(fp + tn, 1)    # ποσοστο νομιμων παραθυρων που σημανθηκαν λαθος
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
            "precision": round(float(pr), 3), "recall": round(float(rc), 3),
            "f1": round(float(f1), 3), "fpr": round(float(fpr), 3)}


def main():
    df = pd.read_csv(HYBRID)
    # Κραταμε ΜΟΝΟ τα παραθυρα του test set για τιμια συγκριση (in_test==1).
    te = df[df["in_test"] == 1].copy()
    y = te["is_attack"].values    # η αληθεια (ground truth) στο test set

    # Η δυαδικη αποφαση καθε μεθοδου ανα παραθυρο, ολες στα ιδια δεδομενα.
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

    # ---- Fig 1: ραβδογραμμα με P/R/F1/FPR ανα μεθοδο ----
    labels = list(methods.keys())
    metrics_names = ["precision", "recall", "f1", "fpr"]
    x = np.arange(len(labels)); w = 0.2   # w = πλατος καθε ραβδου
    plt.figure(figsize=(10, 5))
    for i, mn in enumerate(metrics_names):
        plt.bar(x + i * w, [results[l][mn] for l in labels], w, label=mn.upper())
    plt.xticks(x + 1.5 * w, labels, rotation=15)
    plt.ylabel("score"); plt.ylim(0, 1.05)
    plt.title("Συγκριση μεθοδων ανιχνευσης (held-out test set)")
    plt.legend(); plt.grid(axis="y", alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig1_metrics_comparison.png", dpi=130); plt.close()

    # ---- Fig 2: confusion matrices για τις 3 βασικες μεθοδους ----
    # (καθε πινακας: γραμμες=πραγματικο, στηλες=προβλεψη)
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, name in zip(axes, ["Snort-only", "ML-only (RF)", "Hybrid"]):
        cm = confusion_matrix(y, methods[name], labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for (r, c), v in np.ndenumerate(cm):   # γραψιμο των αριθμων μεσα στα κελια
            ax.text(c, r, int(v), ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black", fontsize=12)
        ax.set_title(name); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Benign", "Attack"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Benign", "Attack"])
    plt.tight_layout(); plt.savefig(f"{FIG}/fig2_confusion_matrices.png", dpi=130); plt.close()

    # ---- Fig 3: καμπυλες Precision-Recall ----
    # Λογω της ανισορροπιας κλασεων, οι PR καμπυλες ειναι πιο κατατοπιστικες απο τις ROC.
    # AP = average precision (εμβαδον κατω απο την καμπυλη).
    plt.figure(figsize=(7, 6))
    for score_col, name in [("rf_score", "RF"), ("if_score", "IsolationForest"),
                            ("risk_score", "Hybrid risk")]:
        pr, rc, _ = precision_recall_curve(y, te[score_col].values)
        ap = average_precision_score(y, te[score_col].values)
        plt.plot(rc, pr, label=f"{name} (AP={ap:.3f})")
    base = y.mean()   # baseline = ποσοστο επιθεσεων (τυχαιος ταξινομητης)
    plt.hlines(base, 0, 1, colors="gray", linestyles="--", label=f"baseline ({base:.3f})")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Precision-Recall curves (held-out test set)")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig3_pr_curves.png", dpi=130); plt.close()

    # ---- Fig 4: ογκος alert στον χρονο (ολη η χρονοσειρα, οχι μονο το test) ----
    # Καθε μεθοδος σε διαφορετικο υψος, ωστε να φαινονται τα σημεια που χτυπα.
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
    plt.xlabel("window_id (1s windows)"); plt.title("Ογκος alert ανα μεθοδο στον χρονο")
    plt.legend(loc="center right"); plt.tight_layout()
    plt.savefig(f"{FIG}/fig4_alert_timeline.png", dpi=130); plt.close()

    # ---- Case studies: πραγματικα παραθυρα οπου οι ανιχνευτες διαφωνουν ----
    def sample(cond, n=3):
        # Επιστρεφει τα πρωτα n παραθυρα που ικανοποιουν τη συνθηκη, με χρησιμα πεδια.
        sub = df[cond]
        cols = ["window_id", "attack_type", "packet_count", "syn_count", "psh_count",
                "icmp_count", "unique_dst_ports", "iat_mean",
                "snort_only", "ml_only", "rf_score", "if_score", "risk_level"]
        return sub[cols].head(n).to_dict("records")

    case_studies = {
        # ML πιανει, Snort χανει (π.χ. low-and-slow, εναρξη scan)
        "ml_catches_snort_misses": sample(
            (df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 1)),
        # Snort πιανει, ML χανει (π.χ. stealth web probe με content match)
        "snort_catches_ml_misses": sample(
            (df.snort_only == 1) & (df.ml_only == 0) & (df.is_attack == 1)),
        # ML false positive ενω ο Snort μενει καθαρος
        "ml_false_positive_snort_clean": sample(
            (df.ml_only == 1) & (df.snort_only == 0) & (df.is_attack == 0)),
    }

    # ---- Προαιρετικο: feedback loop (auto-tuning κατωφλιου απο τα FPs) ----
    # Στοχος: να κρατηθει το FPR κατω απο ενα budget, ρυθμιζοντας το κατωφλι
    # πανω απο το οποιο το hybrid risk_score θεωρειται συναγερμος.
    fp_budget = 0.02
    thresholds = np.linspace(0.2, 0.9, 71)   # δοκιμαζουμε 71 κατωφλια στο [0.2, 0.9]
    chosen = None; sweep = []
    for t in thresholds:
        pred = (te["risk_score"].values >= t).astype(int)
        b = block(y, pred); sweep.append((float(t), b["fpr"], b["recall"], b["f1"]))
        # Το πρωτο (χαμηλοτερο) κατωφλι που φερνει το FPR εντος budget το κραταμε.
        if b["fpr"] <= fp_budget and chosen is None:
            chosen = (float(t), b)
    if chosen is None:   # ασφαλεια: αν κανενα δεν ικανοποιει το budget
        chosen = (0.4, block(y, (te["risk_score"].values >= 0.4).astype(int)))

    # Γραφημα της σαρωσης: FPR / Recall / F1 συναρτησει του κατωφλιου
    sw = np.array(sweep)
    plt.figure(figsize=(8, 5))
    plt.plot(sw[:, 0], sw[:, 1], label="FPR")
    plt.plot(sw[:, 0], sw[:, 2], label="Recall")
    plt.plot(sw[:, 0], sw[:, 3], label="F1")
    plt.axhline(fp_budget, color="red", ls="--", alpha=0.6, label=f"FP budget={fp_budget}")
    plt.axvline(chosen[0], color="green", ls="--", alpha=0.6,
                label=f"chosen t={chosen[0]:.2f}")
    plt.xlabel("hybrid risk threshold"); plt.ylabel("value")
    plt.title("Feedback loop: auto-tuning κατωφλιου υπο budget false positives")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(f"{FIG}/fig5_feedback_loop.png", dpi=130); plt.close()

    # ---- Συγκεντρωση ολων των αποτελεσματων σε ενα json (για την αναφορα) ----
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
