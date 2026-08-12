# Ioannis Kalaitzidis, MTE25012

"""
Εκπαιδευση και τιμια αξιολογηση των μοντελων ML.

Μοντελα (ευθυγραμμισμενα με την υλη του μαθηματος):
  - RandomForest        : supervised, de facto baseline για tabular (διαλ. 3,4)
  - LogisticRegression  : ερμηνευσιμο supervised baseline (διαλ. 3)
  - IsolationForest     : unsupervised anomaly detection (διαλ. 3) -> προαιρετικη
                          συγκριση supervised vs anomaly

Αρχες που τηρουνται (αποφυγη των λαθων circular labeling / leakage - διαλ. 4):
  1. Τα labels προερχονται απο το event_log (ταυτοτητα επιτιθεμενου), ΟΧΙ απο
     τα ιδια τα features.
  2. Ο scaler και ο IsolationForest εκπαιδευονται ΜΟΝΟ στο train split.
  3. Ο IsolationForest εκπαιδευεται μονο σε benign παραθυρα (καθαρη αναφορα
     κανονικοτητας), οπως αρμοζει σε anomaly detection.
  4. Ολες οι headline μετρικες αναφερονται στο held-out test set.

Παραγει:
  ml_detector/predictions.csv : προβλεψεις ολων των μοντελων για ΟΛΑ τα παραθυρα
  ml_detector/rf_model.pkl, scaler.pkl, iforest.pkl
  ml_detector/ml_metrics.json : μετρικες test set ανα μοντελο
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)

# Διαδρομες σχετικες με τη ριζα του project (φορητες, ανεξαρτητα απο το cwd)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MLDIR = os.path.join(BASE, "ml_detector")
FEATURES = os.path.join(MLDIR, "features.csv")
PRED_OUT = os.path.join(MLDIR, "predictions.csv")
METRICS_OUT = os.path.join(MLDIR, "ml_metrics.json")
SEED = 1337


def metrics_block(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    pr, rc, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0)
    fpr = fp / max(fp + tn, 1)
    out = {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
           "precision": round(float(pr), 3), "recall": round(float(rc), 3),
           "f1": round(float(f1), 3), "fpr": round(float(fpr), 3)}
    if y_score is not None and len(set(y_true)) > 1:
        out["auc"] = round(float(roc_auc_score(y_true, y_score)), 3)
    return out


def main():
    df = pd.read_csv(FEATURES)
    feat_cols = [c for c in df.columns
                 if c not in ("window_id", "attack_type", "is_attack")]
    X = df[feat_cols].values
    y = df["is_attack"].values

    print(f"[*] dataset: {len(df)} windows | features: {len(feat_cols)} | "
          f"attack: {int(y.sum())} benign: {int((y==0).sum())}")

    idx = np.arange(len(df))
    Xtr, Xte, ytr, yte, itr, ite = train_test_split(
        X, y, idx, test_size=0.3, random_state=SEED, stratify=y)
    print(f"[*] train: {len(Xtr)} ({int(ytr.sum())} attack) | "
          f"test: {len(Xte)} ({int(yte.sum())} attack)")

    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr)
    Xte_s = scaler.transform(Xte)
    X_all_s = scaler.transform(X)

    metrics = {}

    # --- Random Forest (supervised) ---
    rf = RandomForestClassifier(n_estimators=200, max_depth=8,
                                min_samples_leaf=2, class_weight="balanced",
                                random_state=SEED)
    rf.fit(Xtr, ytr)   # tree-based: δεν χρειαζεται scaling
    rf_pred_te = rf.predict(Xte)
    rf_score_te = rf.predict_proba(Xte)[:, 1]
    metrics["random_forest"] = metrics_block(yte, rf_pred_te, rf_score_te)

    importance = sorted(zip(feat_cols, rf.feature_importances_),
                        key=lambda kv: kv[1], reverse=True)
    metrics["random_forest"]["top_features"] = [
        {"feature": f, "importance": round(float(i), 3)} for f, i in importance[:6]]

    # --- Logistic Regression (ερμηνευσιμο baseline) ---
    lr = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)
    lr.fit(Xtr_s, ytr)
    lr_pred_te = lr.predict(Xte_s)
    lr_score_te = lr.predict_proba(Xte_s)[:, 1]
    metrics["logistic_regression"] = metrics_block(yte, lr_pred_te, lr_score_te)

    # --- Isolation Forest (unsupervised anomaly) ---
    # Εκπαιδευση ΜΟΝΟ σε benign train παραθυρα -> "κανονικοτητα".
    Xtr_benign = Xtr_s[ytr == 0]
    contamination = float(ytr.mean())     # ~ ποσοστο επιθεσεων στο train
    iforest = IsolationForest(n_estimators=200, contamination=contamination,
                              random_state=SEED)
    iforest.fit(Xtr_benign)
    # predict: -1 anomaly, 1 normal -> 1 attack, 0 benign
    if_pred_te = (iforest.predict(Xte_s) == -1).astype(int)
    if_score_te = -iforest.score_samples(Xte_s)   # μεγαλυτερο = πιο ανωμαλο
    metrics["isolation_forest"] = metrics_block(yte, if_pred_te, if_score_te)

    # --- Προβλεψεις για ΟΛΑ τα παραθυρα (για fusion / case studies) ---
    df_out = df[["window_id", "attack_type", "is_attack"] + feat_cols].copy()
    df_out["rf_pred"] = rf.predict(X)
    df_out["rf_score"] = rf.predict_proba(X)[:, 1]
    df_out["lr_pred"] = lr.predict(X_all_s)
    df_out["if_pred"] = (iforest.predict(X_all_s) == -1).astype(int)
    if_score_all = -iforest.score_samples(X_all_s)
    # κανονικοποιηση if_score σε [0,1] για ευκολη χρηση στο fusion
    lo, hi = if_score_all.min(), if_score_all.max()
    df_out["if_score"] = (if_score_all - lo) / max(hi - lo, 1e-9)
    df_out["in_test"] = np.isin(df_out["window_id"], df.iloc[ite]["window_id"].values).astype(int)
    df_out.to_csv(PRED_OUT, index=False)

    with open(METRICS_OUT, "w") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    # Αποθηκευση μοντελων
    for obj, path in [(rf, "rf_model.pkl"), (scaler, "scaler.pkl"), (iforest, "iforest.pkl")]:
        with open(os.path.join(MLDIR, path), "wb") as f:
            pickle.dump(obj, f)

    print("\n[*] TEST-SET metrics:")
    for name in ("random_forest", "logistic_regression", "isolation_forest"):
        m = metrics[name]
        print(f"  {name:20s} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} FPR={m['fpr']:.3f} AUC={m.get('auc','-')}")
    print("\n[*] RF top features:",
          [f["feature"] for f in metrics["random_forest"]["top_features"]])
    print(f"[OK] predictions -> {PRED_OUT}")


if __name__ == "__main__":
    main()
