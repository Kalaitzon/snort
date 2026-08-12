#!/usr/bin/env bash
# Ioannis Kalaitzidis, MTE25012
# Τρεχει ολο το pipeline με τη σειρα. Χρηση: bash run_all.sh
set -e
cd "$(dirname "$0")"
echo "== 1. Dataset synthesis =="
python3 traffic_generation/build_dataset.py
echo "== 2. Feature extraction (labels απο event_log) =="
python3 ml_detector/feature_extraction.py
echo "== 3. Snort rule emulation =="
python3 ml_detector/snort_emulator.py
echo "== 4. ML training (RF + LogReg + IsolationForest) =="
python3 ml_detector/train_model.py
echo "== 5. Hybrid fusion =="
python3 ml_detector/hybrid_fusion.py
echo "== 6. Evaluation + figures =="
python3 ml_detector/evaluation.py
echo "== DONE =="
