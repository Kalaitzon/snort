==============================================================================
 Hybrid IDS (Snort + ML) - Καλαϊτζιδης Ιωαννης, MTE25012
==============================================================================

Το project υλοποιει ενα υβριδικο συστημα ανιχνευσης εισβολων που συνδυαζει
signature-based ανιχνευση (Snort) με ανιχνευση βασισμενη σε μηχανικη μαθηση
(Random Forest, Logistic Regression, Isolation Forest), τα ενωνει με ενα επιπεδο
fusion με βαθμιδες κινδυνου και ρητο χειρισμο διαφωνιων, και τα αξιολογει τιμια
πανω σε ενα ρεαλιστικο, χρονοσφραγισμενο dataset 1.484 παραθυρων.

Η πληρης τεκμηριωση (μοντελο, μεθοδολογια, αποτελεσματα, evasion, ορια εγκυροτητας)
δινεται ξεχωριστα στο Report. Το README δειχνει τι κανει το καθε αρχειο, πως
αντιστοιχουν τα αρχεια στα ζητουμενα, και πως ακριβως τρεχει το καθετι.

ΚΕΝΤΡΙΚΗ ΣΧΕΔΙΑΣΤΙΚΗ ΑΡΧΗ (τιμιοτητα / αποφυγη leakage):
Τα labels των παραθυρων προερχονται απο ανεξαρτητο ground truth (χρονοσφραγιδες στο
event_log.csv και ταυτοτητα επιτιθεμενου), ΟΧΙ απο τα ιδια τα χαρακτηριστικα της
κινησης. Ετσι αποφευγεται το circular labeling και οι μετρικες ειναι πραγματικες
(π.χ. Hybrid F1=0.926, οχι τεχνητο 1.0).


------------------------------------------------------------------------------
 1. ΔΟΜΗ ΦΑΚΕΛΩΝ

    MTE25012_Snort/                     <- ριζα του project
    |
    +-- traffic_generation/
    |     build_dataset.py       συνθεση ντετερμινιστικου pcap + event_log (task 1,2)
    |     traffic_gen.py         live γεννητορας για πραγματικο lab (αναπαραγωγιμοτητα)
    |     web_server.py          απλος server-θυμα για το live mode
    |
    +-- ml_detector/
    |     feature_extraction.py  features ανα παραθυρο + labels απο event_log (task 2,4)
    |     snort_emulator.py      πιστος emulator των κανονων Snort (task 3)
    |     train_model.py         RF + LogReg + IsolationForest, held-out (task 4, προαιρ.)
    |     hybrid_fusion.py       fusion + βαθμιδες + conflict handling (task 5)
    |     evaluation.py          μετρικες, confusion, PR curves, case studies (task 6, προαιρ.)
    |     features.csv, predictions.csv, hybrid_results.csv   (παραγονται)
    |     ml_metrics.json, evaluation.json, conflicts.json    (παραγονται)
    |     rf_model.pkl, scaler.pkl, iforest.pkl               (παραγονται)
    |
    +-- rules/
    |     local.rules            5 εγκυροι Snort 3 κανονες (task 3)
    |     snort.lua              config Snort 3 για offline analysis (task 3)
    |     rules_kali.rules       κανονες συμβατοι με Snort 3.12 (πραγματικη εκτελεση σε Kali)
    |     snort_kali.lua         config συμβατο με Snort 3.12 (πραγματικη εκτελεση σε Kali)
    |
    +-- logs/
    |     event_log.csv          ground truth: χρονοδιαγραμμα επιθεσεων
    |     snort_alerts.csv       alerts ανα πακετο (απο τον emulator)
    |     snort_windows.csv      σημα Snort ανα παραθυρο
    |     alert_fast.txt         alerts απο τον ΠΡΑΓΜΑΤΙΚΟ Snort 3.12 (Kali)
    |
    +-- pcaps/
    |     lab_traffic.pcap       το ενιαιο dataset κινησης
    |
    +-- screenshots/             στιγμιοτυπα εκτελεσης πραγματικου Snort (task 3)
    +-- figures/                 fig1..fig5 (παραγονται απο το evaluation.py, για την αναφορα)
    |
    +-- Report_MTE25012_Hybrid_IDS.docx
    +-- README.txt               αυτο το αρχειο
    +-- TESTBED_DESIGN.md        τοπολογια, labeling, dataset (task 1)
    +-- CASE_STUDIES.md          3 case studies διαφωνιας (task 6)
    +-- SNORT_GUIDE.md           οδηγος εκτελεσης πραγματικου Snort σε Kali (screenshots)
    +-- run_all.sh               τρεχει ολο το pipeline με τη σειρα
    +-- requirements.txt         εξαρτησεις Python


------------------------------------------------------------------------------
 2. ΑΠΑΙΤΗΣΕΙΣ

Python 3.10+. Εγκατασταση εξαρτησεων:

    pip install -r requirements.txt

Το ML pipeline τρεχει ΧΩΡΙΣ εγκατεστημενο Snort (χρησιμοποιει τον emulator). Ο
πραγματικος Snort χρειαζεται μονο για τα screenshots των alerts και τρεχει σε
Kali Linux με Snort 3, offline στο pcap (πληρεις οδηγιες στο SNORT_GUIDE.md).


------------------------------------------------------------------------------
 3. ΕΝΤΟΛΕΣ ΕΚΤΕΛΕΣΗΣ (με τη σειρα)

Ολο το pipeline με μια εντολη (Windows: τρεξε τα βηματα ξεχωριστα με `python`):

    bash run_all.sh

Ή βημα-βημα:

    python traffic_generation/build_dataset.py     -> pcaps/lab_traffic.pcap, logs/event_log.csv
    python ml_detector/feature_extraction.py       -> ml_detector/features.csv
    python ml_detector/snort_emulator.py           -> logs/snort_alerts.csv, snort_windows.csv
    python ml_detector/train_model.py              -> predictions.csv, ml_metrics.json, μοντελα
    python ml_detector/hybrid_fusion.py            -> hybrid_results.csv, conflicts.json
    python ml_detector/evaluation.py               -> figures/, evaluation.json

Πραγματικος Snort (offline, για screenshots) - σε Kali Linux με Snort 3.12:

    sudo apt update && sudo apt install -y snort
    snort -c rules/snort_kali.lua -R rules/rules_kali.rules \
          -r pcaps/lab_traffic.pcap -A alert_fast -l logs -k none

    (πληρεις οδηγιες και επεξηγηση αποτελεσματων στο SNORT_GUIDE.md)


------------------------------------------------------------------------------
 4. ΑΝΤΙΣΤΟΙΧΙΣΗ ΑΡΧΕΙΩΝ ΣΤΑ ΖΗΤΟΥΜΕΝΑ

TASK 1 - Σχεδιασμος testbed & traffic plan: τοπολογια 2 δικτυων (HOME_NET/EXTERNAL_NET),
    υπηρεσια-στοχος, σχεδιο κινησης, ground truth & labeling, αναπαραγωγιμοτητα.
    Αρχεια: TESTBED_DESIGN.md, traffic_generation/build_dataset.py -> pcaps/lab_traffic.pcap,
            logs/event_log.csv.

TASK 2 - Παραγωγη & επισημανση κινησης: benign + 5 κακοβουλα σεναρια (SYN scan,
    ICMP flood, connection flood, HTTP probe, stealth web) + 1 low-and-slow, με pcap
    και label ανα παραθυρο (1.484 παραθυρα, labels απο timeline - χωρις leakage).
    Αρχεια: traffic_generation/build_dataset.py, ml_detector/feature_extraction.py
            -> features.csv.

TASK 3 - Snort με 5 custom κανονες (>3): HTTP suspicious URI, sqlmap UA, ICMP echo
    απο external με threshold, SYN scan, connection flood.
    Αρχεια: rules/local.rules, rules/snort.lua, ml_detector/snort_emulator.py
            -> logs/snort_alerts.csv, logs/snort_windows.csv.
    Επαληθευση με πραγματικο Snort 3.12 σε Kali: rules/snort_kali.lua, rules/rules_kali.rules
            -> logs/alert_fast.txt, screenshots/. Οδηγος: SNORT_GUIDE.md.

TASK 4 - Εξαγωγη 17 χαρακτηριστικων + εκπαιδευση ML με καθαρο held-out split (70/30,
    stratified), scaler/IF μονο στο train, αναφορα preprocessing & hyperparameters.
    Αρχεια: ml_detector/feature_extraction.py, ml_detector/train_model.py
            -> predictions.csv, ml_metrics.json, rf_model.pkl, scaler.pkl, iforest.pkl.

TASK 5 - Hybrid fusion: βαθμος κινδυνου (0.55*RF + 0.30*Snort + 0.15*IF), βαθμιδες
    LOW/MEDIUM/HIGH, ρητος χειρισμος διαφωνιων (C1 signature override, C2 anomaly watch,
    C3 stealth), συγκριση Snort-only / ML-only / Hybrid.
    Αρχεια: ml_detector/hybrid_fusion.py -> hybrid_results.csv, conflicts.json.

TASK 6 - Αξιολογηση: precision/recall/F1/FPR, confusion matrices, PR curves (εμφαση
    λογω imbalance), ογκος alert, 3 case studies διαφωνιας, συζητηση ευσταθειας μετρικων.
    Αρχεια: ml_detector/evaluation.py -> figures/fig1..fig5, evaluation.json;
            CASE_STUDIES.md.

TASK 7 - Evasion & reflection: >=3 τεχνικες evasion (κατατμηση/low-and-slow, stealth
    χαμηλου ογκου, threshold evasion), ποιον ανιχνευτη επηρεαζουν, μειωση false
    positives, ορια εναντι zero-day. Δινεται στην ενοτητα Task 7 της αναφορας.
    Αρχεια: Report_MTE25012_Hybrid_IDS.docx.


------------------------------------------------------------------------------
 5. ΠΡΟΑΙΡΕΤΙΚΑ TASKS

ΠΡΟΑΙΡΕΤΙΚΟ TASK 1 - Συγκριση δυο προσεγγισεων ML: supervised (Random Forest, Logistic
    Regression) vs unsupervised anomaly detection (Isolation Forest), με τις αντισταθμισεις
    τους (το IF εχει υψηλο recall αλλα χαμηλη precision - "το ασυνηθιστο δεν ειναι παντα
    κακοβουλο").
    Αρχεια: ml_detector/train_model.py, ml_detector/evaluation.py -> fig1, fig3.

ΠΡΟΑΙΡΕΤΙΚΟ TASK 2 - Feedback loop: αυτοματη ρυθμιση του κατωφλιου του hybrid ωστε να
    κρατιεται το FPR κατω απο ενα budget (auto-tuning απο τα μετρημενα false positives).
    Αρχεια: ml_detector/evaluation.py -> fig5.


------------------------------------------------------------------------------
 6. ΤΕΚΜΗΡΙΩΣΗ

Το Report (Report_MTE25012_Hybrid_IDS.docx) περιεχει την πληρη περιγραφη:
testbed & μοντελο απειλων, σχεδιο & επισημανση κινησης, κανονες Snort, χαρακτηριστικα
& μοντελα ML με πραγματικες μετρικες, hybrid fusion, αξιολογηση με πινακες/σχηματα,
case studies, evasion & reflection, τα δυο προαιρετικα, και ρητη δηλωση οριων εγκυροτητας.
