# Case Studies: Signature vs Anomaly Detection Disagreement

The following case studies come from **real** windows of the dataset (see
`ml_detector/evaluation.json`) and show cases where one detector catches
what the other misses, exactly the goal of this work. They confirm that no
single mechanism is sufficient.

## Case Study 1: ML catches what Snort misses (low-and-slow + start of scan)

**Total: 98 windows** where RF=1, Snort=0, ground truth=attack.

Example - window 151 (start of SYN scan):
- packet_count=130, unique_dst_ports=122, psh_count=4
- Snort: does **not** fire (the detection_filter requires 40 SYN/2s, and in the first window the counter has not yet accumulated)
- RF: **fires** (rf_score=0.98) via the `unique_dst_ports` feature (scan of 122 ports)

The main source of this category is the **low-and-slow SQLi**: the request breaks into
small pieces (`GET /?id=1` / ` UNION` / ` SELECT` ...) sent with delays,
so (a) no single packet contains the whole signature for a content match
and (b) the rate stays below the thresholds. Snort is blind. RF detects
the anomaly in the timing features (`iat_mean`, `iat_std`) and in the pattern of the small PSH.

**Conclusion**: signature detection fails against evasion via fragmentation and a low
rate, while ML covers the gap.

## Case Study 2: Snort catches what ML misses (stealth web probe)

Example - window 1428 (stealth web probe):
- packet_count=86, psh_count=28, unique_dst_ports=11
- RF: does **not** fire (rf_score=0.12, the volume profile looks like heavy but legitimate browsing)
- Snort: **fires** (sid 1000002, "sqlmap User-Agent") via a content match

Here the attacker sends individual suspicious requests (`/phpmyadmin/`, `User-Agent:
sqlmap`) sparsely, so that the volume looks normal. RF, which relies on aggregate
counts, takes it as benign. Snort, which looks at the **content**, detects it
immediately. Thanks to rule C1 (signature override), the hybrid classifies it as HIGH risk.

**Conclusion**: ML based on volume statistics misses the semantic
signatures, while signature detection catches them with certainty.

## Case Study 3: False positives of ML - where Snort offers precision

**Total: 7 windows** where RF=1, Snort=0, ground truth=benign.

Examples:
- window 692 (benign): heavy but legitimate browsing (16 packets, 4 PSH), rf_score=0.50 - borderline
- window 857 (benign): unusual window with 1 packet, rf_score=0.91

Snort, with precision=1.000 on the test set, produces no false positive. The fusion
rule exploits this: when ML signals but no signature matches, the event
is not automatically escalated to HIGH, reducing alert fatigue (lecture 1).

**Conclusion**: Snort's high precision balances ML's tendency toward false
positives, and the combination gives a better overall trade-off (Hybrid F1=0.926 versus
RF=0.916 and Snort=0.514).
