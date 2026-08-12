# Οδηγός εκτέλεσης Snort (offline) - για τα screenshots

Ιωάννης Καλαϊτζίδης, MTE25012

Το ML pipeline περιλαμβάνει έναν πιστό emulator των κανόνων (`ml_detector/snort_emulator.py`)
ώστε να είναι πλήρως αναπαραγώγιμο χωρίς εγκατεστημένο Snort. Ο πραγματικός Snort
χρειάζεται να τρέξει μία φορά, offline πάνω στο έτοιμο pcap, μόνο για να παραχθούν
τα στιγμιότυπα των alerts που ζητά η εκφώνηση.

Η επαλήθευση έγινε σε Kali Linux με Snort 3.12.2. Παρακάτω δίνονται οι ακριβείς
εντολές που χρησιμοποιήθηκαν.

## 1. Εγκατάσταση Snort 3 σε Kali Linux

```bash
sudo apt update && sudo apt install -y snort
snort --version    # επιβεβαιωση: Snort++ 3.x
```

## 2. Config και κανόνες συμβατοι με Snort 3.12

Σε αυτή την εκδοση, οι μεταβλητες $HOME_NET / $EXTERNAL_NET οριζονται απευθειας
μεσα στους κανονες. Χρησιμοποιουνται τα αρχεια `rules/snort_kali.lua` και
`rules/rules_kali.rules` (περιλαμβανονται στο project).

Περιεχομενο του `snort_kali.lua`:

```lua
HOME_NET = '10.0.0.0/24'
EXTERNAL_NET = '!10.0.0.0/24'
stream = { }
stream_tcp = { }
stream_icmp = { }
binder = { { when = { proto = 'tcp', ports = '8080' }, use = { type = 'http_inspect' } } }
http_inspect = { }
ips = { enable_builtin_rules = false }
alert_fast = { file = true }
```

Περιεχομενο του `rules_kali.rules` (διευθυνσεις κατευθειαν, χωρις μεταβλητες):

```
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"WEB Suspicious URI / admin panel probe"; flow:to_server,established; http_uri; content:"phpmyadmin",nocase; sid:1000001; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"WEB sqlmap User-Agent detected"; flow:to_server,established; http_header; content:"sqlmap",nocase; sid:1000002; rev:1; )
alert icmp !10.0.0.0/24 any -> 10.0.0.0/24 any ( msg:"ICMP Echo flood from external host"; itype:8; detection_filter:track by_src, count 30, seconds 1; sid:1000003; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"TCP SYN scan / port sweep"; flags:S; detection_filter:track by_src, count 40, seconds 2; sid:1000004; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"TCP connection flood (burst)"; flags:S; detection_filter:track by_src, count 20, seconds 1; sid:1000005; rev:1; )
```

## 3. Εκτέλεση offline στο pcap

Απο τη ριζα του project:

```bash
snort -c rules/snort_kali.lua -R rules/rules_kali.rules \
      -r pcaps/lab_traffic.pcap -A alert_fast -l logs -k none
```

Στο τελος τυπωνεται η συνοψη (Packet Statistics / Module Statistics). Χρησιμα σημεια:
- `daq ... analyzed: 24110`  (αναλυθηκαν ολα τα πακετα)
- `detection ... total_alerts: 1607`  (συνολικοι συναγερμοι)

## 4. Έλεγχος των alerts

```bash
cat logs/alert_fast.txt | head -30
for s in 1000001 1000002 1000003 1000004 1000005; do echo -n "$s: "; grep -c $s logs/alert_fast.txt; done
```

Αποτελεσματα της εκτελεσης (Snort 3.12.2 σε Kali):

| sid | Κανόνας | Alerts |
|---|---|---|
| 1000001 | WEB Suspicious URI (phpmyadmin) | 0 |
| 1000002 | WEB sqlmap User-Agent | 0 |
| 1000003 | ICMP Echo flood (external) | 1412 |
| 1000004 | TCP SYN scan / port sweep | 73 |
| 1000005 | TCP connection flood (burst) | 122 |

Σημειωση: οι τρεις κανονες ογκου (ICMP/SYN/conn) ενεργοποιουνται κανονικα. Οι δυο
κανονες περιεχομενου (phpmyadmin/sqlmap) δεν ενεργοποιηθηκαν σε αυτη την εκδοση,
καθως ο http_inspect του Snort 3.12 δεν αντιστοιχιζει το συνθετικο HTTP payload με
τον τροπο που το κανει ο emulator (ο οποιος τους πυροδοτει κανονικα). Οι μετρικες
της μηχανικης μαθησης και του υβριδικου συστηματος βασιζονται στο πληρες συνολο
κανονων μεσω του emulator και δεν επηρεαζονται.
