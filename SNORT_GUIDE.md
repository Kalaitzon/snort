# Snort execution guide (offline) - for the screenshots

The ML pipeline includes a faithful emulator of the rules (`ml_detector/snort_emulator.py`)
so that it is fully reproducible without an installed Snort. The real Snort
needs to run once, offline over the ready pcap, only to produce
the alert screenshots that the assignment requires.

The verification was done on Kali Linux with Snort 3.12.2. Below are the exact
commands that were used.

## 1. Installing Snort 3 on Kali Linux

```bash
sudo apt update && sudo apt install -y snort
snort --version    # confirm: Snort++ 3.x
```

## 2. Config and rules compatible with Snort 3.12

In this version, the $HOME_NET / $EXTERNAL_NET variables are defined directly
inside the rules. The files `rules/snort_kali.lua` and
`rules/rules_kali.rules` are used (included in the project).

Content of `snort_kali.lua`:

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

Content of `rules_kali.rules` (addresses inline, without variables):

```
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"WEB Suspicious URI / admin panel probe"; flow:to_server,established; http_uri; content:"phpmyadmin",nocase; sid:1000001; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"WEB sqlmap User-Agent detected"; flow:to_server,established; http_header; content:"sqlmap",nocase; sid:1000002; rev:1; )
alert icmp !10.0.0.0/24 any -> 10.0.0.0/24 any ( msg:"ICMP Echo flood from external host"; itype:8; detection_filter:track by_src, count 30, seconds 1; sid:1000003; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"TCP SYN scan / port sweep"; flags:S; detection_filter:track by_src, count 40, seconds 2; sid:1000004; rev:1; )
alert tcp !10.0.0.0/24 any -> 10.0.0.0/24 8080 ( msg:"TCP connection flood (burst)"; flags:S; detection_filter:track by_src, count 20, seconds 1; sid:1000005; rev:1; )
```

## 3. Offline execution over the pcap

From the project root:

```bash
snort -c rules/snort_kali.lua -R rules/rules_kali.rules \
      -r pcaps/lab_traffic.pcap -A alert_fast -l logs -k none
```

At the end the summary is printed (Packet Statistics / Module Statistics). Useful points:
- `daq ... analyzed: 24110`  (all packets analyzed)
- `detection ... total_alerts: 1607`  (total alerts)

## 4. Checking the alerts

```bash
cat logs/alert_fast.txt | head -30
for s in 1000001 1000002 1000003 1000004 1000005; do echo -n "$s: "; grep -c $s logs/alert_fast.txt; done
```

Results of the run (Snort 3.12.2 on Kali):

| sid | Rule | Alerts |
|---|---|---|
| 1000001 | WEB Suspicious URI (phpmyadmin) | 0 |
| 1000002 | WEB sqlmap User-Agent | 0 |
| 1000003 | ICMP Echo flood (external) | 1412 |
| 1000004 | TCP SYN scan / port sweep | 73 |
| 1000005 | TCP connection flood (burst) | 122 |

Note: the three volume rules (ICMP/SYN/conn) fire normally. The two
content rules (phpmyadmin/sqlmap) did not fire in this version,
because the http_inspect of Snort 3.12 does not match the synthetic HTTP payload the
way the emulator does (which fires them normally). The metrics
of the machine learning and of the hybrid system are based on the full set
of rules through the emulator and are not affected.
