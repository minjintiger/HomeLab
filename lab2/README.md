# HomeLab 2 — Suricata IDS Detection (Nmap, eve.json, Custom ICMP Rule)

This lab demonstrates intrusion detection using Suricata IDS. I performed Nmap scans from Kali, analyzed alerts in eve.json, verified Suricata’s rule processing, and created a custom ICMP rule. This lab builds on Lab 1 network reconnaissance by showing how scan traffic appears through an IDS.

---

## Lab Environment

|        VM        |    Role    |   IP Address   |
|------------------|------------|----------------|
| Kali Linux       | Attacker   | 192.168.56.101 |
| Ubuntu Server    | IDS Target | 192.168.56.102 |
| Metasploitable 2 | Not used   | 192.168.56.103 |

Network Mode: VirtualBox Host-Only, NAT   
Suricata Interface: enp0s3  
Suricata Logs: /var/log/suricata/eve.json

---

## Objectives

- Verify Suricata installation and rule loading
- Perform Nmap scans to generate IDS alerts
- Analyze alert entries in eve.json using jq
- Understand Suricata alert structure
- Build and trigger a custom ICMP detection rule
- Troubleshoot HOME_NET / EXTERNAL_NET rule-matching problems

---

## Step 1 — Verify Suricata Is Running

Command:
sudo suricata -c /etc/suricata/suricata.yaml -i enp0s3

Expected output:
“Threads created … Engine started.”

Screenshot: images/suricata_running.png

---

## Step 2 — Perform Nmap Scans from Kali

Aggressive Scan:
nmap -sS -sV -A 192.168.56.102

Basic SYN Scan:
nmap -p- -sS 192.168.56.102

PING Test:
ping -c 4 192.168.56.102

Screenshots:
- images/nmap_scan.png
- images/nmap_ping.png

Summary:
- Target responds to ICMP Echo Requests
- All TCP ports return RST (closed)
- No application-layer banners returned
- Suricata detects ICMP anomalies triggered by the scan

---

## Step 3 — Check Suricata Alerts in eve.json

Command to filter alerts only:
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 20

Example fields:
- event_type: "alert"
- src_ip: 192.168.56.101
- dest_ip: 192.168.56.102
- proto: ICMP
- signature: "SURICATA ICMPv4 unknown code"
- direction: "to_server" and "to_client"

Screenshot: images/alert_output.png

---

## Step 4 — Build a Custom Local ICMP Rule

Initial rule attempt (did not fire due to address-group mismatch):
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL ICMP Ping from EXTERNAL to HOME_NET"; sid:1000001; rev:1;)

I discovered that Suricata loads rules from:
 /var/lib/suricata/rules/local.rules
not from the /etc directory.

Screenshot: images/local_rules_before.png  
Screenshot: images/local_rules_after.png  

I confirmed Suricata is loading local.rules via:
Screenshot: images/local_rule_added_to_config.png

Final simplified rule that works in this lab:
alert icmp any any -> any any (msg:"LOCAL ICMP Ping TEST"; sid:1000001; rev:1;)

Reason: Both Kali and Ubuntu belong to HOME_NET (192.168.0.0/16), so EXTERNAL_NET → HOME_NET did not match.

---

## Step 5 — Test Suricata Configuration

Command:
sudo suricata -T -c /etc/suricata/suricata.yaml -v

Expected:
Configuration provided was successfully loaded. 0 rules failed.

Screenshot: images/suricata_config_test.png

---

## Step 6 — Trigger the Custom Rule

From Kali:
ping -c 4 192.168.56.102

Check eve.json:
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 20

Expected:
signature: "LOCAL ICMP Ping TEST"
src_ip: "192.168.56.101"
dest_ip: "192.168.56.102"

Screenshot: images/custom_rule_alert.png

---

## Troubleshooting Summary — Why Original Rule Did Not Trigger

My initial rule required:
EXTERNAL_NET → HOME_NET ICMP

Suricata’s suricata.yaml shows:
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!$HOME_NET"

Because both Kali and Ubuntu are in 192.168.56.0/24, they are BOTH inside HOME_NET.

Therefore:
- Kali → Ubuntu ICMP traffic = HOME_NET → HOME_NET
- My rule only matched EXTERNAL_NET → HOME_NET
- So Suricata ignored it

To fix this, I considered three options:

1. Simplify the rule (chosen)
   alert icmp any any -> $HOME_NET any (...)

2. Redefine HOME_NET and EXTERNAL_NET
   HOME_NET = Ubuntu
   EXTERNAL_NET = Kali

3. Restrict HOME_NET to 192.168.56.0/24

After applying Fix #1, the rule triggered successfully.

---

## Summary

- Suricata successfully detected Nmap ICMP anomalies
- Alerts were extracted from eve.json using jq
- A custom ICMP rule was written, loaded, tested, and validated
- Diagnosed HOME_NET / EXTERNAL_NET mismatch
- Completed full IDS workflow: scanning → alerting → custom rule creation → detection

---

## Files Included in This Lab

```text
/lab2/
├── README.md
├── local.rules
├── Suricata-IDS-Detection.pdf
└── Screenshots/
    ├── suricata_running.png
    ├── nmap_scan.png
    ├── nmap_ping.png
    ├── alert_output.png
    ├── custom_rule_alert.png
    ├── local_rules_before.png
    ├── local_rules_after.png
    ├── local_rule_added_to_config.png
    └── suricata_config_test.png
```
---
