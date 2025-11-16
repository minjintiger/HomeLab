# HomeLab 2 — Suricata IDS Detection (Nmap, eve.json, Custom Rules)

This lab demonstrates intrusion detection using Suricata IDS. I performed Nmap scans from Kali, analyzed alerts in eve.json, and created a custom Suricata rule to detect ICMP traffic. This lab builds directly on Lab 1 by showing how real scan traffic appears inside an IDS.

---

## Lab Environment

|        VM        |    Role    |   IP Address   |
|------------------|------------|----------------|
| Kali Linux       | Attacker   | 192.168.56.101 |
| Ubuntu Server    | IDS Target | 192.168.56.102 |
| Metasploitable 2 | Not used   | 192.168.56.103 |

Network Mode: VirtualBox Host-Only  
Suricata Interface: enp0s3  
Log File: /var/log/suricata/eve.json

---

## Objectives

- Verify Suricata installation and rule loading  
- Perform Nmap scans to generate IDS alerts  
- Extract alert logs from eve.json using jq  
- Understand Suricata alert fields (signature, flow, src/dest IPs)  
- Create & test a custom ICMP detection rule  
- Troubleshoot HOME_NET / EXTERNAL_NET mismatches  

---

## Step 1 — Verify Suricata Installation

Command:
sudo systemctl status suricata

Expected:
- Engine started  
- Threads created  
- No fatal errors  

Screenshot saved as: suricata_running.png

---

## Step 2 — Perform Nmap Scans from Kali

Aggressive + OS detection + NSE scripts:
nmap -sS -sV -A 192.168.56.102

Summary of results:
- Target responds to host discovery  
- Multiple ICMP and TCP probes sent  
- Ubuntu server has no open ports (RST responses)  
- Suricata detects ICMP anomalies and Nmap behavior  

Screenshot saved as: nmap_scan.png

---

## Step 3 — Extract Suricata Alerts from eve.json

Extract alert-only entries:
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 20

Example alert fields:
- event_type: "alert"  
- src_ip: 192.168.56.101 (Kali)  
- dest_ip: 192.168.56.102 (Suricata host)  
- proto: "ICMP"  
- signature: "SURICATA ICMPv4 unknown code"  

Suricata logs both:
- direction: "to_server"  
- direction: "to_client"  

Screenshot saved as: alert_output.png

---

## Step 4 — Create a Custom Suricata Rule

Rule created in local.rules:

alert icmp any any -> any any (msg:"LOCAL ICMP Ping TEST"; sid:1000001; rev:2;)

Saved in:
/var/lib/suricata/rules/local.rules

Test the Suricata configuration:
sudo suricata -T -c /etc/suricata/suricata.yaml -v

Expected:
Configuration provided was successfully loaded.

Screenshots:
- local_rule.png  
- suricata_config_test.png

---

## Step 5 — Trigger the Custom Rule

From Kali:
ping -c 4 192.168.56.102

Extract alerts:
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 20

Expected:
- signature: "LOCAL ICMP Ping TEST"  
- src_ip: Kali  
- dest_ip: Suricata  

Screenshot saved as: custom_rule_alert.png

---

## Troubleshooting — Why My First Rule Didn’t Fire

Original rule:
alert icmp $EXTERNAL_NET any -> $HOME_NET any (...)

Issue:
Suricata’s default HOME_NET was extremely broad:

HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET: "!$HOME_NET"

Because 192.168.56.0/24 is inside 192.168.0.0/16:
- Kali (192.168.56.101) → HOME_NET  
- Ubuntu (192.168.56.102) → HOME_NET  

Therefore:
- Traffic was HOME_NET → HOME_NET  
- My rule required EXTERNAL_NET → HOME_NET  
- So the rule could never match  

---

### Three Correct Fixes Considered

1. **Simplify the rule (chosen)**  
   alert icmp any any -> any any (...)

2. **Redefine HOME_NET and EXTERNAL_NET**  
   HOME_NET: "[192.168.56.102]"  
   EXTERNAL_NET: "[192.168.56.101]"   

3. **Restrict HOME_NET to the VM subnet**  
   192.168.0.0/16 → 192.168.56.0/24  

After applying Fix #1, the custom ICMP rule triggered successfully.

---

## Files Included in This Lab

/lab2-suricata/
├── README.md
├── local.rules
├── Suricata-IDS-Detection.pdf
└── images/
    ├── suricata_running.png
    ├── nmap_scan.png
    ├── alert_output.png
    ├── local_rule.png
    ├── suricata_config_test.png
    ├── custom_rule_alert.png

---

## Summary

- Suricata detected ICMP-based anomalies triggered by Nmap  
- Extracted alerts from eve.json using jq  
- Wrote, tested, and validated a custom ICMP rule  
- Diagnosed HOME_NET / EXTERNAL_NET issues  
- Completed the full IDS workflow: scan → detection → rule creation → alert  
