# HomeLab 6 — Splunk SIEM Log Monitoring & Detection Workflow

This lab builds a Splunk-based SIEM detection pipeline structured identically to the workflow used in HomeLab 5. The primary difference is the SIEM platform: instead of Wazuh, Splunk Enterprise is used to ingest logs, perform searches, correlate events, and visualize security activity.

The lab focuses on stable and reproducible detections using Suricata network IDS alerts and Linux SSH authentication logs. Malicious activity is generated from a Kali Linux attacker using Nmap (network reconnaissance) and Hydra (SSH brute-force). All detections and correlations are implemented using SPL searches and simple dashboards in Splunk.

---

## Lab Environment

VM              | Role                          | IP Address
--------------- | ----------------------------- | -----------
Ubuntu Server   | Target / Suricata / Splunk    | 192.168.56.101
Kali Linux      | Attacker                      | 192.168.56.102

Network: VirtualBox Host-Only  
SIEM Platform: Splunk Enterprise  
Logs collected:
- /var/log/suricata/eve.json
- /var/log/auth.log

---

## Objectives

- Ingest Suricata IDS alerts into Splunk
- Ingest SSH authentication logs into Splunk
- Generate Nmap network scans from Kali
- Generate SSH brute-force attempts using Hydra
- Detect malicious activity using SPL searches
- Correlate network and host-based logs by attacker IP
- Build dashboards to visualize the detection workflow

---

## Step 1 — Suricata Log Ingestion

Suricata was configured on the Ubuntu server to write JSON-formatted events to /var/log/suricata/eve.json. This file was ingested into Splunk with index=main and sourcetype=suricata:json.

Verification search:

index=main sourcetype="suricata:json" | head 20

This confirmed that Suricata events were successfully indexed and searchable.

---

## Step 2 — SSH Authentication Log Ingestion

Linux SSH authentication logs were ingested from /var/log/auth.log using sourcetype=linux_secure and index=main.

Verification search:

index=main sourcetype="linux_secure" | head 20

SSH and system authentication events were immediately visible.

---

## Step 3 — Nmap Network Scan Attack

From the Kali attacker, a SYN scan with service and OS detection was executed:

nmap -sS -sV -O 192.168.56.101

This generated reconnaissance traffic inspected by Suricata.

---

## Step 4 — Nmap Scan Detection (Suricata)

Suricata alerts related to scanning activity were identified using:

index=main sourcetype="suricata:json" event_type=alert
| stats count by alert.signature, src_ip, dest_ip
| sort -count

Scan-related signatures such as “ET SCAN Possible Nmap User-Agent Observed” were consistently triggered.

---

## Step 5 — SSH Brute-Force Attack Setup

A dedicated test user was created on the Ubuntu server:

sudo adduser hydrauser

From Kali, Hydra was used to perform repeated SSH login attempts:

hydra -l hydrauser -P smalllist.txt ssh://192.168.56.101 -t 4 -V

This produced a large number of failed authentication attempts.

---

## Step 6 — SSH Brute-Force Detection

SSH authentication failures were detected using:

index=main sourcetype="linux_secure" "Failed password for"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, user
| sort -count

The attacker IP and target users were clearly identified.

---

## Step 7 — Cross-Source Correlation

To mirror the correlation logic used in HomeLab 5, Suricata alerts and SSH authentication failures were correlated by source IP:

(index=main sourcetype="suricata:json" event_type=alert)
OR
(index=main sourcetype="linux_secure" "Failed password for")
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by sourcetype, src_ip

This confirmed that the same attacker IP appeared in both network IDS alerts and host authentication logs.

---

## Step 8 — Splunk Dashboard

A Splunk dashboard was created to visualize the detection workflow:
- Suricata Alerts (Top Signatures)
- Nmap / Scan Activity
- SSH Failed Logins
- Correlation by Source IP

The dashboard structure mirrors HomeLab 5, replacing Wazuh rules with SPL searches.

---

## Detection Summary

Category                     | Result
---------------------------- | -------------------------------
Suricata alert ingestion     | Working
Nmap scan detection          | Working
SSH authentication logging   | Working
SSH brute-force detection    | Working
Cross-log correlation        | Working
Dashboard visualization      | Working

---

## Key Takeaways

- Combining network IDS alerts with host authentication logs provides strong attacker visibility.
- Field extraction is essential when correlating heterogeneous log sources.
- Splunk SPL enables flexible detection without custom decoders.
- The detection workflow remains consistent across SIEM platforms.

---

## Hardening Suggestions

- Enforce SSH key-based authentication
- Apply rate limiting or Fail2Ban for SSH
- Restrict exposed services via firewall rules
- Alert on scan signatures automatically
- Segment networks in real deployments

---

## Files Included in This Lab

```
/lab6/
├── README.md
├── smalllist.txt
├── Splunk SIEM Log Monitoring & Detection Workflow.pdf
└── screenshots/
    ├── lab6-01-suricata-ingest.png
    ├── lab6-02-authlog-ingest.png
    ├── lab6-03-kali-nmap-attack.png
    ├── lab6-04-nmap-detection.png
    ├── lab6-05-adding-hydrauser.png
    ├── lab6-06-brute-force-hydrauser.png
    ├── lab6-07-ssh-bruteforce.png
    ├── lab6-08-correlation.png
    └── lab6-09-dashboard.png
```

