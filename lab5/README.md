# HomeLab 5 — Wazuh SIEM Log Monitoring & Custom Rule Correlation

This lab demonstrates endpoint log collection, attack detection, and custom correlation rule development using the Wazuh SIEM stack. The lab originally began as a DVWA web-attack detection project, but after extensive troubleshooting of Wazuh’s Apache log decoders and ingestion pipeline, the environment was re-scoped to focus on stable, reproducible SSH authentication and Nmap network-scan detections. This README documents **the entire process**, including the DVWA failure analysis, troubleshooting steps, and the final working detection pipeline.

---

## Lab Environment

VM              | Role                   | IP Address
--------------- | ---------------------- | -----------
Wazuh OVA       | Manager/Indexer/UI     | 192.168.56.103
Ubuntu Server   | Target (Agent)         | 192.168.56.101
Kali Linux      | Attacker               | 192.168.56.102

Network Mode: VirtualBox Host-Only  
Logs collected: `/var/log/auth.log`, `/var/log/syslog`

---

## Background — Why the Lab Shifted from DVWA to SSH/Nmap

This lab initially attempted to detect DVWA attacks through Apache logs. Multiple steps were attempted:

1. **Hydra brute-force on DVWA login**
   - Apache `access.log` showed the attempts.
   - Wazuh generated **zero alerts**.

2. **Custom DVWA web rules with `<decoded_as>web-accesslog</decoded_as>`**
   - `logtest` always returned **“No decoder matched.”**

3. **Plain-text matching fallback**
   - Matched in `logtest`.
   - Produced **no alerts** in live Wazuh pipelines.

4. **Verified log ingestion**
   - Archive index contained Hydra, Nmap, and HTTP entries.
   - Proved agent → manager transport worked.

5. **Found root cause**
   - Default group’s `agent.conf` was empty → logcollector override issues.
   - After fixing → DVWA logs still incompatible with Wazuh’s strict web decoder.

After confirming that Apache logs from DVWA would not decode reliably without rewriting Wazuh’s web-accesslog decoder, the lab direction was changed.

### Final Scope (stable and reproducible):
- SSH authentication failure detection  
- Custom correlation rule based on repeated SSH failure events  
- Nmap scan detection (sS, sV, -A)  
- Clean SIEM workflow with deterministic alerting  

This pivot reflects a real SIEM workflow:  
**investigate → identify ingestion failures → isolate reliable log types → redesign detection strategy.**

---

## Objectives

- Deploy Wazuh all-in-one
- Register Ubuntu agent and verify log ingestion
- Detect Nmap scans (sS, sV, -A)
- Detect SSH authentication failures
- Create correlation rule to detect brute-force attempts
- Validate detection with Hydra attack
- Document findings with screenshots

---

## Step 1 — Wazuh Deployment & Dashboard Access

The Wazuh all-in-one OVA was imported into VirtualBox.

**Screenshot:**  
`screenshots/dashboard_login.png`

---

## Step 2 — Wazuh Agent Installation & Registration

The Ubuntu Server agent was deployed and successfully connected to the Wazuh Manager.

**Screenshots:**  
`screenshots/agent_registration.png`  
`screenshots/agent_connected.png`

---

## Step 3 — Log Collection Setup

To ensure consistent ingestion, the following configuration was applied:

```xml
<agent_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
</agent_config>
```

These logs were confirmed to forward reliably, unlike DVWA/Apache logs.

---

## Step 4 — Nmap Scan Detection

### SYN Scan (`-sS`)

```bash
nmap -sS 192.168.56.101
```

**Screenshots:**  
`screenshots/nmap_sS.png`  
`screenshots/nmap_sS_detected.png`

---

### Version Scan (`-sV`)

```bash
nmap -sV 192.168.56.101
```

**Screenshots:**  
`screenshots/nmap_sV.png`  
`screenshots/nmap_sV_detected.png`

---

### Aggressive Scan (`-A`)

```bash
nmap -A 192.168.56.101
```

**Screenshots:**  
`screenshots/nmap_A.png`  
`screenshots/nmap_A_detected.png`

---

## Step 5 — SSH Authentication Failure Detection

A single invalid login attempt confirmed that SSH logs were parsed correctly by Wazuh.

**Screenshot:**  
`screenshots/ssh_attempt.png`

Wazuh fired rule **5760**, the built-in SSH authentication failure rule.

---

## Step 6 — Custom Correlation Rule (SSH Brute Force)

Goal:  
**Trigger a high-severity alert when the same source IP causes ≥3 SSH failures within 60 seconds.**

### `local_rules.xml` (Final Version)

```xml
<group name="custom-ssh-bruteforce,">

  <rule id="100990" level="8">
    <if_sid>5760</if_sid>
    <description>SSH: Failed login (wrapped SID 5760).</description>
    <group>ssh,authentication_failed,</group>
    <mitre><id>T1110</id></mitre>
  </rule>

  <rule id="100991" level="12" frequency="3" timeframe="60">
    <if_matched_sid>100990</if_matched_sid>
    <same_srcip/>
    <description>SSH: Brute-force suspected (≥3 wrapped 5760 events from same IP in 60s).</description>
    <group>ssh,authentication_failures,bruteforce,</group>
    <mitre><id>T1110</id></mitre>
  </rule>

</group>
```

---

## Step 7 — Brute-Force Validation (Hydra)

Hydra brute-force attempt:

```bash
hydra -l lab -P smalllist.txt ssh://192.168.56.101
```

**Expected rule chain:**

1. 5760 — SSH authentication failure  
2. 100990 — Wrapped failure event  
3. 100991 — Custom brute-force detection  

**Screenshots:**  
`screenshots/custom_rule_brute_force_tested.png`  
`screenshots/custom_rule_ssh.png`

---

## Step 8 — Detection Summary

Category                          | Result
--------------------------------- | ---------------------------------
SSH Failed Login Detection        | Working (Rule 5760)
SSH Brute-Force Correlation       | Working (Rules 100990 + 100991)
Nmap Scans (`sS`, `sV`, `-A`)     | Working (network + web-accesslog rules)
Log Ingestion (syslog/auth.log)   | Stable and consistent
DVWA Web Attack Detection         | Not viable due to decoder mismatch

---

## Hardening Recommendations

- Enforce SSH key-based authentication  
- Apply Fail2Ban or UFW rate-limits  
- Disable unused services (e.g., Apache if unnecessary)  
- Patch and update regularly  
- Centralize logs and implement retention policies  
- Use network segmentation in real-world environments  

---

## Files Included in This Lab

```text
/lab5/
├── README.md
└── screenshots/
    ├── dashboard_login.png
    ├── agent_registration.png
    ├── agent_connected.png
    ├── nmap_sS.png
    ├── nmap_sS_detected.png
    ├── nmap_sV.png
    ├── nmap_sV_detected.png
    ├── nmap_A.png
    ├── nmap_A_detected.png
    ├── ssh_attempt.png
    ├── custom_rule_brute_force_tested.png
    └── custom_rule_ssh.png
```

---

This completes **HomeLab 5 — Wazuh SIEM Log Monitoring & Custom Rule Correlation**, including the DVWA troubleshooting path, decoder analysis, and the final stable SSH + Nmap detection workflow.
```
