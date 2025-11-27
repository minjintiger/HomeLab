# HomeLab 5 — Wazuh SIEM Log Monitoring & Custom Rule Correlation

This lab demonstrates endpoint log collection, attack detection, and custom correlation rule development using the Wazuh SIEM stack. The lab originally began as a DVWA web-attack detection project, but after extensive troubleshooting of Wazuh’s Apache log decoders and ingestion pipeline, the environment was re-scoped to focus on stable, reproducible SSH authentication and Nmap network-scan detections. This README documents **the entire process**, including the DVWA failure analysis, troubleshooting steps, and the final working detection pipeline.

---

## Lab Environment

VM              | Role                   | IP Address
--------------- | ---------------------- | -----------
Wazuh OVA       | Manager/Indexer/UI     | 192.168.56.103
Ubuntu Server   | Target (Agent)         | 192.168.56.101
Kali Linux      | Attacker               | 192.168.56.102

Network: VirtualBox Host-Only, NAT  
Logs collected: `/var/log/auth.log`, `/var/log/syslog`

---

## Background — Started with DVWA, but switched to SSH/Nmap

The original plan was simple:  
**detect Apache/DVWA attacks in Wazuh.**  
But nothing worked correctly after multiple attempts.

### What I tried:

1. **Hydra brute-force on DVWA login**  
   - Apache `access.log` showed every request.  
   - Wazuh showed **no alerts at all**.

2. **Tried custom DVWA rules with `<decoded_as>web-accesslog</decoded_as>`**  
   - `wazuh-logtest` → **“No decoder matched.”**

3. **Tried plain text matching rules**  
   - Matching worked inside `logtest`.  
   - Never produced alerts in `alerts.json`.

4. **Checked if logs were at least arriving**  
   - The archive index *did* show Hydra, Nmap, and DVWA HTTP requests.  
   - So the agent was sending logs but Wazuh was ignoring them.

5. **Found the issue**  
   - Default group’s `agent.conf` was blank → causing overrides.  
   - Even after fixing it, DVWA logs still didn’t match the strict Wazuh web decoder.

At that point, continuing DVWA detection required rewriting Wazuh’s Apache decoder.  
This was outside the scope of the homelab.

### Final decision:
Move the lab to **SSH + system logs + Nmap**, which worked perfectly and gave reliable, clean detections.

This ended up being more realistic anyway:  
figure out ingestion issues → identify stable logs → build detections on top of what works.

---

## Objectives

- Register and verify Wazuh agent
- Collect SSH + system logs
- Detect Nmap scans (sS, sV, -A)
- Detect SSH failed logins
- Build custom brute-force correlation rule
- Validate detection using Hydra
- Document everything

---

## Step 1 — Wazuh Deployment

The Wazuh OVA was imported and the dashboard was accessible.

**Screenshot:**  
`screenshots/dashboard_login.png`

---

## Step 2 — Agent Registration

The Ubuntu agent connected to the Wazuh manager and began sending logs.

**Screenshots:**  
`screenshots/agent_registration.png`  
`screenshots/agent_connected.png`

---

## Step 3 — Log Collection Setup

I set the agent to collect only the logs I actually needed:

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

SSH failures and system events were immediately ingested with no issues.

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

All three Nmap scans triggered alerts consistently.

---

## Step 5 — SSH Authentication Failure

A single failed SSH login triggered the built-in SSH failure rule (SID 5760).

**Screenshot:**  
`screenshots/ssh_attempt.png`

---

## Step 6 — Custom SSH Correlation Rule

I built a correlation rule that fires when the same IP fails SSH login 3 times in 60 seconds.

### local_rules.xml

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

```bash
hydra -l lab -P smalllist.txt ssh://192.168.56.101
```

Firing order was exactly as expected:

1. 5760 — SSH authentication failure  
2. 100990 — wrapped event  
3. 100991 — custom brute-force correlation alert  

**Screenshots:**  
`screenshots/custom_rule_brute_force_tested.png`  
`screenshots/custom_rule_ssh.png`

---

## Detection Summary

Category                     | Result
---------------------------- | -------------------------------
SSH failure detection        | Working (Rule 5760)
Custom brute-force rule      | Working (100990 + 100991)
Nmap scans (sS, sV, -A)      | Working
Log ingestion                | Stable
DVWA detection               | Failed due to decoder mismatch

---

## Hardening Suggestions

- Switch SSH to key-only authentication  
- Add Fail2Ban or UFW throttling  
- Remove Apache if unused  
- Patch regularly  
- Centralize log retention  
- Segment networks in real deployments  

---

## Files Included in This Lab

```text
/lab5/
├── README.md
├── Wazuh SIEM (Centralized Logging, Detection, and Alerting).pdf
├── local.rules.xml
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

This completes **HomeLab 5 — Wazuh SIEM Log Monitoring & Custom Rule Correlation**.  
This lab includes the full DVWA attempt, the troubleshooting steps, and the final working SSH + Nmap detection setup.
```
