# Cybersecurity Homelab Project

This repository contains a complete cybersecurity homelab built using VirtualBox, Kali Linux, Ubuntu Server, and Metasploitable 2.  
The project covers offensive and defensive security, including reconnaissance, IDS/IPS detection, web exploitation, SIEM monitoring, privilege escalation, an end-to-end incident timeline, and automated detection orchestration.

Each lab includes:
- A README documenting procedures and findings  
- Screenshots  
- PCAP/log files  
- A PDF final report  

This project is designed as a portfolio-oriented demonstration of practical cybersecurity skills.

---

## Lab Overview

### 1. Lab 1 — Reconnaissance and Traffic Analysis  
Folder: `/lab1/`  
Description: Conducted Nmap reconnaissance, tcpdump packet capture, and Wireshark traffic analysis to establish baseline network behavior.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab1

---

### 2. Lab 2 — Suricata IDS Detection  
Folder: `/lab2/`  
Description: Deployed Suricata IDS, detected active scanning activity, analyzed EVE JSON alerts, and validated custom detection rules.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab2

---

### 3. Lab 3 — DVWA Web Exploitation (SQLi, Command Injection, XSS, LFI, RFI, CSRF, File Upload RCE)
Folder: `/lab3/`  
Description: Performed full web exploitation against DVWA hosted on Metasploitable2. Executed SQL injection, command injection, reflected/stored XSS, file upload leading to remote code execution, Local/Remote File Inclusion, and CSRF password-change attack. Included explanations, lab walkthrough, mitigations, and security hardening recommendations.  
Link:   
https://github.com/minjintiger/HomeLab/tree/main/lab3

---

### 4. Lab 4 — Linux Privilege Escalation  
Folder: `/lab4/`  
Description: Performed user enumeration and multiple Linux privilege escalation techniques, including SUID/GUID abuse, PATH hijacking, cron exploitation, and kernel-level attacks, followed by post-exploitation documentation.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab4

---

### 5. Lab 5 — Wazuh SIEM Log Monitoring & Custom Correlation  
Folder: `/lab5/`  
Description: Deploy Wazuh Manager and Agent, collect SSH and system logs, detect Nmap scans, perform SSH brute-force attacks, and build a custom correlation rule to identify repeated authentication failures.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab5

---

### 6. Lab 6 — Splunk SIEM Detection (Suricata + SSH + Nmap/Hydra)  
Folder: `/lab6/`  
Description: Build a Splunk-based SIEM pipeline structured similarly to the detection workflow in Lab 5. Ingest Suricata alerts and SSH authentication logs, generate Nmap and Hydra attacks from Kali, write SPL searches to identify malicious activity, and build simple dashboards to visualize the events.      
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab6

---

### 7. Lab 7 — Incident Timeline (Capstone with Splunk)  
Folder: `/lab7/`  
Description: Correlated Suricata alerts, Splunk events, PCAPs, and attacker actions to reconstruct an end-to-end incident timeline and analytical narrative.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab7

---  

### 8. Automation — Security Orchestration  
Folder: `/automation/`  
Description: Automates the detection workflow from Labs 6 and 7 by orchestrating attack execution, Suricata telemetry collection, Splunk saved-search dispatch, evidence export, and automatic incident report generation in a single run.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/automation  

---  

## Environment Summary

- VirtualBox (Host OS varies by lab: Ubuntu Linux, Windows)  
- Kali Linux (Attacker)  
- Ubuntu Server (Target, IDS, SIEM, DVWA host)  
- Metasploitable 2 (Vulnerable web server)  
- Networking: Host-Only Adapter (isolated lab network)  
- `SPLUNK_TOKEN`: Splunk REST API authentication token used to dispatch saved searches and export detection results.  

---

## Repository Structure

README.md          - Project overview and lab index  
lab1–lab7/         - Individual lab folders with documentation  
automation/        - Security orchestration module  
LICENSE

---

## License

This project is licensed under the MIT License.
You may use or modify this work with proper attribution.

---

## Author

Minjin Kim  
Cybersecurity Homelab Project  
Focused on practical offensive, defensive, and detection oriented security engineering.
