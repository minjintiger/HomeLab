# HomeLab
HomeLab project for Cybersecurity

# Cybersecurity Homelab Project

This repository contains a complete cybersecurity homelab built using VirtualBox, Kali Linux, Ubuntu Server, and Metasploitable 2.  
The project covers offensive and defensive security, including reconnaissance, IDS/IPS detection, web exploitation, SIEM monitoring, privilege escalation, and an end-to-end incident timeline.

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
Description: Nmap scanning, tcpdump packet capture, Wireshark filtering, baseline traffic analysis.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab1

---

### 2. Lab 2 — Suricata IDS Detection  
Folder: `/lab2/`  
Description: Install Suricata, enable AF_PACKET monitoring, detect Nmap activity, analyze EVE JSON logs, create custom rules.  
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
Description: User enumeration, SUID/GUID abuse, PATH hijacking, cron exploitation, kernel-level privilege escalation, post-exploitation documentation.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab4

---

### 5. Lab 5 — Wazuh SIEM Log Monitoring & Custom Correlation  
Folder: /lab5/  
Description: Deploy Wazuh Manager and Agent, collect SSH and system logs, detect Nmap scans, perform SSH brute-force attacks, and build a custom correlation rule to identify repeated authentication failures.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab5

---

### 6. Lab 6 — Incident Timeline (Capstone Project)  
Folder: `/lab6/`  
Description: Combine Suricata logs, Wazuh events, PCAP data, and system logs to build a complete end-to-end attack timeline.  
Link:  
https://github.com/minjintiger/HomeLab/tree/main/lab6

---

## Environment Summary

- VirtualBox (Host: Ubuntu Linux)
- Kali Linux (Attacker)
- Ubuntu Server (Target, IDS, SIEM, DVWA host)
- Metasploitable 2 (Vulnerable web server)
- Networking: Host-Only Adapter (isolated lab network)

---

## Repository Structure

README.md 
LICENSE

---

## License

This project is licensed under the MIT License.
You may use or modify this work with proper attribution.

---

## Author

Minjin Kim  
Cybersecurity Homelab Project  
Focused on practical offensive and defensive security.

