# One-Click Security Orchestration (Homelab Automation)

This project implements a one-click security orchestration pipeline on a local homelab.

A single command from the host machine:
- triggers an attack simulation,
- collects host-based and network-based telemetry,
- executes a predefined Splunk detection (saved search),
- exports detection results,
- and automatically generates incident evidence and a response report.

The goal is not to simulate a “perfect SOC”, but to demonstrate end-to-end detection automation, evidence handling, and reproducibility.

---

## Environment Overview

Host:
- Windows desktop (controller)
- Python-based orchestration (run.py)

Virtual Machines (Host-only network):
- Kali Linux
  - Role: attack simulation
- Ubuntu Server
  - Role: Suricata IDS + Splunk
  - Logs:
    - /var/log/suricata/eve.json
    - /var/log/auth.log

All VMs are isolated in a host-only network.
No external connectivity is required.

---

## What This Automation Does

Running the orchestration script performs the following steps:

1. Attack execution (Kali)
   - Executes a predefined attack command (Nmap scan)
   - Captures stdout/stderr as evidence

2. Telemetry collection (Ubuntu)
   - Collects Suricata EVE JSON entries related to the attack
   - Gathers relevant host and network context

3. Detection via Splunk
   - Dispatches an existing Splunk saved search
   - The saved search correlates:
     - Suricata IDS alerts
     - SSH authentication failures
   - Detection results are exported as CSV via the Splunk REST API

4. Evidence packaging
   - All artifacts are stored in a timestamped evidence directory

5. Automatic report generation
   - A markdown incident response report is rendered using a Jinja2 template
   - The report references the generated evidence

All steps above are executed automatically with a single command.

---

## Splunk Design Note

The detection logic is implemented as a Splunk saved search created earlier during the SIEM lab.

Because the saved search is App-shared, it must be accessed through the Splunk REST API using the `nobody` namespace:

/servicesNS/nobody/search/saved/searches/<saved_search_name>/dispatch

This behavior is intentional and reflects how Splunk handles app-level knowledge objects.

---

## Evidence Handling

This repository includes anonymized sample evidence only.

Actual runtime artifacts (tokens, internal IPs, timestamps, execution logs) are excluded by design.

Included sample evidence:

lab7/evidence/sample_run/
- attack_command_sample.txt
- kali_attack_stdout_sample.txt
- ubuntu_eve_tail_sample.json
- splunk_alerts_sample.csv
- incident_response_Report_sample.md

All identifiers are masked while preserving structure and format to maintain technical realism.

---

## What This Project Demonstrates

- Automated attack-to-detection workflow
- Integration of IDS (Suricata) and SIEM (Splunk)
- Programmatic use of the Splunk REST API
- Evidence generation and handling discipline
- Reproducible security automation in a controlled environment

This project is intentionally scoped to remain small, controlled, and explainable.

---

## Reproducibility

The full pipeline can be reproduced locally by:
1. Deploying the same VM layout
2. Creating the required Splunk saved search
3. Providing a valid Splunk token via environment variable
4. Running run.py from the host system

Configuration files containing real environment details are intentionally excluded from version control.

---

## Notes

- Sample evidence is anonymized.
- Host-only networking was used, but data minimization was still applied.
- This automation builds on earlier homelab IDS and SIEM labs and focuses on orchestration rather than tooling breadth.
