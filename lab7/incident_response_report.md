# HomeLab 7 — Incident Timeline Capstone (Splunk)

## 1. Incident Overview

This lab represents the capstone investigation of the HomeLab series.  
The objective is not to build new detections or ingest additional data, but to determine whether previously detected events can be reconstructed into a **single coherent security incident** and analyzed from a SOC analyst’s perspective.

Using Splunk as the SIEM platform, I investigated an external intrusion attempt composed of network reconnaissance followed by an SSH brute-force attempt. The analysis focuses on **time correlation, attacker intent, and outcome**, rather than individual alerts.

---

## 2. Scope and Time Window

To avoid over-correlation and false assumptions, the investigation scope was strictly limited to:

- A single attacker source IP
- A single target host (Ubuntu Server)
- A continuous time window during which the attack activity occurred
- Two validated data sources:
  - Suricata IDS alerts
  - Linux SSH authentication logs

Only events falling within this defined scope were considered part of the incident.

---

## 3. Evidence Sources

The following data sources were used to reconstruct the incident:

- **Suricata IDS**  
  Network-based alerts indicating reconnaissance and scan activity.
- **SSH Authentication Logs**  
  Host-level logs showing repeated failed login attempts.
- **Splunk SIEM**  
  Centralized platform used to correlate events across sources and time.

Each data source alone provides limited context. The incident determination relies on correlation across all three.

---

## 4. Timeline Reconstruction

The incident was reconstructed by ordering events chronologically across data sources.

### T1 — Reconnaissance Activity
Suricata alerts indicate scanning behavior originating from the attacker IP.  
The alerts are consistent with automated reconnaissance tools and occur before any authentication activity.

At this stage, the activity is classified as reconnaissance rather than exploitation.

---

### T2 — Service Targeting
Subsequent Suricata alerts show repeated interaction with the SSH service.  
This narrows attacker intent from general scanning to a specific attack surface.

The attacker has identified SSH as the likely entry point.

---

### T3 — Authentication Abuse Attempt
Shortly after reconnaissance, SSH authentication logs show repeated failed login attempts from the same source IP.  
The frequency and consistency of failures indicate automated brute-force behavior rather than manual login attempts.

This represents a clear transition from reconnaissance to exploitation.

---

### T4 — Attack Termination
No successful authentication events were observed.  
After repeated failures, attacker activity stopped.

There is no evidence of system compromise, privilege escalation, or lateral movement.

---

## 5. Correlation Analysis

Correlation across Suricata and SSH logs confirms:

- A single attacker source IP
- A logical progression of attacker behavior
- A time-aligned sequence:  
  **Reconnaissance → Service targeting → Brute-force attempt**

Neither Suricata alerts nor SSH logs alone are sufficient to classify this activity as an incident.  
Only correlation across data sources supports identifying this as a single intrusion attempt.

---

## 6. Analyst Assessment

From a SOC analyst perspective, this activity is classified as:

- **Incident Type:** External intrusion attempt  
- **Severity:** Low to Moderate  
- **Outcome:** Unsuccessful (no compromise)

Although the attack failed, attacker intent is clear. The activity progressed beyond passive scanning into active exploitation attempts. This incident demonstrates how reconnaissance can escalate if not properly monitored and mitigated.

---

## 7. Mitigations and Recommendations

Based on the observed activity, the following mitigations are recommended:

- **Reconnaissance Mitigation:**  
  Firewall rate limiting and scan detection rules.
- **Brute-force Mitigation:**  
  SSH key-based authentication and tools such as Fail2Ban.
- **Detection Improvement:**  
  Correlation-based alerts combining network and host logs.
- **Response Automation:**  
  Temporary IP blocking after repeated authentication failures.

Each recommendation directly addresses behavior observed in this incident.

---

## 8. Conclusion

This capstone demonstrates the importance of **incident-centric analysis** over isolated alert review.  
While no compromise occurred, the investigation confirms a real intrusion attempt with a clear attack chain and intent.

By correlating multiple detections into a single timeline, this lab reflects how a SOC analyst evaluates, scopes, and concludes an incident. This fulfills the original capstone objective: analyzing security events as incidents rather than standalone detections.

---

## 9. Appendix — Lab 6 Reference

This investigation builds on the Splunk ingestion, detection, and correlation pipeline validated in Lab 6.  
Lab 6 demonstrated that Suricata alerts and SSH authentication logs could be reliably ingested, queried, and visualized in Splunk. Lab 7 focuses exclusively on **incident reconstruction and analyst-level assessment** using that validated pipeline.
