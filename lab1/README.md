# HomeLab 1 — Recon and Traffic Analysis (Nmap, tcpdump, Wireshark)

This lab demonstrates network reconnaissance using Nmap, packet capture with tcpdump, and packet analysis using Wireshark. The goal is to understand how scan traffic appears on the network before deploying Suricata IDS in Lab 2.

---

## Lab Environment

|        VM        |   Role   |   IP Address   |
|------------------|----------|----------------|
| Kali Linux       | Attacker | 192.168.56.101 |
| Ubuntu Server    |  Target  | 192.168.56.102 |
| Metasploitable 2 | Not used | 192.168.56.103 |

Network Mode: VirtualBox Host-Only, NAT  
Monitored Interface: `enp0s3`

---

## Objectives

- Perform reconnaissance using Nmap  
- Capture network packets with tcpdump  
- Analyze packet behavior in Wireshark  
- Understand SYN, ICMP, and service probe behavior  

---

## Step 1 — Identify Network Interface

Command:
ip a

Interface used:
enp0s3

---

## Step 2 — Start Packet Capture (tcpdump)

Command:
sudo tcpdump -i enp0s3 -w nmap_scan.pcap

After stopping with Ctrl+C:
- 14089 packets captured  
- 0 dropped  
- PCAP saved as nmap_scan.pcap

---

## Step 3 — Perform Nmap Scans from Kali

Basic scan:
sudo nmap 192.168.56.102

Service version detection:
sudo nmap -sV 192.168.56.102

OS detection:
sudo nmap -O 192.168.56.102

Aggressive scan:
sudo nmap -A 192.168.56.102

Summary of results:
- Host is reachable  
- All scanned ports are closed (RST responses)  
- No SSH or HTTP banners returned  
- OS detection was inconclusive (expected for minimal Ubuntu Server)

---

## Step 4 — Wireshark Analysis

### SYN Packet Filter
Filter:
tcp.flags.syn == 1 and tcp.flags.ack == 0

Meaning:
Pure SYN packets initiating TCP connections. Shows Nmap probing multiple ports.

---

### SSH/HTTP Probe Filter
Filter:
tcp contains "SSH" or tcp contains "HTTP"

Result: No packets found.

Explanation:
Even though Nmap attempted to probe ports 22 and 80, the server had no open services. Without a completed TCP handshake, no SSH or HTTP payloads were exchanged.

---

### ICMP Host Discovery
Filter:
icmp.type == 8

Meaning:
ICMP Echo Requests used by Nmap to determine host availability. Wireshark also shows the matching Echo Replies.

---

### Strict SYN Flag Filter
Filter:
tcp.flags == 0x002

Meaning:
Shows packets where the TCP flag byte equals exactly SYN (0x02). Matches the same packets as the first filter because the target had no open ports.

---

## Packet Behavior Summary

- Nmap sends SYN packets to many ports on the target  
- The Ubuntu Server responds with RST packets because all ports are closed  
- No SYN/ACK packets appear because no services are running  
- ICMP Echo traffic confirms host availability  
- No application-layer data (SSH/HTTP) appears because no TCP handshake succeeded  

---

## Files Included in This Lab

```text
/lab1/
├── README.md
├── nmap_scan.pcap
├── Recom & Traffic Analysis.pdf
└── Screenshots/
    ├── 14089_packets_captured.png
    ├── icmp_echo.png
    ├── no_http_ssh.png
    ├── syn_packets.png
    └── tcp_flags_0x02.png




