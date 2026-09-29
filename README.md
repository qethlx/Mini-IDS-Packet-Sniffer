# Mini IDS & Network Sniffer

A lightweight, Python-based Intrusion Detection System (IDS) and packet sniffer using `scapy`. This tool monitors network traffic in real-time to detect anomalous behavior (like SYN floods or aggressive port scans) and inspects unencrypted HTTP traffic for leaked credentials.

## Features
- **Anomaly Detection:** Tracks packets per second from source IPs and alerts on high-volume traffic (potential DoS or Port Scan).
- **Cleartext Credential Sniffing:** Inspects HTTP payloads (GET/POST) for common login parameters (e.g., `password=`, `pwd=`) sent without encryption.
- **Low Memory Footprint:** Processes packets on the fly (`store=False`) without hoarding system RAM.

## 🛠️ Installation & Usage

### Prerequisites
You need to install the `scapy` library to capture network packets:
```bash
pip install scapy
