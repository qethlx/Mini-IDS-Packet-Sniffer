# Mini IDS & Network Sniffer

A lightweight, Python-based Intrusion Detection System (IDS) and packet sniffer using `scapy`. This tool monitors network traffic in real-time to detect anomalous behavior (like SYN floods or aggressive port scans) and inspects unencrypted HTTP traffic for leaked credentials.

## Features
- **Anomaly Detection:** Tracks packets per second from source IPs and alerts on high-volume traffic (potential DoS or Port Scan).
- **Cleartext Credential Sniffing:** Inspects HTTP payloads (GET/POST) for common login parameters (e.g., `password=`, `pwd=`) sent without encryption.
- **Low Memory Footprint:** Processes packets on the fly (`store=False`) without hoarding system RAM.

## 🛠️ Installation & Usage

Running the Tool

Note: Packet sniffing requires elevated privileges. You must run this script as root (Linux/macOS) or Administrator (Windows).

# Basic usage (listens on default interface, threshold: 100 pkts/sec)
sudo python3 mini_ids.py

# Specify network interface and custom alert threshold (e.g., 50 pkts/sec)
sudo python3 mini_ids.py -i eth0 -t 50

# Show help menu
python3 mini_ids.py --help

### Prerequisites
You need to install the `scapy` library to capture network packets:
```bash
pip install scapy


