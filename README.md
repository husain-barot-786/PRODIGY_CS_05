# PRODIGY_CS_05
A simple network packet sniffer that captures and analyses packets using Python and Scapy, displaying IPs, protocols, ports, and payload.

# Network Packet Analyzer

## Description

This project is a simple network packet analyser developed using Python and Scapy. It captures and analyses network packets in real time, displaying key information such as source and destination IPs, protocol, protocol types, source and destination ports, and payload data. It is useful for understanding basic network traffic and packet structures.

## Features

- Real-time packet capturing
- Extracts and displays:
  - Source and Destination IP addresses
  - Protocol type (TCP, UDP, ICMP)
  - Source and Destination Port numbers (if applicable)
  - Raw payload data
- Graceful shutdown with `Ctrl + C`

## Requirements

- Python 3.x
- Scapy library
  
  ```bash
  pip install scapy
  ```

> Note: On Windows, Npcap must be installed for Scapy to function correctly.

## How to use

1. Save the Python script as `packet_sniffer.py`.
2. Open a terminal or command prompt.
3. Navigate to the script directory:
```bash
cd path_to_your_file
```
4. Run the script:
```bash
python packet_sniffer.py
```
5. Observe real-time network traffic details in the terminal.

## Files

- `packet_sniffer.py` – Main Python script
- `README.md` – Project documentation

## Disclaimer

Use this tool responsibly and only on networks you have permission to monitor. This project is for learning and internal testing purposes only.

---
