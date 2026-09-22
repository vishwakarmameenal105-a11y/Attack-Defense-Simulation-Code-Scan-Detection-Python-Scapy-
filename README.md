# Attack-Defense Simulation: Port Scan Detection

## Overview
A purple team simulation that demonstrates both the attacker and defender sides of a port scan. Written in Python with Scapy, this project shows how a SYN scan works and how defenders can detect it in real time.

## What It Does
- **Attacker script (`src/port_scanner.py`)**: Simulates a SYN port scan against ports 1-100 on a target IP. Sends crafted TCP SYN packets and classifies each port as open, closed, or filtered based on the response.
- **Detector script (`src/detector.py`)**: Sniffs live network traffic and detects port scan attempts by counting SYN packets from the same source IP within a time window.

## Attack Logic (`src/port_scanner.py`)
The scanner crafts a SYN packet using Scapy's `IP()/TCP()` layer stacking. For each port (1-100), it sends a SYN and waits for a response. A SYN-ACK reply means the port is open. A RST reply means closed. No response within the timeout means filtered by a firewall.

## Detection Logic (`src/detector.py`)
The detector sniffs TCP packets and filters for those with the SYN flag set. It records the timestamp of each SYN per source IP, then removes timestamps older than the time window (5 seconds). If a source sends 20 or more SYNs within that window, it fires an alert and logs it.

## How to Run

### Terminal 1 - Start the detector

sudo python3 src/detector.py

### Terminal 2 - Run the scan

sudo python3 src/port_scanner.py 127.0.0.1

## Results

### Setup

![Setup](screenshots/01_setup.png)

### Scan Output

![Scan Output](screenshots/02_output.png)

### Detection Alert

![Detection Alert](screenshots/03_findings.png)

### Log Files

Alerts were written to `logs/alerts.log` and scan results to `logs/scan_results.log`.

## Finding
During testing, the scanner targeted 127.0.0.1, but the detector logged the source as 10.0.1.162 - the container's actual interface IP. This is expected Linux loopback behavior. In production, the detector would identify attacker IPs accurately regardless of loopback rewriting.

## Purple Team Insight
Writing both sides showed me why detection is hard. Attackers can send hundreds of packets fast. Defenders have to spot the pattern in real time without flooding themselves with false alerts. This project made both perspectives concrete.

## Files
- `src/port_scanner.py` - attacker script
- `src/detector.py` - detection script
- `logs/` - generated logs
- `screenshots/` - visual proof

## Built With
Python, Scapy

## Author
Meenal Vishwakarma | 2026
