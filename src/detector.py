# This module monitors network traffic And detects ports scan attempts

# This is the defense side of Purple Team simulation

# imports - Scapy for packet sniffing, Time for time stamps, Collections for counting

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# contansts - Threshold for alert, time window

SYN_THRESHOLD = 20        # How many SYNs trigger an alert
TIME_WINDOW = 5           # Seconds in the window
# State — track SYN timestamps per source IP
syn_tracker = defaultdict(list)
# Alert log file
ALERT_FILE = "logs/alerts.log"

# A function to process each captured packet and detect scan attempt

def process_packet(packet):
    # Only process TCP packets (we care about SYN flags)
    if not packet.haslayer(TCP):
        return
    # Check if the SYN flag is set (start of a connection attempt)
    if packet[TCP].flags != "S":
        return
    # Get the source IP of the packet
    src_ip = packet[IP].src
    # Record current time and add to tracker
    now = time.time()
    syn_tracker[src_ip].append(now)
    # Remove timestamps older than the time window
    syn_tracker[src_ip] = [
        t for t in syn_tracker[src_ip] if now - t <= TIME_WINDOW
    ]
    # Check if the count exceeds the threshold
    if len(syn_tracker[src_ip]) >= SYN_THRESHOLD:
        alert = f"[ALERT] Port scan detected from {src_ip} — {len(syn_tracker[src_ip])} SYNs in {TIME_WINDOW}s"
        print(alert)
        # Write alert to the log file
        with open(ALERT_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} — {alert}\n")
        # Reset tracker for this IP so we don't spam alerts
        syn_tracker[src_ip] = []

# A function to run the sniffer and start detection

def start_detector():
    print("[*] Starting port scan detector...")
    print(f"    Threshold: {SYN_THRESHOLD} SYNs in {TIME_WINDOW}s")
    print("[*] Listening for traffic. Press Ctrl+C to stop.\n")
    # Sniff packets and call process_packet for each one
    try:
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Detector stopped.")

# A test block to start the detector

if __name__ == "__main__":
    start_detector()