# This module is the attack side of Purple team Simulation & it simulates a port scan By sending SYN packets to port 1 - 100 on a target

# imports - scapy for packet crafting, sys for arguments, time for delays
from scapy.all import IP, TCP, sr1, send
import sys
import time

# Function to scan a target ip on ports 1-100 using SYN packets
def scan_target(target_ip):
    # dict to store scan results
    results = {"open":[],"closed":[],"filtered":[]}
    # print what we're about to do
    print(f"[*]Starting SYN scan on {target_ip} for ports 1-100")
    # loop through ports 1 to 100
    for port in range(1, 100):
        # building the SYN packet - (ip layer + tcp layer) with SYN flag
        packet = IP(dst = target_ip)/TCP (dport=port, flags="S")
        # sending the packet and wait for one response (timeout 1 second)
        response = sr1(packet, timeout=1, verbose=0)
        # check the response to determine port state
        if response is None:
            results["filtered"].append(port)
        elif response.haslayer(TCP) and response[TCP].flags == "SA":
            results["open"].append(port)
        elif response.haslayer(TCP) and response[TCP].flags == "RA":
            results["closed"].append(port)
            # small delay so the scan is realistic and detectable
            time.sleep(0.05)
                # Print summary after the loop
    print(f"[*] Scan complete.")
    print(f"    Open ports: {results['open']}")
    print(f"    Closed ports: {len(results['closed'])}")
    print(f"    Filtered ports: {len(results['filtered'])}")
    return results

# A test block to run a scanner when the file is executed directly
if __name__=="__main__":
    # get target from commandline or default to local host
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "127.0.0.1"

# run the scan
results = scan_target(target)
# log results to file
with open("logs/scan_results.log", "w") as f:
    f.write(f"Target: {target}\n")
    f.write(f"Open ports: {results['open']}\n")
    f.write(f"Closed ports: {results['closed']}\n")
    f.write(f"Filtered ports: {results['filtered']}\n")
    print("[*] Results logged to logs/scan_results.log")

