from scapy.all import *
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def send_large_packet():
    """Send abnormally large packets"""
    # Create a large packet (>1500 bytes)
    payload = "A" * 2000
    packet = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load=payload)
    send(packet, verbose=False)
    print("[+] Sent large packet")

def port_scan():
    """Simulate a port scan"""
    target = "192.168.1.1"
    # Scan multiple ports quickly
    for port in range(20, 50):
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
    print("[+] Completed port scan simulation")

def syn_flood():
    """Simulate a SYN flood attack"""
    target = "192.168.1.1"
    # Send multiple SYN packets to the same port
    for _ in range(50):
        packet = IP(dst=target)/TCP(dport=80, flags="S")
        send(packet, verbose=False)
    print("[+] Completed SYN flood simulation")

def connection_flood():
    """Simulate connection flood"""
    target = "192.168.1.1"
    # Create many connections from different source ports
    for sport in range(1024, 1124):
        packet = IP(dst=target)/TCP(sport=sport, dport=80)
        send(packet, verbose=False)
    print("[+] Completed connection flood simulation")

def main():
    print("Starting malicious traffic simulation...")
    print("This will generate test traffic to trigger detection mechanisms")
    print("Make sure your Network Traffic Analyzer is running!")
    print("\nPress Ctrl+C to stop\n")
    
    try:
        while True:
            # Run different attack simulations
            with ThreadPoolExecutor(max_workers=4) as executor:
                executor.submit(send_large_packet)
                time.sleep(2)  # Wait between attacks
                
                executor.submit(port_scan)
                time.sleep(2)
                
                executor.submit(syn_flood)
                time.sleep(2)
                
                executor.submit(connection_flood)
                time.sleep(5)  # Longer wait before next round
                
    except KeyboardInterrupt:
        print("\n[*] Stopping traffic simulation")

if __name__ == "__main__":
    main() 