import socket
import threading
import time
import random
import requests

def simulate_port_scan():
    """Simulate a port scan by rapidly connecting to multiple ports"""
    target_host = "127.0.0.1"
    print("Simulating port scan...")
    for port in range(5000, 5020):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((target_host, port))
            sock.close()
        except:
            pass
        time.sleep(0.1)

def simulate_high_traffic():
    """Simulate high traffic by making rapid requests"""
    print("Simulating high traffic...")
    url = "http://localhost:5000"
    for _ in range(100):
        try:
            requests.get(url)
        except:
            pass
        time.sleep(0.01)

def simulate_data_exfiltration():
    """Simulate data exfiltration by sending large amounts of data"""
    print("Simulating data exfiltration...")
    target_host = "127.0.0.1"
    target_port = 5000
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_host, target_port))
        
        # Send large amount of data
        large_data = b"X" * 1000000  # 1MB of data
        for _ in range(5):
            sock.send(large_data)
            time.sleep(0.5)
            
        sock.close()
    except:
        pass

def simulate_ddos():
    """Simulate DDoS by creating multiple connections"""
    print("Simulating DDoS attack...")
    threads = []
    for _ in range(50):
        t = threading.Thread(target=simulate_high_traffic)
        threads.append(t)
        t.start()
        time.sleep(0.1)
    
    for t in threads:
        t.join()

def main():
    print("Starting threat simulation...")
    
    # Test each type of threat
    simulate_port_scan()
    time.sleep(2)
    
    simulate_high_traffic()
    time.sleep(2)
    
    simulate_data_exfiltration()
    time.sleep(2)
    
    simulate_ddos()
    
    print("Threat simulation completed.")

if __name__ == "__main__":
    main() 