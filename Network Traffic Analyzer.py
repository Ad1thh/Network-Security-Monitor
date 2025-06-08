#!/usr/bin/env python3
"""
Network Traffic Analyzer
-----------------------
A Python-based network traffic analyzer that captures and classifies network packets
using machine learning techniques. This tool can help identify different types of
network traffic and potential security threats.

Features:
- Real-time packet capture and analysis
- Machine learning-based traffic classification
- Detailed packet information logging
- Support for multiple network interfaces
- Traffic pattern analysis and anomaly detection
- Protocol-specific analysis
"""

import sys
import os
import time
from datetime import datetime
import threading
import queue
import logging
from typing import List, Dict, Any, Optional
import ctypes
from collections import defaultdict
import json
from statistics import mean, stdev

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list, IFACES, DNS, ICMP, ARP, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.error import Scapy_Exception

# Configure logging with UTF-8 encoding
class UTFStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            # Use UTF-8 encoding for console output
            stream.buffer.write(f"{msg}{self.terminator}".encode('utf-8'))
            self.flush()
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        UTFStreamHandler(sys.stdout),
        logging.FileHandler('network_analyzer.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Common ports and their services
COMMON_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    22: 'SSH',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    3306: 'MySQL',
    3389: 'RDP',
    1433: 'MSSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    5432: 'PostgreSQL',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    445: 'SMB',
    139: 'NetBIOS',
    67: 'DHCP',
    68: 'DHCP',
    123: 'NTP',
    161: 'SNMP',
    162: 'SNMP-Trap',
    389: 'LDAP',
    636: 'LDAPS',
    5060: 'SIP',
    5061: 'SIP-TLS'
}

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class Statistics:
    def __init__(self):
        """Initialize traffic statistics."""
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()
        self.protocols = defaultdict(int)
        self.connections = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.dest_ips = defaultdict(int)
        self.service_ports = defaultdict(int)
        self.anomalies = []
        
        # Baseline statistics for anomaly detection
        self.avg_packet_size = 0
        self.packet_size_std = 0
        self.packet_sizes = []
        self.baseline_window = 1000  # Number of packets to establish baseline
        self.anomaly_threshold = 3.0  # Standard deviations for anomaly detection
        
        # Rate limiting for anomaly reporting
        self.last_anomaly_time = defaultdict(float)
        self.min_anomaly_interval = 60  # Minimum seconds between similar anomalies
        
        # Port scan detection
        self.port_scan_threshold = 20  # Number of different ports in short time
        self.port_scan_window = 10  # Time window in seconds
        self.port_attempts = defaultdict(list)  # {source_ip: [(timestamp, port), ...]}

    def update(self, packet):
        """Update statistics with a new packet."""
        self.packet_count += 1
        packet_size = len(packet)
        self.byte_count += packet_size
        
        # Update packet size statistics
        self.packet_sizes.append(packet_size)
        if len(self.packet_sizes) > self.baseline_window:
            self.packet_sizes.pop(0)
            
        # Update baseline statistics
        if self.packet_count % 100 == 0:  # Recalculate periodically
            self.avg_packet_size = np.mean(self.packet_sizes)
            self.packet_size_std = np.std(self.packet_sizes)
        
        # Extract packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update IP statistics
            self.source_ips[src_ip] += 1
            self.dest_ips[dst_ip] += 1
            
            # Protocol statistics
            if TCP in packet:
                proto = "TCP"
                sport, dport = packet[TCP].sport, packet[TCP].dport
                # Update port scan detection
                self._check_port_scan(src_ip, dport)
            elif UDP in packet:
                proto = "UDP"
                sport, dport = packet[UDP].sport, packet[UDP].dport
            else:
                proto = "Other"
                sport = dport = 0
                
            self.protocols[proto] += 1
            self.connections[(src_ip, dst_ip, proto)] += 1
            
            # Service port tracking
            if dport in COMMON_PORTS:
                service = f"{dport}({COMMON_PORTS[dport]})"
                self.service_ports[service] += 1
            
            # Anomaly detection
            self._detect_anomalies(packet, src_ip, dst_ip, proto, packet_size)

    def _detect_anomalies(self, packet, src_ip, dst_ip, proto, packet_size):
        """Detect various types of anomalies in network traffic."""
        current_time = time.time()
        
        # 1. Packet size anomaly (only if we have enough baseline data)
        if len(self.packet_sizes) >= self.baseline_window:
            z_score = abs(packet_size - self.avg_packet_size) / (self.packet_size_std + 1e-6)
            if z_score > self.anomaly_threshold and packet_size > 1500:  # Only report large anomalous packets
                self._add_anomaly("Large Packet", src_ip, dst_ip, proto, 
                                f"Size: {packet_size} bytes (z-score: {z_score:.2f})")
        
        # 2. Connection flood detection
        conn_count = self.connections[(src_ip, dst_ip, proto)]
        if conn_count > 100 and proto == "TCP":
            self._add_anomaly("Connection Flood", src_ip, dst_ip, proto,
                            f"Connection count: {conn_count}")
        
        # 3. Port scan detection
        if hasattr(packet, 'dport'):
            attempts = self._get_recent_port_attempts(src_ip)
            if len(attempts) >= self.port_scan_threshold:
                self._add_anomaly("Port Scan", src_ip, dst_ip, proto,
                                f"Attempted ports: {len(attempts)} in {self.port_scan_window}s")
        
        # 4. TCP Flag analysis
        if TCP in packet:
            flags = packet[TCP].flags
            # SYN flood detection
            if flags & 0x02 and not flags & 0x12:  # SYN without ACK
                self._add_anomaly("SYN Flood", src_ip, dst_ip, proto,
                                "Suspicious TCP flags: SYN without ACK")

    def _add_anomaly(self, anomaly_type, src_ip, dst_ip, proto, details):
        """Add an anomaly with rate limiting."""
        current_time = time.time()
        
        # Rate limit similar anomalies
        key = f"{anomaly_type}:{src_ip}:{dst_ip}"
        if current_time - self.last_anomaly_time[key] < self.min_anomaly_interval:
            return
            
        self.last_anomaly_time[key] = current_time
        
        self.anomalies.append({
            'type': anomaly_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent anomalies
        while len(self.anomalies) > 100:  # Keep last 100 anomalies
            self.anomalies.pop(0)

    def _check_port_scan(self, src_ip, dport):
        """Update and check for port scan attempts."""
        current_time = time.time()
        
        # Add new port attempt
        self.port_attempts[src_ip].append((current_time, dport))
        
        # Remove old attempts
        self.port_attempts[src_ip] = [
            (t, p) for t, p in self.port_attempts[src_ip]
            if current_time - t <= self.port_scan_window
        ]

    def _get_recent_port_attempts(self, src_ip):
        """Get unique ports attempted recently by source IP."""
        current_time = time.time()
        recent_attempts = set(
            port for t, port in self.port_attempts[src_ip]
            if current_time - t <= self.port_scan_window
        )
        return recent_attempts

class PacketAnalyzer:
    """Main class for packet capture and analysis."""
    
    def __init__(self):
        """Initialize the PacketAnalyzer with necessary components."""
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.model = None
        self.scaler = None
        self.features = [
            'protocol', 'src_port', 'dst_port', 'packet_size',
            'tcp_window_size', 'tcp_flags', 'time_delta'
        ]
        self.stats = Statistics()
        self.last_summary_time = time.time()
        self.summary_interval = 5  # Print summary every 5 seconds
        
    def load_model(self, model_path: str = 'network_traffic_model.pkl') -> None:
        """
        Load the trained machine learning model and scaler.
        
        Args:
            model_path: Path to the saved model file
        """
        try:
            # Create dummy data with proper feature names
            dummy_data = pd.DataFrame(np.zeros((1, len(self.features))), columns=self.features)
            
            if os.path.exists(model_path):
                loaded_data = joblib.load(model_path)
                # Handle different model save formats
                if isinstance(loaded_data, dict):
                    self.model = loaded_data.get('model')
                    self.scaler = loaded_data.get('scaler')
                else:
                    # If it's not a dict, assume it's just the model
                    self.model = loaded_data
                    self.scaler = None
                
                if self.model is not None:
                    logger.info("[+] Model loaded successfully")
                    if self.scaler is None:
                        logger.warning("[!] No scaler found in model file, initializing default scaler")
                        # Initialize a default scaler with feature names
                        self.scaler = StandardScaler()
                        self.scaler.fit(dummy_data)
                else:
                    logger.warning("[!] No model found in file")
            else:
                logger.warning("[!] No existing model found. Will need to train a new one.")
                # Initialize empty model and scaler
                self.model = RandomForestClassifier()
                self.scaler = StandardScaler()
                # Train with dummy data to set feature names
                self.model.fit(dummy_data, [0])
                self.scaler.fit(dummy_data)
        except Exception as e:
            logger.error(f"[X] Error loading model: {str(e)}")
            # Initialize empty model and scaler as fallback
            self.model = RandomForestClassifier()
            self.scaler = StandardScaler()
            # Train with dummy data to set feature names
            self.model.fit(dummy_data, [0])
            self.scaler.fit(dummy_data)

    def extract_features(self, packet: Any) -> pd.DataFrame:
        """
        Extract relevant features from a network packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            pandas DataFrame containing extracted features
        """
        # Initialize features with default values
        features = {
            'protocol': 0,  # Default to 0 for unknown
            'src_port': 0,
            'dst_port': 0,
            'packet_size': len(packet),
            'tcp_window_size': 0,
            'tcp_flags': 0,
            'time_delta': 0
        }
        
        if IP in packet:
            if TCP in packet:
                features.update({
                    'protocol': 6,  # TCP
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_window_size': packet[TCP].window,
                    'tcp_flags': packet[TCP].flags
                })
            elif UDP in packet:
                features.update({
                    'protocol': 17,  # UDP
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
        
        # Create DataFrame with proper feature names
        df = pd.DataFrame([features], columns=self.features)
        return df

    def analyze_packet(self, packet: Any) -> Dict[str, Any]:
        """Analyze a network packet and extract relevant information."""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'service': None
        }

        if IP in packet:
            analysis['protocol'] = 'IP'
            analysis['src_ip'] = packet[IP].src
            analysis['dst_ip'] = packet[IP].dst

            if TCP in packet:
                analysis['protocol'] = 'TCP'
                analysis['src_port'] = packet[TCP].sport
                analysis['dst_port'] = packet[TCP].dport
                analysis['flags'] = packet[TCP].flags
                
                # HTTP Detection
                if packet[TCP].dport == 80 or packet[TCP].sport == 80 or \
                   packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    if Raw in packet:
                        payload = packet[Raw].load
                        try:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            if any(method in payload_str for method in ['GET ', 'POST ', 'HTTP/1.', 'HTTP/2']):
                                analysis['protocol'] = 'HTTP' if packet[TCP].dport == 80 or packet[TCP].sport == 80 else 'HTTPS'
                        except:
                            pass

            elif UDP in packet:
                analysis['protocol'] = 'UDP'
                analysis['src_port'] = packet[UDP].sport
                analysis['dst_port'] = packet[UDP].dport

            elif ICMP in packet:
                analysis['protocol'] = 'ICMP'

            # DNS Analysis
            if DNS in packet:
                analysis['protocol'] = 'DNS'
                if hasattr(packet[DNS], 'qd') and packet[DNS].qd is not None:
                    analysis['dns_query'] = packet[DNS].qd.qname.decode('utf-8')

            # ARP Analysis
            elif ARP in packet:
                analysis['protocol'] = 'ARP'
                analysis['src_ip'] = packet[ARP].psrc
                analysis['dst_ip'] = packet[ARP].pdst

        # Service identification
        if analysis['dst_port'] in COMMON_PORTS:
            analysis['service'] = COMMON_PORTS[analysis['dst_port']]

        # ML-based classification if model is loaded
        if hasattr(self, 'model') and self.model is not None:
            try:
                features_df = self.extract_features(packet)
                if not features_df.empty:
                    # Ensure feature order matches training data
                    features_df = features_df[self.features]
                    # Transform while preserving feature names
                    features_scaled = pd.DataFrame(
                        self.scaler.transform(features_df),
                        columns=self.features
                    )
                    prediction = self.model.predict(features_scaled)
                    analysis['ml_classification'] = prediction[0]
            except Exception as e:
                logger.debug(f"ML classification skipped: {str(e)}")
                analysis['ml_classification'] = None

        return analysis

    def packet_callback(self, packet: Any) -> None:
        """
        Callback function for packet processing.
        
        Args:
            packet: Captured network packet
        """
        try:
            if IP in packet:
                # Extract features and update statistics
                features = self.extract_features(packet)
                analysis = self.analyze_packet(packet)
                self.stats.update(packet)
                
                # Print packet info
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = analysis['protocol']
                service = analysis.get('service', 'Unknown')
                
                log_msg = f"[>] {protocol}: {src_ip}:{analysis.get('src_port', '')} -> "
                log_msg += f"{dst_ip}:{analysis.get('dst_port', '')} "
                log_msg += f"({service}) Size: {len(packet)} bytes"
                
                if 'dns_query' in analysis:
                    log_msg += f" Query: {analysis['dns_query']}"
                
                logger.info(log_msg)
                
                # Print periodic summary
                current_time = time.time()
                if current_time - self.last_summary_time >= self.summary_interval:
                    self._print_summary()
                    self.last_summary_time = current_time
                
        except Exception as e:
            logger.error(f"[X] Error processing packet: {str(e)}")

    def _print_summary(self):
        """Print traffic summary."""
        summary = {
            'protocols': dict(self.stats.protocols),
            'top_sources': dict(sorted(self.stats.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(self.stats.dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_connections': {f"{src}->{dst} ({proto})": count 
                              for (src, dst, proto), count in sorted(self.stats.connections.items(), 
                                                                   key=lambda x: x[1], 
                                                                   reverse=True)[:10]},
            'service_ports': dict(self.stats.service_ports),
            'recent_anomalies': self.stats.anomalies[-5:] if self.stats.anomalies else [],
            'traffic_rate': {
                'packets_per_second': self.stats.packet_count / (time.time() - self.stats.start_time),
                'bytes_per_second': self.stats.byte_count / (time.time() - self.stats.start_time)
            }
        }
        
        logger.info("\n" + "="*50)
        logger.info("Traffic Summary:")
        logger.info("-"*50)
        
        # Protocol Statistics
        logger.info("\nProtocol Distribution:")
        for proto, count in summary['protocols'].items():
            logger.info(f"  {proto}: {count}")
        
        # Traffic rates
        logger.info("\nTraffic Rates:")
        logger.info(f"  Packets/sec: {summary['traffic_rate']['packets_per_second']:.2f}")
        logger.info(f"  Bytes/sec: {summary['traffic_rate']['bytes_per_second']:.2f}")
        
        # Recent anomalies with detailed information
        if summary['recent_anomalies']:
            logger.info("\nRecent Anomalies:")
            for anomaly in summary['recent_anomalies']:
                if anomaly['type'] == 'Connection Flood':
                    logger.info(f"\n  🚨 {anomaly['type']} Detected:")
                    logger.info(f"    Source IP: {anomaly['src_ip']}")
                    logger.info(f"    Target IP: {anomaly['dst_ip']}")
                    logger.info(f"    Protocol: {anomaly['protocol']}")
                    logger.info(f"    {anomaly['details']}")
                    logger.info(f"    Time: {anomaly['timestamp']}")
                elif anomaly['type'] == 'Port Scan':
                    logger.info(f"\n  🔍 {anomaly['type']} Detected:")
                    logger.info(f"    Scanner IP: {anomaly['src_ip']}")
                    logger.info(f"    Target IP: {anomaly['dst_ip']}")
                    logger.info(f"    {anomaly['details']}")
                    logger.info(f"    Time: {anomaly['timestamp']}")
                elif anomaly['type'] == 'Large Packet':
                    logger.info(f"\n  📦 {anomaly['type']} Detected:")
                    logger.info(f"    From: {anomaly['src_ip']}")
                    logger.info(f"    To: {anomaly['dst_ip']}")
                    logger.info(f"    {anomaly['details']}")
                    logger.info(f"    Time: {anomaly['timestamp']}")
                elif anomaly['type'] == 'SYN Flood':
                    logger.info(f"\n  ⚠️ {anomaly['type']} Detected:")
                    logger.info(f"    Attacker IP: {anomaly['src_ip']}")
                    logger.info(f"    Target IP: {anomaly['dst_ip']}")
                    logger.info(f"    {anomaly['details']}")
                    logger.info(f"    Time: {anomaly['timestamp']}")
        
        logger.info("="*50 + "\n")

    def get_active_interface(self) -> Optional[str]:
        """
        Get the most suitable network interface for packet capture.
        
        Returns:
            The name of the active interface or None if not found
        """
        try:
            # Get list of interfaces
            interfaces = IFACES.data.values()
            
            # Print available interfaces
            logger.info("\n[*] Available Network Interfaces:")
            for idx, iface in enumerate(interfaces):
                logger.info(f"[{idx}] {iface.name}")
                logger.info(f"    Description: {iface.description}")
                if hasattr(iface, 'mac'):
                    logger.info(f"    MAC: {iface.mac}")
                if hasattr(iface, 'ips'):
                    try:
                        ips = [str(ip) for ip in iface.ips]
                        logger.info(f"    IPs: {', '.join(ips)}")
                    except:
                        pass
                logger.info("")
            
            # First try to find WiFi or Ethernet interface
            for iface in interfaces:
                if ("Wi-Fi" in iface.description or 
                    "Wireless" in iface.description or 
                    "Ethernet" in iface.description):
                    return iface.name
            
            # If no WiFi/Ethernet found, return the first non-loopback interface
            for iface in interfaces:
                if "Loopback" not in iface.description:
                    return iface.name
            
            return None
            
        except Exception as e:
            logger.error(f"[X] Error getting network interfaces: {str(e)}")
            return None

    def start_capture(self, interface: Optional[str] = None, timeout: int = None) -> None:
        """
        Start capturing network packets.
        
        Args:
            interface: Network interface to capture from
            timeout: Capture duration in seconds
        """
        if not is_admin():
            logger.error("[X] This script requires administrator privileges!")
            logger.info("[!] Please run this script as administrator")
            return
            
        try:
            # If no interface specified, try to find an active one
            if not interface:
                interface = self.get_active_interface()
                if not interface:
                    logger.error("[X] No suitable network interface found!")
                    return
            
            logger.info(f"[+] Starting packet capture on interface: {interface}")
            logger.info("[*] Press Ctrl+C to stop capturing")
            
            # Configure Scapy settings for Windows
            conf.sniff_promisc = False  # Disable promiscuous mode
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                timeout=timeout,
                stop_filter=lambda _: self.stop_capture.is_set()
            )
            
        except Scapy_Exception as e:
            logger.error(f"[X] Scapy error: {str(e)}")
            logger.info("\n[*] Troubleshooting Steps:")
            logger.info("1. Make sure Npcap is installed (https://npcap.com)")
            logger.info("2. Run 'netsh winsock reset' as administrator")
            logger.info("3. Run 'netsh int ip reset' as administrator")
            logger.info("4. Restart your computer")
            logger.info("5. Run this script as administrator")
        except Exception as e:
            logger.error(f"[X] Capture error: {str(e)}")

    def stop(self) -> None:
        """Stop the packet capture."""
        self.stop_capture.set()
        logger.info("[*] Stopping packet capture...")
        
        # Save final statistics
        summary = {
            'protocols': dict(self.stats.protocols),
            'top_sources': dict(sorted(self.stats.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(self.stats.dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_connections': {f"{src}->{dst} ({proto})": count 
                              for (src, dst, proto), count in sorted(self.stats.connections.items(), 
                                                                   key=lambda x: x[1], 
                                                                   reverse=True)[:10]},
            'service_ports': {f"{port}({COMMON_PORTS.get(port, 'Unknown')})": count 
                            for port, count in sorted(self.stats.service_ports.items(), 
                                                    key=lambda x: x[1], 
                                                    reverse=True)[:10]},
            'recent_anomalies': self.stats.anomalies[-5:] if self.stats.anomalies else [],
            'traffic_rate': {
                'packets_per_second': self.stats.packet_count / (time.time() - self.stats.start_time),
                'bytes_per_second': self.stats.byte_count / (time.time() - self.stats.start_time)
            }
        }
        with open('traffic_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info("[+] Traffic summary saved to traffic_summary.json")

def main():
    """Main function to run the Network Traffic Analyzer."""
    try:
        # Check for admin privileges
        if not is_admin():
            logger.error("[X] This script requires administrator privileges!")
            logger.info("[!] Please run this script as administrator")
            return
            
        analyzer = PacketAnalyzer()
        analyzer.load_model()
        
        logger.info("[+] Starting Network Traffic Analyzer...")
        
        # Start packet capture
        analyzer.start_capture()
        
    except KeyboardInterrupt:
        logger.info("\n[*] Capture stopped by user")
        analyzer.stop()
    except Exception as e:
        logger.error(f"[X] Error: {str(e)}")
    finally:
        logger.info("[*] Network Traffic Analyzer stopped")

if __name__ == "__main__":
    main()
