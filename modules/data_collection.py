from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import numpy as np
import pandas as pd
from datetime import datetime
import threading
import queue
import logging
from typing import Dict, List, Tuple
import psutil
import time
import socket
import subprocess
import platform
import re

class FlowFeatureExtractor:
    def __init__(self, flow_timeout: int = 600):
        self.flow_timeout = flow_timeout
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'packets': [],
            'bytes': 0,
            'packet_times': [],
            'packet_sizes': [],
            'flags': set(),
            'protocols': set()
        })
        self.flow_queue = queue.Queue()
        self.lock = threading.Lock()
        
    def _get_flow_key(self, packet) -> Tuple[str, str, int, int]:
        """Generate a unique flow key from packet information."""
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Ensure consistent ordering of flow key
            if src_port < dst_port:
                return (src_ip, dst_ip, src_port, dst_port)
            return (dst_ip, src_ip, dst_port, src_port)
        return None

    def extract_packet_features(self, packet) -> Dict:
        """Extract relevant features from a single packet."""
        features = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': 'Unknown'
        }

        if IP in packet:
            features.update({
                'ip_len': packet[IP].len,
                'ip_ttl': packet[IP].ttl,
                'ip_proto': packet[IP].proto
            })

            if TCP in packet:
                features.update({
                    'protocol': 'TCP',
                    'tcp_flags': packet[TCP].flags,
                    'tcp_window': packet[TCP].window
                })
            elif UDP in packet:
                features.update({
                    'protocol': 'UDP'
                })

        return features

    def process_packet(self, packet):
        """Process a single packet and update flow statistics."""
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        with self.lock:
            flow = self.flows[flow_key]
            if not flow['start_time']:
                flow['start_time'] = datetime.now()

            packet_features = self.extract_packet_features(packet)
            flow['packets'].append(packet_features)
            flow['bytes'] += packet_features['size']
            flow['packet_times'].append(packet_features['timestamp'])
            flow['packet_sizes'].append(packet_features['size'])
            
            if packet_features['protocol'] != 'Unknown':
                flow['protocols'].add(packet_features['protocol'])
            
            if 'tcp_flags' in packet_features:
                flow['flags'].add(packet_features['tcp_flags'])

            # Check if flow is complete
            self._check_flow_timeout(flow_key)

    def _check_flow_timeout(self, flow_key: Tuple):
        """Check if a flow has timed out and should be processed."""
        flow = self.flows[flow_key]
        if not flow['packet_times']:
            return

        duration = (flow['packet_times'][-1] - flow['packet_times'][0]).total_seconds()
        if duration >= self.flow_timeout:
            flow_features = self._compute_flow_features(flow)
            self.flow_queue.put(flow_features)
            del self.flows[flow_key]

    def _compute_flow_features(self, flow: Dict) -> Dict:
        """Compute statistical features from a complete flow."""
        packet_sizes = np.array(flow['packet_sizes'])
        packet_times = np.array([(t - flow['packet_times'][0]).total_seconds() 
                               for t in flow['packet_times']])
        
        if len(packet_times) > 1:
            inter_arrival_times = np.diff(packet_times)
        else:
            inter_arrival_times = np.array([0])

        return {
            'duration': packet_times[-1],
            'total_packets': len(flow['packets']),
            'total_bytes': flow['bytes'],
            'packet_size_mean': float(np.mean(packet_sizes)),
            'packet_size_std': float(np.std(packet_sizes)) if len(packet_sizes) > 1 else 0,
            'packet_size_min': float(np.min(packet_sizes)),
            'packet_size_max': float(np.max(packet_sizes)),
            'iat_mean': float(np.mean(inter_arrival_times)),
            'iat_std': float(np.std(inter_arrival_times)) if len(inter_arrival_times) > 1 else 0,
            'iat_min': float(np.min(inter_arrival_times)),
            'iat_max': float(np.max(inter_arrival_times)),
            'protocols': list(flow['protocols']),
            'tcp_flags': list(flow['flags']) if flow['flags'] else []
        }

class NetworkDataCollector:
    def __init__(self, interface=None, flow_timeout=600):
        """Initialize the network data collector."""
        self.flow_timeout = flow_timeout
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_packets_sent = 0
        self.last_packets_recv = 0
        self.last_check_time = time.time()
        
        # Get all available interfaces
        self.interfaces_stats = psutil.net_if_stats()
        self.interfaces_addrs = psutil.net_if_addrs()
        
        # Find default interface if none specified
        if not interface:
            interface = self._get_best_interface()
        
        self.interface = interface
        self.initialize_interface()

    def _get_best_interface(self):
        """Find the best available network interface."""
        # First try to find an active interface
        for iface, stats in self.interfaces_stats.items():
            if (stats.isup and 
                iface not in ['lo', 'localhost'] and 
                not iface.startswith('veth')):
                return iface
        
        # If no active interface found, return first available non-loopback interface
        for iface in self.interfaces_stats:
            if iface not in ['lo', 'localhost'] and not iface.startswith('veth'):
                return iface
        
        return None

    def get_available_interfaces(self):
        """Get list of all available network interfaces with their details."""
        interfaces = []
        for iface in self.interfaces_stats:
            if iface not in ['lo', 'localhost'] and not iface.startswith('veth'):
                stats = self.interfaces_stats[iface]
                interface_type = self._detect_interface_type(iface)
                
                # Get IP addresses
                addresses = []
                if iface in self.interfaces_addrs:
                    for addr in self.interfaces_addrs[iface]:
                        if addr.family == socket.AF_INET:  # IPv4
                            addresses.append(addr.address)
                
                interfaces.append({
                    'name': iface,
                    'type': interface_type,
                    'status': 'up' if stats.isup else 'down',
                    'speed': stats.speed if hasattr(stats, 'speed') else None,
                    'mtu': stats.mtu,
                    'addresses': addresses
                })
        
        return interfaces

    def _detect_interface_type(self, iface):
        """Detect the type of network interface."""
        try:
            if platform.system() == 'Windows':
                # Use Windows commands to detect interface type
                cmd = f'netsh interface show interface "{iface}"'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                output = result.stdout.lower()
                
                if 'wireless' in output:
                    return 'Wireless'
                elif 'ethernet' in output:
                    return 'Ethernet'
                else:
                    # Try to detect by interface name pattern
                    if iface.lower().startswith('wi'):
                        return 'Wireless'
                    elif iface.lower().startswith('eth') or iface.lower().startswith('en'):
                        return 'Ethernet'
                    return 'Other'
            else:
                # For Linux/Unix systems
                try:
                    cmd = f'iwconfig {iface} 2>/dev/null'
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                    if result.stdout:
                        return 'Wireless'
                    return 'Ethernet'
                except:
                    # Fallback to interface name pattern
                    if iface.lower().startswith('wl'):
                        return 'Wireless'
                    elif iface.lower().startswith('eth') or iface.lower().startswith('en'):
                        return 'Ethernet'
                    return 'Other'
        except:
            return 'Unknown'

    def change_interface(self, new_interface):
        """Change the monitored network interface."""
        if new_interface in self.interfaces_stats:
            self.interface = new_interface
            self.initialize_interface()
            return True
        return False

    def initialize_interface(self):
        """Initialize and detect the network interface details."""
        try:
            self.interface_stats = self.interfaces_stats.get(self.interface)
            self.interface_type = self._detect_interface_type(self.interface)
            self.interface_speed = self._get_interface_speed()
            
        except Exception as e:
            print(f"Error initializing interface: {str(e)}")
            self.interface_stats = None
            self.interface_type = "Unknown"
            self.interface_speed = 0

    def _get_interface_speed(self):
        """Get the interface speed in Mbps."""
        try:
            if self.interface_stats:
                return self.interface_stats.speed if self.interface_stats.speed != 0 else None
            return None
        except:
            return None

    def _measure_latency(self):
        """Measure network latency using ping."""
        try:
            host = "8.8.8.8"  # Google DNS server
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            cmd = ['ping', param, '3', host]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if platform.system().lower() == 'windows':
                match = re.search(r'Average = (\d+)ms', result.stdout)
            else:
                match = re.search(r'min/avg/max/mdev = [\d.]+/([\d.]+)', result.stdout)
            
            return float(match.group(1)) if match else None
        except:
            return None

    def _calculate_packet_loss(self, stats):
        """Calculate packet loss percentage."""
        try:
            packets_sent = stats.packets_sent
            packets_recv = stats.packets_recv
            if packets_sent > 0:
                return ((packets_sent - packets_recv) / packets_sent) * 100
            return 0
        except:
            return 0

    def get_flow_features(self):
        """Get network flow features including interface details and health metrics."""
        try:
            current_time = time.time()
            stats = psutil.net_io_counters(pernic=True).get(self.interface)
            
            if not stats:
                return {}

            # Calculate rates
            time_diff = current_time - self.last_check_time
            bytes_sent_rate = (stats.bytes_sent - self.last_bytes_sent) / time_diff
            bytes_recv_rate = (stats.bytes_recv - self.last_bytes_recv) / time_diff
            packets_sent_rate = (stats.packets_sent - self.last_packets_sent) / time_diff
            packets_recv_rate = (stats.packets_recv - self.last_packets_recv) / time_diff

            # Update last values
            self.last_bytes_sent = stats.bytes_sent
            self.last_bytes_recv = stats.bytes_recv
            self.last_packets_sent = stats.packets_sent
            self.last_packets_recv = stats.packets_recv
            self.last_check_time = current_time

            # Get additional metrics
            latency = self._measure_latency()
            packet_loss = self._calculate_packet_loss(stats)

            return {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface,
                'interface_type': self.interface_type,
                'interface_speed': self.interface_speed,
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'bytes_sent_rate': bytes_sent_rate,
                'bytes_recv_rate': bytes_recv_rate,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'packets_sent_rate': packets_sent_rate,
                'packets_recv_rate': packets_recv_rate,
                'errors': stats.errin + stats.errout,
                'dropped': stats.dropin + stats.dropout,
                'latency': latency,
                'packet_loss': packet_loss,
                'status': 'up' if self.interface_stats and self.interface_stats.isup else 'down'
            }
        except Exception as e:
            print(f"Error collecting network data: {str(e)}")
            return {}

    def get_connection_details(self) -> List[Dict]:
        """Get detailed information about current network connections."""
        try:
            connections = []
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_ip': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_ip': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            return connections
        except Exception as e:
            self.logger.error(f"Error getting connection details: {str(e)}")
            return []

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    collector = NetworkDataCollector(interface="eth0")
    
    try:
        collector.start_collection()
    except KeyboardInterrupt:
        collector.stop_collection()
        print("\nStopped packet capture") 