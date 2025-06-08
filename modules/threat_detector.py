import pandas as pd
import numpy as np
from typing import Dict, List, Union
import logging
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import time
from collections import deque

class ThreatDetector:
    def __init__(self, config: Dict = None):
        """Initialize the threat detector with configuration."""
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Initialize threat detection parameters
        self.threshold = self.config.get('threshold', 0.8)
        self.window_size = self.config.get('window_size', 300)  # 5 minutes
        
        # Initialize anomaly detection model
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        
        # Initialize data buffers
        self.traffic_history = deque(maxlen=self.window_size)
        self.last_check = time.time()
        
        # Initialize baseline metrics
        self.baseline = {
            'bytes_sent_rate': 0,
            'bytes_recv_rate': 0,
            'packets_sent_rate': 0,
            'packets_recv_rate': 0,
            'error_rate': 0
        }
        
        # Initialize detection flags
        self.is_trained = False
        
        # Initialize threat patterns
        self.threat_patterns = {
            'port_scan': {
                'unique_ports_threshold': 10,
                'time_window': 60  # seconds
            },
            'ddos': {
                'packet_rate_threshold': 5000,
                'connection_threshold': 1000
            },
            'data_exfiltration': {
                'upload_threshold': 10000000,  # 10MB/s
                'ratio_threshold': 5.0  # upload/download ratio
            }
        }
        
        self.connection_history = []
        
    def update_baseline(self, stats: Dict):
        """Update baseline metrics using exponential moving average."""
        alpha = 0.1  # Smoothing factor
        
        for metric in self.baseline:
            if metric in stats:
                current = float(stats[metric])
                self.baseline[metric] = (alpha * current + 
                                       (1 - alpha) * self.baseline[metric])
    
    def detect_port_scan(self, stats: Dict) -> List[Dict]:
        """Detect potential port scanning activity."""
        threats = []
        
        # Check for high rate of new connections
        if stats.get('packets_sent_rate', 0) > self.baseline['packets_sent_rate'] * 5:
            if stats.get('bytes_sent_rate', 0) < stats.get('packets_sent_rate', 0) * 100:
                threats.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'details': 'High rate of small packets detected'
                })
                
        return threats
    
    def detect_ddos(self, stats: Dict) -> List[Dict]:
        """Detect potential DDoS attacks."""
        threats = []
        
        # Check for abnormal traffic rates
        if (stats.get('packets_recv_rate', 0) > self.baseline['packets_recv_rate'] * 10 or
            stats.get('bytes_recv_rate', 0) > self.baseline['bytes_recv_rate'] * 10):
            
            threats.append({
                'type': 'ddos',
                'severity': 'critical',
                'details': 'Abnormally high incoming traffic detected'
            })
            
        return threats
    
    def detect_data_exfiltration(self, stats: Dict) -> List[Dict]:
        """Detect potential data exfiltration."""
        threats = []
        
        # Check for unusual outbound traffic
        if stats.get('bytes_sent_rate', 0) > self.baseline['bytes_sent_rate'] * 3:
            if stats.get('bytes_sent_rate', 0) > 1000000:  # More than 1 MB/s
                threats.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'details': 'Unusual high volume of outbound traffic'
                })
                
        return threats
    
    def detect_anomalies(self, stats: Dict) -> List[Dict]:
        """Detect general network anomalies using Isolation Forest."""
        threats = []
        
        if not self.is_trained:
            return threats
            
        try:
            # Prepare feature vector
            features = np.array([[
                stats.get('bytes_sent_rate', 0),
                stats.get('bytes_recv_rate', 0),
                stats.get('packets_sent_rate', 0),
                stats.get('packets_recv_rate', 0),
                stats.get('error_rate', 0)
            ]])
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict anomaly
            prediction = self.isolation_forest.predict(features_scaled)
            
            if prediction[0] == -1:  # Anomaly detected
                threats.append({
                    'type': 'anomaly',
                    'severity': 'medium',
                    'details': 'Unusual network behavior detected'
                })
                
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            
        return threats
    
    def detect_high_traffic(self, stats: Dict) -> List[Dict]:
        """Detect sustained high traffic conditions."""
        threats = []
        
        # Check for sustained high traffic
        if (stats.get('bytes_sent_rate', 0) + stats.get('bytes_recv_rate', 0) > 
            (self.baseline['bytes_sent_rate'] + self.baseline['bytes_recv_rate']) * 2):
            
            threats.append({
                'type': 'high_traffic',
                'severity': 'low',
                'details': 'Sustained high traffic detected'
            })
            
        return threats
    
    def detect_threats(self, stats: Dict) -> Dict[str, List[Dict]]:
        """Detect all types of threats."""
        try:
            # Update traffic history
            self.traffic_history.append(stats)
            
            # Update baseline metrics
            self.update_baseline(stats)
            
            # Detect various threats
            threats = {
                'anomalies': self.detect_anomalies(stats),
                'port_scans': self.detect_port_scan(stats),
                'ddos': self.detect_ddos(stats),
                'data_exfiltration': self.detect_data_exfiltration(stats),
                'high_traffic': self.detect_high_traffic(stats)
            }
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Error detecting threats: {str(e)}")
            return {
                'anomalies': [], 'port_scans': [], 'ddos': [],
                'data_exfiltration': [], 'high_traffic': []
            }
    
    def train(self, stats: Dict):
        """Train the anomaly detection model."""
        try:
            # Add to traffic history
            self.traffic_history.append(stats)
            
            # Only train if we have enough data
            if len(self.traffic_history) >= 50:
                # Prepare training data
                X = np.array([[
                    d.get('bytes_sent_rate', 0),
                    d.get('bytes_recv_rate', 0),
                    d.get('packets_sent_rate', 0),
                    d.get('packets_recv_rate', 0),
                    d.get('error_rate', 0)
                ] for d in self.traffic_history])
                
                # Fit scaler
                self.scaler.fit(X)
                X_scaled = self.scaler.transform(X)
                
                # Train Isolation Forest
                self.isolation_forest.fit(X_scaled)
                self.is_trained = True
                
                self.logger.info("Anomaly detection model trained successfully")
                
        except Exception as e:
            self.logger.error(f"Error training anomaly detection model: {str(e)}")

    def _detect_port_scan(self, connections: List[Dict]) -> List[Dict]:
        """Detect potential port scanning activity."""
        threats = []
        now = datetime.now()
        
        # Add new connections to history
        for conn in connections:
            self.connection_history.append({
                'timestamp': now,
                'local_port': conn.get('local_port'),
                'remote_ip': conn.get('remote_ip')
            })
            
        # Remove old connections
        self.connection_history = [
            conn for conn in self.connection_history
            if now - conn['timestamp'] < timedelta(seconds=self.threat_patterns['port_scan']['time_window'])
        ]
        
        # Check for port scanning
        for remote_ip in set(conn['remote_ip'] for conn in self.connection_history if conn['remote_ip']):
            ip_connections = [
                conn for conn in self.connection_history
                if conn['remote_ip'] == remote_ip
            ]
            unique_ports = len(set(conn['local_port'] for conn in ip_connections if conn['local_port']))
            
            if unique_ports > self.threat_patterns['port_scan']['unique_ports_threshold']:
                threats.append({
                    'type': 'port_scan',
                    'remote_ip': remote_ip,
                    'unique_ports': unique_ports,
                    'timestamp': now.isoformat()
                })
                
        return threats
        
    def _detect_ddos(self, flow_data: pd.DataFrame) -> List[Dict]:
        """Detect potential DDoS attacks."""
        threats = []
        
        for _, flow in flow_data.iterrows():
            packet_rate = flow.get('packets_recv_rate', 0)
            connection_count = flow.get('connections_established', 0)
            
            if (packet_rate > self.threat_patterns['ddos']['packet_rate_threshold'] or
                connection_count > self.threat_patterns['ddos']['connection_threshold']):
                threats.append({
                    'type': 'ddos',
                    'packet_rate': packet_rate,
                    'connection_count': connection_count,
                    'timestamp': flow['timestamp'].isoformat()
                })
                
        return threats
        
    def _detect_data_exfiltration(self, flow_data: pd.DataFrame) -> List[Dict]:
        """Detect potential data exfiltration."""
        threats = []
        
        for _, flow in flow_data.iterrows():
            upload_rate = flow.get('bytes_sent_rate', 0)
            download_rate = flow.get('bytes_recv_rate', 0)
            
            if upload_rate > self.threat_patterns['data_exfiltration']['upload_threshold']:
                ratio = upload_rate / (download_rate + 1e-6)
                if ratio > self.threat_patterns['data_exfiltration']['ratio_threshold']:
                    threats.append({
                        'type': 'data_exfiltration',
                        'upload_rate': upload_rate,
                        'ratio': ratio,
                        'timestamp': flow['timestamp'].isoformat()
                    })
                    
        return threats
        
    def _analyze_behavior(self, X: pd.DataFrame) -> List[Dict]:
        """Analyze network behavior for suspicious patterns."""
        behavioral_threats = []
        
        try:
            # Check for sudden traffic spikes
            if 'bytes_sent' in X.columns and 'bytes_recv' in X.columns:
                total_traffic = X['bytes_sent'] + X['bytes_recv']
                mean_traffic = total_traffic.mean()
                std_traffic = total_traffic.std()
                
                # Detect traffic spikes (more than 3 standard deviations)
                spikes = total_traffic > (mean_traffic + 3 * std_traffic)
                if spikes.any():
                    behavioral_threats.append({
                        'type': 'traffic_spike',
                        'severity': 'medium',
                        'details': 'Unusual traffic volume detected'
                    })
            
            # Check for port scanning behavior
            if 'dst_port' in X.columns:
                unique_ports = X['dst_port'].nunique()
                if unique_ports > 100:  # Threshold for port scanning
                    behavioral_threats.append({
                        'type': 'port_scanning',
                        'severity': 'high',
                        'details': f'Possible port scanning detected ({unique_ports} ports)'
                    })
            
            # Check for DDoS patterns
            if 'src_ip' in X.columns and 'dst_ip' in X.columns:
                unique_sources = X['src_ip'].nunique()
                unique_targets = X['dst_ip'].nunique()
                
                if unique_sources > 100 and unique_targets < 3:
                    behavioral_threats.append({
                        'type': 'ddos_attempt',
                        'severity': 'critical',
                        'details': 'Possible DDoS attack pattern detected'
                    })
            
        except Exception as e:
            self.logger.error(f"Error in behavioral analysis: {str(e)}")
        
        return behavioral_threats

    def _check_known_threats(self, X: pd.DataFrame) -> List[Dict]:
        """Check for known threat patterns."""
        known_threats = []
        
        try:
            # Check against known malicious patterns
            for pattern_name, pattern in self.threat_patterns.items():
                matches = self._match_pattern(X, pattern)
                if matches:
                    known_threats.append({
                        'type': 'known_threat',
                        'pattern': pattern_name,
                        'matches': matches,
                        'severity': pattern.get('severity', 'high')
                    })
            
        except Exception as e:
            self.logger.error(f"Error checking known threats: {str(e)}")
        
        return known_threats

    def _match_pattern(self, X: pd.DataFrame, pattern: Dict) -> List[Dict]:
        """Match traffic against a known threat pattern."""
        matches = []
        
        try:
            # Pattern matching logic based on pattern type
            if pattern['type'] == 'signature':
                # Signature-based matching
                for signature in pattern['signatures']:
                    mask = pd.Series(True, index=X.index)
                    for field, value in signature.items():
                        if field in X.columns:
                            mask &= (X[field] == value)
                    
                    matching_rows = X[mask]
                    if not matching_rows.empty:
                        matches.append({
                            'signature': signature,
                            'matches': len(matching_rows)
                        })
            
            elif pattern['type'] == 'threshold':
                # Threshold-based matching
                for field, threshold in pattern['thresholds'].items():
                    if field in X.columns:
                        if threshold['type'] == 'max':
                            violations = X[X[field] > threshold['value']]
                        elif threshold['type'] == 'min':
                            violations = X[X[field] < threshold['value']]
                        
                        if not violations.empty:
                            matches.append({
                                'field': field,
                                'threshold': threshold,
                                'violations': len(violations)
                            })
            
        except Exception as e:
            self.logger.error(f"Error in pattern matching: {str(e)}")
        
        return matches

    def update_threat_patterns(self, api_url: str = None):
        """Update known threat patterns from threat intelligence source."""
        try:
            if api_url:
                # Fetch latest threat patterns from API
                response = requests.get(api_url)
                if response.status_code == 200:
                    new_patterns = response.json()
                    self.threat_patterns.update(new_patterns)
                    self.logger.info("Threat patterns updated successfully")
                else:
                    self.logger.warning(f"Failed to update threat patterns: {response.status_code}")
            
        except Exception as e:
            self.logger.error(f"Error updating threat patterns: {str(e)}")

    def save_state(self, path: str):
        """Save detector state and models."""
        try:
            state = {
                'threat_patterns': self.threat_patterns,
                'reconstruction_threshold': self.reconstruction_threshold,
                'threshold_multiplier': self.threshold_multiplier
            }
            
            with open(f"{path}_state.json", 'w') as f:
                json.dump(state, f)
            
            self.logger.info(f"Detector state saved to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving detector state: {str(e)}")
            raise

    def load_state(self, path: str):
        """Load detector state and models."""
        try:
            with open(f"{path}_state.json", 'r') as f:
                state = json.load(f)
            
            self.threat_patterns = state['threat_patterns']
            self.reconstruction_threshold = state['reconstruction_threshold']
            self.threshold_multiplier = state['threshold_multiplier']
            
            self.logger.info(f"Detector state loaded from {path}")
            
        except Exception as e:
            self.logger.error(f"Error loading detector state: {str(e)}")
            raise 