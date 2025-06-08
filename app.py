from flask import Flask, render_template, jsonify, request
import psutil
from datetime import datetime, timedelta
import socket
from modules.data_collection import NetworkDataCollector
from modules.traffic_classifier import HybridTrafficClassifier
from modules.threat_detector import ThreatDetector
import logging
import json
import os
import threading
import time
from typing import Dict
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Also enable Flask debug mode
app = Flask(__name__)
app.debug = True

class NetworkMonitor:
    def __init__(self, config_path: str = 'config.json'):
        """Initialize the network monitoring system."""
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.current_threats = {
            'anomalies': [],
            'port_scans': [],
            'ddos': [],
            'data_exfiltration': [],
            'high_traffic': []
        }
        self.initialize_components()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return {
                'network': {
                    'interface': None,
                    'flow_timeout': 600
                },
                'threat_detection': {
                    'threshold': 0.8,
                    'window_size': 300
                }
            }

    def initialize_components(self):
        """Initialize all system components."""
        try:
            # Initialize data collector
            network_config = self.config.get('network', {})
            self.collector = NetworkDataCollector(
                interface=network_config.get('interface'),
                flow_timeout=network_config.get('flow_timeout', 600)
            )
            
            # Initialize traffic classifier
            self.classifier = HybridTrafficClassifier()
            
            # Initialize threat detector
            self.detector = ThreatDetector(
                config=self.config.get('threat_detection', {})
            )
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {str(e)}")
            raise

    def get_stats(self):
        """Get current network and system statistics."""
        try:
            # Get network stats
            network_stats = self.collector.get_flow_features()
            if not network_stats:
                return None

            # Get system stats
            stats = {
                'system': {
                    'cpu_percent': psutil.cpu_percent(interval=0.1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'connections_established': len([conn for conn in psutil.net_connections() 
                                                 if conn.status == 'ESTABLISHED'])
                },
                'network': {
                    network_stats['interface']: network_stats
                }
            }

            # Get traffic classifications
            try:
                traffic_data = {
                    'bytes_sent_rate': network_stats['bytes_sent_rate'],
                    'bytes_recv_rate': network_stats['bytes_recv_rate'],
                    'packets_sent_rate': network_stats['packets_sent_rate'],
                    'packets_recv_rate': network_stats['packets_recv_rate']
                }
                classifications = self.classifier.predict(traffic_data)
                stats['classifications'] = {
                    'types': list(set(classifications)) if classifications else [],
                    'counts': {t: classifications.count(t) for t in set(classifications)} if classifications else {}
                }
            except Exception as e:
                self.logger.error(f"Error classifying traffic: {str(e)}")
                stats['classifications'] = {'types': [], 'counts': {}}

            # Update threat detection
            try:
                new_threats = self.detector.detect_threats(network_stats)
                if new_threats:
                    for threat_type, threats in new_threats.items():
                        if threat_type in self.current_threats:
                            # Add new threats with timestamp
                            for threat in threats:
                                if isinstance(threat, dict):
                                    threat['timestamp'] = datetime.now().isoformat()
                                    self.current_threats[threat_type].append(threat)
                            
                            # Keep only last 100 threats
                            self.current_threats[threat_type] = self.current_threats[threat_type][-100:]

                stats['threats'] = self.current_threats
            except Exception as e:
                self.logger.error(f"Error detecting threats: {str(e)}")
                stats['threats'] = self.current_threats

            # Get active connections
            try:
                stats['connections'] = self.collector.get_connection_details()
            except Exception as e:
                self.logger.error(f"Error getting connections: {str(e)}")
                stats['connections'] = []

            return stats
        except Exception as e:
            self.logger.error(f"Error getting stats: {str(e)}")
            return None

    def train_models(self):
        """Train the ML models with latest data."""
        try:
            # Get latest network stats
            network_stats = self.collector.get_flow_features()
            if network_stats:
                # Train threat detector
                self.detector.train(network_stats)
                
                # Train traffic classifier if we have labeled data
                # self.classifier.train(network_stats)
                
                self.logger.info("Models trained with latest data")
        except Exception as e:
            self.logger.error(f"Error training models: {str(e)}")

monitor = NetworkMonitor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats')
def get_stats():
    """Get current network and system statistics."""
    stats = monitor.get_stats()
    return jsonify(stats)

@app.route('/interfaces')
def get_interfaces():
    """Get available network interfaces."""
    interfaces = monitor.collector.get_available_interfaces()
    return jsonify(interfaces)

@app.route('/interface/<interface_name>', methods=['POST'])
def change_interface(interface_name):
    """Change the monitored network interface."""
    success = monitor.collector.change_interface(interface_name)
    return jsonify({'success': success})

def periodic_tasks():
    """Run periodic tasks like model training."""
    while True:
        try:
            monitor.train_models()
            time.sleep(300)  # Train every 5 minutes
        except Exception as e:
            logging.error(f"Error in periodic tasks: {str(e)}")
            time.sleep(60)

if __name__ == '__main__':
    try:
        # Start periodic tasks in a separate thread
        tasks_thread = threading.Thread(target=periodic_tasks)
        tasks_thread.daemon = True
        tasks_thread.start()
        
        # Start Flask app
        app.run(host='0.0.0.0', port=5000)
    except Exception as e:
        logging.error(f"Error starting application: {str(e)}")
        raise 