
# Network Security Monitor Dashboard

A real-time network monitoring system with an interactive dashboard for tracking network statistics, threat detection, and traffic classification.

## Features

- Real-time network interface monitoring
- Network traffic analysis and classification
- Threat detection and alerting
- System resource monitoring
- Interactive dark-themed dashboard
- Network health metrics (latency, packet loss)
- Traffic pattern visualization
- Automated traffic classification using hybrid approach

## Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose (optional, for containerized deployment)
- Network interface with monitoring permissions
- Sufficient system privileges for network packet capture

## Installation

### Option 1: Local Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd network-security-monitor
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows
.\venv\Scripts\activate
# On Unix or MacOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Option 2: Docker Installation

1. Build and run using Docker Compose:
```bash
docker-compose up --build
```

## Configuration

1. Copy `config.json.example` to `config.json` (if not exists)
2. Adjust the configuration parameters in `config.json`:
   - Network interfaces to monitor
   - Logging settings
   - Alert thresholds
   - Update intervals

## Usage

### Running the Application

1. Local execution:
```bash
python app.py
```

2. Access the dashboard:
   - Open a web browser
   - Navigate to `http://localhost:5000`

### Dashboard Features

- **System Stats**: CPU, memory, and disk usage
- **Network Stats**: Interface status, throughput, and health metrics
- **Threat Detection**: Real-time threat monitoring and alerts
- **Traffic Classification**: ML-based traffic pattern analysis
- **Data Export**: Export monitoring data for analysis

## Security Considerations

- Ensure proper network permissions
- Keep dependencies updated
- Review and adjust alert thresholds
- Monitor log files regularly
- Implement access controls as needed

## Troubleshooting

Common issues and solutions:

1. Network Interface Detection
   - Ensure running with sufficient privileges
   - Check interface names in config.json
   - Verify network adapter status

2. Data Collection Issues
   - Check log files in `network_analyzer.log`
   - Verify database connectivity
   - Ensure required ports are accessible

3. Dashboard Not Updating
   - Check browser console for errors
   - Verify WebSocket connectivity
   - Clear browser cache if needed

## Project Structure

```
network-security-monitor/
├── app.py                    # Main application file
├── modules/                  # Core functionality modules
├── static/                   # Static assets (JS, CSS)
│   ├── css/
│   └── js/
├── templates/               # HTML templates
├── data/                   # Data storage
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker configuration
└── docker-compose.yml     # Docker Compose configuration
```

 ## Outcomes

- Successfully implemented a modular, real-time network monitoring system combining classical machine learning and efficient system design.
- Integrated an Isolation Forest model for anomaly detection and a Random Forest classifier for intelligent traffic classification.
- Achieved high precision and recall across multiple traffic categories using live data without relying on external datasets.
- Deployed a responsive Flask-based dashboard for live visualization of system stats, traffic patterns, and threats.

## Limitations

- Does not currently support encrypted traffic inspection or advanced deep learning models for complex threat detection.
- Performance is optimized for academic or small enterprise environments and may require tuning for high-throughput production systems.
- Requires elevated privileges to access low-level packet data, which may limit portability in some OS configurations.
- Limited feature engineering for protocol-specific analysis, which could affect detection depth.

## Future Scope

- Extend support for encrypted traffic analysis using flow-based ML techniques.
- Integrate deep learning models for more robust detection of zero-day and stealthy attacks.
- Add centralized logging and integration with SIEM platforms like Splunk or ELK Stack.
- Enhance dashboard with customizable reporting, user authentication, and multi-interface support.
- Expand dataset variety by incorporating publicly labeled traffic samples for hybrid training.
