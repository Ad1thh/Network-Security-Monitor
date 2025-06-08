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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a Pull Request

## License

[Add your license information here]

## Acknowledgments

- List any third-party tools or libraries used
- Credit contributors or inspiration sources 