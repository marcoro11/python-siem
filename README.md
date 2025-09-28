# Python SIEM

This project implements a custom Security Information and Event Management (SIEM) system using Python. It's designed to collect logs from various sources, parse them into a usable format, analyze the data for security events and anomalies, and provide alerts.  The goal is to give you a flexible platform for monitoring your systems without relying on commercial SIEM solutions.

## Project Structure

```
python-siem/
├── src/
│   ├── collectors/          # Module for collecting log data
│   ├── parsers/             # Module for parsing log data
│   ├── analyzers/           # Module for analyzing parsed data
│   │   ├── anomaly_detector.py   # Detects anomalies in logs
│   │   ├── correlation_engine.py # Correlates multiple events
│   │   └── rules.py              # Security detection rules  
│   ├── storage/             # Module for database interactions
│   ├── enrichment/          # Module for enriching log data
│   │   └── threat_intel.py  # Threat intelligence integration
│   ├── alert/               # Module for alert notifications
│   ├── api/                 # REST API for integrations
│   └── main.py              # Entry point of the application
├── config/                  # Configuration files
│   └── config.yaml          # Configuration settings for the SIEM
├── data/                    # Data files for the application
│   └── blocklists/          # IP blocklists for threat intelligence
│       ├── botnet_ips.txt
│       ├── spamhaus_drop.txt
│       └── tor_exit_nodes.txt
├── grafana/                 # Grafana visualization dashboards
│   ├── dashboards/          # Dashboard JSON definitions
│   │   └── siem_overview.json
│   └── provisioning/        # Grafana provisioning configuration
├── test_logs/               # Sample logs for testing
├── docker-compose.yml       # Docker Compose configuration
├── test_all.sh              # Script to generate test logs
├── Grafana_Dashboard.png    # Screenshot of Grafana dashboard
└── Pipfile                  # Python dependencies (Pipenv)
```

## Features

*   **Log Collection**: Supports collecting logs from files and syslog sources.
*   **Log Parsing**: Parses log entries into structured data for easier analysis.
*   **Anomaly Detection**: Analyzes parsed data using customizable security rules to identify suspicious activity.
*   **Event Correlation**: Correlates multiple events to detect complex attack patterns and reduce false positives.
*   **Threat Intelligence**: Enriches logs with data from threat intelligence sources to identify known malicious IPs and domains.
*   **Database Storage**: Stores logs in a PostgreSQL database for efficient querying and analysis.
*   **Alert Notifications**: Sends alerts when anomalies are detected.
*   **REST API**: Provides a REST API for external integrations and data access.
*   **Grafana Dashboards**: Includes comprehensive Grafana dashboards for visualizing SIEM data and monitoring security events.

## Getting Started

### Prerequisites

*   Python 3.12 or higher
*   Docker & Docker Compose (recommended for easy setup)

### Installation

#### Docker Installation

1.  Clone the repository and navigate to the directory:
    ```bash
    git clone https://github.com/marcoro11/python-siem.git
    cd python-siem
    ```
2.  Start the containers:
    ```bash
    docker-compose up -d
    ```

### Configuration

Edit `config/config.yaml` to configure:

*   Database connection settings
*   Log file paths and sources
*   Alert thresholds and notification settings
*   Threat intelligence sources
*   API settings

## Usage

### Running the SIEM

To run the SIEM application:
```bash
pipenv run python src/main.py
```

### Generating Test Logs

To generate comprehensive sample logs for testing the SIEM:
```bash
./test_all.sh
```

### Accessing Grafana Dashboards

1. Open your web browser and navigate to `http://localhost:3000`.
2. Log in with your Grafana credentials (default: admin/admin).
3. Navigate to the "SIEM Overview Dashboard" to view:
   - Real-time alert statistics
   - Log volume and distribution
   - Security event timelines
   - Threat intelligence detections
   - System performance metrics

### Using the REST API

The SIEM provides a REST API for external integrations:

- **Health check**: `GET /api/health`
- **Query logs**: `GET /api/logs?start_time=2025-01-01&end_time=2025-01-02&level=ERROR`
- **Query alerts**: `GET /api/alerts?severity=high&limit=50`

## Grafana Dashboard Screenshot

Below is a screenshot of the Grafana dashboard showcasing the SIEM's visualization capabilities:

![Grafana Dashboard](Grafana_Dashboard.png)
