# SOC IoT Device Discovery Toolkit

A modular Security Operations Center toolkit for discovering and cataloging IoT devices on a network. Built for collaborative development with a focus on robust scanning, detailed device fingerprinting, and professional data management.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)
8. [Database Schema](#database-schema)
9. [Module Documentation](#module-documentation)
10. [API Reference](#api-reference)
11. [Contributing](#contributing)
12. [Troubleshooting](#troubleshooting)
13. [License](#license)

---

## Overview

This toolkit provides automated network reconnaissance capabilities specifically designed for IoT device discovery within enterprise and home network environments. It leverages industry-standard tools like Nmap for comprehensive network scanning and device fingerprinting.

### Use Cases

- Network asset inventory management
- IoT device security auditing
- Shadow IT detection
- Network topology mapping
- Vulnerability assessment preparation

---

## Features

### Network Discovery
- Automatic network interface detection
- CIDR range identification and selection
- Multiple interface support (Ethernet, WiFi, Virtual)
- Hotspot and connected network monitoring

### Device Scanning
- Deep port scanning using Nmap
- MAC address extraction
- Vendor/Manufacturer identification via OUI lookup
- Device type classification
- Operating system fingerprinting
- Service detection on open ports

### Data Management
- PostgreSQL database backend
- Scan history with unique identifiers (timestamp-based)
- Device tracking across multiple scans
- Export capabilities (CSV, JSON)

### User Interface
- Streamlit-based web interface
- Real-time scan progress monitoring
- Historical scan comparison
- Detailed device information views
- Interface and CIDR selection controls

---

## Architecture

```
soc_iot_toolkit/
|-- app.py                      # Streamlit application entry point
|-- config/
|   |-- __init__.py
|   |-- settings.py             # Configuration management
|   |-- database.yaml           # Database configuration template
|-- core/
|   |-- __init__.py
|   |-- interface_manager.py    # Network interface detection
|   |-- cidr_manager.py         # CIDR identification and management
|   |-- process_manager.py      # Scan process management
|-- scanners/
|   |-- __init__.py
|   |-- base_scanner.py         # Abstract scanner base class
|   |-- nmap_scanner.py         # Nmap implementation
|   |-- device_fingerprint.py   # Device type identification
|   |-- vendor_lookup.py        # MAC vendor resolution
|-- database/
|   |-- __init__.py
|   |-- models.py               # SQLAlchemy ORM models
|   |-- connection.py           # Database connection management
|   |-- operations.py           # CRUD operations
|-- ui/
|   |-- __init__.py
|   |-- components.py           # Reusable UI components
|   |-- pages/
|       |-- __init__.py
|       |-- dashboard.py        # Main dashboard
|       |-- scan_view.py        # Scan execution and monitoring
|       |-- history.py          # Historical scan browser
|       |-- device_details.py   # Individual device view
|-- utils/
|   |-- __init__.py
|   |-- logger.py               # Logging configuration
|   |-- validators.py           # Input validation
|   |-- exporters.py            # Data export utilities
|-- tests/
|   |-- __init__.py
|   |-- test_scanners.py
|   |-- test_database.py
|   |-- test_core.py
```

---

## Prerequisites

### System Requirements

- Linux operating system (Ubuntu 20.04+ recommended)
- Python 3.9 or higher
- Docker and Docker Compose (for PostgreSQL)
- Nmap 7.80 or higher
- Root/sudo privileges for network scanning

### Required System Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y nmap python3-dev python3-venv

# Install Docker (if not installed)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# Fedora/RHEL
sudo dnf install -y nmap python3-devel docker docker-compose

# Arch Linux
sudo pacman -S nmap python docker docker-compose
```

---

## Installation

### Quick Setup (Recommended)

```bash
# Clone and enter directory
git clone https://github.com/your-org/soc-iot-toolkit.git
cd soc-iot-toolkit

# Run automated setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Start the application
sudo ./scripts/run.sh
```

The setup script will:
1. Check and install dependencies
2. Create Python virtual environment
3. Start PostgreSQL in Docker
4. Initialize database schema
5. Provide run instructions

### Manual Setup

#### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/soc-iot-toolkit.git
cd soc-iot-toolkit
```

#### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 4: Start PostgreSQL with Docker

```bash
# Start the database container
docker compose up -d

# Verify it is running
docker ps | grep soc_iot_postgres
```

#### Step 5: Configure Environment Variables

```bash
cp .env.example .env
# Edit .env if you changed database credentials in docker-compose.yml
```

#### Step 6: Initialize Database

```bash
python -m soc_iot_toolkit.database.init_db
```

#### Step 7: Run the Application

```bash
# Requires sudo for network scanning capabilities
sudo $(which streamlit) run app.py --server.port 8501
```

### Alternative: Manual PostgreSQL Setup (Without Docker)

If you prefer not to use Docker:

```bash
# Install PostgreSQL
sudo apt-get install -y postgresql postgresql-contrib libpq-dev

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE USER soc_toolkit WITH PASSWORD 'soc_toolkit_pass';
CREATE DATABASE soc_iot_db OWNER soc_toolkit;
GRANT ALL PRIVILEGES ON DATABASE soc_iot_db TO soc_toolkit;
EOF
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=soc_iot_db
DB_USER=soc_toolkit
DB_PASSWORD=your_secure_password

# Application Settings
LOG_LEVEL=INFO
SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=3

# Nmap Settings
NMAP_PATH=/usr/bin/nmap
NMAP_ARGUMENTS=-sS -sV -O -T4
```

### Database Configuration

Edit `config/database.yaml`:

```yaml
database:
  host: localhost
  port: 5432
  name: soc_iot_db
  user: soc_toolkit
  pool_size: 5
  max_overflow: 10
```

---

## Usage

### Starting the Application

```bash
# Development mode
sudo streamlit run app.py

# Production mode
sudo streamlit run app.py --server.headless true --server.port 8501
```

### Performing a Network Scan

1. Open the web interface at `http://localhost:8501`
2. Navigate to the Scan page
3. Select a network interface from the dropdown
4. Choose a CIDR range from the detected networks
5. Configure scan options (port range, scan intensity)
6. Click "Start Scan" to begin
7. Monitor progress in real-time

### Viewing Scan Results

1. Navigate to the History page
2. Select a scan by its ID (format: SCAN_YYYYMMDD_HHMMSS)
3. View discovered devices with full details
4. Export results as needed

---

## Database Schema

### Tables

#### scans

| Column | Type | Description |
|--------|------|-------------|
| scan_id | VARCHAR(50) | Primary key, format: SCAN_YYYYMMDD_HHMMSS |
| interface | VARCHAR(50) | Network interface used |
| cidr | VARCHAR(50) | CIDR range scanned |
| start_time | TIMESTAMP | Scan start timestamp |
| end_time | TIMESTAMP | Scan end timestamp |
| status | VARCHAR(20) | Status: running, completed, failed |
| total_hosts | INTEGER | Number of hosts discovered |

#### devices

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| scan_id | VARCHAR(50) | Foreign key to scans |
| ip_address | INET | Device IP address |
| mac_address | MACADDR | Device MAC address |
| vendor | VARCHAR(255) | Vendor from OUI lookup |
| manufacturer | VARCHAR(255) | Manufacturer details |
| device_name | VARCHAR(255) | Hostname or device name |
| device_type | VARCHAR(100) | Classification (router, camera, etc.) |
| os_info | VARCHAR(255) | Operating system details |
| last_seen | TIMESTAMP | Last detection timestamp |

#### ports

| Column | Type | Description |
|--------|------|-------------|
| id | SERIAL | Primary key |
| device_id | INTEGER | Foreign key to devices |
| port_number | INTEGER | Port number |
| protocol | VARCHAR(10) | TCP/UDP |
| state | VARCHAR(20) | open, closed, filtered |
| service | VARCHAR(100) | Service name |
| version | VARCHAR(255) | Service version |

---

## Module Documentation

### Core Modules

#### interface_manager.py
Handles detection and management of network interfaces.

```python
from core.interface_manager import InterfaceManager

manager = InterfaceManager()
interfaces = manager.get_available_interfaces()
active_interface = manager.get_active_interface()
```

#### cidr_manager.py
Manages CIDR range detection and validation.

```python
from core.cidr_manager import CIDRManager

cidr_mgr = CIDRManager(interface='eth0')
available_cidrs = cidr_mgr.detect_cidrs()
```

### Scanner Modules

#### nmap_scanner.py
Primary scanning implementation using Nmap.

```python
from scanners.nmap_scanner import NmapScanner

scanner = NmapScanner(cidr='192.168.1.0/24')
results = scanner.execute_scan()
```

#### vendor_lookup.py
MAC address to vendor resolution.

```python
from scanners.vendor_lookup import VendorLookup

lookup = VendorLookup()
vendor = lookup.get_vendor('AA:BB:CC:DD:EE:FF')
```

---

## API Reference

### InterfaceManager

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| get_available_interfaces() | None | List[dict] | Returns all network interfaces |
| get_active_interface() | None | str | Returns primary active interface |
| set_interface(name) | name: str | bool | Sets the working interface |
| get_interface_details(name) | name: str | dict | Returns interface configuration |

### CIDRManager

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| detect_cidrs() | None | List[str] | Detects available CIDR ranges |
| validate_cidr(cidr) | cidr: str | bool | Validates CIDR notation |
| get_host_count(cidr) | cidr: str | int | Returns host count in range |

### NmapScanner

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| execute_scan() | None | ScanResult | Performs network scan |
| get_progress() | None | float | Returns scan progress (0-100) |
| cancel_scan() | None | bool | Cancels running scan |

---

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make changes following the coding standards
5. Run tests: `pytest tests/`
6. Submit a pull request

### Coding Standards

- Follow PEP 8 style guidelines
- Use type hints for all function signatures
- Document all public methods with docstrings
- Maintain test coverage above 80%

### Module Development Guidelines

Each module should:
- Be self-contained with minimal external dependencies
- Include comprehensive error handling
- Provide logging at appropriate levels
- Include unit tests in the tests/ directory

---

## Troubleshooting

### Common Issues

#### Permission Denied for Network Scanning
```
Error: Operation not permitted
Solution: Run with sudo privileges
```

#### Database Connection Failed
```
Error: psycopg2.OperationalError: connection refused
Solution: Verify PostgreSQL is running and credentials are correct
```

#### Nmap Not Found
```
Error: nmap command not found
Solution: Install nmap and verify path in configuration
```

#### Interface Not Detected
```
Error: No network interfaces found
Solution: Check network configuration and driver installation
```

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Acknowledgments

- Nmap Project for network scanning capabilities
- IEEE for OUI database
- Streamlit for the web framework
- PostgreSQL for database management

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-04 | Initial release |

---

## Contact

For issues and feature requests, please use the GitHub issue tracker.
