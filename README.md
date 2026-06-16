# OMNI-SCAN v2.0 - Advanced Internet Scanner & Exploitation Platform

**For Authorized Security Testing Only**

## Overview

OMNI-SCAN is a comprehensive network reconnaissance and exploitation platform built with Python, Streamlit, and advanced async/await patterns. It combines port scanning, service detection, vulnerability assessment, exploit testing, and cloud resource discovery into a single unified interface.

## Features

### 🔎 Port Scanning

- **Async Port Scanner** - Fast, multi-threaded scanning
- **Service Detection** - Automatic service identification
- **Banner Grabbing** - Extract service information
- **Version Detection** - Identify software versions
- **Stealth Scanning** - SYN scans using Scapy (requires root/admin)

### 🎯 Advanced Scanning

- **OAuth Endpoint Discovery** - Locate and analyze OAuth configurations
- **Cloud Resource Detection** - Find S3 buckets, GCS, Azure resources
- **IoT Device Identification** - Detect IoT devices with default credentials
- **SSL/TLS Analysis** - Certificate enumeration
- **HTTP Header Analysis** - Security header detection

### 💉 Exploitation

- **Default Credential Testing** - SSH, MySQL, PostgreSQL, MongoDB, Redis, FTP
- **Web Service Testing** - Form-based auth attempts
- **Zombie Network Management** - Track compromised hosts
- **Automated Exploit Chain** - Run multiple exploits sequentially

### 📊 Analytics & Reporting

- **Real-time Dashboard** - Live scan results
- **Vulnerability Severity Heatmaps** - Visual risk assessment
- **GeoIP Mapping** - Geographic threat analysis
- **OS Fingerprinting** - Operating system detection
- **Data Export** - JSON/CSV export functionality

## Installation

### Prerequisites

- Python 3.10+
- Linux/Unix environment (macOS/WSL2 supported)
- Root/Admin access (for stealth scanning with Scapy)

### Setup

1. **Clone and navigate:**

```bash
cd omni_scan_complete
```

1. **Create virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

1. **Install dependencies:**

```bash
pip install -r requirements.txt
```

1. **Optional: Install system dependencies**

```bash
# Ubuntu/Debian
sudo apt-get install nmap libpcap-dev

# macOS
brew install nmap libpcap

# Kali (already included)
nmap --version
```

## Usage

### Launch Streamlit App

```bash
streamlit run app.py
```

The application will open at `http://localhost:8501`

### Command-line Usage

You can also use the scanner modules directly in Python:

```python
import asyncio
from scanners import OmniScanner

async def scan():
    scanner = OmniScanner()
    result = await scanner.full_scan("8.8.8.8")
    print(result)

asyncio.run(scan())
```

## Configuration

### Scanner Settings

- **Max Threads**: Adjust concurrent scanning threads (10-500)
- **Timeout**: Set connection timeout (1-10 seconds)
- **Port Selection**: Choose from presets (Top 100/1000, Common, Custom)

### Exploit Testing

- **Default Credentials**: Customize in `utils.py` (IOTDetector.DEFAULT_CREDS)
- **Target Services**: Configure service-specific tests in `exploits.py`
- **Vulnerability Database**: Update in `scanners.py` (VulnerabilityScanner.KNOWN_VULNS)

## Project Structure

```
omni_scan_complete/
├── app.py                 # Streamlit web application
├── database.py            # SQLite database operations
├── scanners.py           # Core scanning engines
├── exploits.py           # Exploitation framework
├── utils.py              # Utility functions & helpers
├── requirements.txt      # Python dependencies
├── README.md             # This file
└── omni_scan.db          # SQLite database (generated)
```

## Module Reference

### database.py

- `Database` - SQLite database management
  - `init_tables()` - Create database schema
  - `insert_host()` - Add/update host
  - `insert_port()` - Record open port
  - `insert_vulnerability()` - Log vulnerability
  - `insert_credentials()` - Store found credentials
  - `get_statistics()` - Database statistics
  - `export_json()` - Export host data

### scanners.py

- `PortScanner` - Async port scanning
  - `scan_port()` - Single port scan
  - `scan_ip()` - Full IP scan
  - `scan_subnet()` - Subnet scanning
- `ServiceDetector` - Service identification
  - `get_banner()` - Grab service banner
  - `detect_service()` - Identify service
  - `extract_version()` - Get version info
- `WebScanner` - Web service analysis
  - `scan_web_service()` - Full HTTP/HTTPS scan
  - OAuth, cloud resource detection
- `OmniScanner` - Main orchestrator
  - `full_scan()` - Complete target scan
  - `scan_range()` - Multiple IPs

### exploits.py

- `ExploitEngine` - Credential testing
  - `test_ssh()` - SSH default creds
  - `test_mysql()` - MySQL default creds
  - `test_mongodb()` - MongoDB unauthenticated
  - `test_redis()` - Redis unauthenticated
  - `run_all_tests()` - Run all available exploits
- `ZombieManager` - Compromised host tracking
  - `add_zombie()` - Register compromised host
  - `list_zombies()` - View all zombies
  - `get_stats()` - Zombie network statistics

### utils.py

- `GeoIP` - Geographic IP lookup
- `BannerGrabber` - Service banner extraction
- `URLParser` - Extract endpoints & OAuth config
- `CloudDetector` - S3/GCS/Azure detection
- `IOTDetector` - IoT device identification
- `VersionDetector` - Software version extraction

## Performance Tips

### Optimize Scanning Speed

1. Use `Max Threads: 200-300` for large IP ranges
1. Reduce timeout to 2s for faster scanning
1. Use `Top 100` ports preset for quick discovery
1. Run scans during off-peak hours

### Database Optimization

1. Periodically export and clear data
1. Use indexed queries for large datasets
1. Enable WAL mode for concurrent access

### Memory Management

1. Scan in smaller IP ranges (< 256 hosts per batch)
1. Limit concurrent exploits to avoid connection exhaustion
1. Clear zombie network after analysis

## Security Considerations

### Responsible Use

- **Authorization**: Only scan systems you own or have written permission to test
- **Rate Limiting**: Adjust scan rates to avoid triggering IDS/WAF
- **Logging**: Monitor target logs during testing
- **Data Handling**: Secure sensitive credentials found during scans

### Network Safety

- Use VPN/Proxy for remote scanning
- Avoid scanning critical production systems
- Test exploit payloads in controlled lab first
- Disable aggressive scanning on sensitive networks

### Legal Compliance

- Comply with local laws and regulations
- Maintain proper documentation of authorization
- Report findings responsibly
- Follow bug bounty program rules

## Troubleshooting

### “Port already in use” Error

```bash
streamlit run app.py --server.port 8502
```

### Async Runtime Errors

Ensure Python 3.10+ and Windows Python paths are correct

### Permission Denied (Scapy)

Stealth scanning requires root:

```bash
sudo python3 -m streamlit run app.py
```

### Database Locked

Multiple instances accessing database:

```bash
# Use separate database files per instance
export OMNI_DB_PATH="omni_scan_instance2.db"
```

### Import Errors

Install missing dependencies:

```bash
pip install --upgrade -r requirements.txt
```

## Advanced Usage

### Custom Scan Profile

```python
from scanners import OmniScanner

scanner = OmniScanner()

# Custom port list
custom_ports = [22, 80, 443, 3306, 5432, 27017, 6379]
result = await scanner.full_scan("10.0.0.1", ports=custom_ports)
```

### Batch Scanning

```python
import asyncio

async def batch_scan():
    scanner = OmniScanner()
    ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    
    tasks = [scanner.full_scan(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    
    return results
```

### Export Scan Results

```python
import json

# Export from Streamlit
db = Database()
export_data = db.export_json(host_id=1)

with open("scan_results.json", "w") as f:
    json.dump(export_data, f, indent=2)
```

## API Reference

### Quick Start Example

```python
import asyncio
from scanners import OmniScanner
from exploits import ExploitEngine
from database import Database

async def main():
    # Initialize
    scanner = OmniScanner()
    exploits = ExploitEngine()
    db = Database()
    
    # Scan target
    result = await scanner.full_scan("8.8.8.8")
    
    # Store results
    host_id = db.insert_host(result["target"])
    
    for port_info in result["ports"]:
        db.insert_port(host_id, port_info["port"], port_info["service"])
    
    # Test exploits
    creds = exploits.test_ssh("8.8.8.8", 22)
    if creds:
        db.insert_credentials(host_id, None, "SSH", creds[0], creds[1])
    
    # Get stats
    stats = db.get_statistics()
    print(f"Scan complete: {stats}")

asyncio.run(main())
```

## Contributing

To extend OMNI-SCAN:

1. Add new scanner class to `scanners.py`
1. Register in `OmniScanner` orchestrator
1. Add corresponding database schema in `database.py`
1. Create Streamlit UI in `app.py`

## License

**Authorized Use Only** - This tool is designed for authorized security professionals conducting legitimate penetration testing and bug bounty work.

## Disclaimer

Users are responsible for legal compliance. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse of this tool.

-----

**OMNI-SCAN v2.0** | Advanced Offensive Security Platform | [zwanski.bio](https://zwanski.bio)