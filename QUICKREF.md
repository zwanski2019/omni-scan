# OMNI-SCAN v2.0 - Quick Reference Guide

## Installation (60 seconds)

### Linux/macOS

```bash
cd omni_scan_complete
chmod +x setup.sh
./setup.sh
source venv/bin/activate
streamlit run app.py
```

### Windows

```bash
cd omni_scan_complete
setup.bat
streamlit run app.py
```

### Docker

```bash
cd omni_scan_complete
docker-compose up -d
# Access at http://localhost:8501
```

-----

## 🔎 Port Scanner Tab

### Quick Scan

1. **Select Scan Type**: Single IP, IP Range, or Subnet
1. **Enter Target**: `8.8.8.8` or `192.168.1.0-192.168.1.10`
1. **Choose Ports**: Top 100 (default) → Top 1000 → Common → Custom
1. **Start Scan**: Click “Start Scan” button
1. **View Results**: Open ports, services, versions, GeoIP

### Port Preset Options

|Preset  |Ports                            |Use Case              |
|--------|---------------------------------|----------------------|
|Top 100 |Most common ports                |Quick reconnaissance  |
|Top 1000|Extended port list               |General scanning      |
|Common  |21,22,80,443,3306,5432,6379,27017|Database/service focus|
|Custom  |User-defined                     |Targeted assessment   |

-----

## 🎯 Full Scan Tab

### Complete Target Analysis

1. **Enter target IP** in input field
1. **Select Scan Profile**:
- **Quick**: Basic port scan only
- **Thorough**: Ports + services + vulns
- **Aggressive**: All features + exploit tests
1. **Click “Start Full Scan”**
1. **View comprehensive results**:
- Open ports & services
- Vulnerabilities & CVEs
- Web service analysis
- OAuth configuration
- Cloud resources detected
- IoT devices found

### Output Breakdown

- **Ports Tab**: List of open ports with service names
- **Vulnerabilities Tab**: Known CVEs for detected services
- **Web Services Tab**: HTTP/HTTPS analysis, endpoints, cloud buckets
- **OAuth Tab**: Discovered OAuth configurations

-----

## 💉 Exploit Engine Tab

### Test Default Credentials

1. **Enter target IP**: `192.168.1.1`
1. **Enter port** (optional): Auto-selects standard ports
1. **Click service button**:
- 🔑 SSH (port 22)
- 🐬 MySQL (port 3306)
- 🔴 Redis (port 6379)
- 🍃 MongoDB (port 27017)
1. **View results**:
- ✅ Credentials found
- ❌ Authentication required
- Data extracted (Redis/MongoDB)

### Run All Tests

- **Button**: “🔥 Run All Tests”
- **Behavior**: Tests all service ports simultaneously
- **Output**: JSON results for each service
- **Zombie Network**: Automatically adds compromised hosts

-----

## 🧟 Zombie Network Tab

### Manage Compromised Hosts

- **Total Zombies**: Active compromised systems
- **By Service**: Distribution (SSH, MySQL, etc.)
- **Zombie List**: IP:Port, Service, Status, Creds

### Zombie Actions

1. Click on zombie for details
1. Use credentials for lateral movement
1. Execute commands on compromised hosts
1. Track exploitation chain

-----

## 📊 Dashboard Tab

### Security Metrics

|Metric           |Shows                 |
|-----------------|----------------------|
|🖥️ Hosts Scanned  |Total unique IPs      |
|✅ Alive Hosts    |Responsive systems    |
|🔌 Open Ports     |Total open ports found|
|⚠️ Vulnerabilities|Critical + High issues|
|🔑 Credentials    |Found working creds   |
|🤖 IoT Devices    |Detected IoT systems  |

### Visualizations

- **Vulnerability Heatmap**: Severity distribution
- **Scan Activity**: Type and count of scans
- **Service Distribution**: Port to service mapping

-----

## ⚙️ Settings Tab

### Scanner Configuration

- **Timeout**: How long to wait for connection (1-10s)
- **Max Threads**: Concurrent connections (10-500)
- **Scan Rate**: Packets per second limit

### Recommended Settings

|Scenario|Timeout|Threads|Rate|
|--------|-------|-------|----|
|Stealth |5-10s  |50     |100 |
|Speed   |1-2s   |300    |5000|
|Balanced|3s     |100    |1000|

### Database Operations

- **View Database**: Current statistics
- **Export Data**: Download as JSON
- **Clear Database**: Remove all scans

-----

## Common Workflows

### Workflow 1: External Perimeter Scan

```
1. Port Scanner → Enter target IP → Select "Top 1000" → Scan
2. View open ports and services
3. Full Scan → Same target → Thorough profile
4. Check vulnerabilities and cloud resources
5. Dashboard → View summary
```

### Workflow 2: Default Credentials Hunt

```
1. Port Scanner → Quick scan to find services
2. Exploit Engine → Enter IP
3. Click service buttons for credentials
4. View Zombie Network for successful compromises
5. Export credentials
```

### Workflow 3: OAuth Security Assessment

```
1. Full Scan → Web services tab
2. Check OAuth configuration endpoints
3. Analyze discovered endpoints
4. Check for missing security headers
5. Document findings
```

### Workflow 4: Cloud Security Review

```
1. Full Scan → Web services tab
2. Look for cloud resource detection
3. Check for S3/GCS bucket exposure
4. Verify bucket permissions
5. Exploit Engine → Test service compromises
```

### Workflow 5: IoT Device Discovery

```
1. Port Scanner → Subnet scan (e.g., 192.168.1.0/24)
2. Full Scan → Check IoT Devices section
3. Exploit Engine → Test device credentials
4. Zombie Network → Track compromised devices
5. Export device inventory
```

-----

## Advanced Features

### Stealth Scanning

- ✓ SYN scans using Scapy
- ✓ Requires root/admin privileges
- ✓ Slower but harder to detect
- ✓ Works on custom ports

### OAuth Endpoint Analysis

- ✓ Automatic endpoint discovery
- ✓ Configuration parsing
- ✓ OIDC well-known endpoint detection
- ✓ Redirect URI extraction
- ✓ Scope enumeration

### Cloud Resource Detection

|Provider    |Detection           |
|------------|--------------------|
|AWS S3      |Bucket names, URLs  |
|Google Cloud|GCS bucket detection|
|Azure       |Blob storage, SQL DB|
|Generic     |Exposed endpoints   |

### IoT Device Recognition

- Hikvision cameras
- Dahua DVRs
- Ubiquiti UniFi
- TP-Link routers
- Netgear devices
- D-Link devices
- Axis cameras

-----

## Keyboard Shortcuts

|Shortcut      |Action           |
|--------------|-----------------|
|`Ctrl+R`      |Refresh dashboard|
|`Ctrl+Shift+R`|Clear cache      |
|`Ctrl+,`      |Settings         |
|`Ctrl+Q`      |Export results   |

-----

## Troubleshooting

### “No open ports found”

- Increase timeout to 5-10s
- Target may be blocking ICMP
- Firewall may be filtering ports
- Try different port preset

### Slow scanning

- Reduce max threads (check network capacity)
- Use fewer ports
- Increase timeout (waits longer per connection)
- Check network bandwidth

### Database errors

- Clear database if corruption
- Check disk space
- Verify write permissions
- Restart application

### Memory issues

- Reduce max threads
- Scan smaller IP ranges
- Clear zombie network
- Export and clear database

-----

## Security Best Practices

### Before Scanning

- ✓ Get written authorization
- ✓ Notify network admins
- ✓ Test on authorized networks first
- ✓ Use VPN for remote scanning

### During Scanning

- ✓ Monitor target systems logs
- ✓ Avoid critical production hours
- ✓ Gradual scan rate increase
- ✓ Document findings

### After Scanning

- ✓ Secure credentials found
- ✓ Report vulnerabilities
- ✓ Recommend remediations
- ✓ Delete sensitive data from database

-----

## Tips & Tricks

### Speed Up Scanning

```
1. Use "Top 100" ports preset
2. Set timeout to 2s
3. Increase max threads to 300
4. Run multiple scans in parallel
```

### Improve Accuracy

```
1. Use "Top 1000" ports preset
2. Set timeout to 5s
3. Run full scan (not quick)
4. Check multiple times for transient issues
```

### Optimize Exploitation

```
1. Start with SSH (port 22)
2. Test database services (3306, 5432)
3. Check NoSQL (27017, 6379)
4. Test web services last
```

-----

## Export & Reporting

### Download Results

1. Go to **Settings** tab
1. Click **📤 Export Data**
1. Select JSON format
1. File saves as `omni_scan_export_YYYYMMDD_HHMMSS.json`

### Create Report

1. Use exported JSON
1. Parse with Python or Excel
1. Create summary tables
1. Add screenshots from dashboard

### Share Results

```python
import json

# Load exported data
with open("omni_scan_export_20240115_120000.json") as f:
    data = json.load(f)

# Extract key findings
vulnerabilities = data.get("vulnerabilities", [])
credentials = data.get("credentials_found", 0)
iot_devices = data.get("iot_devices", 0)

print(f"Summary: {len(vulnerabilities)} vulns, {credentials} creds, {iot_devices} IoT")
```

-----

**OMNI-SCAN v2.0** | For Authorized Security Testing | Use Responsibly