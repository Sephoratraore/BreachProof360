# 🔐 BreachProof360: Network Vulnerability Scanner

A beginner-friendly network vulnerability scanner designed to help small businesses and learners identify open ports and running services on any device or server.

## ✅ Issue Fixed: Permission Denied Error

**Problem:** The error `[Errno 13] Permission denied: 'BreachProof360.py'` was occurring because `BreachProof360.py` was a directory instead of a file.

**Solution Applied:**
1. ✅ Removed the `BreachProof360.py/` directory
2. ✅ Renamed `.gitattributes.py` to `BreachProof360.py` (proper main application file)
3. ✅ Created proper `.gitattributes` file for Git configuration
4. ✅ Updated `.gitignore` with comprehensive Python project ignores

## 🚀 Features

- **Quick Scan**: Scan common ports (22, 80, 443, 3389, 445)
- **Full Scan**: Comprehensive scan of ports 1-1024
- **Network Discovery**: Discover all devices on your local network
- **Device Classification**: Automatically identify device types (Windows, Linux, Printers, Routers, etc.)
- **Risk Assessment**: Color-coded risk levels (High 🔴, Medium 🟡, Low 🟢)
- **Export Reports**: Download scan results as CSV files
- **Threat Intelligence**: Integration with AbuseIPDB for IP reputation checks

## 📋 Prerequisites

### Required Software

1. **Python 3.8+**
2. **Nmap** - Download from [nmap.org](https://nmap.org/download.html)
   - Windows: Install to default location (`C:\Program Files\Nmap\`)
   - Add to PATH if installed elsewhere

### Python Dependencies

Install required packages:

```bash
pip install streamlit python-nmap pandas requests psutil
```

Or create a virtual environment (recommended):

```bash
python -m venv venv
venv\Scripts\activate  # On Windows
pip install streamlit python-nmap pandas requests psutil
```

## 🎯 Usage

### Running the Application

```bash
streamlit run BreachProof360.py
```

The application will open in your default web browser at `http://localhost:8501`

### Scanning Targets

1. **Enter Target**: Input an IP address (e.g., `8.8.8.8`) or domain name (e.g., `scanme.nmap.org`)
2. **Choose Scan Type**:
   - ⚡ **Quick Scan**: Fast scan of common ports
   - 🧭 **Full Scan**: Comprehensive scan (takes longer)
   - 🌐 **Network Discovery**: Find all devices on your network
3. **View Results**: See open ports, services, versions, and risk levels
4. **Export**: Download results as CSV for reporting

### Testing API Integration

To test the AbuseIPDB integration:

```bash
# Set your API key as environment variable
set ABUSEIPDB_API_KEY=your_api_key_here

# Run the test script
python test_api.py
```

## 🛡️ Security & Compliance

BreachProof360 uses trusted, publicly available security resources:
- **CISA Known Exploited Vulnerabilities (KEV)** - U.S. government catalog
- **AbuseIPDB** - Crowdsourced malicious IP database
- **AlienVault OTX** - Community-driven threat intelligence

### Responsible Use
- ✅ Only scan systems you own or have explicit permission to test
- ✅ Respect API rate limits and terms of service
- ✅ Use results to improve security, never to exploit vulnerabilities
- ✅ Comply with legal and ethical penetration testing guidelines

## 📁 Project Structure

```
BreachProof360/
├── BreachProof360.py          # Main Streamlit application
├── test_api.py                # AbuseIPDB API testing script
├── README.md                  # This file
├── TODO.md                    # Task tracking
├── .gitignore                 # Git ignore rules
├── .gitattributes             # Git attributes configuration
├── Legal compliance statement # Legal and compliance information
└── app.py/                    # Additional resources
```

## 🐛 Troubleshooting

### "nmap.exe not found" Error
- Ensure Nmap is installed from [nmap.org](https://nmap.org/download.html)
- Verify installation path: `C:\Program Files\Nmap\nmap.exe`
- Or add Nmap to your system PATH

### Slow Scan Performance
- **Quick Scan should complete in 5-15 seconds**
- If scans are slow, see [PERFORMANCE_TIPS.md](PERFORMANCE_TIPS.md) for optimization strategies
- Test with `scanme.nmap.org` or `127.0.0.1` for fastest results
- Check your network connection and firewall settings

### Permission Errors
- Run Command Prompt or PowerShell as Administrator
- Ensure you have permission to scan the target network
- Check firewall settings if scans fail

### Import Errors
- Verify all dependencies are installed: `pip list`
- Reinstall packages: `pip install --upgrade streamlit python-nmap pandas requests psutil`

## 📝 License

This tool is for educational and authorized security assessment purposes only.

## 🤝 Contributing

Contributions are welcome! Please ensure all scans are performed ethically and legally.

---

**BreachProof360** - Always scan responsibly and with proper authorization.
