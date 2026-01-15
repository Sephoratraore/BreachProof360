# 🔐 BreachProof360 - Setup & Run Instructions

## Prerequisites

### 1. Install Nmap (Required)
BreachProof360 uses Nmap for network scanning. You must install it first:

**Download Nmap for Windows:**
- Visit: https://nmap.org/download.html
- Download: `nmap-<version>-setup.exe`
- Run the installer and follow the setup wizard
- **Important:** Use the default installation path (C:\Program Files (x86)\Nmap\ or C:\Program Files\Nmap\)

### 2. Install Python Dependencies
Open Command Prompt or PowerShell in this directory and run:

```bash
pip install -r requirements.txt
```

This will install:
- streamlit
- python-nmap
- pandas
- psutil

## Running BreachProof360

### Option 1: Run from Command Prompt/PowerShell
Navigate to this directory and run:

```bash
streamlit run BreachProof360.py
```

### Option 2: Run from VSCode Terminal
1. Open VSCode
2. Open the integrated terminal (Ctrl + `)
3. Navigate to this directory:
   ```bash
   cd "C:\Users\Sephora\Desktop\password_generator.py\BreachProof360"
   ```
4. Run the app:
   ```bash
   streamlit run BreachProof360.py
   ```

### Option 3: Double-click Batch File (Coming Soon)
You can create a `run.bat` file for easy launching.

## What Happens When You Run It?

1. Streamlit will start a local web server
2. Your default browser will automatically open
3. The app will be available at: `http://localhost:8501`
4. You'll see the BreachProof360 interface

## Using BreachProof360

### Quick Scan
- Scans common ports: 22, 80, 443, 3389, 445
- Fast results (10-30 seconds)
- Good for quick security checks

### Full Scan
- Scans ports 1-1024
- Includes service version detection
- Takes longer (1-3 minutes)
- More comprehensive results

### Network Discovery
- Discovers all devices on your local network
- Shows IP addresses, MAC addresses, and vendors
- Useful for network inventory

## Important Notes

⚠️ **Legal & Ethical Use:**
- Only scan networks and devices you own or have permission to scan
- Unauthorized scanning may be illegal in your jurisdiction
- Use responsibly and ethically

🔒 **Administrator Privileges:**
- Some scans may require administrator/elevated privileges
- If you get permission errors, try running Command Prompt as Administrator

🌐 **Firewall Warnings:**
- Windows Firewall may prompt you to allow Python/Streamlit
- Click "Allow access" to enable the web interface

## Troubleshooting

### "nmap.exe not found" Error
**Solution:** Install Nmap from https://nmap.org/download.html

### "Module not found" Error
**Solution:** Run `pip install -r requirements.txt`

### Port Already in Use
**Solution:** Streamlit uses port 8501 by default. If it's busy, run:
```bash
streamlit run BreachProof360.py --server.port 8502
```

### Scan Takes Too Long
**Solution:** Use Quick Scan instead of Full Scan, or scan specific targets rather than entire subnets

## Stopping the App

Press `Ctrl + C` in the terminal where Streamlit is running, or simply close the terminal window.

## Support

For issues or questions:
- Check Nmap installation: `nmap --version` in Command Prompt
- Check Python packages: `pip list | findstr "streamlit nmap pandas psutil"`
- Verify Python version: `python --version` (should be 3.7+)

---

**BreachProof360** - Network Vulnerability Scanner
Always scan responsibly and with proper authorization.
