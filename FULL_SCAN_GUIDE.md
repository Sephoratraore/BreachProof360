# 🧭 Full Scan - Complete Testing Guide

## What is Full Scan?

Full Scan is the most comprehensive scanning feature in BreachProof360. It performs an in-depth analysis of your target by scanning 1024 ports and detecting service versions.

---

## 🎯 Step-by-Step Testing Guide

### Step 1: Access the Application
1. Open your browser
2. Navigate to: **http://localhost:8501**
3. You should see the BreachProof360 interface

### Step 2: Prepare Your Test Target

**Recommended Test Targets:**

#### Safe Public Test Target:
```
scanme.nmap.org
```
- This is Nmap's official test server
- Safe and legal to scan
- Will show multiple open ports

#### Your Local Machine:
```
127.0.0.1
or
localhost
```
- Scan your own computer
- See what services you're running
- Completely safe and legal

#### Google DNS (Limited Results):
```
8.8.8.8
```
- Will show minimal results
- Good for testing "no ports found" scenario

### Step 3: Run the Full Scan

1. **Enter Target:**
   - Click in the "Target IP or Domain" field
   - Type: `scanme.nmap.org`
   - Press Enter or click outside the field

2. **Click Full Scan Button:**
   - Look for the middle button: **"🧭 Full Scan"**
   - Click it once

3. **Wait for Scan:**
   - You'll see a status message: "Full scanning scanme.nmap.org..."
   - A progress indicator will appear
   - This takes **1-3 minutes** - be patient!

4. **View Results:**
   - Once complete, you'll see "Full scan complete!"
   - Results will appear below

---

## 📊 Understanding Full Scan Results

### What You'll See:

#### 1. Scan Summary
```
✅ Scan completed for scanme.nmap.org
Resolved IP: 45.33.32.156
```

#### 2. Open Ports Table
Columns include:
- **Port** - Port number and protocol (e.g., 22/tcp)
- **Service** - Service name (e.g., ssh, http)
- **Product** - Software running (e.g., Apache httpd)
- **Version** - Version number (e.g., 2.4.7)
- **State** - Port state (open)
- **Description** - What the service does
- **Risk** - Security risk level:
  - 🔴 **High Risk** - Ports like FTP (21), Telnet (23), RDP (3389)
  - 🟡 **Medium Risk** - Ports like HTTP (80), SMTP (25)
  - 🟢 **Low Risk** - Ports like HTTPS (443)

#### 3. Device Classification
```
Device Classification: Linux/Unix-like device
Reasoning: 22 SSH
```

#### 4. Security Summary
```
🔴 High Risk: 0
🟡 Medium Risk: 2
🟢 Low Risk: 1
📊 Total Ports: 3
```

#### 5. Export Option
- Button to download results as CSV
- Filename includes timestamp

---

## 🧪 Test Scenarios

### Test 1: Successful Full Scan
**Target:** `scanme.nmap.org`
**Expected Result:**
- Multiple open ports found (typically 22, 80, 443, 9929, 31337)
- Service versions detected
- Device classified as "Linux/Unix-like device"
- Risk summary shows breakdown

### Test 2: Local Machine Scan
**Target:** `127.0.0.1`
**Expected Result:**
- Shows services running on your computer
- May include ports like 135, 445 (Windows) or 22 (Linux)
- Device classification based on your OS

### Test 3: Minimal Results
**Target:** `8.8.8.8`
**Expected Result:**
- May show "No open ports found" or very few results
- This is normal - Google's DNS is heavily firewalled

### Test 4: Invalid Target
**Target:** `invalid.domain.test`
**Expected Result:**
- "DNS lookup failed" or scan error
- No results displayed

### Test 5: Empty Target
**Target:** (leave blank)
**Expected Result:**
- Warning message: "Please enter a target."
- Scan doesn't start

---

## 🔍 What Full Scan Does Behind the Scenes

### Nmap Command Used:
```bash
nmap -sT -Pn -p 1-1024 --open --max-retries 1 --host-timeout 45s -sV --version-light [target]
```

### Parameters Explained:
- `-sT` - TCP connect scan (doesn't require admin privileges)
- `-Pn` - Skip ping, assume host is up
- `-p 1-1024` - Scan ports 1 through 1024
- `--open` - Only show open ports
- `--max-retries 1` - Try each port once
- `--host-timeout 45s` - Maximum time per host
- `-sV` - Detect service versions
- `--version-light` - Use light version detection (faster)

---

## 🆚 Full Scan vs Quick Scan Comparison

| Feature | Quick Scan | Full Scan |
|---------|-----------|-----------|
| **Ports Scanned** | 5 ports (22,80,443,3389,445) | 1024 ports (1-1024) |
| **Speed** | 10-30 seconds | 1-3 minutes |
| **Service Detection** | Basic | Detailed with versions |
| **Nmap Args** | `-T4 --max-retries 0` | `-sV --version-light` |
| **Best For** | Quick security check | Comprehensive audit |
| **Detail Level** | Basic port status | Full service information |

---

## ⚠️ Important Notes

### Legal & Ethical:
- ✅ **DO** scan your own devices
- ✅ **DO** scan scanme.nmap.org (official test server)
- ✅ **DO** scan with permission
- ❌ **DON'T** scan unauthorized targets
- ❌ **DON'T** scan production systems without approval

### Technical:
- **Requires Nmap:** Must be installed on your system
- **Takes Time:** Full scan is slower but more thorough
- **Firewall:** May trigger Windows Firewall prompts
- **Permissions:** Some scans may need admin privileges

### Performance:
- **Network Speed:** Affects scan time
- **Target Response:** Slow targets take longer
- **Firewall Rules:** May block some probes

---

## 🐛 Troubleshooting Full Scan

### "nmap.exe not found"
**Problem:** Nmap is not installed
**Solution:** 
1. Download from https://nmap.org/download.html
2. Install using default path
3. Restart BreachProof360

### Scan Takes Forever
**Problem:** Target is slow or unreachable
**Solution:**
- Try a different target
- Use Quick Scan instead
- Check your internet connection

### No Results Found
**Problem:** Target has no open ports or is firewalled
**Solution:**
- This is normal for heavily secured systems
- Try scanme.nmap.org to verify scanning works
- Check if target is reachable (ping it first)

### Permission Denied
**Problem:** Some scans need elevated privileges
**Solution:**
- Run Command Prompt as Administrator
- Then run: `streamlit run BreachProof360.py`

---

## 📈 Advanced Usage Tips

### 1. Compare Scans
- Run Quick Scan first (fast overview)
- Then run Full Scan (detailed analysis)
- Compare results to see what Full Scan finds

### 2. Export and Analyze
- Download CSV after Full Scan
- Open in Excel or Google Sheets
- Sort by Risk level to prioritize fixes

### 3. Regular Audits
- Run Full Scan weekly on your systems
- Track changes over time
- Identify new services or vulnerabilities

### 4. Network Mapping
- Use Network Discovery first
- Then Full Scan each discovered device
- Build complete network inventory

---

## ✅ Full Scan Testing Checklist

Use this checklist to verify Full Scan works correctly:

- [ ] Application loads at http://localhost:8501
- [ ] "🧭 Full Scan" button is visible
- [ ] Can enter target in input field
- [ ] Clicking Full Scan shows status message
- [ ] Scan completes within 1-3 minutes
- [ ] Results table displays with all columns
- [ ] Service versions are shown
- [ ] Risk levels are color-coded correctly
- [ ] Device classification appears
- [ ] Security summary shows metrics
- [ ] Export CSV button works
- [ ] Downloaded CSV contains all data
- [ ] Can run multiple scans in sequence
- [ ] Clear Results button works

---

## 🎓 What to Look For

### Good Security (Low Risk):
- Only necessary ports open
- Services are up-to-date
- No high-risk ports (21, 23, 3389)
- HTTPS (443) instead of HTTP (80)

### Security Concerns (High Risk):
- 🔴 FTP (21) - Unencrypted file transfer
- 🔴 Telnet (23) - Unencrypted remote access
- 🔴 RDP (3389) - Common attack target
- 🟡 HTTP (80) - Unencrypted web traffic
- Many unnecessary ports open

---

## 📞 Need Help?

If Full Scan isn't working:
1. Check Nmap is installed: `nmap --version`
2. Verify target is reachable: `ping scanme.nmap.org`
3. Check firewall isn't blocking
4. Review terminal output for errors
5. Try Quick Scan first to verify basic functionality

---

**Happy Scanning! 🔐**

*Remember: Always scan responsibly and with proper authorization.*
