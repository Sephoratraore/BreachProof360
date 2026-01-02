import streamlit as st
import nmap
import os
import pandas as pd
import time
import socket
import ipaddress
import shutil
from datetime import datetime, timedelta
import threading
import hashlib
import json
import requests
from typing import Dict, List, Optional

# Configure Streamlit page
st.set_page_config(page_title="BreachProof360", layout="centered")

# Scan cache configuration
CACHE_DURATION_MINUTES = 10
SCAN_CACHE = {}
THREAT_INTEL_CACHE = {}

# Threat Intelligence Configuration
THREAT_INTEL_APIS = {
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/check",
        "key": os.getenv("ABUSEIPDB_API_KEY", ""),  # Set via environment variable
        "enabled": False  # Will be enabled if API key is present
    },
    "virustotal": {
        "url": "https://www.virustotal.com/api/v3/ip_addresses/",
        "key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "enabled": False
    }
}

# CVE Database (sample - in production, use NVD API)
CVE_DATABASE = {
    21: ["CVE-2023-1234: FTP Anonymous Login", "CVE-2022-5678: FTP Buffer Overflow"],
    22: ["CVE-2023-2345: SSH Weak Encryption", "CVE-2021-3156: Sudo Heap Overflow"],
    23: ["CVE-2023-3456: Telnet Remote Code Execution"],
    80: ["CVE-2023-4567: HTTP Server Vulnerability"],
    443: ["CVE-2023-5678: SSL/TLS Heartbleed"],
    3389: ["CVE-2019-0708: BlueKeep RDP Vulnerability", "CVE-2023-6789: RDP Authentication Bypass"],
    445: ["CVE-2017-0144: EternalBlue SMB Vulnerability", "CVE-2023-7890: SMB Remote Code Execution"],
    3306: ["CVE-2023-8901: MySQL Authentication Bypass"],
    5432: ["CVE-2023-9012: PostgreSQL SQL Injection"],
}

def get_cache_key(target, scan_type):
    """Generate cache key for scan results"""
    return hashlib.md5(f"{target}:{scan_type}".encode()).hexdigest()

def get_cached_result(target, scan_type):
    """Retrieve cached scan result if valid"""
    cache_key = get_cache_key(target, scan_type)
    if cache_key in SCAN_CACHE:
        cached_data = SCAN_CACHE[cache_key]
        cache_time = cached_data.get("timestamp")
        if cache_time and datetime.now() - cache_time < timedelta(minutes=CACHE_DURATION_MINUTES):
            return cached_data.get("result")
    return None

def cache_result(target, scan_type, result):
    """Cache scan result with timestamp"""
    cache_key = get_cache_key(target, scan_type)
    SCAN_CACHE[cache_key] = {
        "timestamp": datetime.now(),
        "result": result
    }

def get_ip_geolocation(ip: str) -> Dict:
    """Get geolocation information for an IP address"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "as": data.get("as", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            }
    except Exception as e:
        pass
    return {"country": "Unknown", "region": "Unknown", "city": "Unknown", "isp": "Unknown", "org": "Unknown", "as": "Unknown", "lat": 0, "lon": 0}

def check_ip_reputation(ip: str) -> Dict:
    """Check IP reputation using threat intelligence APIs"""
    cache_key = f"threat_{ip}"
    
    # Check cache first
    if cache_key in THREAT_INTEL_CACHE:
        cached_data = THREAT_INTEL_CACHE[cache_key]
        if datetime.now() - cached_data["timestamp"] < timedelta(hours=24):
            return cached_data["result"]
    
    reputation = {
        "threat_score": 0,
        "is_malicious": False,
        "abuse_reports": 0,
        "threat_categories": [],
        "last_seen": "Never",
        "confidence": "Unknown"
    }
    
    try:
        # Try AbuseIPDB
        if THREAT_INTEL_APIS["abuseipdb"]["enabled"]:
            headers = {
                "Key": THREAT_INTEL_APIS["abuseipdb"]["key"],
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            response = requests.get(
                THREAT_INTEL_APIS["abuseipdb"]["url"],
                headers=headers,
                params=params,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                reputation["threat_score"] = data.get("abuseConfidenceScore", 0)
                reputation["abuse_reports"] = data.get("totalReports", 0)
                reputation["is_malicious"] = reputation["threat_score"] > 50
                reputation["last_seen"] = data.get("lastReportedAt", "Never")
    except Exception as e:
        pass
    
    # Simulate threat intelligence for demo purposes
    # In production, integrate with real APIs
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            reputation["confidence"] = "Low Risk (Private IP)"
            reputation["threat_score"] = 0
        else:
            # Simulate some threat scoring based on IP characteristics
            reputation["confidence"] = "Medium"
            reputation["threat_score"] = 15  # Low default score
    except:
        pass
    
    # Cache the result
    THREAT_INTEL_CACHE[cache_key] = {
        "timestamp": datetime.now(),
        "result": reputation
    }
    
    return reputation

def get_port_vulnerabilities(port: int) -> List[str]:
    """Get known CVEs for a specific port/service"""
    return CVE_DATABASE.get(port, [])

def calculate_risk_score(open_ports: List[int], ip_reputation: Dict) -> Dict:
    """Calculate overall risk score based on open ports and IP reputation"""
    risk_score = 0
    risk_factors = []
    
    # Port-based risk
    high_risk_ports = {21, 23, 3389, 445, 1433, 3306, 5432}
    medium_risk_ports = {22, 25, 80, 110, 143, 8080}
    
    for port in open_ports:
        if port in high_risk_ports:
            risk_score += 30
            risk_factors.append(f"High-risk port {port} is open")
        elif port in medium_risk_ports:
            risk_score += 10
            risk_factors.append(f"Medium-risk port {port} is open")
        
        # Check for known vulnerabilities
        cves = get_port_vulnerabilities(port)
        if cves:
            risk_score += len(cves) * 5
            risk_factors.append(f"Port {port} has {len(cves)} known CVEs")
    
    # IP reputation risk
    threat_score = ip_reputation.get("threat_score", 0)
    if threat_score > 75:
        risk_score += 50
        risk_factors.append("IP has very high threat score")
    elif threat_score > 50:
        risk_score += 30
        risk_factors.append("IP has high threat score")
    elif threat_score > 25:
        risk_score += 15
        risk_factors.append("IP has moderate threat score")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = "🔴 CRITICAL"
        color = "red"
    elif risk_score >= 50:
        risk_level = "🟠 HIGH"
        color = "orange"
    elif risk_score >= 25:
        risk_level = "🟡 MEDIUM"
        color = "yellow"
    else:
        risk_level = "🟢 LOW"
        color = "green"
    
    return {
        "score": min(risk_score, 100),
        "level": risk_level,
        "color": color,
        "factors": risk_factors
    }

def _find_nmap():
    """Find nmap executable in common installation paths"""
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        shutil.which("nmap"),
    ]
    return next((c for c in candidates if c and os.path.exists(c)), None)

def scan_target(target: str, args: str, progress_callback=None):
    """Perform nmap scan on target with given arguments"""
    nmap_path = _find_nmap()
    if not nmap_path:
        return {"error": "nmap.exe not found. Install Nmap or add it to PATH."}

    nm = nmap.PortScanner(nmap_search_path=[nmap_path])
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = "DNS lookup failed"

    try:
        start_time = time.time()
        nm.scan(hosts=target, arguments=args)
        scan_duration = time.time() - start_time
        
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, info in nm[host][proto].items():
                    if info.get("state") == "open":
                        results.append({
                            "host": host, 
                            "proto": proto,
                            "port": int(port), 
                            "name": info.get("name", ""),
                            "product": info.get("product", "N/A"),
                            "version": info.get("version", "N/A"),
                            "state": info.get("state", "")
                        })
        
        result = {
            "resolved_ip": resolved_ip,
            "results": results,
            "scan_duration": round(scan_duration, 2),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        } if results else {
            "note": f"No open ports found",
            "resolved_ip": resolved_ip,
            "scan_duration": round(scan_duration, 2),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return result
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

def _get_local_subnet_guess():
    """Guess the local subnet for network discovery"""
    try:
        import psutil
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "family", None) == 2:
                    ip, mask = getattr(a, "address", ""), getattr(a, "netmask", "")
                    if ip.startswith(("10.", "172.", "192.168.")) and mask:
                        import ipaddress as ipa
                        return str(ipa.IPv4Network(f"{ip}/{mask}", strict=False))
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip.startswith(("10.", "172.", "192.168.")):
            a, b, c, _ = ip.split(".")
            return f"{a}.{b}.{c}.0/24"
    except Exception:
        pass
    return "192.168.1.0/24"

def discover_network(subnet: str = None):
    """Discover devices on the network"""
    nmap_path = _find_nmap()
    if not nmap_path:
        return {"error": "nmap.exe not found. Install Nmap or add it to PATH."}

    nm = nmap.PortScanner(nmap_search_path=[nmap_path])
    target_subnet = subnet or _get_local_subnet_guess()
    
    try:
        nm.scan(hosts=target_subnet, arguments="-sn")
        hosts = []
        for host in nm.all_hosts():
            state = nm[host].state()
            mac = nm[host]["addresses"].get("mac", "Unknown")
            vendor = nm[host].get("vendor", {}).get(mac, "Unknown")
            hosts.append({"ip": host, "state": state, "mac": mac, "vendor": vendor})
        return {"subnet": target_subnet, "hosts": hosts}
    except Exception as e:
        return {"error": f"Network discovery failed: {str(e)}"}

def classify_device(open_ports: set, ip: str):
    """Classify device type based on open ports"""
    label, why = "Unknown device", []
    try: 
        is_private = ipaddress.ip_address(ip).is_private
    except: 
        is_private = True

    if 135 in open_ports or 445 in open_ports:
        label = "Windows PC / Server"
        if 135 in open_ports: why.append("135 MSRPC")
        if 445 in open_ports: why.append("445 SMB")
    elif {9100, 515, 631} & open_ports:
        label = "Printer"
        if 9100 in open_ports: why.append("9100 raw print")
        if 631 in open_ports: why.append("631 IPP")
        if 515 in open_ports: why.append("515 LPR")
    elif 53 in open_ports and (80 in open_ports or 443 in open_ports):
        label = "Router / DNS appliance"
        why.append("53 + web mgmt")
    elif {80, 443, 8080, 8443} & open_ports:
        label = "Web-managed device"
        if is_private: why.append("private IP (likely router/IoT)")
    elif 3389 in open_ports: 
        label = "Windows (RDP)"
        why.append("3389 RDP")
    elif 22 in open_ports and 135 not in open_ports and 445 not in open_ports:
        label = "Linux/Unix-like device"
        why.append("22 SSH")
    elif 53 in open_ports: 
        label = "DNS server"
        why.append("53 DNS")
    
    return label, why

def get_port_info(port):
    """Get port description and severity"""
    PORT_DESCRIPTIONS = {
        21: "FTP - File Transfer Protocol",
        22: "SSH - Secure Shell",
        23: "Telnet - Unencrypted text communication",
        25: "SMTP - Simple Mail Transfer Protocol",
        53: "DNS - Domain Name System",
        80: "HTTP - World Wide Web",
        110: "POP3 - Post Office Protocol",
        143: "IMAP - Internet Message Access Protocol",
        443: "HTTPS - HTTP Secure",
        993: "IMAPS - IMAP over SSL",
        995: "POP3S - POP3 over SSL",
        1433: "MSSQL - Microsoft SQL Server",
        3306: "MySQL - Database",
        3389: "RDP - Remote Desktop Protocol",
        5432: "PostgreSQL - Database",
        8080: "HTTP Alternate"
    }
    
    PORT_SEVERITY = {
        21: "high",     # FTP - Often unencrypted
        23: "high",     # Telnet - Unencrypted
        25: "medium",   # SMTP - Can be exploited for spam
        80: "medium",   # HTTP - Unencrypted
        110: "medium",  # POP3 - Often unencrypted
        143: "medium",  # IMAP - Often unencrypted
        443: "low",     # HTTPS - Encrypted
        3389: "high",   # RDP - Common target for attacks
        5900: "medium"  # VNC - Remote desktop
    }
    
    description = PORT_DESCRIPTIONS.get(port, "")
    severity = PORT_SEVERITY.get(port, "low")
    
    if severity == "high":
        color = "🔴"
    elif severity == "medium":
        color = "🟡"
    else:
        color = "🟢"
    
    return description, severity, color

# Initialize session state
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "network_results" not in st.session_state:
    st.session_state.network_results = None
if "force_rescan" not in st.session_state:
    st.session_state.force_rescan = False
if "scan_profile" not in st.session_state:
    st.session_state.scan_profile = "quick"

# App Title and Introduction
st.title("🔐 BreachProof360: Vulnerability Scanner")

with st.expander("ℹ️ What is BreachProof360?"):
    st.write("""
    **BreachProof360** is a beginner-friendly network vulnerability scanner designed to help small businesses and learners identify open ports and running services on any device or server.

    🛡️ Use it to:
    - Check for exposed services that hackers might target.
    - Identify connected devices and discover their manufacturers.
    - Scan for open ports and flag high risk configurations.

    ⚠️ This tool uses **Nmap** under the hood — a powerful scanning utility trusted by cybersecurity professionals.

    **Always scan responsibly and with permission.**
    """)

# Scan Profile Selection
st.subheader("🎯 Select Scan Profile")
scan_profiles = {
    "lightning": {
        "name": "⚡ Lightning Scan",
        "description": "Ultra-fast (2-3 sec) - Ports 80, 443 only",
        "args": "-sT -Pn -p 80,443 --open --max-retries 0 --host-timeout 3s -T5 --min-rate 1000",
        "ports": "80, 443",
        "time": "2-3 seconds"
    },
    "quick": {
        "name": "🚀 Quick Scan",
        "description": "Fast (3-8 sec) - Common ports",
        "args": "-sT -Pn -p 22,80,443,3389,445 --open --max-retries 0 --host-timeout 5s -T5 --min-rate 1000",
        "ports": "22, 80, 443, 3389, 445",
        "time": "3-8 seconds"
    },
    "balanced": {
        "name": "⚖️ Balanced Scan",
        "description": "Moderate (30-60 sec) - Top 100 ports",
        "args": "-sT -Pn --top-ports 100 --open --max-retries 1 --host-timeout 20s -T4",
        "ports": "Top 100 common ports",
        "time": "30-60 seconds"
    },
    "full": {
        "name": "🧭 Full Scan",
        "description": "Thorough (2-5 min) - Ports 1-1024 + versions",
        "args": "-sT -Pn -p 1-1024 --open --max-retries 1 --host-timeout 30s -sV --version-light -T4",
        "ports": "1-1024",
        "time": "2-5 minutes"
    },
    "deep": {
        "name": "🔍 Deep Scan",
        "description": "Comprehensive (10+ min) - All 65535 ports",
        "args": "-sT -Pn -p- --open --max-retries 2 --host-timeout 60s -sV --version-light -T3",
        "ports": "1-65535",
        "time": "10+ minutes"
    }
}

profile_cols = st.columns(5)
for idx, (key, profile) in enumerate(scan_profiles.items()):
    with profile_cols[idx]:
        if st.button(
            profile["name"],
            key=f"profile_{key}",
            help=f"{profile['description']}\nPorts: {profile['ports']}\nEstimated time: {profile['time']}",
            use_container_width=True
        ):
            st.session_state.scan_profile = key

# Display selected profile info
selected_profile = scan_profiles[st.session_state.scan_profile]
st.info(f"**Selected:** {selected_profile['name']} - {selected_profile['description']}")

# Target Input
col_target, col_force = st.columns([4, 1])
with col_target:
    target = st.text_input(
        "Target IP or Domain",
        key="main_target_input",
        placeholder="scanme.nmap.org or 8.8.8.8",
        help="Enter an IP address or domain name to scan"
    )
with col_force:
    st.write("")  # Spacing
    st.write("")  # Spacing
    force_rescan = st.checkbox("Force Rescan", help="Bypass cache and perform fresh scan")

# Scan Buttons
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("🚀 Start Scan", key="start_scan_btn", type="primary", use_container_width=True):
        if not target.strip():
            st.warning("Please enter a target.")
        else:
            # Check cache first
            cached_result = None if force_rescan else get_cached_result(target, st.session_state.scan_profile)
            
            if cached_result:
                st.session_state.scan_results = cached_result
                st.success("✅ Loaded from cache (scan completed within last 10 minutes)")
            else:
                profile = scan_profiles[st.session_state.scan_profile]
                with st.status(f"Scanning {target} with {profile['name']}...", expanded=True) as status:
                    st.write(f"⏱️ Estimated time: {profile['time']}")
                    st.write(f"🔍 Scanning ports: {profile['ports']}")
                    st.write("⚡ Scanning in progress...")
                    
                    start_time = time.time()
                    
                    # Perform the actual scan
                    result = scan_target(target, profile["args"])
                    st.session_state.scan_results = result
                    
                    # Cache the result
                    cache_result(target, st.session_state.scan_profile, result)
                    
                    elapsed = time.time() - start_time
                    status.update(label=f"✅ Scan complete in {elapsed:.2f} seconds!", state="complete")

with col2:
    if st.button("🌐 Network Discovery", key="network_scan_btn", use_container_width=True):
        with st.status("Discovering network devices...", expanded=True) as status:
            st.write("🔍 Scanning local network...")
            st.write("⚡ Discovery in progress...")
            
            st.session_state.network_results = discover_network()
            status.update(label="✅ Network discovery complete!", state="complete")

with col3:
    if st.button("🗑️ Clear Cache", key="clear_cache_btn", use_container_width=True):
        SCAN_CACHE.clear()
        st.success("Cache cleared!")
        time.sleep(1)
        st.rerun()

# Display Scan Results
if st.session_state.scan_results:
    data = st.session_state.scan_results
    
    # Handle errors
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    elif isinstance(data, dict) and "note" in data and "results" not in data:
        st.info(data["note"])
        col1, col2, col3 = st.columns(3)
        col1.metric("🌐 Resolved IP", data.get('resolved_ip', '?'))
        col2.metric("⏱️ Scan Duration", f"{data.get('scan_duration', 0)}s")
        col3.metric("📅 Scan Time", data.get('scan_time', 'N/A'))
    else:
        # Display results with metrics
        st.success(f"✅ Scan completed for {target}")
        
        resolved_ip = data.get('resolved_ip', '?')
        
        # Get threat intelligence
        with st.spinner("🔍 Gathering threat intelligence..."):
            geo_info = get_ip_geolocation(resolved_ip)
            ip_reputation = check_ip_reputation(resolved_ip)
        
        # Scan metrics
        metric_cols = st.columns(5)
        metric_cols[0].metric("🌐 Resolved IP", resolved_ip)
        metric_cols[1].metric("⏱️ Duration", f"{data.get('scan_duration', 0)}s")
        metric_cols[2].metric("📅 Scan Time", data.get('scan_time', 'N/A'))
        metric_cols[3].metric("🔍 Profile", scan_profiles[st.session_state.scan_profile]["name"])
        
        # Threat score
        threat_score = ip_reputation.get("threat_score", 0)
        threat_color = "🔴" if threat_score > 75 else "🟠" if threat_score > 50 else "🟡" if threat_score > 25 else "🟢"
        metric_cols[4].metric("🛡️ Threat Score", f"{threat_color} {threat_score}/100")
        
        # Geolocation Information
        st.subheader("🌍 Geolocation & Network Information")
        geo_cols = st.columns(4)
        geo_cols[0].metric("🌎 Country", geo_info.get("country", "Unknown"))
        geo_cols[1].metric("🏙️ City", geo_info.get("city", "Unknown"))
        geo_cols[2].metric("🏢 ISP", geo_info.get("isp", "Unknown")[:20])
        geo_cols[3].metric("🔢 ASN", geo_info.get("as", "Unknown")[:20])
        
        results = data.get("results", [])
        if results:
            # Create enhanced dataframe with port information
            enhanced_results = []
            for result in results:
                port = result["port"]
                description, severity, color = get_port_info(port)
                enhanced_results.append({
                    "Port": f"{port}/{result['proto']}",
                    "Service": result["name"],
                    "Product": result["product"],
                    "Version": result["version"],
                    "State": result["state"],
                    "Description": description,
                    "Risk": f"{color} {severity.title()}"
                })
            
            df = pd.DataFrame(enhanced_results)
            st.dataframe(df, use_container_width=True)
            
            # Device classification
            ports = set(result["port"] for result in results)
            label, why = classify_device(ports, data.get("resolved_ip", ""))
            st.info(f"**Device Classification:** {label}")
            if why:
                st.caption("Reasoning: " + " • ".join(why))
            
            # Calculate overall risk score
            open_port_numbers = [result["port"] for result in results]
            risk_assessment = calculate_risk_score(open_port_numbers, ip_reputation)
            
            # Security Summary
            st.subheader("🛡️ Security Assessment")
            
            # Overall Risk Score
            st.markdown(f"### Overall Risk Level: {risk_assessment['level']}")
            st.progress(risk_assessment['score'] / 100)
            
            risk_cols = st.columns(2)
            with risk_cols[0]:
                st.metric("🎯 Risk Score", f"{risk_assessment['score']}/100")
                st.metric("⚠️ Risk Factors", len(risk_assessment['factors']))
            
            with risk_cols[1]:
                high_risk = sum(1 for r in enhanced_results if "🔴" in r["Risk"])
                medium_risk = sum(1 for r in enhanced_results if "🟡" in r["Risk"])
                low_risk = sum(1 for r in enhanced_results if "🟢" in r["Risk"])
                st.metric("🔴 High Risk Ports", high_risk)
                st.metric("🟡 Medium Risk Ports", medium_risk)
            
            # Risk Factors
            if risk_assessment['factors']:
                st.subheader("⚠️ Identified Risk Factors")
                for factor in risk_assessment['factors']:
                    st.warning(factor)
            
            # CVE Information
            st.subheader("🔒 Known Vulnerabilities (CVEs)")
            cve_found = False
            for result in results:
                port = result["port"]
                cves = get_port_vulnerabilities(port)
                if cves:
                    cve_found = True
                    with st.expander(f"⚠️ Port {port} - {len(cves)} Known CVEs"):
                        for cve in cves:
                            st.error(f"• {cve}")
            
            if not cve_found:
                st.success("✅ No known CVEs found for open ports")
            
            # Threat Intelligence Details
            if ip_reputation.get("threat_score", 0) > 0:
                st.subheader("🕵️ Threat Intelligence")
                threat_cols = st.columns(3)
                threat_cols[0].metric("🚨 Abuse Reports", ip_reputation.get("abuse_reports", 0))
                threat_cols[1].metric("📊 Confidence", ip_reputation.get("confidence", "Unknown"))
                threat_cols[2].metric("👁️ Last Seen", ip_reputation.get("last_seen", "Never")[:10])
                
                if ip_reputation.get("is_malicious", False):
                    st.error("⚠️ WARNING: This IP has been reported for malicious activity!")
            
            # Port Statistics
            st.subheader("📊 Port Statistics")
            stat_cols = st.columns(4)
            stat_cols[0].metric("📊 Total Ports", len(results))
            stat_cols[1].metric("🔴 High Risk", high_risk)
            stat_cols[2].metric("🟡 Medium Risk", medium_risk)
            stat_cols[3].metric("🟢 Low Risk", low_risk)
            
            # Export functionality
            st.subheader("📥 Export Results")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create comprehensive report
            report_data = {
                "Scan Information": {
                    "Target": target,
                    "Resolved IP": resolved_ip,
                    "Scan Time": data.get('scan_time', 'N/A'),
                    "Scan Duration": f"{data.get('scan_duration', 0)}s",
                    "Profile": scan_profiles[st.session_state.scan_profile]["name"]
                },
                "Geolocation": geo_info,
                "Threat Intelligence": ip_reputation,
                "Risk Assessment": risk_assessment,
                "Open Ports": enhanced_results
            }
            
            # JSON Export
            json_data = json.dumps(report_data, indent=2)
            
            export_cols = st.columns(2)
            with export_cols[0]:
                csv_data = df.to_csv(index=False)
                st.download_button(
                    label="📄 Download CSV Report",
                    data=csv_data,
                    file_name=f"breachproof360_scan_{timestamp}.csv",
                    mime="text/csv",
                    key="download_scan_csv"
                )
            
            with export_cols[1]:
                st.download_button(
                    label="📋 Download JSON Report",
                    data=json_data,
                    file_name=f"breachproof360_scan_{timestamp}.json",
                    mime="application/json",
                    key="download_scan_json"
                )
        else:
            st.info("No open ports found.")

# Display Network Discovery Results
if st.session_state.network_results:
    data = st.session_state.network_results
    
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    else:
        st.success(f"🌐 Network Discovery Results")
        st.caption(f"Subnet scanned: {data.get('subnet', '?')}")
        
        hosts = data.get("hosts", [])
        if hosts:
            df_hosts = pd.DataFrame(hosts)
            st.dataframe(df_hosts, use_container_width=True)
            
            # Export network results
            st.subheader("📥 Export Network Results")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_data = df_hosts.to_csv(index=False)
            st.download_button(
                label="Download Network CSV",
                data=csv_data,
                file_name=f"breachproof360_network_{timestamp}.csv",
                mime="text/csv",
                key="download_network_csv"
            )
        else:
            st.info("No devices found on the network.")

# Clear Results Button
if st.session_state.scan_results or st.session_state.network_results:
    if st.button("🗑️ Clear Results", key="clear_results_btn"):
        st.session_state.scan_results = None
        st.session_state.network_results = None
        st.rerun()

# Footer
st.markdown("---")
st.markdown("**BreachProof360** - Always scan responsibly and with proper authorization.")
