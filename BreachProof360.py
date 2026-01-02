import streamlit as st
import nmap
import os
import pandas as pd
import time
import socket
import ipaddress
import shutil
from datetime import datetime

# Configure Streamlit page
st.set_page_config(page_title="BreachProof360", layout="centered")

def _find_nmap():
    """Find nmap executable in common installation paths"""
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        shutil.which("nmap"),
    ]
    return next((c for c in candidates if c and os.path.exists(c)), None)

def scan_target(target: str, args: str):
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
        nm.scan(hosts=target, arguments=args)
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
        
        return {"resolved_ip": resolved_ip, "results": results} if results else {
            "note": f"No open ports found with: {args}", "resolved_ip": resolved_ip
        }
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

# Target Input (with unique key)
target = st.text_input(
    "Target IP or Domain",
    key="main_target_input",
    placeholder="8.8.8.8 or scanme.nmap.org",
    help="Enter an IP address or domain name to scan"
)

# Scan Buttons (with unique keys)
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("⚡ Quick Scan", key="quick_scan_btn", help="Scan common ports (22,80,443,3389,445)"):
        if not target.strip():
            st.warning("Please enter a target.")
        else:
            with st.status(f"Quick scanning {target}...", expanded=True) as status:
                args = "-sT -Pn -p 22,80,443,3389,445 --open --max-retries 0 --host-timeout 10s -T4"
                st.session_state.scan_results = scan_target(target, args)
                status.update(label="Quick scan complete!", state="complete")

with col2:
    if st.button("🧭 Full Scan", key="full_scan_btn", help="Scan ports 1-1024"):
        if not target.strip():
            st.warning("Please enter a target.")
        else:
            with st.status(f"Full scanning {target}...", expanded=True) as status:
                args = "-sT -Pn -p 1-1024 --open --max-retries 1 --host-timeout 45s -sV --version-light"
                st.session_state.scan_results = scan_target(target, args)
                status.update(label="Full scan complete!", state="complete")

with col3:
    if st.button("🌐 Network Discovery", key="network_scan_btn", help="Discover devices on your network"):
        with st.status("Discovering network devices...", expanded=True) as status:
            st.session_state.network_results = discover_network()
            status.update(label="Network discovery complete!", state="complete")

# Display Scan Results
if st.session_state.scan_results:
    data = st.session_state.scan_results
    
    # Handle errors
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    elif isinstance(data, dict) and "note" in data and "results" not in data:
        st.info(data["note"])
        st.caption(f"Resolved IP: {data.get('resolved_ip', '?')}")
    else:
        # Display results
        st.success(f"✅ Scan completed for {target}")
        st.caption(f"Resolved IP: {data.get('resolved_ip', '?')}")
        
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
            
            # Security Summary
            st.subheader("🛡️ Security Summary")
            high_risk = sum(1 for r in enhanced_results if "🔴" in r["Risk"])
            medium_risk = sum(1 for r in enhanced_results if "🟡" in r["Risk"])
            low_risk = sum(1 for r in enhanced_results if "🟢" in r["Risk"])
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("🔴 High Risk", high_risk)
            col2.metric("🟡 Medium Risk", medium_risk)
            col3.metric("🟢 Low Risk", low_risk)
            col4.metric("📊 Total Ports", len(results))
            
            # Export functionality
            st.subheader("📥 Export Results")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_data = df.to_csv(index=False)
            st.download_button(
                label="Download CSV Report",
                data=csv_data,
                file_name=f"breachproof360_scan_{timestamp}.csv",
                mime="text/csv",
                key="download_scan_csv"
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
