import streamlit as st
import nmap
import os
import pandas as pd
import time
from datetime import datetime

st.set_page_config(page_title="BreachProof360", layout="centered")

# 🔹 App Title
st.title("🔐 BreachProof360: Vulnerability Scanner")

# 🔹 Introduction
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

# 🔹 Common port descriptions
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

# 🔹 Port severity levels (for color coding)
PORT_SEVERITY = {
    21: "high",     # FTP - Often unencrypted
    23: "high",     # Telnet - Unencrypted
    25: "medium",  # SMTP - Can be exploited for spam
    80: "medium",  # HTTP - Unencrypted
    110: "medium", # POP3 - Often unencrypted
    143: "medium", # IMAP - Often unencrypted
    443: "low",    # HTTPS - Encrypted
    3389: "high",  # RDP - Common target for attacks
    5900: "medium" # VNC - Remote desktop
}

# 🔹 User Input
st.write("Enter a target IP address or domain name to scan for open ports and services.")

target = st.text_input("Target IP or Domain")

# 🔹 Scan Button
if st.button("Start Scan"):
    if not target:
        st.warning("Please enter a valid target.")
    else:
        # Record scan start time
        scan_start_time = time.time()
        scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Set the path to nmap executable
        nmap_path = "C:\\Program Files\\Nmap\\nmap.exe"
        if not os.path.exists(nmap_path):
            nmap_path = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
        
        # Initialize PortScanner with the nmap path
        scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
        st.info(f"Scanning {target}...")
        try:
            scanner.scan(hosts=target, arguments='-sV')
            scan_duration = time.time() - scan_start_time
            
            if target in scanner.all_hosts():
                st.success(f"Scan complete for {target}")
                st.markdown(f"**Scan Timestamp:** {scan_timestamp}")
                st.markdown(f"**Scan Duration:** {scan_duration:.2f} seconds")
                
                # Prepare data for export
                scan_results = []
                
                for host in scanner.all_hosts():
                    st.subheader(f"Results for {host}")
                    for proto in scanner[host].all_protocols():
                        ports = scanner[host][proto].keys()
                        for port in sorted(ports):
                            state = scanner[host][proto][port]['state']
                            name = scanner[host][proto][port]['name']
                            product = scanner[host][proto][port].get('product', 'N/A')
                            version = scanner[host][proto][port].get('version', 'N/A')
                            
                            # Get port description
                            description = PORT_DESCRIPTIONS.get(port, "")
                            
                            # Determine severity color
                            severity = PORT_SEVERITY.get(port, "low")
                            if severity == "high":
                                color = "🔴"
                            elif severity == "medium":
                                color = "🟡"
                            else:
                                color = "🟢"
                            
                            # Add to results for export
                            scan_results.append({
                                "IP": host,
                                "Port": port,
                                "Protocol": proto,
                                "State": state,
                                "Service": name,
                                "Product": product,
                                "Version": version,
                                "Description": description,
                                "Severity": severity
                            })
                            
                            # Display port information with color coding and description
                            port_info = f"{color} **Port {port}/{proto}:** {state} - {name}"
                            if product != "N/A":
                                port_info += f" ({product} {version})"
                            if description:
                                port_info += f" - {description}"
                            
                            st.markdown(port_info)
                
                # Create DataFrame for export
                df = pd.DataFrame(scan_results)
                
                # Export options
                st.subheader("Export Scan Results")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="📥 Download CSV Report",
                        data=df.to_csv(index=False),
                        file_name=f"breachproof360_scan_{scan_timestamp.replace(':', '-')}.csv",
                        mime="text/csv"
                    )
                
                with col2:
                    # For PDF export, we'll provide CSV as primary export option
                    # PDF export would require additional libraries like reportlab or weasyprint
            
                    st.download_button(
                        label="📄 Download CSV Report (Alternative)",
                        data=df.to_csv(index=False),
                        file_name=f"breachproof360_scan_{scan_timestamp.replace(':', '-')}.csv",
                        mime="text/csv"
                    )
                # Display summary statistics
                st.subheader("Scan Summary")
                high_risk_ports = len([r for r in scan_results if r["Severity"] == "high"])
                medium_risk_ports = len([r for r in scan_results if r["Severity"] == "medium"])
                low_risk_ports = len([r for r in scan_results if r["Severity"] == "low"])
                
                st.markdown(f"**High Risk Ports:** {high_risk_ports} 🔴")
                st.markdown(f"**Medium Risk Ports:** {medium_risk_ports} 🟡")
                st.markdown(f"**Low Risk Ports:** {low_risk_ports} 🟢")
                st.markdown(f"**Total Ports Found:** {len(scan_results)}")
                
            else:
                st.warning(f"No results found for {target}")
        except Exception as e:
            st.error(f"An error occurred: {e}")

#   # Send email alert
            import socket
            def get_hostname(ip_or_domain):
                try:
                    return socket.getfqdn(ip_or_domain)
                except Exception:
                    return "Unknown"
            hostname = get_hostname(target)
            # Define a placeholder for send_email_alert to avoid NameError
            def send_email_alert(target, scan_data, hostname):
                # Placeholder: Implement email sending logic here
                pass
            send_email_alert(target, df.to_dict('records'), hostname)

import nmap
import os

def scan_target(target):
    nmap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "nmap.exe", "nmap.exe"))
    
    if not os.path.exists(nmap_path):
        return {"error": f"nmap.exe not found at {nmap_path}"}
        
    try:
        scanner = nmap.PortScanner(nmap_search_path=[nmap_path])
        scanner.scan(hosts=target, arguments='-sV')
        results = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service = scanner[host][proto][port]
                    results.append({
                        'ip': host,
                        'port': port,
                        'name': service['name'],
                        'state': service['state'],
                        'product': service.get('product', 'unknown'),
                        'version': service.get('version', 'unknown')
                    })
        return results
    except nmap.nmap.PortScannerError as e:
        return {"error": f"Nmap scan failed: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

