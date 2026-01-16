"""
Threat Intelligence Module for BreachProof360
Provides CVE lookups, threat scoring, and security recommendations
"""

import requests
from typing import Dict, List, Tuple
from datetime import datetime

# Offline CVE Database - Common vulnerabilities for popular services
KNOWN_CVES = {
    # SSH vulnerabilities
    "openssh": {
        "7.4": [
            {"cve": "CVE-2018-15473", "severity": "medium", "score": 5.3, 
             "description": "Username enumeration vulnerability"},
        ],
        "7.9": [
            {"cve": "CVE-2020-15778", "severity": "medium", "score": 6.8,
             "description": "Command injection via scp"},
        ],
        "default": [
            {"cve": "CVE-2023-38408", "severity": "high", "score": 9.8,
             "description": "Remote code execution in older versions"},
        ]
    },
    # Apache vulnerabilities
    "apache": {
        "2.4.49": [
            {"cve": "CVE-2021-41773", "severity": "critical", "score": 9.8,
             "description": "Path traversal and RCE vulnerability"},
        ],
        "2.4.50": [
            {"cve": "CVE-2021-42013", "severity": "critical", "score": 9.8,
             "description": "Path traversal and RCE (incomplete fix)"},
        ],
        "default": [
            {"cve": "CVE-2023-25690", "severity": "high", "score": 7.5,
             "description": "HTTP request smuggling vulnerability"},
        ]
    },
    # MySQL vulnerabilities
    "mysql": {
        "5.7": [
            {"cve": "CVE-2023-21980", "severity": "high", "score": 7.1,
             "description": "Privilege escalation vulnerability"},
        ],
        "default": [
            {"cve": "CVE-2023-22084", "severity": "medium", "score": 6.5,
             "description": "Authentication bypass in older versions"},
        ]
    },
    # FTP vulnerabilities
    "vsftpd": {
        "2.3.4": [
            {"cve": "CVE-2011-2523", "severity": "critical", "score": 10.0,
             "description": "Backdoor in vsftpd 2.3.4"},
        ],
        "default": [
            {"cve": "CVE-2015-1419", "severity": "high", "score": 7.5,
             "description": "Denial of service vulnerability"},
        ]
    },
    # Windows RDP
    "ms-wbt-server": {
        "default": [
            {"cve": "CVE-2019-0708", "severity": "critical", "score": 9.8,
             "description": "BlueKeep - Remote code execution"},
            {"cve": "CVE-2019-1181", "severity": "critical", "score": 9.8,
             "description": "Remote code execution vulnerability"},
        ]
    },
    # Telnet (inherently insecure)
    "telnet": {
        "default": [
            {"cve": "N/A", "severity": "critical", "score": 10.0,
             "description": "Telnet transmits data in plaintext - inherently insecure"},
        ]
    }
}

# Port-based threat intelligence
PORT_THREATS = {
    21: {
        "threat_level": "high",
        "common_attacks": ["Brute force", "Anonymous login", "Bounce attacks"],
        "exploits": ["FTP bounce attack", "Directory traversal"],
        "recommendation": "Disable FTP. Use SFTP (port 22) or FTPS instead."
    },
    22: {
        "threat_level": "medium",
        "common_attacks": ["Brute force", "SSH key theft", "Man-in-the-middle"],
        "exploits": ["Weak password attacks", "Key-based authentication bypass"],
        "recommendation": "Use key-based authentication, disable password login, implement fail2ban."
    },
    23: {
        "threat_level": "critical",
        "common_attacks": ["Credential sniffing", "Session hijacking", "MITM"],
        "exploits": ["Plaintext credential capture"],
        "recommendation": "DISABLE IMMEDIATELY. Use SSH (port 22) instead."
    },
    25: {
        "threat_level": "medium",
        "common_attacks": ["Spam relay", "Email spoofing", "Phishing"],
        "exploits": ["Open relay exploitation", "SMTP injection"],
        "recommendation": "Require authentication, implement SPF/DKIM/DMARC, use TLS."
    },
    80: {
        "threat_level": "medium",
        "common_attacks": ["SQL injection", "XSS", "CSRF", "DDoS"],
        "exploits": ["Web application vulnerabilities", "Unencrypted data transmission"],
        "recommendation": "Migrate to HTTPS (port 443), implement WAF, regular security updates."
    },
    443: {
        "threat_level": "low",
        "common_attacks": ["SSL/TLS vulnerabilities", "Certificate attacks"],
        "exploits": ["Weak cipher suites", "Expired certificates"],
        "recommendation": "Use TLS 1.3, strong cipher suites, valid certificates."
    },
    3306: {
        "threat_level": "high",
        "common_attacks": ["SQL injection", "Brute force", "Data exfiltration"],
        "exploits": ["Default credentials", "Unpatched vulnerabilities"],
        "recommendation": "Never expose to internet. Use firewall, strong passwords, latest patches."
    },
    3389: {
        "threat_level": "critical",
        "common_attacks": ["BlueKeep exploit", "Brute force", "Ransomware"],
        "exploits": ["CVE-2019-0708", "Weak passwords", "Unpatched systems"],
        "recommendation": "Use VPN, enable NLA, implement MFA, restrict access by IP."
    },
    5432: {
        "threat_level": "high",
        "common_attacks": ["SQL injection", "Brute force", "Data theft"],
        "exploits": ["Default credentials", "Privilege escalation"],
        "recommendation": "Never expose to internet. Use firewall, strong authentication."
    },
    5900: {
        "threat_level": "high",
        "common_attacks": ["Brute force", "Screen capture", "Remote control"],
        "exploits": ["Weak passwords", "Unencrypted connections"],
        "recommendation": "Use VPN, strong passwords, enable encryption."
    },
    8080: {
        "threat_level": "medium",
        "common_attacks": ["Web exploits", "Proxy abuse", "DDoS"],
        "exploits": ["Misconfigured proxies", "Admin panel exposure"],
        "recommendation": "Secure admin interfaces, use authentication, implement rate limiting."
    }
}

def get_service_cves(product: str, version: str) -> List[Dict]:
    """
    Get known CVEs for a service and version
    Returns list of CVE dictionaries with details
    """
    product_lower = product.lower()
    cves = []
    
    # Check if product exists in our database
    for known_product, versions in KNOWN_CVES.items():
        if known_product in product_lower:
            # Try exact version match first
            if version and version in versions:
                cves.extend(versions[version])
            # Fall back to default CVEs
            elif "default" in versions:
                cves.extend(versions["default"])
            break
    
    return cves

def get_port_threat_intel(port: int) -> Dict:
    """
    Get threat intelligence for a specific port
    Returns threat level, common attacks, and recommendations
    """
    return PORT_THREATS.get(port, {
        "threat_level": "low",
        "common_attacks": ["General network attacks"],
        "exploits": ["Service-specific vulnerabilities"],
        "recommendation": "Keep service updated and properly configured."
    })

def calculate_threat_score(scan_results: List[Dict]) -> Tuple[int, str, List[str]]:
    """
    Calculate overall threat score based on scan results
    Returns: (score 0-100, severity level, list of concerns)
    """
    if not scan_results:
        return 0, "safe", ["No open ports detected"]
    
    score = 0
    concerns = []
    
    for result in scan_results:
        port = result.get("port")
        product = result.get("product", "").lower()
        version = result.get("version", "")
        
        # Port-based scoring
        port_intel = get_port_threat_intel(port)
        threat_level = port_intel.get("threat_level", "low")
        
        if threat_level == "critical":
            score += 30
            concerns.append(f"CRITICAL: Port {port} ({result.get('name')}) is extremely dangerous")
        elif threat_level == "high":
            score += 20
            concerns.append(f"HIGH RISK: Port {port} ({result.get('name')}) poses significant threat")
        elif threat_level == "medium":
            score += 10
            concerns.append(f"MEDIUM RISK: Port {port} ({result.get('name')}) requires attention")
        else:
            score += 5
        
        # CVE-based scoring
        cves = get_service_cves(product, version)
        for cve in cves:
            cve_score = cve.get("score", 0)
            if cve_score >= 9.0:
                score += 25
                concerns.append(f"CRITICAL CVE: {cve['cve']} in {product} - {cve['description']}")
            elif cve_score >= 7.0:
                score += 15
                concerns.append(f"HIGH CVE: {cve['cve']} in {product} - {cve['description']}")
            elif cve_score >= 4.0:
                score += 10
                concerns.append(f"MEDIUM CVE: {cve['cve']} in {product}")
    
    # Cap score at 100
    score = min(score, 100)
    
    # Determine severity level
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    elif score >= 20:
        severity = "low"
    else:
        severity = "safe"
    
    return score, severity, concerns

def get_security_recommendations(scan_results: List[Dict]) -> List[Dict]:
    """
    Generate prioritized security recommendations based on scan results
    Returns list of recommendation dictionaries
    """
    recommendations = []
    priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    
    for result in scan_results:
        port = result.get("port")
        product = result.get("product", "N/A")
        version = result.get("version", "N/A")
        service = result.get("name", "unknown")
        
        # Get port-specific recommendations
        port_intel = get_port_threat_intel(port)
        threat_level = port_intel.get("threat_level", "low")
        recommendation_text = port_intel.get("recommendation", "Keep service updated")
        
        # Get CVE-specific recommendations
        cves = get_service_cves(product, version)
        cve_details = []
        max_cve_severity = "low"
        
        for cve in cves:
            cve_severity = cve.get("severity", "low")
            cve_details.append({
                "cve_id": cve.get("cve"),
                "severity": cve_severity,
                "score": cve.get("score"),
                "description": cve.get("description")
            })
            
            # Track highest CVE severity
            if priority_map.get(cve_severity, 4) < priority_map.get(max_cve_severity, 4):
                max_cve_severity = cve_severity
        
        # Use highest severity between port and CVE
        final_severity = threat_level if priority_map.get(threat_level, 4) <= priority_map.get(max_cve_severity, 4) else max_cve_severity
        
        recommendations.append({
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "severity": final_severity,
            "priority": priority_map.get(final_severity, 4),
            "recommendation": recommendation_text,
            "cves": cve_details,
            "common_attacks": port_intel.get("common_attacks", []),
            "exploits": port_intel.get("exploits", [])
        })
    
    # Sort by priority (1=critical, 4=low)
    recommendations.sort(key=lambda x: x["priority"])
    
    return recommendations

def get_threat_summary(threat_score: int, severity: str) -> str:
    """
    Generate a human-readable threat summary
    """
    if severity == "critical":
        return f"🚨 CRITICAL THREAT (Score: {threat_score}/100) - Immediate action required! Your system has critical vulnerabilities that are actively exploited in the wild."
    elif severity == "high":
        return f"⚠️ HIGH THREAT (Score: {threat_score}/100) - Urgent attention needed. Multiple high-risk vulnerabilities detected."
    elif severity == "medium":
        return f"🟡 MEDIUM THREAT (Score: {threat_score}/100) - Security improvements recommended. Some vulnerabilities present."
    elif severity == "low":
        return f"🟢 LOW THREAT (Score: {threat_score}/100) - Relatively secure, but monitor for updates."
    else:
        return f"✅ SAFE (Score: {threat_score}/100) - No significant threats detected. Maintain good security practices."
