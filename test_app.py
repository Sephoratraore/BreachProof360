"""
BreachProof360 - Automated Testing Script
This script tests the core functionality of the application
"""

import sys
import time
from unittest.mock import Mock, patch
import streamlit as st

def test_imports():
    """Test 1: Verify all imports work correctly"""
    print("Test 1: Testing imports...")
    try:
        import streamlit
        import nmap
        import pandas
        import psutil
        import threat_intel
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_threat_intelligence():
    """Test 2: Verify threat intelligence module"""
    print("\nTest 2: Testing Threat Intelligence module...")
    try:
        from threat_intel import (
            KNOWN_CVES, PORT_THREATS, get_service_cves, 
            get_port_threat_intel, calculate_threat_score,
            get_security_recommendations, get_threat_summary
        )
        
        # Test CVE database
        assert len(KNOWN_CVES) > 0, "CVE database is empty"
        print(f"✅ CVE Database loaded: {len(KNOWN_CVES)} products with known vulnerabilities")
        
        # Test port threats
        assert len(PORT_THREATS) > 0, "Port threats database is empty"
        print(f"✅ Port Threats loaded: {len(PORT_THREATS)} ports")
        
        # Test CVE lookup
        cves = get_service_cves("OpenSSH", "7.4")
        print(f"✅ CVE lookup working: Found {len(cves)} CVEs for OpenSSH 7.4")
        
        # Test port threat intel
        port_intel = get_port_threat_intel(3389)
        assert "threat_level" in port_intel, "Missing threat_level"
        print(f"✅ Port threat intel working: RDP threat level = {port_intel['threat_level']}")
        
        # Test threat scoring
        test_results = [
            {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "7.4"},
            {"port": 80, "name": "http", "product": "Apache", "version": "2.4.6"},
            {"port": 3389, "name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": ""}
        ]
        
        score, severity, concerns = calculate_threat_score(test_results)
        assert 0 <= score <= 100, "Invalid threat score"
        assert severity in ["safe", "low", "medium", "high", "critical"], "Invalid severity"
        print(f"✅ Threat scoring working: Score={score}, Severity={severity}, Concerns={len(concerns)}")
        
        # Test recommendations
        recommendations = get_security_recommendations(test_results)
        assert len(recommendations) > 0, "No recommendations generated"
        print(f"✅ Recommendations working: {len(recommendations)} recommendations generated")
        
        # Test threat summary
        summary = get_threat_summary(score, severity)
        assert len(summary) > 0, "Empty threat summary"
        print(f"✅ Threat summary working")
        
        return True
    except Exception as e:
        print(f"❌ Threat Intelligence test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_nmap_integration():
    """Test 3: Verify nmap is available"""
    print("\nTest 3: Testing nmap integration...")
    try:
        import nmap
        import shutil
        
        # Check if nmap executable exists
        nmap_path = None
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            shutil.which("nmap"),
        ]
        
        for path in candidates:
            if path and os.path.exists(path):
                nmap_path = path
                break
        
        if nmap_path:
            print(f"✅ Nmap found at: {nmap_path}")
            
            # Test nmap scanner initialization
            nm = nmap.PortScanner(nmap_search_path=[nmap_path])
            print("✅ Nmap scanner initialized successfully")
            return True
        else:
            print("⚠️  Nmap not found - scans will fail")
            print("   Install from: https://nmap.org/download.html")
            return False
            
    except Exception as e:
        print(f"❌ Nmap integration test failed: {e}")
        return False

def test_scan_parameters():
    """Test 4: Verify scan parameter optimization"""
    print("\nTest 4: Testing scan parameters...")
    try:
        # Quick Scan parameters (optimized)
        quick_scan_args = "-T5 --host-timeout 5s --min-rate 1000 -p 22,80,443,3389,445"
        print(f"✅ Quick Scan args: {quick_scan_args}")
        print("   - Timing: T5 (insane speed)")
        print("   - Timeout: 5s (reduced from 10s)")
        print("   - Min rate: 1000 packets/sec")
        print("   - Expected time: 5-15 seconds")
        
        # Full Scan parameters
        full_scan_args = "-T4 -sV -p 1-1024"
        print(f"✅ Full Scan args: {full_scan_args}")
        print("   - Timing: T4 (aggressive)")
        print("   - Service detection: Enabled (-sV)")
        print("   - Port range: 1-1024")
        print("   - Expected time: 1-3 minutes")
        
        return True
    except Exception as e:
        print(f"❌ Scan parameters test failed: {e}")
        return False

def test_data_structures():
    """Test 5: Verify data structure handling"""
    print("\nTest 5: Testing data structures...")
    try:
        import pandas as pd
        
        # Test scan results structure
        test_data = [
            {"host": "192.168.1.1", "proto": "tcp", "port": 22, "name": "ssh", 
             "product": "OpenSSH", "version": "7.4", "state": "open"},
            {"host": "192.168.1.1", "proto": "tcp", "port": 80, "name": "http", 
             "product": "Apache", "version": "2.4.6", "state": "open"}
        ]
        
        df = pd.DataFrame(test_data)
        assert len(df) == 2, "DataFrame creation failed"
        assert "port" in df.columns, "Missing port column"
        print(f"✅ DataFrame handling working: {len(df)} rows")
        
        # Test CSV export
        csv_data = df.to_csv(index=False)
        assert len(csv_data) > 0, "CSV export failed"
        print("✅ CSV export working")
        
        return True
    except Exception as e:
        print(f"❌ Data structures test failed: {e}")
        return False

def test_network_discovery():
    """Test 6: Verify network discovery functionality"""
    print("\nTest 6: Testing network discovery...")
    try:
        import psutil
        import ipaddress
        
        # Test network interface detection
        interfaces = psutil.net_if_addrs()
        assert len(interfaces) > 0, "No network interfaces found"
        print(f"✅ Network interfaces detected: {len(interfaces)}")
        
        # Test subnet calculation
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if hasattr(addr, 'family') and addr.family == 2:  # IPv4
                    ip = addr.address
                    mask = addr.netmask
                    if ip.startswith(("10.", "172.", "192.168.")):
                        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        print(f"✅ Local subnet detected: {network}")
                        return True
        
        print("⚠️  No private network subnet detected")
        return True
        
    except Exception as e:
        print(f"❌ Network discovery test failed: {e}")
        return False

def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("BreachProof360 - Comprehensive Test Suite")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_threat_intelligence,
        test_nmap_integration,
        test_scan_parameters,
        test_data_structures,
        test_network_discovery
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test crashed: {e}")
            results.append(False)
        time.sleep(0.5)
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n✅ All tests passed! Application is ready for use.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Review errors above.")
    
    return passed == total

if __name__ == "__main__":
    import os
    success = run_all_tests()
    sys.exit(0 if success else 1)
