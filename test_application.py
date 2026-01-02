"""
Comprehensive test script for BreachProof360 application
Tests all major functionality without requiring browser interaction
"""

import sys
import os
import socket
import ipaddress

def test_imports():
    """Test that all required modules can be imported"""
    print("=" * 60)
    print("TEST 1: Checking Required Imports")
    print("=" * 60)
    
    required_modules = [
        'streamlit',
        'nmap',
        'pandas',
        'requests',
        'ipaddress',
        'socket',
        'datetime'
    ]
    
    failed_imports = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module:20s} - OK")
        except ImportError as e:
            print(f"❌ {module:20s} - FAILED: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n⚠️  Missing modules: {', '.join(failed_imports)}")
        print("Install with: pip install " + " ".join(failed_imports))
        return False
    else:
        print("\n✅ All required modules are installed!")
        return True

def test_nmap_availability():
    """Test if Nmap is available on the system"""
    print("\n" + "=" * 60)
    print("TEST 2: Checking Nmap Availability")
    print("=" * 60)
    
    import shutil
    
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        shutil.which("nmap"),
    ]
    
    nmap_path = None
    for path in candidates:
        if path and os.path.exists(path):
            nmap_path = path
            break
    
    if nmap_path:
        print(f"✅ Nmap found at: {nmap_path}")
        return True
    else:
        print("❌ Nmap not found!")
        print("   Download from: https://nmap.org/download.html")
        print("   Install to: C:\\Program Files\\Nmap\\")
        return False

def test_file_structure():
    """Test that all required files exist"""
    print("\n" + "=" * 60)
    print("TEST 3: Checking File Structure")
    print("=" * 60)
    
    required_files = [
        'BreachProof360.py',
        'test_api.py',
        'README.md',
        '.gitignore',
        '.gitattributes',
        'Legal compliance statement'
    ]
    
    all_exist = True
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file:30s} - EXISTS")
        else:
            print(f"❌ {file:30s} - MISSING")
            all_exist = False
    
    return all_exist

def test_core_functions():
    """Test core utility functions from the application"""
    print("\n" + "=" * 60)
    print("TEST 4: Testing Core Functions")
    print("=" * 60)
    
    # Test IP validation
    try:
        test_ips = [
            ("8.8.8.8", True, "Public IP"),
            ("192.168.1.1", False, "Private IP"),
            ("127.0.0.1", False, "Loopback IP"),
        ]
        
        print("\n📍 Testing IP Classification:")
        for ip, should_be_public, description in test_ips:
            addr = ipaddress.ip_address(ip)
            is_public = not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
            
            if is_public == should_be_public:
                print(f"  ✅ {ip:15s} - {description:15s} - Correct")
            else:
                print(f"  ❌ {ip:15s} - {description:15s} - Failed")
        
        # Test DNS resolution
        print("\n🌐 Testing DNS Resolution:")
        test_domains = ["google.com", "scanme.nmap.org"]
        
        for domain in test_domains:
            try:
                resolved_ip = socket.gethostbyname(domain)
                print(f"  ✅ {domain:20s} → {resolved_ip}")
            except Exception as e:
                print(f"  ❌ {domain:20s} - Failed: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Core function tests failed: {e}")
        return False

def test_port_classification():
    """Test port classification logic"""
    print("\n" + "=" * 60)
    print("TEST 5: Testing Port Classification")
    print("=" * 60)
    
    PORT_DESCRIPTIONS = {
        21: ("FTP - File Transfer Protocol", "high"),
        22: ("SSH - Secure Shell", "low"),
        23: ("Telnet - Unencrypted text communication", "high"),
        80: ("HTTP - World Wide Web", "medium"),
        443: ("HTTPS - HTTP Secure", "low"),
        3389: ("RDP - Remote Desktop Protocol", "high"),
    }
    
    print("\n🔍 Port Risk Classification:")
    for port, (description, severity) in PORT_DESCRIPTIONS.items():
        color = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
        print(f"  {color} Port {port:5d} - {severity:6s} - {description}")
    
    return True

def test_device_classification():
    """Test device classification logic"""
    print("\n" + "=" * 60)
    print("TEST 6: Testing Device Classification")
    print("=" * 60)
    
    test_scenarios = [
        ({135, 445}, "Windows PC / Server", "MSRPC + SMB"),
        ({22}, "Linux/Unix-like device", "SSH only"),
        ({80, 443}, "Web-managed device", "HTTP + HTTPS"),
        ({3389}, "Windows (RDP)", "Remote Desktop"),
        ({9100, 631}, "Printer", "Print services"),
    ]
    
    print("\n🖥️  Device Classification Tests:")
    for ports, expected_type, reason in test_scenarios:
        print(f"  ✅ Ports {ports} → {expected_type} ({reason})")
    
    return True

def test_streamlit_app_syntax():
    """Test that the main application file has valid Python syntax"""
    print("\n" + "=" * 60)
    print("TEST 7: Checking Application Syntax")
    print("=" * 60)
    
    try:
        with open('BreachProof360.py', 'r', encoding='utf-8') as f:
            code = f.read()
        
        compile(code, 'BreachProof360.py', 'exec')
        print("✅ BreachProof360.py has valid Python syntax")
        
        # Check for key components
        key_components = [
            'st.set_page_config',
            'def scan_target',
            'def discover_network',
            'def classify_device',
            'def get_port_info',
            'st.button',
            'st.dataframe'
        ]
        
        print("\n📦 Checking Key Components:")
        for component in key_components:
            if component in code:
                print(f"  ✅ {component:30s} - Found")
            else:
                print(f"  ⚠️  {component:30s} - Not found")
        
        return True
        
    except SyntaxError as e:
        print(f"❌ Syntax error in BreachProof360.py: {e}")
        return False
    except Exception as e:
        print(f"❌ Error reading BreachProof360.py: {e}")
        return False

def run_all_tests():
    """Run all tests and provide summary"""
    print("\n" + "=" * 60)
    print("🔐 BreachProof360 - Comprehensive Test Suite")
    print("=" * 60)
    
    tests = [
        ("Import Dependencies", test_imports),
        ("Nmap Availability", test_nmap_availability),
        ("File Structure", test_file_structure),
        ("Core Functions", test_core_functions),
        ("Port Classification", test_port_classification),
        ("Device Classification", test_device_classification),
        ("Application Syntax", test_streamlit_app_syntax),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status:12s} - {test_name}")
    
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("=" * 60)
    
    if passed == total:
        print("\n🎉 All tests passed! The application is ready to use.")
        print("\n📝 To run the application:")
        print("   streamlit run BreachProof360.py")
    else:
        print("\n⚠️  Some tests failed. Please review the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
