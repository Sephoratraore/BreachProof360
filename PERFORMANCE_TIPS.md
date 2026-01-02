# ⚡ BreachProof360 - Performance Optimization Guide

## Scan Speed Comparison

### Quick Scan (Optimized)
- **Ports Scanned**: 5 common ports (22, 80, 443, 3389, 445)
- **Typical Duration**: 5-15 seconds
- **Parameters**: `-sT -Pn -p 22,80,443,3389,445 --open --max-retries 0 --host-timeout 10s -T4`
- **Best For**: Fast security checks, initial reconnaissance

### Full Scan
- **Ports Scanned**: 1-1024 (1,024 ports)
- **Typical Duration**: 2-5 minutes
- **Parameters**: `-sT -Pn -p 1-1024 --open --max-retries 1 --host-timeout 45s -sV --version-light`
- **Best For**: Comprehensive security audits

### Network Discovery
- **Typical Duration**: 10-30 seconds (depends on network size)
- **Parameters**: `-sn` (ping scan only, no port scanning)
- **Best For**: Finding all devices on your network

## Why Scans Can Be Slow

1. **Network Latency**: Distance to target affects response time
2. **Firewall Filtering**: Firewalls may drop packets, causing timeouts
3. **Target Responsiveness**: Busy or slow servers take longer to respond
4. **Version Detection**: `-sV` flag significantly increases scan time
5. **Number of Ports**: More ports = longer scan time

## Optimization Strategies

### For Faster Scans:
```bash
# Ultra-fast scan (no version detection)
-T4 --max-retries 0 --host-timeout 5s

# Aggressive scan (fastest, may miss some results)
-T5 --max-retries 0 --host-timeout 3s
```

### For More Accurate Scans:
```bash
# Thorough scan with version detection
-T3 --max-retries 2 -sV --version-intensity 5

# Comprehensive scan (slowest, most accurate)
-T2 --max-retries 3 -sV -sC --version-all
```

## Timing Templates (-T)

| Template | Speed | Accuracy | Use Case |
|----------|-------|----------|----------|
| -T0 (Paranoid) | Extremely Slow | Highest | IDS evasion |
| -T1 (Sneaky) | Very Slow | Very High | Stealth scanning |
| -T2 (Polite) | Slow | High | Avoid network congestion |
| -T3 (Normal) | Moderate | Good | Default balanced scan |
| -T4 (Aggressive) | Fast | Good | **Quick Scan (Current)** |
| -T5 (Insane) | Very Fast | Lower | Speed over accuracy |

## Current Configuration

### Quick Scan (Optimized for Speed)
```python
args = "-sT -Pn -p 22,80,443,3389,445 --open --max-retries 0 --host-timeout 10s -T4"
```

**What each parameter does:**
- `-sT`: TCP connect scan (most compatible)
- `-Pn`: Skip host discovery (assume host is up)
- `-p 22,80,443,3389,445`: Scan only these 5 critical ports
- `--open`: Show only open ports
- `--max-retries 0`: Don't retry failed probes (faster)
- `--host-timeout 10s`: Give up on unresponsive hosts after 10 seconds
- `-T4`: Aggressive timing (faster scans)

### Full Scan (Balanced)
```python
args = "-sT -Pn -p 1-1024 --open --max-retries 1 --host-timeout 45s -sV --version-light"
```

**Additional parameters:**
- `-p 1-1024`: Scan first 1,024 ports
- `--max-retries 1`: Retry once for reliability
- `--host-timeout 45s`: Longer timeout for thorough scanning
- `-sV`: Detect service versions
- `--version-light`: Light version detection (faster than full)

## Troubleshooting Slow Scans

### If Quick Scan is Still Slow:

1. **Check Network Connection**
   ```bash
   ping scanme.nmap.org
   ```

2. **Test with Local Target**
   ```bash
   # Scan your own machine (should be instant)
   127.0.0.1
   ```

3. **Verify Nmap Installation**
   ```bash
   nmap --version
   ```

4. **Check Firewall Settings**
   - Windows Firewall may slow down scans
   - Temporarily disable for testing (re-enable after)

### If Scans Timeout:

1. **Increase Timeout**
   - Edit `BreachProof360.py`
   - Change `--host-timeout 10s` to `--host-timeout 30s`

2. **Reduce Aggressiveness**
   - Change `-T4` to `-T3` for more reliable scans

3. **Check Target Availability**
   - Some targets may block scans
   - Try `scanme.nmap.org` (designed for testing)

## Recommended Targets for Testing

### Fast Responders:
- `scanme.nmap.org` - Official Nmap test server
- `127.0.0.1` - Your local machine (instant)
- `8.8.8.8` - Google DNS (usually fast)

### Avoid:
- Government websites
- Banking sites
- Any site you don't own or have permission to scan

## Performance Benchmarks

Based on typical home network conditions:

| Scan Type | Target | Expected Time |
|-----------|--------|---------------|
| Quick Scan | scanme.nmap.org | 5-15 seconds |
| Quick Scan | Local network device | 2-5 seconds |
| Full Scan | scanme.nmap.org | 2-5 minutes |
| Network Discovery | /24 subnet | 10-30 seconds |

## Advanced: Custom Scan Profiles

You can modify `BreachProof360.py` to add custom scan profiles:

```python
# Ultra-Fast Scan (3-5 seconds)
args = "-sT -Pn -p 80,443 --open --max-retries 0 --host-timeout 5s -T5"

# Stealth Scan (slower but harder to detect)
args = "-sS -Pn -p 22,80,443 --open --max-retries 2 --host-timeout 30s -T2"

# Comprehensive Scan (10+ minutes)
args = "-sT -Pn -p- --open --max-retries 2 -sV -sC -T3"
```

## Conclusion

The current Quick Scan configuration is optimized for:
- ✅ Speed (5-15 seconds typical)
- ✅ Reliability (finds open ports consistently)
- ✅ Compatibility (works on most networks)
- ✅ Safety (non-intrusive scanning)

For even faster scans, you can sacrifice some accuracy, but the current settings provide the best balance for most use cases.
