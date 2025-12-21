import os
import requests
# import requests
# api_key = os.getenv("ABUSEIPDB_API_KEY")
# def check_abuseipdb(ip):
#     ...

api_key = os.getenv("ABUSEIPDB_API_KEY")
print(f"Loaded API Key: {api_key[:10]}...")  # Just print the first few characters

url = "https://api.abuseipdb.com/api/v2/check"
query = {
    "ipAddress": "8.8.8.8",
    "maxAgeInDays": "90"
}
headers = {
    "Accept": "application/json",
    "Key": api_key
}

response = requests.get(url, headers=headers, params=query)
print(response.status_code)
print(response.json())
import ipaddress

def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)

def check_ip_validity(target_ip: str) -> dict:
    """Check if the target IP is valid for public threat intel lookup."""
    if not is_public_ip(target_ip):
        return {"status": "skipped", "reason": "Private/local IPs are not supported for public threat intel lookups."}
    return {"status": "valid", "ip": target_ip}

# Test the function
target_ip = "8.8.8.8"
result = check_ip_validity(target_ip)
print(f"IP validation result: {result}")
