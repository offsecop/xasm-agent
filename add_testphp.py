#!/usr/bin/env python3
"""Add testphp.vulnweb.com for vulnerability scanning demo"""
import requests

API_URL = "http://localhost:3001/api"

# Login
response = requests.post(
    f"{API_URL}/auth/login",
    json={"username": "admin@asm-platform.local", "password": "Admin123!"}
)
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Add testphp.vulnweb.com
print("Adding testphp.vulnweb.com (vulnerable web app)...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={"type": "FQDN", "value": "testphp.vulnweb.com"}
)

if response.status_code == 201:
    asset_id = response.json()["id"]
    print(f"✓ Asset created: {asset_id}")
    print(f"✓ Workflow will automatically:")
    print(f"  1. Resolve DNS")
    print(f"  2. Scan for port 80")
    print(f"  3. Fingerprint web server")
    print(f"  4. Crawl website")
    print(f"  5. Run Nuclei web vulnerability scan")
    print(f"  6. Create findings for SQL injection, XSS, etc.")
else:
    print(f"Error: {response.text}")
