#!/usr/bin/env python3
import requests
import time

API_URL = "http://localhost:3001/api"

# Login
response = requests.post(f"{API_URL}/auth/login", json={"username": "admin@asm-platform.local", "password": "Admin123!"})
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Add testphp IP directly for FAST results
print("Adding 44.228.249.3 (testphp) for QUICK scan...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={"type": "IP_ADDRESS", "value": "44.228.249.3"}
)

print(f"✓ Asset created: {response.json()['id']}")
print("✓ Workflow will trigger nmap:quick_scan (60 seconds)")
print("✓ When port 80 found, nuclei:high_scan will execute")
print("\nMonitoring for 3 minutes...")

for i in range(18):
    time.sleep(10)
    # Check services
    services = requests.get(f"{API_URL}/services", headers=headers).json()
    testphp_services = [s for s in services if s.get('asset', {}).get('value') == '44.228.249.3']

    # Check findings
    findings = requests.get(f"{API_URL}/findings", headers=headers).json()

    print(f"[{i*10}s] Services: {len(testphp_services)}, Findings: {len(findings)}")

    if len(findings) > 0:
        print("\n✓✓✓ FINDINGS DETECTED! ✓✓✓")
        for f in findings[:3]:
            print(f"  - {f['severity']}: {f['title']} ({f['sourceTool']})")
        break

    if len(testphp_services) > 0 and i == 12:
        print(f"\n✓ Services found but no findings yet. Nuclei may still be running...")

print("\nDone!")
