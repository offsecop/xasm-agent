#!/usr/bin/env python3
"""FINAL TEST - testphp.vulnweb.com E2E with REAL findings"""
import requests
import time

API_URL = "http://localhost:3001/api"

print("="*70)
print("FINAL E2E TEST - testphp.vulnweb.com")
print("Nuclei verified: 21 findings available")
print("="*70)

# Login
response = requests.post(f"{API_URL}/auth/login", json={"username": "admin@asm-platform.local", "password": "Admin123!"})
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Clean slate
print("\n[1] Cleaning database...")
requests.delete(f"{API_URL}/assets", headers=headers)  # If endpoint exists

# Add testphp.vulnweb.com
print("\n[2] Adding testphp.vulnweb.com...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={"type": "FQDN", "value": "testphp.vulnweb.com"}
)

if response.status_code == 201:
    asset_id = response.json()["id"]
    print(f"✓ Asset created: {asset_id}")
    print("\nExpected workflow:")
    print("  1. DNS: testphp.vulnweb.com → 44.228.249.3 (10s)")
    print("  2. Quick port scan (60s)")
    print("  3. Port 80 discovery")
    print("  4. Service fingerprinting (30s)")
    print("  5. Nuclei web scan (60-120s)")
    print("  6. 21+ findings created")
    print("\nTotal ETA: 3-5 minutes")
else:
    print(f"Failed: {response.status_code} - {response.text}")
    exit(1)

print("\n[3] Monitoring (15s intervals, 10 minutes max)...")

for i in range(40):  # 10 minutes
    time.sleep(15)

    # Check services
    services = requests.get(f"{API_URL}/services", headers=headers).json()
    testphp_services = [s for s in services if '44.228' in str(s.get('asset', {}).get('value', ''))]

    # Check findings
    findings = requests.get(f"{API_URL}/findings", headers=headers).json()

    # Check jobs
    jobs = requests.get(f"{API_URL}/jobs", headers=headers).json()
    completed = len([j for j in jobs if j['status'] == 'COMPLETED'])
    nuclei_jobs = [j for j in jobs if 'nuclei' in j.get('toolName', '')]

    print(f"[{i*15}s] Services: {len(testphp_services)}, Nuclei: {len(nuclei_jobs)}, Findings: {len(findings)}, Jobs: {completed}")

    if len(findings) > 0:
        print("\n" + "="*70)
        print("✓✓✓ SUCCESS - FINDINGS DETECTED!")
        print("="*70)
        for f in findings[:10]:
            print(f"{f['severity']}: {f['title']} ({f['sourceTool']})")
        print("="*70)
        print(f"\nTotal Findings: {len(findings)}")
        break

    if len(testphp_services) > 0 and i > 10:
        print(f"  → Port 80 found, waiting for Nuclei...")

print("\nDone!")
