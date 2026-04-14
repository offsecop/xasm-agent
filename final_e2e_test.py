#!/usr/bin/env python3
"""FINAL E2E TEST - testphp.vulnweb.com with REAL findings"""
import requests
import time

API_URL = "http://localhost:3001/api"

# Login
print("Logging in...")
response = requests.post(f"{API_URL}/auth/login", json={"username": "admin@asm-platform.local", "password": "Admin123!"})
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Add testphp.vulnweb.com as FQDN
print("\nAdding testphp.vulnweb.com (FQDN)...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={"type": "FQDN", "value": "testphp.vulnweb.com"}
)

if response.status_code == 201:
    asset_id = response.json()["id"]
    print(f"✓ Asset created: {asset_id}")
else:
    print(f"Asset response: {response.status_code} - {response.text}")

print("\nExpected workflow:")
print("  1. DNS resolution (10s)")
print("  2. IP creation (auto)")
print("  3. Quick port scan (60s)")
print("  4. Port 80 discovery")
print("  5. Service fingerprinting (30s)")
print("  6. HTTP detected → Web discovery")
print("  7. Nuclei scan (30-60s)")
print("  8. Findings created")
print("\nTotal ETA: ~3-5 minutes")
print("\nMonitoring every 15 seconds...")

for i in range(24):  # 6 minutes
    time.sleep(15)

    # Check services
    services_response = requests.get(f"{API_URL}/services", headers=headers)
    all_services = services_response.json()
    testphp_services = [s for s in all_services if '44.228' in str(s.get('asset', {}).get('value', ''))]

    # Check findings
    findings_response = requests.get(f"{API_URL}/findings", headers=headers)
    findings = findings_response.json()

    # Check jobs
    jobs_response = requests.get(f"{API_URL}/jobs", headers=headers, params={"status": "COMPLETED"})
    completed_jobs = jobs_response.json()

    print(f"[{i*15}s] Services: {len(testphp_services)}, Findings: {len(findings)}, Jobs completed: {len(completed_jobs)}")

    if len(findings) > 0:
        print("\n" + "="*70)
        print("✓✓✓ SUCCESS - FINDINGS DETECTED!")
        print("="*70)
        for finding in findings[:5]:
            print(f"\n{finding['severity']}: {finding['title']}")
            print(f"  Source: {finding['sourceTool']}")
            print(f"  CVE/Ref: {finding.get('vulnerabilityRef', 'N/A')}")
        break

    if len(testphp_services) > 0:
        print(f"  → Port 80 found! Service: {testphp_services[0].get('serviceName', 'unknown')}")

print("\nFinal check...")
print(f"Total services on testphp: {len(testphp_services)}")
print(f"Total findings: {len(findings)}")
