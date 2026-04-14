#!/usr/bin/env python3
"""Add Juice Shop and monitor for findings"""
import requests
import time
import json

API_URL = "http://localhost:3001/api"

print("="*70)
print("JUICE SHOP E2E TEST - SYSTEMATIC VALIDATION")
print("="*70)

# Login
response = requests.post(f"{API_URL}/auth/login", json={"username": "admin@asm-platform.local", "password": "Admin123!"})
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Add 127.0.0.1 IP (Juice Shop runs here on port 8888)
print("\n[1] Adding 127.0.0.1 as IP asset...")
response = requests.post(f"{API_URL}/assets", headers=headers, json={"type": "IP_ADDRESS", "value": "127.0.0.1"})

if response.status_code in [201, 409]:
    print("✓ Asset ready (may already exist)")
else:
    print(f"Response: {response.status_code} - {response.text}")

print("\n[2] Monitoring workflow (polling every 10s for 5 minutes)...")
print("Expected: port 8888 → HTTP service → Nuclei scan → Findings")
print("")

for i in range(30):  # 5 minutes
    time.sleep(10)

    # Check services
    services_response = requests.get(f"{API_URL}/services", headers=headers)
    all_services = services_response.json()
    juice_service = [s for s in all_services if s.get('port') == 8888]

    # Check findings
    findings_response = requests.get(f"{API_URL}/findings", headers=headers)
    findings = findings_response.json()

    # Check jobs for Juice Shop
    jobs_response = requests.get(f"{API_URL}/jobs", headers=headers)
    all_jobs = jobs_response.json()
    nuclei_jobs = [j for j in all_jobs if 'nuclei' in j.get('toolName', '')]

    print(f"[{i*10}s] Port 8888: {len(juice_service)}, Nuclei jobs: {len(nuclei_jobs)}, Findings: {len(findings)}")

    if len(findings) > 0:
        print("\n" + "="*70)
        print("✓✓✓ SUCCESS - FINDINGS DETECTED!")
        print("="*70)
        for finding in findings[:5]:
            print(f"\n{finding['severity']}: {finding['title']}")
            print(f"  Tool: {finding['sourceTool']}")
            print(f"  CVE: {finding.get('vulnerabilityRef', 'N/A')}")
            print(f"  Status: {finding['status']}")
        print("\n" + "="*70)
        break

    if len(juice_service) > 0:
        print(f"  → Port 8888 FOUND! Service: {juice_service[0].get('serviceName','unknown')}")

print("\n[FINAL] Summary:")
print(f"  Services on port 8888: {len(juice_service)}")
print(f"  Total Nuclei jobs: {len(nuclei_jobs)}")
print(f"  Total Findings: {len(findings)}")

if len(findings) == 0:
    print("\n⚠️ No findings yet. Checking database...")
    # Direct DB check
    import subprocess
    result = subprocess.run([
        'docker', 'exec', 'asm-platform-db',
        'psql', '-U', 'postgres', '-d', 'asm_platform',
        '-c', 'SELECT COUNT(*) FROM findings;'
    ], capture_output=True, text=True)
    print(result.stdout)
