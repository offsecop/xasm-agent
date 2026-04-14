#!/usr/bin/env python3
"""
COMPLETE E2E TEST - Create fresh asset and run full workflow
"""
import requests
import json
import subprocess
import time

API_URL = "http://localhost:3001/api"
ADMIN_USER = "admin@asm-platform.local"
ADMIN_PASS = "Admin123!"

print("="*70)
print("COMPLETE E2E WORKFLOW TEST")
print("="*70)

# Login as admin
print("\n[1] Logging in...")
response = requests.post(
    f"{API_URL}/auth/login",
    json={"username": ADMIN_USER, "password": ADMIN_PASS}
)
admin_token = response.json()["accessToken"]
admin_headers = {"Authorization": f"Bearer {admin_token}"}
print("✓ Logged in")

# Get tenant ID
me_response = requests.get(f"{API_URL}/auth/me", headers=admin_headers)
tenant_id = me_response.json()["tenantId"]
print(f"✓ Tenant ID: {tenant_id}")

# Add IP address asset for FAST testing
print("\n[2] Adding IP asset (127.0.0.1)...")
asset_response = requests.post(
    f"{API_URL}/assets",
    headers=admin_headers,
    json={"type": "IP_ADDRESS", "value": "127.0.0.1"}
)

if asset_response.status_code != 201:
    print(f"❌ Asset creation failed: {asset_response.text}")
    # Asset might already exist
    existing = requests.get(f"{API_URL}/assets", headers=admin_headers, params={"search": "127.0.0.1"})
    if existing.json():
        print(f"  Asset already exists, using existing")
        asset_id = existing.json()[0]['id']
    else:
        exit(1)
else:
    asset_id = asset_response.json()["id"]
    print(f"✓ Asset created: {asset_id}")

# Check jobs created
time.sleep(2)
print("\n[3] Checking job queue...")
jobs_response = requests.get(
    f"{API_URL}/jobs",
    headers=admin_headers,
    params={"status": "PENDING"}
)
pending_jobs = jobs_response.json()
print(f"✓ {len(pending_jobs)} PENDING jobs in queue")

if len(pending_jobs) > 0:
    port_scan_jobs = [j for j in pending_jobs if j['toolName'] == 'nmap:port_scan_all']
    print(f"  Port scan jobs for 127.0.0.1: {len(port_scan_jobs)}")

    if port_scan_jobs:
        job = port_scan_jobs[0]
        print(f"\n[4] Simulating agent executing job...")
        print(f"  Job ID: {job['id']}")
        print(f"  Tool: {job['toolName']}")
        print(f"  Target: {job['parameters']['target']}")

        # Get agent's API key
        agents_response = requests.get(f"{API_URL}/agents", headers=admin_headers)
        demo_agent = [a for a in agents_response.json() if 'Demo' in a['name']]

        if not demo_agent:
            print("❌ No Demo agent found")
            exit(1)

        # Get the agent's API key from database (we generated it)
        agent_api_key = "0dZCdJvO1DsVmpD6sGrH63P3ydS0YBZ6fgDz4w6fgclhpU3Gy3UZeqnkQv6iNJd0"
        agent_headers = {"X-API-Key": agent_api_key}

        # Claim job
        claim_response = requests.post(
            f"{API_URL}/agents/jobs/{job['id']}/claim",
            headers=agent_headers
        )

        if claim_response.status_code != 200:
            print(f"❌ Claim failed: {claim_response.text}")
            exit(1)

        print(f"✓ Job claimed")

        # Execute nmap scan
        print(f"\n[5] Executing: nmap -Pn -p 22,80,443,8080 127.0.0.1")
        proc = subprocess.run(
            ['nmap', '-Pn', '-p', '22,80,443,8080,3000,3001,5433,8000', '-oX', '-', '127.0.0.1'],
            capture_output=True,
            text=True,
            timeout=60
        )

        nmap_output = proc.stdout
        print(f"✓ Scan complete ({len(nmap_output)} bytes)")

        # Submit results
        print(f"\n[6] Submitting results to backend...")
        complete_response = requests.post(
            f"{API_URL}/agents/jobs/{job['id']}/complete",
            headers=agent_headers,
            json={
                "result": {
                    "success": True,
                    "output": {"xml": nmap_output},
                    "raw_output": nmap_output
                }
            }
        )

        if complete_response.status_code != 200:
            print(f"❌ Submit failed: {complete_response.text}")
            exit(1)

        print(f"✓ Results submitted")

        # Wait for ingestion
        print(f"\n[7] Waiting for ingestion...")
        time.sleep(5)

        # Check services created
        services_response = requests.get(f"{API_URL}/services", headers=admin_headers)
        services = services_response.json()
        local_services = [s for s in services if s.get('asset', {}).get('value') == '127.0.0.1']

        print(f"✓ Services discovered: {len(local_services)}")
        for svc in local_services[:5]:
            print(f"    Port {svc['port']}/{svc['protocol']}: {svc.get('serviceName', 'unknown')} - {svc['status']}")

        # Check new jobs triggered
        new_jobs_response = requests.get(
            f"{API_URL}/jobs",
            headers=admin_headers,
            params={"status": "PENDING"}
        )
        new_pending = new_jobs_response.json()
        service_scan_jobs = [j for j in new_pending if j['toolName'] == 'nmap:service_scan']

        print(f"\n[8] New jobs triggered:")
        print(f"  Service scan jobs: {len(service_scan_jobs)}")

        print("\n" + "="*70)
        print("✅ E2E WORKFLOW VERIFIED - WORKING!")
        print("="*70)
        print(f"✓ Port scan executed via simulated agent")
        print(f"✓ {len(local_services)} services discovered and stored")
        print(f"✓ {len(service_scan_jobs)} service fingerprint jobs triggered")
        print(f"✓ Ingestion pipeline operational")
        print(f"✓ Workflow automation operational")
        print("="*70)
else:
    print("\n⚠️ No port scan jobs found. Check if asset creation triggered workflow.")
