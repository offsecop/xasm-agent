#!/usr/bin/env python3
"""
Setup script for ASM Platform agent demonstration
"""
import requests
import json
import yaml

API_URL = "http://localhost:3001/api"
ADMIN_USER = "admin@asm-platform.local"
ADMIN_PASS = "Admin123!"

print("="*50)
print("ASM Platform - Agent Setup & Demo")
print("="*50)
print()

# Step 1: Login
print("[1/6] Logging in as admin...")
response = requests.post(
    f"{API_URL}/auth/login",
    json={"username": ADMIN_USER, "password": ADMIN_PASS}
)

if response.status_code != 201:
    print(f"❌ Login failed: {response.text}")
    exit(1)

token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}
print("✓ Logged in successfully")

# Step 2: Onboard Agent
print()
print("[2/6] Onboarding agent...")
response = requests.post(
    f"{API_URL}/agents",
    headers=headers,
    json={
        "name": "Demo-Local-Agent",
        "description": "Local demonstration scanning agent",
        "tags": ["internal", "scanner", "demo"],
        "tools": [
            {"toolName": "system:dns_resolve", "toolSchema": {}},
            {"toolName": "nmap:host_discovery", "toolSchema": {}},
            {"toolName": "nmap:port_scan_all", "toolSchema": {}},
            {"toolName": "nmap:service_scan", "toolSchema": {}},
            {"toolName": "nuclei:critical_scan", "toolSchema": {}},
            {"toolName": "nuclei:full_scan", "toolSchema": {}}
        ]
    }
)

if response.status_code != 201:
    print(f"❌ Agent onboarding failed: {response.text}")
    exit(1)

agent_data = response.json()
print(f"  Response: {json.dumps(agent_data, indent=2)}")

agent_id = agent_data.get("id") or agent_data.get("agent", {}).get("id")
api_key = agent_data.get("apiKey") or agent_data.get("agent", {}).get("apiKey")

if not api_key:
    print(f"❌ No API key in response")
    exit(1)

print(f"✓ Agent onboarded")
print(f"  ID: {agent_id}")
print(f"  API Key: {api_key[:30]}...")

# Step 3: Create config.yaml
print()
print("[3/6] Creating agent config.yaml...")
config = {
    "agent": {
        "name": "Demo-Local-Agent",
        "description": "Local demonstration scanning agent",
        "tags": ["internal", "scanner", "demo"]
    },
    "server": {
        "api_url": "http://localhost:3001/api",
        "api_key": api_key
    },
    "tools": [
        {"name": "system:dns_resolve", "enabled": True},
        {"name": "nmap:host_discovery", "enabled": True},
        {"name": "nmap:port_scan_all", "enabled": True},
        {"name": "nmap:service_scan", "enabled": True},
        {"name": "nuclei:critical_scan", "enabled": True},
        {"name": "nuclei:full_scan", "enabled": True},
    ],
    "heartbeat_interval": 30,
    "poll_interval": 5
}

with open("config.yaml", "w") as f:
    yaml.dump(config, f, default_flow_style=False)

print("✓ config.yaml created")

# Step 4: Add test asset
print()
print("[4/6] Adding test asset (scanme.nmap.org)...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={
        "type": "FQDN",
        "value": "scanme.nmap.org"
    }
)

if response.status_code != 201:
    print(f"❌ Asset creation failed: {response.text}")
    exit(1)

asset_data = response.json()
asset_id = asset_data["id"]
print(f"✓ Asset created: scanme.nmap.org (ID: {asset_id})")

# Step 5: Check pending jobs
print()
print("[5/6] Checking job queue...")
response = requests.get(
    f"{API_URL}/jobs",
    headers=headers,
    params={"status": "PENDING"}
)

jobs = response.json()
print(f"✓ Found {len(jobs)} pending job(s)")

if len(jobs) > 0:
    print(f"  First job: {jobs[0]['toolName']} (Expected: system:dns_resolve)")

# Step 6: Instructions
print()
print("[6/6] Setup complete!")
print()
print("="*50)
print("READY TO START AGENT")
print("="*50)
print()
print("Start the agent now:")
print("  source venv/bin/activate")
print("  python main.py")
print()
print("The agent will automatically:")
print("  1. Connect via WebSocket")
print("  2. Pick up DNS resolution job")
print("  3. Discover IP address")
print("  4. Trigger port scan")
print("  5. Scan all 65k ports")
print("  6. Fingerprint services")
print("  7. Run Nuclei vulnerability scans")
print()
print("Monitor progress:")
print("  - UI: http://localhost:3000")
print("  - Jobs: http://localhost:3000/jobs")
print("  - Assets: http://localhost:3000/assets")
print()
print("="*50)
print(f"Agent API Key: {api_key}")
print(f"Asset ID: {asset_id}")
print(f"Pending Jobs: {len(jobs)}")
print("="*50)
