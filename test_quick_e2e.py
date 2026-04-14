#!/usr/bin/env python3
"""
FAST E2E TEST - Test quick_scan and nuclei:critical_scan with REAL results
"""
import requests
import json
import sys

API_URL = "http://localhost:3001/api"

print("="*70)
print("FAST E2E TEST - QUICK SCAN + NUCLEI")
print("="*70)

# Login
response = requests.post(f"{API_URL}/auth/login", json={"username": "admin@asm-platform.local", "password": "Admin123!"})
token = response.json()["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

# Re-onboard agent with NEW tools
print("\n[1] Re-onboarding agent with all tool variants...")
response = requests.post(
    f"{API_URL}/agents",
    headers=headers,
    json={
        "name": "Complete-Agent",
        "description": "Agent with all tool variants",
        "tags": ["internal", "scanner"],
        "tools": [
            {"toolName": "system:dns_resolve", "toolSchema": {}},
            {"toolName": "nmap:quick_scan", "toolSchema": {}},
            {"toolName": "nmap:full_scan", "toolSchema": {}},
            {"toolName": "nmap:service_scan", "toolSchema": {}},
            {"toolName": "nuclei:critical_scan", "toolSchema": {}},
            {"toolName": "nuclei:high_scan", "toolSchema": {}},
            {"toolName": "nuclei:full_scan", "toolSchema": {}}
        ]
    }
)

if response.status_code == 201:
    agent_data = response.json()
    api_key = agent_data["agent"]["apiKey"] if "agent" in agent_data else agent_data["apiKey"]
    print(f"✓ Agent created with {len(agent_data.get('agent', {}).get('tools', []) or [])} tools")
    print(f"  API Key: {api_key[:40]}...")

    # Update config.yaml
    import yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    config["server"]["api_key"] = api_key
    config["tools"] = [
        {"name": "system:dns_resolve", "enabled": True},
        {"name": "nmap:quick_scan", "enabled": True},
        {"name": "nmap:full_scan", "enabled": True},
        {"name": "nmap:service_scan", "enabled": True},
        {"name": "nuclei:critical_scan", "enabled": True},
        {"name": "nuclei:high_scan", "enabled": True},
        {"name": "nuclei:full_scan", "enabled": True}
    ]

    with open("config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print("✓ config.yaml updated")
else:
    print(f"❌ Failed: {response.text}")
    sys.exit(1)

# Add IP with quick scan
print("\n[2] Adding test IP for QUICK scan...")
response = requests.post(
    f"{API_URL}/assets",
    headers=headers,
    json={"type": "IP_ADDRESS", "value": "44.228.249.3"}  # testphp IP
)

if response.status_code in [201, 409]:  # 409 = already exists
    print(f"✓ Asset ready (testphp IP)")
else:
    print(f"❌ Asset creation failed: {response.text}")

print("\n" + "="*70)
print("SETUP COMPLETE - Now restart agent to use new tools:")
print("  pkill -f 'python.*main.py'")
print("  source venv/bin/activate")
print("  python -u main.py 2>&1 | tee /tmp/agent_new.log &")
print("="*70)
print("\nAgent will execute quick_scan (top 1000 ports) within 60 seconds")
print("Then Nuclei scans will find REAL vulnerabilities")
print("="*70)
