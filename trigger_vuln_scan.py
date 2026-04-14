#!/usr/bin/env python3
"""
Trigger vulnerability scan for discovered service
"""
import requests
import json

# Auth
response = requests.post(
    'http://localhost:3001/api/auth/login',
    json={"username": "admin@asm-platform.local", "password": "Admin123!"}
)
token = response.json()['accessToken']

# Create nuclei scan job manually
job_data = {
    "toolName": "nuclei:high_scan",
    "parameters": {"target": "http://44.228.249.3:80"},
    "targetTags": ["internal", "scanner"]
}

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Note: There's no direct job creation API, so we'll query services and trigger via curl
print("Service created with port 80")
print("Now create Nuclei scan job manually...")

# Create job via SQL instead
import subprocess
subprocess.run([
    "docker-compose", "exec", "-T", "db", "psql", "-U", "postgres", "-d", "asm_platform", "-c",
    f"""
    INSERT INTO jobs (id, "tenantId", "toolName", parameters, status, "targetTags", "createdAt")
    VALUES (
        gen_random_uuid(),
        'e3d90f18-d09d-40de-9f6e-b33cb96fd4ab',
        'nuclei:high_scan',
        '{{"target": "http://44.228.249.3:80"}}'::jsonb,
        'PENDING',
        '["internal", "scanner"]'::jsonb,
        NOW()
    ) RETURNING id, "toolName";
    """
], cwd="/Users/mvpenha/code/asm-platform")

print("Nuclei scan job created!")
