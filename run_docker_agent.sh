#!/bin/bash
set -e

echo "=================================================="
echo "ASM Platform - Docker Agent Setup"
echo "=================================================="

# Login and onboard agent
echo "[1/4] Onboarding Docker agent..."
TOKEN=$(curl -s -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin@asm-platform.local","password":"Admin123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['accessToken'])")

AGENT_RESPONSE=$(curl -s -X POST http://localhost:3001/api/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Docker-Scanner-Agent",
    "description": "Dockerized agent with nmap and nuclei",
    "tags": ["docker", "scanner", "internal"],
    "tools": [
      {"toolName": "system:dns_resolve", "toolSchema": {}},
      {"toolName": "nmap:quick_scan", "toolSchema": {}},
      {"toolName": "nmap:service_scan", "toolSchema": {}},
      {"toolName": "nuclei:critical_scan", "toolSchema": {}},
      {"toolName": "nuclei:high_scan", "toolSchema": {}}
    ]
  }')

API_KEY=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('agent',{}).get('apiKey') or d.get('apiKey',''))")

if [ -z "$API_KEY" ]; then
  echo "❌ Failed to onboard agent"
  echo "$AGENT_RESPONSE"
  exit 1
fi

echo "✓ Agent onboarded"
echo "  API Key: ${API_KEY:0:40}..."

# Create config
echo ""
echo "[2/4] Creating Docker config..."
cat > config.docker.yaml <<EOF
agent:
  name: "Docker-Scanner-Agent"
  description: "Dockerized agent with nmap and nuclei"
  tags: [docker, scanner, internal]
server:
  api_url: "http://host.docker.internal:3001/api"
  ws_url: "ws://host.docker.internal:3001/agent-ws"
  api_key: "$API_KEY"
tools:
  - {name: "system:dns_resolve", enabled: true}
  - {name: "nmap:quick_scan", enabled: true}
  - {name: "nmap:service_scan", enabled: true}
  - {name: "nuclei:critical_scan", enabled: true}
  - {name: "nuclei:high_scan", enabled: true}
heartbeat_interval: 30
poll_interval: 5
EOF

echo "✓ Config created"

# Run Docker agent
echo ""
echo "[3/4] Starting Docker agent..."
docker run -d \
  --name asm-agent \
  --network host \
  -v $(pwd)/config.docker.yaml:/app/config.yaml:ro \
  asm-agent:latest

sleep 5

echo "✓ Agent started"

# Verify running
echo ""
echo "[4/4] Verifying agent..."
docker logs asm-agent 2>&1 | head -20

echo ""
echo "=================================================="
echo "Docker Agent Running"
echo "=================================================="
echo "Container: asm-agent"
echo "API Key: $API_KEY"
echo "Check logs: docker logs -f asm-agent"
echo "Check UI: http://localhost:3000/agents"
echo "=================================================="
