#!/bin/bash
set -e

echo "========================================="
echo "ASM Platform - Agent Setup & Demo"
echo "========================================="
echo ""

# Step 1: Login and get token
echo "[1/6] Getting admin authentication token..."
TOKEN=$(curl -s -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin@asm-platform.local","password":"Admin123!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['accessToken'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo "❌ Failed to get auth token. Is the backend running?"
  exit 1
fi
echo "✓ Got auth token"

# Step 2: Onboard agent
echo ""
echo "[2/6] Onboarding new agent..."
AGENT_RESPONSE=$(curl -s -X POST http://localhost:3001/api/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Demo-Local-Agent",
    "description": "Local demonstration agent",
    "tags": ["internal", "scanner", "demo"]
  }')

AGENT_API_KEY=$(echo "$AGENT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['apiKey'])" 2>/dev/null)
AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null)

if [ -z "$AGENT_API_KEY" ]; then
  echo "❌ Failed to onboard agent"
  echo "$AGENT_RESPONSE"
  exit 1
fi

echo "✓ Agent onboarded successfully"
echo "  Agent ID: $AGENT_ID"
echo "  API Key: ${AGENT_API_KEY:0:20}..."

# Step 3: Create config.yaml
echo ""
echo "[3/6] Creating agent configuration..."
cat > config.yaml <<EOF
agent:
  name: "Demo-Local-Agent"
  description: "Local demonstration agent"
  tags:
    - internal
    - scanner
    - demo

server:
  api_url: "http://localhost:3001/api"
  ws_url: "ws://localhost:3001/agent-ws"
  api_key: "$AGENT_API_KEY"

tools:
  - name: "system:dns_resolve"
    enabled: true
  - name: "nmap:host_discovery"
    enabled: true
  - name: "nmap:port_scan_all"
    enabled: true
  - name: "nmap:service_scan"
    enabled: true
  - name: "nuclei:critical_scan"
    enabled: true
  - name: "nuclei:full_scan"
    enabled: true

heartbeat_interval: 30
poll_interval: 5
EOF

echo "✓ Configuration created: config.yaml"

# Step 4: Add a test asset
echo ""
echo "[4/6] Adding test asset (scanme.nmap.org)..."
ASSET_RESPONSE=$(curl -s -X POST http://localhost:3001/api/assets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"FQDN","value":"scanme.nmap.org"}')

ASSET_ID=$(echo "$ASSET_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null)

if [ -z "$ASSET_ID" ]; then
  echo "❌ Failed to create asset"
  echo "$ASSET_RESPONSE"
  exit 1
fi

echo "✓ Test asset created: scanme.nmap.org (ID: $ASSET_ID)"

# Step 5: Check pending jobs
echo ""
echo "[5/6] Checking job queue..."
sleep 2
JOBS=$(curl -s -X GET "http://localhost:3001/api/jobs?status=PENDING" \
  -H "Authorization: Bearer $TOKEN")

JOB_COUNT=$(echo "$JOBS" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

echo "✓ Found $JOB_COUNT pending job(s) waiting for agent"

# Step 6: Instructions
echo ""
echo "[6/6] Ready to start agent!"
echo ""
echo "========================================="
echo "Next Steps:"
echo "========================================="
echo ""
echo "1. Start the agent in this terminal:"
echo "   source venv/bin/activate"
echo "   python main.py"
echo ""
echo "2. Watch the agent execute jobs automatically"
echo ""
echo "3. Monitor progress:"
echo "   - UI: http://localhost:3000 → Operations → Jobs"
echo "   - Assets: http://localhost:3000 → Inventory → Assets"
echo "   - Services: http://localhost:3000 → Inventory → Services"
echo "   - Findings: http://localhost:3000 → Findings"
echo ""
echo "4. View results in real-time as the workflow executes:"
echo "   scanme.nmap.org → DNS → IP → Port Scan → Service Scan → Nuclei Scan → Findings"
echo ""
echo "========================================="
echo "Agent configuration saved to: config.yaml"
echo "Test asset added: scanme.nmap.org"
echo "Pending jobs: $JOB_COUNT"
echo "========================================="
