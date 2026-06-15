#!/bin/bash
# Agent entrypoint: generate config if missing, update nuclei templates, run agent
set -e

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

# Auto-generate config YAML if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
  # Determine agent name/index from config file name
  case "$CONFIG_FILE" in
    config.docker.yaml|config.yaml) AGENT_NAME="Agent-001"; AGENT_IDX=1 ;;
    config.agent2.yaml)             AGENT_NAME="Agent-002"; AGENT_IDX=2 ;;
    config.agent3.yaml)             AGENT_NAME="Agent-003"; AGENT_IDX=3 ;;
    config.agent4.yaml)             AGENT_NAME="Agent-004"; AGENT_IDX=4 ;;
    config.agent5.yaml)             AGENT_NAME="Agent-005"; AGENT_IDX=5 ;;
    *)                              AGENT_NAME="Agent-001"; AGENT_IDX=1 ;;
  esac

  echo "[Entrypoint] Generating $CONFIG_FILE for $AGENT_NAME..."
  cat > "$CONFIG_FILE" <<YAML
agent:
  name: "$AGENT_NAME"
  description: "ASM Platform $AGENT_NAME (Docker)"
  tags:
    - internal
    - scanner

server:
  api_url: "http://backend:3001/api"
  ws_url: "ws://backend:3001/agent-ws"
  api_key: ""

heartbeat_interval: 30
poll_interval: 5

darkweb:
  tor_proxy_url: "socks5://tor-proxy:9050"
  enable_onion_sources: true
  onion_sources_file: "tools/data/darkweb_onion_sources.json"
  onion_use_browser: false
  onion_fetch_timeout_seconds: 45
YAML
  echo "[Entrypoint] Config generated: $CONFIG_FILE"
fi

echo "[Entrypoint] Updating nuclei templates on startup..."
nuclei -update-templates 2>&1 | tail -5 || echo "[Entrypoint] Template update failed (non-fatal), continuing..."

TEMPLATE_COUNT=$(find /root/nuclei-templates -name '*.yaml' -type f 2>/dev/null | wc -l)
echo "[Entrypoint] Nuclei templates ready: ${TEMPLATE_COUNT} templates"

echo "[Entrypoint] Starting agent..."
exec python -u main_rest.py
