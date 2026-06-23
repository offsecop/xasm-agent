#!/bin/bash
# Agent entrypoint: generate config if missing, update nuclei templates, run agent
set -e

CONFIG_FILE="${CONFIG_FILE:-config.docker.yaml}"

# Auto-generate config YAML if it doesn't exist.
# Phase 3a (2026-05-16) collapsed per-agent configs into one shared config.docker.yaml.
# Per-instance identity (WP4) comes from AGENT_CLIENT_ID/AGENT_CLIENT_SECRET +
# AGENT_INSTALLATION_UID (set per-service in docker-compose) — the instance
# self-enrolls for its own key. AGENT_NAME is set per-service too.
if [ ! -f "$CONFIG_FILE" ]; then
  AGENT_NAME="${AGENT_NAME:-Agent-001}"

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
