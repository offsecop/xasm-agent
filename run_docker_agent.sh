#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ -z "${AGENT_API_URL:-}" ]]; then
  echo "AGENT_API_URL is required (example: https://asm.example.com/api)" >&2
  exit 1
fi

has_dedicated_enrollment=false
has_tenant_enrollment=false
if [[ -n "${AGENT_ENROLLMENT_ID:-}" && -n "${AGENT_ENROLLMENT_TOKEN:-}" ]]; then
  has_dedicated_enrollment=true
fi
if [[ -n "${AGENT_CLIENT_ID:-}" && -n "${AGENT_CLIENT_SECRET:-}" ]]; then
  has_tenant_enrollment=true
fi

if [[ "$has_dedicated_enrollment" != true && "$has_tenant_enrollment" != true ]]; then
  echo "Set either AGENT_ENROLLMENT_ID + AGENT_ENROLLMENT_TOKEN or AGENT_CLIENT_ID + AGENT_CLIENT_SECRET." >&2
  exit 1
fi

export AGENT_NAME="${AGENT_NAME:-Remote-Agent}"
export AGENT_TAGS="${AGENT_TAGS:-remote,scanner}"
export XASM_AGENT_IMAGE="${XASM_AGENT_IMAGE:-xasm-agent:latest}"

docker compose -f docker-compose.agent.yml up -d --build
docker compose -f docker-compose.agent.yml ps

echo
echo "Agent started. Follow enrollment and job logs with:"
echo "  docker compose -f docker-compose.agent.yml logs -f xasm-agent"
