"""
Agent entry point - REST API version
"""

import asyncio
import yaml
import os
import time
from agent_core_rest import Agent

def parse_env_tags(raw_tags: str):
    if not raw_tags:
        return []
    return [tag.strip() for tag in raw_tags.split(',') if tag.strip()]

def load_config(config_file='config.yaml'):
    """Load configuration from YAML file, or use defaults for cloud deployment.

    #524 — when CONFIG_FILE is explicitly set (docker-compose mounts
    `config.docker.yaml`) the file is EXPECTED to exist. A fresh deploy can race
    the volume mount, so retry briefly before degrading to env-var defaults —
    otherwise a boot-time FileNotFoundError silently pins `api_url` to the
    `http://localhost:3001/api` fallback and the long-running agent enrolls
    against the wrong backend until someone manually restarts it. The cloud
    bootstrap path (no CONFIG_FILE) is unchanged: it goes straight to env-var
    defaults on the first miss.
    """
    config_path = os.environ.get('CONFIG_FILE', config_file)
    explicit = bool(os.environ.get('CONFIG_FILE'))
    attempts = max(1, int(os.environ.get('AGENT_CONFIG_RETRY_ATTEMPTS', '10' if explicit else '1')))
    interval = float(os.environ.get('AGENT_CONFIG_RETRY_INTERVAL_S', '3'))

    for attempt in range(attempts):
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            if attempt < attempts - 1:
                print(
                    f"[Config] {config_path} not found "
                    f"(attempt {attempt + 1}/{attempts}) — waiting {interval:.0f}s for the mounted config…"
                )
                time.sleep(interval)

    if explicit:
        print(
            f"[Config] WARNING: {config_path} still missing after {attempts} attempt(s); "
            f"falling back to env-var defaults — api_url will be "
            f"'{os.environ.get('AGENT_API_URL', 'http://localhost:3001/api')}'. "
            f"If this is docker-compose, the agent volume mount did not appear in time."
        )
    else:
        print(f"[Config] {config_path} not found — using env var defaults (cloud mode)")
    return {
            'agent': {
                'name': os.environ.get('AGENT_NAME', ''),
                'description': os.environ.get('AGENT_DESCRIPTION', 'xASM Agent (Cloud Bootstrap)'),
                'tags': parse_env_tags(os.environ.get('AGENT_TAGS', 'cloud,scanner')),
            },
            'server': {
                'api_url': os.environ.get('AGENT_API_URL', 'http://localhost:3001/api'),
                # Per-instance identity (WP4): the instance enrolls itself via
                # these tenant installer creds — there is no static api_key.
                'client_id': os.environ.get('AGENT_CLIENT_ID', ''),
                'client_secret': os.environ.get('AGENT_CLIENT_SECRET', ''),
                # Dedicated per-agent bootstrap (platform "Create Agent" flow):
                # a unique enrollmentId/token bound to one tenant-scoped Agent
                # row. When set, takes precedence over the installer creds above
                # and enrolls via POST /agents/enroll. (Agent.__init__ also reads
                # these env vars directly; mirrored here for config parity.)
                'enrollment_id': os.environ.get('AGENT_ENROLLMENT_ID', ''),
                'enrollment_token': os.environ.get('AGENT_ENROLLMENT_TOKEN', ''),
            },
            'heartbeat_interval': 30,
            'poll_interval': 30,
            'pubsub': {
                # Push-only delivery (POST /pubsub/push) + GET /agents/poll/jobs
                # backstop. No pull subscription, so no subscription_id needed here.
                'project_id': os.environ.get('GCP_PROJECT_ID', 'xasm-local'),
            },
        }

async def main():
    """Main entry point"""
    try:
        config = load_config()
        agent = Agent(config)
        await agent.run()
    except KeyboardInterrupt:
        print("\nShutting down agent...")
    except Exception as e:
        print(f"Fatal error: {e}")
        raise

if __name__ == '__main__':
    asyncio.run(main())



