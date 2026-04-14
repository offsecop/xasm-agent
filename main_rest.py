"""
Agent entry point - REST API version
"""

import asyncio
import yaml
import os
from agent_core_rest import Agent

def parse_env_tags(raw_tags: str):
    if not raw_tags:
        return []
    return [tag.strip() for tag in raw_tags.split(',') if tag.strip()]

def load_config(config_file='config.yaml'):
    """Load configuration from YAML file, or use defaults for cloud deployment"""
    config_path = os.environ.get('CONFIG_FILE', config_file)
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[Config] {config_path} not found — using env var defaults (cloud mode)")
        return {
            'agent': {
                'name': os.environ.get('AGENT_NAME', ''),
                'description': os.environ.get('AGENT_DESCRIPTION', 'xASM Agent (Cloud Bootstrap)'),
                'tags': parse_env_tags(os.environ.get('AGENT_TAGS', 'cloud,scanner')),
            },
            'server': {
                'api_url': os.environ.get('AGENT_API_URL', 'http://localhost:3001/api'),
                'api_key': os.environ.get('AGENT_API_KEY', ''),
                'client_id': os.environ.get('AGENT_CLIENT_ID', ''),
                'client_secret': os.environ.get('AGENT_CLIENT_SECRET', ''),
                'enrollment_id': os.environ.get('AGENT_ENROLLMENT_ID', ''),
                'enrollment_token': os.environ.get('AGENT_ENROLLMENT_TOKEN', ''),
            },
            'heartbeat_interval': 30,
            'poll_interval': 30,
            'pubsub': {
                'project_id': os.environ.get('GCP_PROJECT_ID', 'xasm-local'),
                'subscription_id': os.environ.get('PUBSUB_SUBSCRIPTION_ID', 'agent-push'),
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



