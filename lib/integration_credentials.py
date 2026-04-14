"""
Integration Credentials Helper
Fetches API keys from backend integrations with agent access enabled
"""

import os
import aiohttp
from typing import Optional, Dict


async def get_integration_credentials(provider: str) -> Optional[Dict[str, str]]:
    """
    Fetch integration credentials from the backend.

    The integration must have `enableAgentAccess` set to true.

    Args:
        provider: Integration provider name (e.g., 'SHODAN')

    Returns:
        Dict with credentials (e.g., {'apiKey': '...'}) or None if not available
    """
    # Get backend URL and agent API key from config
    api_url = os.environ.get('API_URL', 'http://backend:3001/api')
    agent_api_key = os.environ.get('AGENT_API_KEY')

    # Also try to load from config file
    if not agent_api_key:
        try:
            import yaml
            config_file = os.environ.get('CONFIG_FILE', 'config.docker.yaml')
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), config_file)
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    agent_api_key = config.get('server', {}).get('api_key')
                    if not api_url or api_url == 'http://backend:3001/api':
                        api_url = config.get('server', {}).get('api_url', api_url)
        except Exception as e:
            print(f"[Credentials] Could not load config: {e}")

    if not agent_api_key:
        print("[Credentials] Agent API key not configured")
        return None

    url = f"{api_url}/integrations/{provider.upper()}/credentials-for-agent"

    try:
        async with aiohttp.ClientSession() as session:
            headers = {'X-API-Key': agent_api_key}
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('credentials')
                elif response.status == 403:
                    print(f"[Credentials] Agent access not enabled for {provider}")
                    return None
                elif response.status == 404:
                    print(f"[Credentials] Integration {provider} not found")
                    return None
                else:
                    error_text = await response.text()
                    print(f"[Credentials] Error fetching {provider} credentials: {response.status} - {error_text}")
                    return None
    except Exception as e:
        print(f"[Credentials] Exception fetching {provider} credentials: {e}")
        return None


async def get_shodan_api_key() -> Optional[str]:
    """
    Get Shodan API key from integration or environment.

    Checks in order:
    1. SHODAN_API_KEY environment variable
    2. Backend integration with agent access enabled

    Returns:
        Shodan API key or None
    """
    # First check environment
    api_key = os.environ.get('SHODAN_API_KEY')
    if api_key:
        return api_key

    # Then try backend integration
    credentials = await get_integration_credentials('SHODAN')
    if credentials:
        return credentials.get('apiKey')

    return None
