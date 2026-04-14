#!/usr/bin/env python3
"""
Simple Host-Based Agent - Runs nmap/nuclei directly on host machine
Bypasses Docker networking issues
"""
import asyncio
import requests
import json
import time
from agent_core import Agent

# Use existing config
import yaml
config = yaml.safe_load(open('config.yaml'))

# Override to use localhost (not Docker networking)
config['server']['api_url'] = 'http://localhost:3001/api'
config['server']['ws_url'] = 'ws://localhost:3001/agent-ws'

print("="*60)
print("HOST-BASED AGENT - Direct Execution")
print("="*60)
print(f"Agent: {config['agent']['name']}")
print(f"Server: {config['server']['api_url']}")
print(f"Tools: {len(config.get('tools', []))}")
print("="*60)

# Create and run agent
agent = Agent(config)

async def main():
    try:
        await agent.run()
    except KeyboardInterrupt:
        print("\nStopping...")
        await agent.stop()

if __name__ == '__main__':
    asyncio.run(main())
