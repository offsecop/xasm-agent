# ASM Platform Agent

The agent is responsible for executing security scanning tools and reporting results back to the platform.

## Features

- REST API polling for job acquisition (5-second interval)
- Plugin-based architecture for custom tools
- 57+ scanning tools across 20+ tool categories
- Heartbeat monitoring with configurable interval
- Output streaming and progress tracking
- Reusable aiohttp session for efficient HTTP communication

## Setup (Docker -- Recommended)

The agent runs as part of the Docker Compose stack (5 agent containers by default):

```bash
docker-compose up -d
```

To restart all agents after code changes:

```bash
docker-compose restart agent agent2 agent3 agent4 agent5
```

Agent configuration for Docker is in `config.docker.yaml`.

### Standalone Setup (Development Only)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create configuration file:
```bash
cp config.yaml.example config.yaml
```

3. Edit `config.yaml`:
   - Set your agent name and tags
   - Configure server URLs (use `http://localhost:3001/api` for local backend)
   - Add your API key (obtain from platform UI)
   - Enable/disable tools

4. Run:
```bash
python main.py
```

## Creating Custom Tools

1. Create a new Python file in the `tools/` directory
2. Inherit from `ToolPlugin` base class
3. Implement required methods:
   - `name`: Unique tool identifier (format: "category:tool_name")
   - `description`: Tool description
   - `schema`: Parameter schema (JSON Schema format)
   - `execute`: Tool execution logic

Example:
```python
from plugin_interface import ToolPlugin

class MyCustomTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "custom:my_scanner"

    @property
    def description(self) -> str:
        return "My custom scanner tool"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"}
            },
            "required": ["target"]
        }

    async def execute(self, parameters):
        target = parameters['target']
        # Your scanning logic here
        return {"result": "success"}
```

4. Add tool to `config.yaml` (or `config.docker.yaml` for Docker):
```yaml
tools:
  - name: "custom:my_scanner"
    enabled: true
```

5. Restart all agents:
```bash
docker-compose restart agent agent2 agent3 agent4 agent5
```

## Architecture

The agent uses a REST polling architecture:

1. Agent registers with the backend via `POST /api/agents/register`
2. Sends periodic heartbeats via `POST /api/agents/heartbeat`
3. Polls for pending jobs via `GET /api/agents/jobs/next`
4. Executes the assigned tool and streams output/progress updates
5. Reports job completion via `PATCH /api/jobs/:id`

Key files:

- `main.py` -- Entry point
- `agent_core_rest.py` -- Core agent logic, REST polling, job execution
- `plugin_interface.py` -- Base class for all tool plugins
- `plugin_loader.py` -- Tool discovery and loading system
- `config.docker.yaml` -- Docker agent configuration
- `tools/` -- All scanning tool implementations (57+ tools)
