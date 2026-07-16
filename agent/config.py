import uuid
import json
from pathlib import Path

_CONFIG_FILE = Path(__file__).parent.parent / ".agent_config.json"


def _load_or_create_agent_id() -> str:
    if _CONFIG_FILE.exists():
        try:
            data = json.loads(_CONFIG_FILE.read_text())
            return data["agent_id"]
        except (KeyError, json.JSONDecodeError):
            pass
    agent_id = str(uuid.uuid4())
    _CONFIG_FILE.write_text(json.dumps({"agent_id": agent_id}))
    return agent_id


# NOT YET AVAILABLE: no central SOC server is deployed at this address (or
# anywhere else) yet. sender.py's remote-sync path will silently fail every
# time until a real server exists here — all events are stored locally
# regardless (see sender._save_locally), so this has no effect on the agent
# working correctly today.
SERVER_URL = "https://optisec-soc.com/api"
AGENT_ID = _load_or_create_agent_id()
SCAN_INTERVAL = 30
LOG_LEVEL = "INFO"
