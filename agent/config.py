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


SERVER_URL = "https://optisec-soc.com/api"
AGENT_ID = _load_or_create_agent_id()
SCAN_INTERVAL = 30
LOG_LEVEL = "INFO"
