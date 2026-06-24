import base64
import json
import logging
import os
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent.config import AGENT_ID, SERVER_URL

logger = logging.getLogger(__name__)

_KEY_FILE = Path(__file__).parent.parent / ".aes_key"
_LOGS_DIR = Path(__file__).parent.parent / "logs"
_EVENTS_FILE = _LOGS_DIR / "events.json"


def _load_or_create_key() -> bytes:
    if _KEY_FILE.exists():
        return bytes.fromhex(_KEY_FILE.read_text().strip())
    key = os.urandom(32)
    _KEY_FILE.write_text(key.hex())
    _KEY_FILE.chmod(0o600)
    return key


_AES_KEY = _load_or_create_key()


def _encrypt(data: dict) -> dict:
    aesgcm = AESGCM(_AES_KEY)
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }


def _save_locally(event: dict) -> bool:
    """Append event to the local events.json log. Returns True on success."""
    try:
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)
        events: list = []
        if _EVENTS_FILE.exists():
            try:
                events = json.loads(_EVENTS_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                events = []
        events.append(event)
        _EVENTS_FILE.write_text(json.dumps(events, indent=2))
        logger.info("Event saved locally (%d total)", len(events))
        return True
    except OSError as exc:
        logger.error("Failed to save event locally: %s", exc)
        return False


def _try_remote(event: dict) -> bool:
    """Single best-effort POST to the remote SOC server. Never raises."""
    payload = {"agent_id": AGENT_ID, "data": _encrypt(event)}
    try:
        resp = requests.post(
            f"{SERVER_URL}/events",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        resp.raise_for_status()
        logger.info("Event forwarded to remote SOC server")
        return True
    except requests.exceptions.RequestException as exc:
        logger.debug("Remote SOC server unreachable (offline fallback active): %s", exc)
        return False


def send_event(event: dict) -> bool:
    """Save event locally (primary), then attempt remote delivery (optional fallback)."""
    saved = _save_locally(event)
    _try_remote(event)
    return saved
