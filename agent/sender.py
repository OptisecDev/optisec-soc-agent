import base64
import json
import logging
import os
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent.config import AGENT_ID, SERVER_URL

logger = logging.getLogger(__name__)

_KEY_FILE = Path(__file__).parent.parent / ".aes_key"


def _load_or_create_key() -> bytes:
    """Load persisted AES-256 key or generate and save a new one."""
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


def send_event(event: dict, max_retries: int = 3) -> bool:
    payload = {
        "agent_id": AGENT_ID,
        "data": _encrypt(event),
    }
    headers = {"Content-Type": "application/json"}

    for attempt in range(max_retries):
        try:
            resp = requests.post(
                f"{SERVER_URL}/events",
                json=payload,
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            logger.info("Event sent successfully")
            return True
        except requests.exceptions.RequestException as exc:
            logger.warning("Send attempt %d/%d failed: %s", attempt + 1, max_retries, exc)
            if attempt < max_retries - 1:
                time.sleep(2**attempt)

    logger.error("Failed to send event after %d attempts", max_retries)
    return False
