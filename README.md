# Optisec SOC Agent

A lightweight, autonomous Security Operations Center (SOC) agent that continuously monitors local networks for suspicious activity and reports findings to the Optisec SOC platform.

## Features

- **ARP network scanning** — discovers all devices on local private networks every 30 seconds
- **Unknown device detection** — alerts on any new MAC address that appears on the network
- **Port scan detection** — flags processes with an abnormally high number of outbound SYN connections
- **Encrypted event reporting (not yet available)** — the agent can AES-256-GCM encrypt events and attempt delivery to a central SOC server, but no such server is deployed yet; every event is stored locally regardless (see Local event log below)
- **Local event log** — all scan results are persisted to `logs/events.json` for offline analysis

## Project Structure

```
optisec-soc-agent/
├── agent/
│   ├── __init__.py
│   ├── config.py       # Configuration: server URL, scan interval, agent ID
│   ├── core.py         # Main scan loop and threat detection logic
│   └── sender.py       # AES-GCM encryption and HTTP event delivery
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- Root/sudo privileges (required for ARP scanning via Scapy)

## Installation

```bash
git clone https://github.com/OptisecDev/optisec-soc-agent.git
cd optisec-soc-agent

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Configuration

Edit `agent/config.py` to set:

| Variable        | Default                          | Description                        |
|-----------------|----------------------------------|------------------------------------|
| `SERVER_URL`    | `https://optisec-soc.com/api`   | SOC server endpoint — **not yet live**; no server is deployed here or elsewhere, so remote delivery currently always fails silently and every event stays local-only |
| `SCAN_INTERVAL` | `30`                             | Seconds between scans              |
| `LOG_LEVEL`     | `INFO`                           | Python logging level               |

The agent auto-generates a unique `agent_id` on first run and persists it to `.agent_config.json`.  
An AES-256 key is auto-generated and stored in `.aes_key` (mode `0600`). **Never commit these files.**

## Running

```bash
sudo .venv/bin/python -m agent.core
```

> Root privileges are needed so Scapy can send raw ARP packets.

## Security Notes

- `.aes_key` and `.agent_config.json` are excluded from version control via `.gitignore`
- If a central server existed, events would be encrypted with AES-256-GCM before sending — but no such server is deployed yet, so this has no effect today (see `SERVER_URL` in Configuration above)
- Logs in `logs/` are also excluded; rotate or archive them externally

## License

Proprietary — © 2026 Optisec. All rights reserved.

Purchase a license at [optisecdev.github.io/optisec-store](https://optisecdev.github.io/optisec-store) ($99/year) · Contact: [ahssanali84.syber@gmail.com](mailto:ahssanali84.syber@gmail.com)
