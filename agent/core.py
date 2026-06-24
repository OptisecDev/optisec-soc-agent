import datetime
import json
import logging
import socket
import time
from pathlib import Path

import psutil
from scapy.all import ARP, Ether, srp

from agent.config import LOG_LEVEL, SCAN_INTERVAL
from agent.sender import send_event

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

LOGS_DIR = Path(__file__).parent.parent / "logs"
EVENTS_FILE = LOGS_DIR / "events.json"


def _get_local_networks() -> list[dict]:
    """Return IPv4 interfaces that belong to private address space."""
    networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith(("192.168.", "10.", "172.")):
                    networks.append({"interface": iface, "ip": ip, "netmask": addr.netmask})
    return networks


def _cidr_from_ip(ip: str, netmask: str) -> str:
    """Convert an IP + netmask to CIDR notation (e.g. 192.168.1.5/24)."""
    try:
        bits = sum(bin(int(b)).count("1") for b in netmask.split("."))
    except Exception:
        bits = 24
    prefix = ".".join(ip.split(".")[:3]) + ".0"
    return f"{prefix}/{bits}"


def _arp_scan(network: str) -> list[dict]:
    """ARP-scan a network and return discovered devices."""
    devices = []
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=3, verbose=False)
        for _, rcv in answered:
            try:
                hostname = socket.gethostbyaddr(rcv.psrc)[0]
            except socket.herror:
                hostname = "unknown"
            devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "hostname": hostname})
    except Exception as exc:
        logger.error("ARP scan failed for %s: %s", network, exc)
    return devices


def _detect_port_scan(connections: list) -> list[dict]:
    """Flag processes that have an unusually high number of outbound connections."""
    from collections import Counter
    pid_counts: Counter = Counter()
    for conn in connections:
        if conn.status == "SYN_SENT":
            pid_counts[conn.pid] += 1

    alerts = []
    for pid, count in pid_counts.items():
        if count > 20:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
            alerts.append({"type": "port_scan", "pid": pid, "process": name, "syn_count": count, "severity": "high"})
    return alerts


def _log_event(event: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    events: list = []
    if EVENTS_FILE.exists():
        try:
            events = json.loads(EVENTS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            events = []
    events.append(event)
    EVENTS_FILE.write_text(json.dumps(events, indent=2))


def run() -> None:
    logger.info("OptiSec SOC Agent starting (interval=%ds)", SCAN_INTERVAL)
    known_macs: set[str] = set()

    while True:
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        scan_results = []
        suspicious: list[dict] = []

        networks = _get_local_networks()
        for net in networks:
            network_cidr = _cidr_from_ip(net["ip"], net["netmask"])
            devices = _arp_scan(network_cidr)

            new_devices = [d for d in devices if d["mac"] not in known_macs]
            for d in new_devices:
                suspicious.append({"type": "unknown_device", "device": d, "severity": "medium"})
                known_macs.add(d["mac"])

            scan_results.append({"interface": net["interface"], "network": network_cidr, "devices": devices})

        try:
            connections = psutil.net_connections(kind="inet")
            suspicious.extend(_detect_port_scan(connections))
        except psutil.AccessDenied:
            logger.warning("Insufficient permissions to read network connections")

        event = {
            "timestamp": timestamp,
            "scans": scan_results,
            "suspicious": suspicious,
        }

        _log_event(event)

        if suspicious:
            logger.warning("Suspicious activity detected: %d finding(s)", len(suspicious))
            send_event(event)
        else:
            logger.info("Scan complete — %d network(s), no threats", len(scan_results))

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run()
