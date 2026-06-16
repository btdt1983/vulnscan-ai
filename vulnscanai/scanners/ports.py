"""Network exposure scanner.

Wraps `ss -tulpn` to find listening sockets reachable from the network and flags
the risky ones. Conservative by default: only sockets on a non-loopback address
that are either a plaintext/legacy protocol (telnet, ftp, vnc, X11, ...) or a
sensitive service that should not face the network (databases/caches). Expected
public services (HTTP/HTTPS/SSH) are not flagged generically.

Remediation is service-dependent (bind to localhost, a firewall rule, or disable
the service), so the AI picks the appropriate fix; when it touches a config or
service it runs through the transactional engine.
"""

from __future__ import annotations

import re
import sys
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..models import Finding
from .base import Scanner, have, run

# Minimal firewalld service -> "port/proto" map for the common cases that show
# up as listeners; explicit --list-ports covers everything else.
_SERVICE_PORTS = {
    "ssh": "22/tcp", "http": "80/tcp", "https": "443/tcp", "ftp": "21/tcp",
    "telnet": "23/tcp", "mysql": "3306/tcp", "postgresql": "5432/tcp",
    "redis": "6379/tcp", "mongodb": "27017/tcp", "vnc-server": "5900/tcp",
}

# Plaintext / legacy protocols that should not be exposed (port -> label).
_PLAINTEXT: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 23: "telnet", 69: "tftp", 79: "finger",
    161: "snmp", 162: "snmp-trap", 512: "rexec", 513: "rlogin", 514: "rsh",
    873: "rsync", 2049: "nfs",
}
# Sensitive services (databases/caches/brokers) that should stay off the network.
_SENSITIVE: Dict[int, str] = {
    1433: "mssql", 1521: "oracle", 2379: "etcd", 2380: "etcd",
    3306: "mysql/mariadb", 5432: "postgresql", 5672: "amqp/rabbitmq",
    5984: "couchdb", 6379: "redis", 9042: "cassandra", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb",
}
_PROC_RE = re.compile(r'\("([^"]+)"')


def _is_loopback(addr: str) -> bool:
    a = addr.strip("[]")
    return a == "::1" or a.startswith("127.")


def classify(port: int) -> Optional[Tuple[str, str, str]]:
    """Return (category, severity, label) for a risky port, else None."""
    if port in _PLAINTEXT:
        return ("plaintext", "important", _PLAINTEXT[port])
    if 5900 <= port <= 5906:
        return ("plaintext", "important", "vnc")
    if 6000 <= port <= 6010:
        return ("plaintext", "important", "x11")
    if port in _SENSITIVE:
        return ("sensitive", "important", _SENSITIVE[port])
    return None


def parse_ss(text: str) -> List[Dict[str, object]]:
    """Parse `ss -tulpn` into listening-socket dicts."""
    out: List[Dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() not in ("tcp", "udp"):
            continue
        if parts[1].upper() not in ("LISTEN", "UNCONN"):
            continue
        local = parts[4]
        if ":" not in local:
            continue
        addr, _, port_s = local.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            continue
        proc = ""
        m = _PROC_RE.search(line)
        if m:
            proc = m.group(1)
        out.append({"proto": parts[0].lower(), "address": addr,
                    "port": port, "process": proc})
    return out


def firewall_allowed_ports() -> Optional[Set[str]]:
    """Return the set of "port/proto" the firewall lets through, or None when
    firewalld isn't running (so we can't tell -> assume reachable)."""
    if not have("firewall-cmd"):
        return None
    try:
        rc, state, _ = run(["firewall-cmd", "--state"], timeout=10)
    except Exception:  # noqa: BLE001
        return None
    if "running" not in (state or "").lower():
        return None
    allowed: Set[str] = set()
    try:
        _, ports, _ = run(["firewall-cmd", "--list-ports"], timeout=10)
        allowed.update(ports.split())
        _, svcs, _ = run(["firewall-cmd", "--list-services"], timeout=10)
        for svc in svcs.split():
            if svc in _SERVICE_PORTS:
                allowed.add(_SERVICE_PORTS[svc])
    except Exception:  # noqa: BLE001
        return None
    return allowed


def audit_ports(sockets: List[Dict[str, object]], *,
                allowed: Callable[[str, int], Optional[bool]] =
                lambda _proto, _port: None) -> List[Finding]:
    """Apply the conservative exposure policy to parsed sockets.

    `allowed(proto, port)` returns True/False if the host firewall's stance on
    the port is known, or None when unknown. A port the firewall blocks (False)
    isn't reachable off-host, so it's dropped (not a real exposure).
    """
    out: List[Finding] = []
    seen = set()
    for s in sockets:
        addr = str(s["address"])
        port = int(s["port"])
        proto = str(s["proto"])
        if _is_loopback(addr):
            continue  # not reachable off-host
        if allowed(proto, port) is False:
            continue  # firewall blocks it -> not actually exposed
        hit = classify(port)
        if not hit:
            continue
        category, severity, label = hit
        proc = str(s["process"]) or "unknown"
        key = (proc, port, category)
        if key in seen:
            continue  # collapse IPv4/IPv6 duplicates of the same listener
        seen.add(key)
        why = ("a plaintext/legacy protocol" if category == "plaintext"
               else "a sensitive service that should not face the network")
        out.append(Finding(
            source="ports",
            title=f"{label} ({proc}) exposed on {addr}:{port}/{s['proto']}",
            severity=severity,
            description=(f"{proc or label} is listening on {addr}:{port} "
                        f"({s['proto']}), reachable off-host. Port {port} is "
                        f"{why}. Bind it to localhost, restrict it with the "
                        f"firewall, or disable the service if unused."),
            raw={"proto": s["proto"], "address": addr, "port": port,
                 "process": proc, "category": category, "service": label},
        ))
    return out


class PortScanner(Scanner):
    name = "ports"

    def available(self) -> bool:
        return have("ss")

    def scan(self) -> List[Finding]:
        try:
            rc, out, _ = run(["ss", "-tulpn"], timeout=30)
        except Exception:  # noqa: BLE001
            return []
        if not out.strip():
            return []
        sockets = parse_ss(out)
        fw = firewall_allowed_ports()
        if fw is None:
            return audit_ports(sockets)
        pred = (lambda proto, port: f"{port}/{proto}" in fw)
        findings = audit_ports(sockets, allowed=pred)
        suppressed = len(audit_ports(sockets)) - len(findings)
        if suppressed:
            print(f"    ports: {suppressed} exposure(s) suppressed "
                  f"(blocked by firewalld)", file=sys.stderr)
        return findings
