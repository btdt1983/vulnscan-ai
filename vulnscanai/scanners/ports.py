# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Network exposure scanner.

Wraps `ss -tulpn` to find listening sockets reachable from the network and flags
the risky ones. Conservative by default: only sockets on a non-loopback address
that are either a plaintext/legacy protocol (telnet, ftp, vnc, X11, ...) or a
sensitive service that should not face the network (databases/caches). Expected
public services (HTTP/HTTPS/SSH) are not flagged generically.

A port the host firewall already blocks isn't a real exposure, so findings are
suppressed when firewalld (authoritative when running) or, as a fallback, raw
nftables can confidently prove the port unreachable from off-host.

Remediation is service-dependent (bind to localhost, a firewall rule, or disable
the service), so the AI picks the appropriate fix; when it touches a config or
service it runs through the transactional engine.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..models import Finding
from .base import Scanner, have, run

# A port matcher: (proto, lo, hi). proto is "tcp"/"udp", or None for both.
Matcher = Tuple[Optional[str], int, int]

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


# --------------------------------------------------------------------------- #
# nftables (raw, no firewalld) firewall awareness
# --------------------------------------------------------------------------- #
def _matches(matchers: List[Matcher], proto: str, port: int) -> bool:
    return any((m[0] is None or m[0] == proto) and m[1] <= port <= m[2]
               for m in matchers)


def _expr_dports(right, proto: Optional[str],
                 named: Dict[str, List[Tuple[int, int]]]) -> List[Matcher]:
    """Turn an nft match right-hand side into port matchers."""
    out: List[Matcher] = []
    if isinstance(right, int):
        out.append((proto, right, right))
    elif isinstance(right, str):
        if right.startswith("@"):                       # named set reference
            for lo, hi in named.get(right[1:], []):
                out.append((proto, lo, hi))
        else:
            try:
                p = int(right)
                out.append((proto, p, p))
            except ValueError:
                pass
    elif isinstance(right, dict):
        if "range" in right and isinstance(right["range"], list):
            lo, hi = right["range"][0], right["range"][1]
            out.append((proto, int(lo), int(hi)))
        elif "set" in right and isinstance(right["set"], list):
            for elem in right["set"]:
                out.extend(_expr_dports(elem, proto, named))
    return out


def _named_sets(ruleset: List[dict]) -> Dict[str, List[Tuple[int, int]]]:
    """Collect named-set port ranges keyed by set name."""
    named: Dict[str, List[Tuple[int, int]]] = {}
    for item in ruleset:
        s = item.get("set") if isinstance(item, dict) else None
        if not s or "name" not in s:
            continue
        ranges: List[Tuple[int, int]] = []
        for elem in s.get("elem", []) or []:
            if isinstance(elem, int):
                ranges.append((elem, elem))
            elif isinstance(elem, dict) and "range" in elem:
                r = elem["range"]
                ranges.append((int(r[0]), int(r[1])))
        named[s["name"]] = ranges
    return named


def parse_nft_ruleset(obj: dict) -> Tuple[List[Matcher], List[Matcher], bool]:
    """Parse `nft --json list ruleset` into (accept, drop, default_deny).

    accept/drop are port matchers; default_deny is True when an input-hook
    chain has a drop policy. Best-effort and deliberately conservative: it only
    feeds the "blocked" decision, and unmatched ports stay reachable.
    """
    ruleset = obj.get("nftables", []) if isinstance(obj, dict) else []
    named = _named_sets(ruleset)
    accept: List[Matcher] = []
    drop: List[Matcher] = []
    default_deny = False

    for item in ruleset:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if chain and chain.get("hook") == "input" and chain.get("policy") == "drop":
            default_deny = True
        rule = item.get("rule")
        if not rule:
            continue
        exprs = rule.get("expr", []) or []
        verb = None
        dports: List[Matcher] = []
        for e in exprs:
            if not isinstance(e, dict):
                continue
            if "match" in e:
                m = e["match"]
                left = m.get("left", {})
                payload = left.get("payload") if isinstance(left, dict) else None
                if payload and payload.get("field") == "dport":
                    proto = payload.get("protocol")
                    proto = proto if proto in ("tcp", "udp") else None
                    dports.extend(_expr_dports(m.get("right"), proto, named))
            elif "accept" in e:
                verb = "accept"
            elif "drop" in e or "reject" in e:
                verb = "drop"
        if not dports:
            continue
        if verb == "accept":
            accept.extend(dports)
        elif verb == "drop":
            drop.extend(dports)
    return accept, drop, default_deny


def matchers_to_predicate(accept: List[Matcher], drop: List[Matcher],
                          default_deny: bool) -> Callable[[str, int], Optional[bool]]:
    """Wrap parsed nftables matchers into an `allowed(proto, port)` predicate."""
    def allowed(proto: str, port: int) -> Optional[bool]:
        if _matches(accept, proto, port):
            return True               # explicitly reachable
        if _matches(drop, proto, port):
            return False              # explicitly blocked
        if default_deny:
            return False              # default-deny and no accept matched
        return None
    return allowed


def nft_predicate() -> Optional[Callable[[str, int], Optional[bool]]]:
    """Build a firewall predicate from raw nftables, or None if unusable.

    The fallback for hosts without firewalld. Returns None (rather than a
    permissive predicate) when nothing can be confidently called "blocked", so
    a parse miss never hides a real exposure.
    """
    if not have("nft"):
        return None
    try:
        rc, out, _ = run(["nft", "--json", "list", "ruleset"], timeout=10)
    except Exception:  # noqa: BLE001
        return None
    if rc != 0 or not out.strip():
        return None
    try:
        obj = json.loads(out)
    except (ValueError, TypeError):
        return None
    accept, drop, default_deny = parse_nft_ruleset(obj)
    if not (default_deny or drop):
        return None  # nothing we can confidently call "blocked"
    return matchers_to_predicate(accept, drop, default_deny)


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
        if fw is not None:
            pred, backend = (lambda proto, port: f"{port}/{proto}" in fw), "firewalld"
        else:
            pred, backend = nft_predicate(), "nftables"
        if pred is None:
            return audit_ports(sockets)
        findings = audit_ports(sockets, allowed=pred)
        suppressed = len(audit_ports(sockets)) - len(findings)
        if suppressed:
            print(f"    ports: {suppressed} exposure(s) suppressed "
                  f"(blocked by {backend})", file=sys.stderr)
        return findings
