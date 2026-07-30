# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Shared network-exposure risk taxonomy: which ports are risky to expose.

Extracted from the `ports` scanner (local `ss` listeners) so `ports` (local)
and `network` (remote nmap) score exposure with the exact same rules -- one
risk model, observed from two vantage points.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# Plaintext / legacy protocols that should not be exposed (port -> label).
PLAINTEXT_PORTS: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 23: "telnet", 69: "tftp", 79: "finger",
    161: "snmp", 162: "snmp-trap", 512: "rexec", 513: "rlogin", 514: "rsh",
    873: "rsync", 2049: "nfs",
}
# Sensitive services (databases/caches/brokers) that should stay off the network.
SENSITIVE_PORTS: Dict[int, str] = {
    1433: "mssql", 1521: "oracle", 2379: "etcd", 2380: "etcd",
    3306: "mysql/mariadb", 5432: "postgresql", 5672: "amqp/rabbitmq",
    5984: "couchdb", 6379: "redis", 9042: "cassandra", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb",
}


def classify(port: int) -> Optional[Tuple[str, str, str]]:
    """Return (category, severity, label) for a risky port, else None."""
    if port in PLAINTEXT_PORTS:
        return ("plaintext", "important", PLAINTEXT_PORTS[port])
    if 5900 <= port <= 5906:
        return ("plaintext", "important", "vnc")
    if 6000 <= port <= 6010:
        return ("plaintext", "important", "x11")
    if port in SENSITIVE_PORTS:
        return ("sensitive", "important", SENSITIVE_PORTS[port])
    return None


def flagged_port_spec() -> str:
    """Comma-joined nmap `-p` spec covering every port classify() can flag."""
    ports = sorted(set(PLAINTEXT_PORTS) | set(SENSITIVE_PORTS))
    return ",".join([str(p) for p in ports] + ["5900-5906", "6000-6010"])


# Service-name -> (category, severity, label), for classifying a risky service
# found on a NON-standard port (nmap -sV detected it by protocol fingerprint,
# not by port number). Keys are nmap's own `-sV` probe MATCH names (from
# nmap-service-probes), verified against a real installed nmap, NOT the
# generic nmap-services port->name table -- those two vocabularies disagree
# for several of these (e.g. the probe name is "login"/"shell", not
# "rlogin"/"rsh"; "memcached", not "memcache"). Only names that come from a
# confirmed protocol match belong here.
#
# Deliberately absent: nfs, etcd (no nmap fingerprint exists for either --
# nfs is identified via RPC/portmapper, outside the -sV match engine; etcd
# has no match line at all) and couchdb/rabbitmq-mgmt (only resolvable
# generically as "http", which must NEVER be a key here -- it would flag
# every ordinary web server as a sensitive-service exposure).
_SERVICE_NAME_MAP: Dict[str, Tuple[str, str, str]] = {
    "ftp": ("plaintext", "important", "ftp"),
    "telnet": ("plaintext", "important", "telnet"),
    "tftp": ("plaintext", "important", "tftp"),
    "finger": ("plaintext", "important", "finger"),
    "snmp": ("plaintext", "important", "snmp"),
    "rsync": ("plaintext", "important", "rsync"),
    "exec": ("plaintext", "important", "rexec"),
    "rexec": ("plaintext", "important", "rexec"),
    "login": ("plaintext", "important", "rlogin"),
    "shell": ("plaintext", "important", "rsh"),
    "vnc": ("plaintext", "important", "vnc"),
    "x11": ("plaintext", "important", "x11"),
    "ms-sql-s": ("sensitive", "important", "mssql"),
    "oracle-tns": ("sensitive", "important", "oracle"),
    "mysql": ("sensitive", "important", "mysql/mariadb"),
    "postgresql": ("sensitive", "important", "postgresql"),
    "amqp": ("sensitive", "important", "amqp/rabbitmq"),
    "redis": ("sensitive", "important", "redis"),
    "cassandra-native": ("sensitive", "important", "cassandra"),
    "memcached": ("sensitive", "important", "memcached"),
    "mongodb": ("sensitive", "important", "mongodb"),
    # Real match name, but narrow coverage in practice: it's keyed on the
    # binary transport protocol's "This is not a HTTP port" reply (normally
    # port 9300); the REST API (normally 9200) just looks like plain http.
    "elasticsearch": ("sensitive", "important", "elasticsearch"),
}


def classify_by_service(name: str) -> Optional[Tuple[str, str, str]]:
    """Return (category, severity, label) for a risky service NAME (from
    nmap's -sV fingerprint), else None. Only meant to be called on a
    confidently-probed match -- see network.py's confidence gate."""
    return _SERVICE_NAME_MAP.get((name or "").strip().lower())
