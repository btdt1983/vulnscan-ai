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
