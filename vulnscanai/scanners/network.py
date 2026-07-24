# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Remote network-exposure scanner: nmap against an explicit, config-only
allow-list of hosts/CIDRs the operator is authorized to test.

Everything else this tool does inspects the LOCAL host only. This scanner is
different in kind: it flags exposed/risky services on OTHER machines. V1 is
scoped to port/service exposure ONLY -- nmap host discovery + a port scan +
service/version detection (-sV) -- using the exact same plaintext/sensitive
risk taxonomy as the `ports` scanner (see `net_classify.py`), just observed
remotely. NO CVE/CPE matching on detected versions in v1 (too high a
false-positive risk without more validation; parked for a later phase).

Safety: this is the one scanner that can affect machines other than the one
it runs on, so it is gated on an explicit, config-only `network_targets`
allow-list (never a CLI flag) and genuinely refuses to run (`available()`
False) when that list is empty OR nmap isn't installed -- this is a safety
rail, not a UX default. Every real invocation prints a stderr reminder that
only authorized hosts belong in `network_targets`.

Findings from this scanner carry `Finding.target` (the remote host/IP) and
are, on principle, remediation-detection-only: `remediation.py` refuses to
attach executable commands to a target-bearing finding, since the local
apply engine can only run commands on ITS OWN host, never on the flagged one.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List

from ..models import Finding
from ..net_classify import classify, flagged_port_spec
from .base import Scanner, have, run

# Permissive but flag-safe: hostnames / IPv4 / IPv4 CIDR only (no leading '-',
# no whitespace/shell metacharacters). Rejecting ':' also scopes OUT IPv6 for
# v1 (needs nmap's -6 plus separate invocation grouping; backlog).
_TARGET_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.\-/_]*[A-Za-z0-9])?$')


def _valid_targets(raw: List[str]) -> List[str]:
    """Filter a config target list down to safe, well-formed entries.

    Silently drops anything that doesn't look like a plain hostname/IPv4/
    IPv4-CIDR -- never passed to a shell, but nmap itself takes these as
    argv entries, so this is a sanity/authorization-scope filter, not just
    injection defence.
    """
    out = []
    for t in raw:
        t = str(t).strip()
        if not t or ":" in t or not _TARGET_RE.match(t):
            continue
        out.append(t)
    return out


@dataclass
class NmapPort:
    proto: str
    port: int
    service_name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class NmapHost:
    address: str
    hostnames: List[str] = field(default_factory=list)
    state: str = "unknown"
    ports: List[NmapPort] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# pure parser (unit-testable without nmap; grounded in the nmap XML DTD)
# --------------------------------------------------------------------------- #
def parse_nmap_xml(xml_text: str) -> List[NmapHost]:
    """Parse `nmap -oX -` output into host/open-port records.

    Only ports in state "open" are kept (closed/filtered dropped, mirroring
    ports.parse_ss which only extracts LISTEN sockets). Never raises: a
    malformed document returns [].

    Real `nmap -oX -` output always carries a bare `<!DOCTYPE nmaprun>` (no
    internal subset) -- that is expected and harmless, so only a custom
    `<!ENTITY` declaration (the actual XXE/billion-laughs primitive; nmap
    itself never emits one) is rejected outright. Service banners in this XML
    originate from the REMOTE, potentially adversarial host being scanned,
    unlike the SCAP datastreams other parsers in this codebase treat as
    trusted, hence this defence in depth on top of ElementTree/expat's own
    default refusal to resolve external entities.
    """
    if "<!ENTITY" in xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)  # nosec B314 - ENTITY rejected above
    except ET.ParseError:
        return []
    hosts: List[NmapHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        state = (status.get("state") if status is not None else None) or "unknown"
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue  # v1 is IPv4-only; no usable address -> skip the host
        address = (addr_el.get("addr") or "").strip()
        if not address:
            continue
        hostnames = [hn.get("name") or "" for hn in host_el.findall("hostnames/hostname")]
        hostnames = [h for h in hostnames if h]
        ports: List[NmapPort] = []
        for port_el in host_el.findall("ports/port"):
            pstate = port_el.find("state")
            if pstate is None or pstate.get("state") != "open":
                continue
            proto = port_el.get("protocol") or ""
            try:
                portnum = int(port_el.get("portid") or "")
            except ValueError:
                continue
            svc = port_el.find("service")
            ports.append(NmapPort(
                proto=proto, port=portnum,
                service_name=((svc.get("name") if svc is not None else "") or ""),
                product=((svc.get("product") if svc is not None else "") or ""),
                version=((svc.get("version") if svc is not None else "") or ""),
            ))
        hosts.append(NmapHost(address=address, hostnames=hostnames, state=state, ports=ports))
    return hosts


# --------------------------------------------------------------------------- #
# rule engine (pure) -- reuses net_classify.classify(), the `ports` taxonomy
# --------------------------------------------------------------------------- #
def audit_network(hosts: List[NmapHost]) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for host in hosts:
        if host.state != "up":
            continue
        for port in host.ports:
            hit = classify(port.port)
            if not hit:
                continue
            category, severity, label = hit
            key = (host.address, port.port, category)
            if key in seen:
                continue
            seen.add(key)
            host_label = host.address
            if host.hostnames:
                host_label += f" ({host.hostnames[0]})"
            svc_bits = " ".join(x for x in (port.product, port.version) if x)
            svc_note = f" ({svc_bits})" if svc_bits else ""
            why = ("a plaintext/legacy protocol" if category == "plaintext"
                   else "a sensitive service that should not face the network")
            out.append(Finding(
                source="network",
                title=f"{label} exposed on {host_label}:{port.port}/{port.proto}{svc_note}",
                severity=severity,
                description=(
                    f"nmap found {label} open on {host_label}:{port.port}/{port.proto}"
                    f"{svc_note}, reachable over the network from wherever this scan "
                    f"ran. Port {port.port} is {why}. Restrict it with a firewall "
                    f"rule, bind the service to an internal-only interface, or "
                    f"disable it if unused. This finding describes a REMOTE host: "
                    f"any fix must be applied on {host.address} itself -- this tool "
                    f"cannot apply changes there."
                ),
                target=host.address,
                raw={"proto": port.proto, "port": port.port, "category": category,
                     "service": label, "service_name": port.service_name,
                     "product": port.product, "version": port.version,
                     "hostnames": host.hostnames},
            ))
    return out


# --------------------------------------------------------------------------- #
# thin Scanner subclass
# --------------------------------------------------------------------------- #
class NetworkScanner(Scanner):
    name = "network"

    def _targets(self) -> List[str]:
        raw = list(getattr(self.config, "network_targets", None) or [])
        return _valid_targets(raw)

    def available(self) -> bool:
        return bool(self._targets()) and have("nmap")

    def scan(self) -> List[Finding]:
        raw = list(getattr(self.config, "network_targets", None) or [])
        targets = _valid_targets(raw)
        if not targets:
            return []
        if len(targets) != len(raw):
            print(f"    network: {len(raw) - len(targets)} network_targets "
                  f"entry/entries ignored (invalid format)", file=sys.stderr)
        preview = ", ".join(targets[:5]) + (", ..." if len(targets) > 5 else "")
        print(f"    network: ⚠ probing {len(targets)} authorized target(s) "
              f"via nmap ({preview}). Only scan hosts/networks you are "
              f"explicitly authorized to test.", file=sys.stderr)
        timeout = int(getattr(self.config, "network_scan_timeout", 900) or 900)
        cmd = ["nmap", "-sV", "-n", "--host-timeout", "300", "--max-retries", "2",
               "-p", flagged_port_spec(), "-oX", "-", *targets]
        try:
            rc, out, _err = run(cmd, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            print(f"    ! network scan failed: {exc}", file=sys.stderr)
            return []
        if rc != 0 or not out.strip():
            return []
        hosts = parse_nmap_xml(out)
        down = sum(1 for h in hosts if h.state != "up")
        if down:
            print(f"    - network: {down} target(s) unreachable (no response)",
                  file=sys.stderr)
        return audit_network(hosts)
