# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Remote network-exposure scanner: nmap against an explicit, config-only
allow-list of hosts/CIDRs/hostnames (IPv4 and IPv6) the operator is
authorized to test.

Everything else this tool does inspects the LOCAL host only. This scanner is
different in kind: it flags exposed/risky services on OTHER machines. Scoped
to port/service exposure ONLY -- nmap host discovery + a port scan +
service/version detection (-sV) -- using the exact same plaintext/sensitive
risk taxonomy as the `ports` scanner (see `net_classify.py`), just observed
remotely, plus a service-name fallback (see `audit_network`) for a risky
service found on a non-standard port. NO CVE/CPE matching on detected
versions (too high a false-positive risk without more validation; stays
parked).

Safety: this is the one scanner that can affect machines other than the one
it runs on, so it is gated on an explicit `network_targets` allow-list and
genuinely refuses to run (`available()` False) when that list is empty OR
nmap isn't installed -- this is a safety rail, not a UX default. There is no
per-scan CLI override (`scan` never takes a `--target` flag); the
`vulnscan-ai network` subcommand only manages the persisted allow-list, it
never scans. Every real invocation prints a stderr reminder that only
authorized hosts belong in `network_targets`.

Findings from this scanner carry `Finding.target` (the remote host/IP) and
are, on principle, remediation-detection-only: `remediation.py` refuses to
attach executable commands to a target-bearing finding, since the local
apply engine can only run commands on ITS OWN host, never on the flagged one.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Tuple

from ..models import Finding
from ..net_classify import classify, classify_by_service, flagged_port_spec
from .base import Scanner, have, run

# Hostname fallback when a target doesn't parse as an IP/CIDR (nmap also
# accepts a "host/mask" shorthand, hence the permissive charset). No leading
# '-', no whitespace/shell metacharacters -- never passed to a shell, but
# nmap itself takes these as argv entries, so this is a sanity/authorization-
# scope filter, not injection defence.
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.\-/_]*[A-Za-z0-9])?$')

# A confidently-probed nmap service-name match above this floor is trusted
# for the classify_by_service() fallback. nmap's own unconfirmed "table"
# guess caps out around conf=3 (see the real captured fixture in tests); a
# genuine protocol match reports conf=10 -- 7 is a safe buffer, not a
# fragile cutoff.
_SERVICE_CONF_MIN = 7

# An IPv6 target wider than this is syntactically valid but operationally
# pointless: nmap will never finish sweeping it and will just burn the full
# timeout every scan. /112 = 2**16 addresses is the cutoff for the warning.
_IPV6_WARN_ADDRESSES = 2 ** 16


def valid_target(t: str) -> bool:
    """True if `t` looks like a safe, well-formed nmap target: an IPv4/IPv6
    address or CIDR, or a plain hostname (optionally with a mask suffix)."""
    t = (t or "").strip()
    if not t:
        return False
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(t))


def _valid_targets(raw: List[str]) -> List[str]:
    """Filter a config target list down to safe, well-formed entries.

    Silently drops anything that doesn't validate via valid_target().
    """
    out = []
    for t in raw:
        t = str(t).strip()
        if valid_target(t):
            out.append(t)
    return out


def _partition_targets(targets: List[str]) -> Tuple[List[str], List[str]]:
    """Split validated targets into (ipv4-and-hostnames, ipv6).

    nmap cannot mix address families in one invocation -- `-6` switches the
    ENTIRE invocation to IPv6, so an IPv6 target needs a separate nmap call.
    Hostnames can't be classified by family ahead of resolution, so they
    stay in the (unchanged, no -6) first group, same as today.
    """
    v4_and_hosts: List[str] = []
    v6: List[str] = []
    for t in targets:
        try:
            is_v6 = ipaddress.ip_network(t, strict=False).version == 6
        except ValueError:
            is_v6 = False
        (v6 if is_v6 else v4_and_hosts).append(t)
    return v4_and_hosts, v6


def _ipv6_blast_radius_warning(t: str) -> str:
    """Return a stderr warning string if `t` is an IPv6 target wide enough
    that nmap will realistically never finish sweeping it, else ""."""
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return ""
    if net.version != 6 or net.num_addresses <= _IPV6_WARN_ADDRESSES:
        return ""
    return (f"    ! {t} has {net.num_addresses:.2e} addresses; nmap will "
            f"very likely never finish -- use individual hosts or a "
            f"narrower prefix")


@dataclass
class NmapPort:
    proto: str
    port: int
    service_name: str = ""
    product: str = ""
    version: str = ""
    method: str = ""    # "table" (nmap's static port->service guess) | "probed" (real -sV match)
    conf: int = 0        # nmap's confidence in service_name, 0-10


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
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue  # no usable address -> skip the host
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
            conf_raw = (svc.get("conf") if svc is not None else None) or ""
            try:
                conf = int(conf_raw)
            except ValueError:
                conf = 0
            ports.append(NmapPort(
                proto=proto, port=portnum,
                service_name=((svc.get("name") if svc is not None else "") or ""),
                product=((svc.get("product") if svc is not None else "") or ""),
                version=((svc.get("version") if svc is not None else "") or ""),
                method=((svc.get("method") if svc is not None else "") or ""),
                conf=conf,
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
            detected_by = "port"
            if not hit and port.method == "probed" and port.conf >= _SERVICE_CONF_MIN:
                hit = classify_by_service(port.service_name)
                detected_by = "service-name"
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
            provenance = (
                f" nmap identified this by service fingerprint on a "
                f"non-default port (detected service: {port.service_name})."
                if detected_by == "service-name" else "")
            out.append(Finding(
                source="network",
                title=f"{label} exposed on {host_label}:{port.port}/{port.proto}{svc_note}",
                severity=severity,
                description=(
                    f"nmap found {label} open on {host_label}:{port.port}/{port.proto}"
                    f"{svc_note}, reachable over the network from wherever this scan "
                    f"ran. Port {port.port} is {why}.{provenance} Restrict it with a "
                    f"firewall rule, bind the service to an internal-only interface, "
                    f"or disable it if unused. This finding describes a REMOTE host: "
                    f"any fix must be applied on {host.address} itself -- this tool "
                    f"cannot apply changes there."
                ),
                target=host.address,
                raw={"proto": port.proto, "port": port.port, "category": category,
                     "service": label, "service_name": port.service_name,
                     "product": port.product, "version": port.version,
                     "hostnames": host.hostnames, "detected_by": detected_by},
            ))
    return out


# A literal custom nmap -p spec: digits, commas, hyphens only (defence
# against a hand-edited config typo producing a confusing nmap error, not
# injection defence -- this is always a single argv token after "-p").
_PORT_SPEC_RE = re.compile(r'^[\d,\-]+$')


def _nmap_port_args(cfg) -> List[str]:
    """Translate `network_scan_ports` into the nmap argv fragment that
    controls port breadth. "known" (default) keeps today's behavior: only
    the fixed plaintext/sensitive port list. Widening this is what makes
    the service-name classification fallback in audit_network() useful."""
    spec = str(getattr(cfg, "network_scan_ports", "known") or "known").strip()
    if spec == "known":
        return ["-p", flagged_port_spec()]
    if spec == "top1000":
        return ["--top-ports", "1000"]
    if spec == "all":
        return ["-p", "1-65535"]
    if not _PORT_SPEC_RE.match(spec):
        print(f"    ! network_scan_ports '{spec}' doesn't look like a valid "
              f"-p spec; falling back to 'known'", file=sys.stderr)
        return ["-p", flagged_port_spec()]
    return ["-p", spec]


def _run_and_parse(targets: List[str], port_args: List[str], timeout: int,
                    extra_args: List[str]) -> List["NmapHost"]:
    """Run one nmap invocation against `targets` and parse its XML output.
    Isolated per call so one address family's failure/timeout can't discard
    the other family's real results."""
    cmd = ["nmap", "-sV", "-n", "--host-timeout", "300", "--max-retries", "2",
           *port_args, *extra_args, "-oX", "-", *targets]
    label = "IPv6 " if "-6" in extra_args else ""
    try:
        rc, out, _err = run(cmd, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"    ! network {label}scan failed ({len(targets)} target(s)): "
              f"{exc}", file=sys.stderr)
        return []
    if rc != 0 or not out.strip():
        return []
    return parse_nmap_xml(out)


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
        for t in targets:
            warning = _ipv6_blast_radius_warning(t)
            if warning:
                print(warning, file=sys.stderr)
        preview = ", ".join(targets[:5]) + (", ..." if len(targets) > 5 else "")
        print(f"    network: ⚠ probing {len(targets)} authorized target(s) "
              f"via nmap ({preview}). Only scan hosts/networks you are "
              f"explicitly authorized to test.", file=sys.stderr)
        timeout = int(getattr(self.config, "network_scan_timeout", 900) or 900)
        port_args = _nmap_port_args(self.config)
        v4_targets, v6_targets = _partition_targets(targets)
        hosts: List[NmapHost] = []
        if v4_targets:
            hosts += _run_and_parse(v4_targets, port_args, timeout, [])
        if v6_targets:
            hosts += _run_and_parse(v6_targets, port_args, timeout, ["-6"])
        down = sum(1 for h in hosts if h.state != "up")
        if down:
            print(f"    - network: {down} target(s) unreachable (no response)",
                  file=sys.stderr)
        return audit_network(hosts)
