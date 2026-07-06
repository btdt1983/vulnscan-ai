# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Container runtime hardening scanner (Podman / Docker).

A patched host can still be one running container away from compromise: a
container started with ``--privileged``, with the runtime control socket
bind-mounted, or sharing the host network/PID namespace is effectively a host
escape. This scanner enumerates *running* containers via ``podman``/``docker``
and flags dangerous runtime settings, CIS-Docker-benchmark style.

Detection is read-only and deterministic: it shells out to ``<runtime> ps`` to
list running containers and ``<runtime> inspect`` for their resolved config,
then applies a fixed ruleset to the JSON. No images are pulled and no network
lookups happen. These are runtime-configuration findings (not package CVEs), so
they carry no package/CVE/advisory — just enough context in ``raw`` (container,
image, runtime, the offending setting and the recommended change) for the AI to
propose a fix. The fix is necessarily *manual* (recreate the container without
the flag); nothing here can be applied by reloading a service.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from ..models import Finding
from .base import Scanner, have, run

# Cap so a host running hundreds of containers can't make the scan run away.
_MAX_FINDINGS = 200

# Capabilities worth flagging when added (beyond the runtime's safe defaults).
# value = (severity, why). "ALL" is handled separately (it implies all of them).
_DANGEROUS_CAPS: Dict[str, Tuple[str, str]] = {
    "SYS_MODULE": ("critical", "load/unload kernel modules — full host takeover"),
    "SYS_ADMIN": ("important", "near-root: mount, namespaces and many escapes"),
    "SYS_PTRACE": ("important", "trace/inject into processes outside the container"),
    "SYS_RAWIO": ("important", "raw I/O to devices and memory"),
    "DAC_READ_SEARCH": ("important", "bypass file-read checks (open_by_handle escape)"),
    "BPF": ("important", "load eBPF programs into the kernel"),
    "SYS_BOOT": ("moderate", "reboot the host or load a new kernel"),
    "DAC_OVERRIDE": ("moderate", "bypass file read/write/execute permission checks"),
    "NET_ADMIN": ("moderate", "reconfigure host networking (interfaces, firewall)"),
    "SYS_TIME": ("moderate", "change the host clock"),
    "NET_RAW": ("low", "craft raw/spoofed packets"),
}

# Host paths that should not be handed to a container. value = (label,
# severity-when-writable); a read-only mount is downgraded one step.
_SENSITIVE_MOUNTS: Dict[str, Tuple[str, str]] = {
    "/": ("the entire host filesystem", "critical"),
    "/etc": ("host /etc (passwd, shadow, system config)", "critical"),
    "/var/lib/docker": ("Docker's storage (all images/containers)", "critical"),
    "/var/lib/containers": ("Podman's storage (all images/containers)", "critical"),
    "/boot": ("the host boot partition / kernel", "important"),
    "/root": ("root's home directory", "important"),
    "/proc": ("the host /proc (kernel/process interface)", "important"),
    "/sys": ("the host /sys (kernel/device interface)", "important"),
    "/dev": ("host devices", "important"),
    "/run": ("the host runtime dir (sockets, secrets)", "important"),
    "/var/run": ("the host runtime dir (sockets, secrets)", "important"),
    "/home": ("user home directories", "moderate"),
    "/var/log": ("host logs", "low"),
}

# Bind sources ending in one of these are the runtime control socket: mounting
# it gives the container full control of the daemon == root on the host.
_RUNTIME_SOCKETS = ("docker.sock", "podman.sock")

_SEV_ORDER = ["critical", "important", "moderate", "low"]


def _downgrade(severity: str) -> str:
    """One step less severe (read-only mounts are less dangerous than rw)."""
    try:
        i = _SEV_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]


def _norm_cap(cap: str) -> str:
    """Normalise a capability name: strip CAP_ prefix, upper-case."""
    cap = (cap or "").strip().upper()
    return cap[4:] if cap.startswith("CAP_") else cap


def classify_mount(source: str, rw: bool) -> Optional[Tuple[str, str, str]]:
    """Map a host bind source to (label, severity, reason), or None if benign."""
    src = os.path.normpath(str(source) if source else "")
    base = os.path.basename(src)
    if base in _RUNTIME_SOCKETS or src.endswith(_RUNTIME_SOCKETS):
        return ("the container runtime control socket", "critical",
                "a process that can talk to the runtime socket can start a "
                "privileged container and take over the host")
    # Longest (most specific) matching sensitive prefix wins.
    best: Optional[Tuple[str, str]] = None
    best_len = -1
    for prefix, (label, sev) in _SENSITIVE_MOUNTS.items():
        if prefix == "/":
            match = src == "/"
        else:
            match = src == prefix or src.startswith(prefix.rstrip("/") + "/")
        if match and len(prefix) > best_len:
            best, best_len = (label, sev), len(prefix)
    if best is None:
        return None
    label, sev = best
    if not rw:
        sev = _downgrade(sev)
    mode = "read-write" if rw else "read-only"
    return (label, sev,
            f"is bind-mounted {mode} from the host; this exposes {label} to the "
            f"container and is a common escape/credential-theft path")


def _mounts(info: Dict) -> List[Tuple[str, str, bool]]:
    """Return [(source, destination, rw), ...] from inspect output.

    Prefers the normalised ``Mounts`` list (present on both runtimes); falls
    back to parsing ``HostConfig.Binds`` ("src:dst[:opts]").
    """
    out: List[Tuple[str, str, bool]] = []
    for m in info.get("Mounts") or []:
        if not isinstance(m, dict):
            continue
        if m.get("Type") not in (None, "bind"):  # only host binds matter here
            continue
        src = m.get("Source") or ""
        if not src:
            continue
        out.append((src, m.get("Destination") or "", bool(m.get("RW", True))))
    if out:
        return out
    for b in (info.get("HostConfig") or {}).get("Binds") or []:
        parts = str(b).split(":")
        if len(parts) < 2:
            continue
        src, dst = parts[0], parts[1]
        rw = not (len(parts) > 2 and "ro" in parts[2].split(","))
        out.append((src, dst, rw))
    return out


def _is_root_user(user: str) -> bool:
    user = (user or "").strip()
    if user == "":
        return True                       # default: root
    name = user.split(":", 1)[0]          # "uid:gid" or "name:group"
    return name in ("0", "root")


def assess_container(info: Dict, runtime: str = "") -> List[Finding]:
    """Apply the hardening ruleset to one inspect object, returning findings."""
    if not isinstance(info, dict):
        return []                        # malformed inspect JSON -> no findings
    host = info.get("HostConfig")
    host = host if isinstance(host, dict) else {}
    conf = info.get("Config")
    conf = conf if isinstance(conf, dict) else {}
    name = (info.get("Name") or "").lstrip("/") or (info.get("Id") or "")[:12]
    cid = (info.get("Id") or "")[:12]
    image = conf.get("Image") or info.get("ImageName") or ""
    out: List[Finding] = []

    def add(title: str, severity: str, desc: str, issue: str,
            recommended: str, **extra) -> None:
        raw = {"container": name, "id": cid, "image": image,
               "runtime": runtime, "issue": issue, "recommended": recommended}
        raw.update(extra)
        out.append(Finding(
            source="container",
            title=f"{title}: container '{name}'",
            severity=severity, description=desc, raw=raw))

    if host.get("Privileged"):
        add("Privileged container", "critical",
            f"Container '{name}' ({image}) runs with --privileged: it gets "
            "almost all capabilities, host devices and relaxed seccomp/SELinux, "
            "which is effectively root on the host. Recreate it without "
            "--privileged and grant only the specific --cap-add it needs.",
            "privileged", "remove --privileged; add only required capabilities")

    for src, dst, rw in _mounts(info):
        cls = classify_mount(src, rw)
        if not cls:
            continue
        label, sev, reason = cls
        add(f"Sensitive host mount ({label})", sev,
            f"Container '{name}' has {src} -> {dst} "
            f"({'rw' if rw else 'ro'}): it {reason}. Remove the mount or scope "
            "it to a minimal, dedicated path (read-only where possible).",
            "mount", "remove or narrow the bind mount (read-only if required)",
            source=src, destination=dst, rw=rw)

    netmode = str(host.get("NetworkMode") or "")
    if netmode == "host":
        add("Host network namespace", "important",
            f"Container '{name}' uses --network host: it shares the host's "
            "network stack, so it can sniff traffic, bind host ports and reach "
            "loopback-only services. Use a bridge/user network and publish only "
            "the ports you need.",
            "network_host", "drop --network host; publish specific ports")
    if str(host.get("PidMode") or "") == "host":
        add("Host PID namespace", "important",
            f"Container '{name}' uses --pid host: it can see and signal every "
            "process on the host (and inspect their memory via /proc). Remove "
            "--pid host.",
            "pid_host", "remove --pid host")
    if str(host.get("IpcMode") or "") == "host":
        add("Host IPC namespace", "moderate",
            f"Container '{name}' uses --ipc host: it shares host shared-memory "
            "and can interfere with other processes' IPC. Remove --ipc host.",
            "ipc_host", "remove --ipc host")

    caps = [_norm_cap(c) for c in (host.get("CapAdd") or [])]
    if "ALL" in caps:
        add("All Linux capabilities granted", "critical",
            f"Container '{name}' was started with --cap-add ALL: it holds every "
            "Linux capability, which enables numerous container escapes. Drop "
            "all capabilities (--cap-drop ALL) and add back only what is needed.",
            "cap_all", "--cap-drop ALL, then --cap-add only required caps")
    else:
        for cap in caps:
            if cap in _DANGEROUS_CAPS:
                sev, why = _DANGEROUS_CAPS[cap]
                add(f"Dangerous capability {cap}", sev,
                    f"Container '{name}' adds capability {cap}, which lets it "
                    f"{why}. Drop it unless the workload genuinely requires it.",
                    "capability", f"remove --cap-add {cap}", capability=cap)

    secopt = [str(s).lower() for s in (host.get("SecurityOpt") or [])]
    joined = " ".join(secopt)
    if "seccomp=unconfined" in joined:
        add("Seccomp disabled", "moderate",
            f"Container '{name}' runs with seccomp=unconfined: the syscall "
            "filter that blocks dangerous syscalls is off. Drop "
            "--security-opt seccomp=unconfined to restore the default profile.",
            "seccomp_unconfined", "remove --security-opt seccomp=unconfined")
    if "apparmor=unconfined" in joined:
        add("AppArmor disabled", "moderate",
            f"Container '{name}' runs with apparmor=unconfined (no AppArmor "
            "confinement). Remove it to restore the default profile.",
            "apparmor_unconfined", "remove --security-opt apparmor=unconfined")
    if "label=disable" in joined or "label:disable" in joined:
        add("SELinux separation disabled", "important",
            f"Container '{name}' runs with label=disable: SELinux no longer "
            "isolates it from the host and other containers. Remove the "
            "--security-opt label=disable.",
            "selinux_disabled", "remove --security-opt label=disable")

    if _is_root_user(str(conf.get("User") or "")):
        add("Container process runs as root", "low",
            f"Container '{name}' runs as root (uid 0) inside the container; "
            "combined with any escape this maps closer to host root. Set a "
            "non-root USER in the image or run with --user.",
            "runs_as_root", "run as a non-root user (--user or USER in image)")

    return out


def _list_running(runtime: str) -> List[str]:
    """Container IDs currently running under `runtime` (empty on any failure)."""
    rc, out, _ = run([runtime, "ps", "--format", "{{.ID}}"], timeout=30)
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _inspect(runtime: str, ids: List[str]) -> List[Dict]:
    """Parsed `<runtime> inspect` for the given container IDs."""
    if not ids:
        return []
    rc, out, _ = run([runtime, "inspect", *ids], timeout=60)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [d for d in data if isinstance(d, dict)]


class ContainerScanner(Scanner):
    name = "container"

    @staticmethod
    def _runtimes() -> List[str]:
        # Podman first (RHEL-native). `docker` is often a podman shim here; the
        # scan de-duplicates by container ID so the same container isn't double
        # reported.
        return [rt for rt in ("podman", "docker") if have(rt)]

    def available(self) -> bool:
        return bool(self._runtimes())

    def scan(self) -> List[Finding]:
        out: List[Finding] = []
        seen: set = set()
        for runtime in self._runtimes():
            ids = _list_running(runtime)
            for info in _inspect(runtime, ids):
                cid = info.get("Id") or ""
                if cid and cid in seen:
                    continue
                seen.add(cid)
                out.extend(assess_container(info, runtime))
                if len(out) >= _MAX_FINDINGS:
                    return out[:_MAX_FINDINGS]
        return out
