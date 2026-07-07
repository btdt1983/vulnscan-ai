# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Effective-state scanner: what the RUNNING system is still using.

A patch on disk is not a patch in RAM. Two read-only ground-truth checks:

  1. **Kernel currency** — the running kernel (``os.uname``) vs the newest
     installed ``kernel`` package. If an update landed but the host has not
     rebooted, it keeps executing the OLD (vulnerable) kernel while every package
     scanner reports it CLEAN (the already-patched filter even drops the dnf
     kernel finding the instant the RPM lands). -> one "reboot required" finding.
  2. **Superseded libraries in use** — a process still mapping a DELETED library
     file (its ``.so`` was replaced by an update) runs the old code until it
     restarts. We read ``/proc/<pid>/maps`` for ``(deleted)`` library mappings and
     map each PID to its systemd unit via ``/proc/<pid>/cgroup``. A deleted CORE
     library (glibc/loader/systemd) means a reboot; a deleted app library
     (e.g. openssl) in a specific service means restart THAT service.

Pure stdlib (reads ``/proc``, ``os.uname``, ``rpm``). When dnf-utils'
``needs-restarting -r`` is present it is used as the authoritative reboot verdict.
No kpatch/livepatch handling in this release (kept deliberately additive — the
findings are independent posture findings that no enricher reconciles away).
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Set, Tuple

from ..models import Finding
from .base import Scanner, have, run

_KERNEL_PKG = "kernel"

# Basename markers of "core" libraries whose replacement needs a reboot (they are
# mapped by PID 1 / almost everything), as opposed to an app library where
# restarting the one affected service suffices.
_CORE_LIB_MARKERS = ("libc.so", "libc-", "ld-linux", "ld-2.", "ld-musl",
                     "libpthread.so", "libsystemd")

# Don't emit an unbounded flood of per-service findings after a broad update.
_MAX_SERVICE_FINDINGS = 25

# Library-file location prefixes (a deleted mapping outside these — a tmp file,
# a memfd, /dev/zero — is not a superseded library and is ignored).
_LIB_PREFIXES = ("/usr/lib", "/lib", "/usr/lib64", "/lib64", "/usr/local/lib")


def running_kernel() -> str:
    """The kernel release the host is executing right now (no subprocess)."""
    return os.uname().release


def installed_kernels() -> List[str]:
    """Installed ``kernel`` builds as version-release.arch, newest-installed first.

    Uses ``rpm -q --last``. For the kernel this tracks version order in practice
    (dnf installs newer builds later), and the reboot verdict is corroborated by
    ``needs-restarting -r`` when that tool is present.
    """
    rc, out, _ = run(["rpm", "-q", "--last", _KERNEL_PKG], timeout=30)
    if rc != 0 or not out.strip():
        return []
    out_list: List[str] = []
    for line in out.splitlines():
        toks = line.split()
        if toks and toks[0].startswith(_KERNEL_PKG + "-"):
            out_list.append(toks[0][len(_KERNEL_PKG) + 1:])
    return out_list


def newest_installed_kernel() -> Optional[str]:
    """The most recently installed ``kernel`` build's version-release.arch."""
    kernels = installed_kernels()
    return kernels[0] if kernels else None


def _kernel_outdated() -> bool:
    """True only when the running kernel is a known-installed ``kernel`` build
    that is not the newest. The membership check avoids a false positive on
    kernel-rt / kernel-debug / custom kernels, whose ``uname`` release is not in
    the standard ``kernel`` package set and cannot be compared this way."""
    running = running_kernel()
    kernels = installed_kernels()
    if not kernels or running not in kernels:
        return False
    return running != kernels[0]


def _needs_restarting_reboot() -> Optional[bool]:
    """Authoritative reboot verdict from dnf-utils, or None if unavailable.

    ``needs-restarting -r`` exits 0 (no reboot) or 1 (reboot recommended); any
    other code means we could not get a verdict.
    """
    if not have("needs-restarting"):
        return None
    rc, _, _ = run(["needs-restarting", "-r"], timeout=90)
    if rc == 0:
        return False
    if rc == 1:
        return True
    return None


def _is_library(path: str) -> bool:
    return path.startswith(_LIB_PREFIXES) and ".so" in os.path.basename(path)


def _is_core_lib(basename: str) -> bool:
    return any(m in basename for m in _CORE_LIB_MARKERS)


def _parse_deleted_libs(maps_text: str) -> Set[str]:
    """Basenames of deleted/replaced library files in a /proc/<pid>/maps dump."""
    libs: Set[str] = set()
    for line in maps_text.splitlines():
        if "(deleted)" not in line:
            continue
        # maps row: address perms offset dev inode  pathname [ (deleted)]
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        path = parts[5].rstrip("\n")
        if not path.endswith("(deleted)"):
            continue
        path = path[: -len("(deleted)")].strip()
        if _is_library(path):
            libs.add(os.path.basename(path))
    return libs


def _parse_unit_from_cgroup(cgroup_text: str) -> Optional[str]:
    """The systemd *system* service named in a /proc/<pid>/cgroup dump, or None.

    Only host system services are returned; user services (``user.slice``),
    containers/VMs (``machine.slice``) and transient/init scopes are skipped, so
    a container's processes never masquerade as a host service. (cgroup v2 line:
    ``0::/system.slice/sshd.service``.)
    """
    for line in cgroup_text.splitlines():
        path = line.rsplit(":", 1)[-1]
        if "/system.slice/" not in path:
            continue
        comp = path.rstrip("/").split("/")[-1]
        if comp.endswith(".service"):
            return comp
    return None


def _deleted_libs_for_pid(pid: str) -> Set[str]:
    """Basenames of deleted/replaced library files still mapped by this PID."""
    try:
        with open(f"/proc/{pid}/maps", encoding="utf-8", errors="replace") as fh:
            return _parse_deleted_libs(fh.read())
    except (OSError, ValueError):
        return set()


def _pid_unit(pid: str) -> Optional[str]:
    """The systemd system service a PID belongs to (via /proc/<pid>/cgroup)."""
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as fh:
            return _parse_unit_from_cgroup(fh.read())
    except OSError:
        return None


def _scan_proc() -> Tuple[bool, Dict[str, Set[str]]]:
    """Scan /proc once. Returns (core_lib_superseded, {unit: {app-lib basenames}}).

    ``core_lib_superseded`` is True when any process still maps a deleted CORE
    library (glibc/loader/systemd) — that implies a reboot. Per-unit entries
    carry only NON-core (app) libraries, where restarting the one service loads
    the fix without a reboot.
    """
    core = False
    per_unit: Dict[str, Set[str]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return False, {}
    for entry in entries:
        if not entry.isdigit():
            continue
        libs = _deleted_libs_for_pid(entry)
        if not libs:
            continue
        noncore: Set[str] = set()
        for lib in libs:
            if _is_core_lib(lib):
                core = True
            else:
                noncore.add(lib)
        if not noncore:
            continue
        unit = _pid_unit(entry)
        if unit is None:
            continue
        per_unit.setdefault(unit, set()).update(noncore)
    return core, per_unit


def reboot_pending() -> bool:
    """Ground-truth: does the host need a reboot to activate installed updates?

    Prefers dnf-utils' authoritative verdict; falls back to stdlib signals
    (running kernel older than newest installed, or a deleted CORE library still
    mapped). Used by the remediation engine to overwrite a fix's predicted
    ``requires_reboot`` with reality after it is applied.
    """
    nr = _needs_restarting_reboot()
    if nr is not None:
        return nr
    if _kernel_outdated():
        return True
    core, _ = _scan_proc()
    return core


class EffectiveStateScanner(Scanner):
    """Detects vulnerabilities that persist in RAM after an on-disk patch."""

    name = "effective"

    def available(self) -> bool:
        # Linux-only; needs /proc. rpm/needs-restarting are optional (degrades).
        return os.path.isdir("/proc")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        running = running_kernel()
        newest = newest_installed_kernel()
        kernel_outdated = _kernel_outdated()
        core_superseded, per_unit = _scan_proc()

        # Reboot verdict: authoritative when available, else derived from the
        # stdlib signals. A definitive "no" from needs-restarting suppresses the
        # kernel heuristic (which can false-positive if an older kernel was the
        # most recently installed build).
        nr = _needs_restarting_reboot()
        reboot = nr if nr is not None else (kernel_outdated or core_superseded)

        if reboot and kernel_outdated:
            findings.append(Finding(
                source=self.name,
                title="Reboot required: running an older kernel than the one installed",
                severity="important",
                package=_KERNEL_PKG,
                installed_version=running,
                fixed_version=newest,
                description=(
                    f"The running kernel is {running} but {newest} is installed. "
                    f"Until this host reboots it keeps executing the OLDER kernel, "
                    f"so any fixes in the newer build — including security fixes — "
                    f"are NOT active, even though package scanners report the "
                    f"kernel as patched. Reboot to activate the installed kernel."),
                raw={"category": "reboot-kernel", "running": running,
                     "newest": newest},
            ))
        elif reboot:
            # Reboot needed but the kernel is current -> core packages/libraries
            # were updated since boot and are not yet active.
            findings.append(Finding(
                source=self.name,
                title="Reboot recommended: updated core packages are not yet active",
                severity="moderate",
                description=(
                    "Core packages or libraries have been updated on disk since "
                    "this host last booted, but the running system still holds the "
                    "old code. Reboot to activate the installed updates "
                    "(needs-restarting -r reports a reboot is required)."),
                raw={"category": "reboot-core"},
            ))

        for unit, libs in sorted(per_unit.items())[:_MAX_SERVICE_FINDINGS]:
            libnames = ", ".join(sorted(libs))
            findings.append(Finding(
                source=self.name,
                title=f"{unit}: running with superseded libraries; restart to load the update",
                severity="moderate",
                description=(
                    f"The service {unit} still maps deleted/replaced library "
                    f"file(s) ({libnames}): its libraries were updated on disk but "
                    f"the running process holds the OLD code. Restart it to load "
                    f"the fix:  systemctl restart {unit}"),
                raw={"category": "restart-service", "service": unit,
                     "libs": sorted(libs)},
            ))

        extra = len(per_unit) - _MAX_SERVICE_FINDINGS
        if extra > 0:
            findings.append(Finding(
                source=self.name,
                title=f"{extra} more service(s) run superseded libraries (not listed)",
                severity="moderate",
                description=(
                    f"{extra} further service(s) map deleted/replaced libraries; "
                    f"only the first {_MAX_SERVICE_FINDINGS} are listed. A reboot "
                    f"clears all of them at once."),
                raw={"category": "restart-service-overflow", "count": extra},
            ))

        return findings
