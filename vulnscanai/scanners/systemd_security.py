# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""systemd service hardening scanner.

Wraps `systemd-analyze security`, which scores each service unit's sandboxing
(0-10 exposure + a predicate OK/MEDIUM/EXPOSED/UNSAFE). Almost every service is
rated UNSAFE out of the box and many units legitimately cannot be hardened, so
this scanner is conservative by default: only UNSAFE units at/above an exposure
threshold, excluding a skip-list of un-hardenable/internal units, and only ones
that are actually enabled or active.

Each finding's fix is a drop-in override under /etc/systemd/system/<unit>.d/,
which the transactional remediation engine applies safely (backup -> write ->
daemon-reload -> validate -> restart -> rollback on failure).
"""

from __future__ import annotations

import fnmatch
import os
from typing import Callable, List, Optional, Tuple

from ..models import Finding
from .base import Scanner, have, run

# Units that cannot be meaningfully sandboxed or are internal plumbing.
_SKIP = (
    "getty@*", "serial-getty@*", "console-getty.service", "container-getty@*",
    "emergency.service", "rescue.service", "dm-event.service",
    "systemd-*", "user@*", "user-runtime-dir@*", "dbus-broker.service",
    "init.scope", "session-*.scope",
)

_DEFAULT_MIN_EXPOSURE = 9.0

# Conservative baseline directives to recommend (lower risk of breaking units).
_BASELINE = ("NoNewPrivileges=yes, PrivateTmp=yes, ProtectSystem=full, "
             "ProtectHome=read-only, ProtectControlGroups=yes, "
             "ProtectKernelTunables=yes, RestrictSUIDSGID=yes")


def _min_exposure() -> float:
    try:
        return float(os.environ.get("VULNSCANAI_SYSTEMD_MIN_EXPOSURE",
                                    _DEFAULT_MIN_EXPOSURE))
    except ValueError:
        return _DEFAULT_MIN_EXPOSURE


def parse_security_overview(text: str) -> List[Tuple[str, float, str]]:
    """Parse `systemd-analyze security` overview rows -> (unit, exposure, pred)."""
    rows: List[Tuple[str, float, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].endswith(".service"):
            continue
        try:
            exposure = float(parts[1])
        except ValueError:
            continue  # header ("EXPOSURE") or malformed line
        rows.append((parts[0], exposure, parts[2].upper()))
    return rows


def parse_unit_detail(text: str, limit: int = 6) -> List[str]:
    """From `systemd-analyze security <unit>`, return the descriptions of the
    highest-scoring failing (✗) checks."""
    scored: List[Tuple[float, str]] = []
    for line in text.splitlines():
        if not line.lstrip().startswith("✗"):  # ✗
            continue
        # trailing token is the exposure contribution (a float) when present
        toks = line.split()
        try:
            score = float(toks[-1])
        except (ValueError, IndexError):
            continue
        # description is the text between the directive name and the score
        body = line.lstrip("✗ ").rsplit(None, 1)[0]
        # drop the leading directive token, keep the human description
        desc = body.split(None, 1)[1] if len(body.split(None, 1)) > 1 else body
        scored.append((score, desc.strip()))
    scored.sort(key=lambda s: s[0], reverse=True)
    return [d for _, d in scored[:limit]]


def _skipped(unit: str) -> bool:
    return any(fnmatch.fnmatch(unit, pat) for pat in _SKIP)


def audit_units(rows: List[Tuple[str, float, str]], *,
                relevant: Callable[[str], bool] = lambda _u: True,
                min_exposure: Optional[float] = None,
                detail: Optional[Callable[[str], List[str]]] = None
                ) -> List[Finding]:
    """Apply the conservative policy to parsed overview rows -> findings."""
    threshold = _min_exposure() if min_exposure is None else min_exposure
    out: List[Finding] = []
    for unit, exposure, predicate in rows:
        if predicate != "UNSAFE" or exposure < threshold:
            continue
        if _skipped(unit) or not relevant(unit):
            continue
        missing = detail(unit) if detail else []
        desc = (f"systemd rates {unit} as UNSAFE (exposure {exposure}/10): it "
                f"runs with little sandboxing.")
        if missing:
            desc += " Weakest points: " + "; ".join(missing) + "."
        out.append(Finding(
            source="systemd",
            title=f"systemd service '{unit}' is weakly sandboxed "
                  f"(exposure {exposure}/10, UNSAFE)",
            severity="moderate",
            description=desc,
            raw={
                "unit": unit,
                "exposure": exposure,
                "predicate": predicate,
                "missing": missing,
                "dropin": f"/etc/systemd/system/{unit}.d/10-hardening.conf",
                "recommended": _BASELINE,
            },
        ))
    return out


class SystemdSecurityScanner(Scanner):
    name = "systemd"

    def available(self) -> bool:
        return have("systemd-analyze")

    def _relevant(self, unit: str) -> bool:
        """True if the unit is enabled or currently active (worth hardening)."""
        for state_cmd in (["systemctl", "is-enabled", unit],
                          ["systemctl", "is-active", unit]):
            try:
                rc, out, _ = run(state_cmd, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            val = out.strip()
            if rc == 0 and val in ("enabled", "enabled-runtime", "static", "active"):
                return True
        return False

    def _detail(self, unit: str) -> List[str]:
        try:
            rc, out, _ = run(["systemd-analyze", "security", unit, "--no-pager"],
                             timeout=30)
            return parse_unit_detail(out) if out else []
        except Exception:  # noqa: BLE001
            return []

    def scan(self) -> List[Finding]:
        try:
            rc, out, _ = run(["systemd-analyze", "security", "--no-pager"],
                             timeout=60)
        except Exception:  # noqa: BLE001
            return []
        if not out.strip():
            return []
        rows = parse_security_overview(out)
        return audit_units(rows, relevant=self._relevant, detail=self._detail)
