# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Runtime-exposure enricher.

A vulnerability in an installed package only bites at runtime when something
actually exercises the vulnerable code. For packages whose attack surface is a
daemon, that means the service has to be running — or able to start. This
enricher tags each package finding with its runtime exposure:

  - "no-service": the package ships no systemd service/socket units, so its risk
    is library/CLI level and independent of service state — left untouched.
  - "active": at least one shipped unit is running, enabled, static, or has a
    listening socket — fully exposed.
  - "inactive": the package ships service units but ALL of them are stopped AND
    disabled/masked — dormant. models.apply_service_states downgrades these.
  - None: exposure could not be determined (no systemd, lookup failed) — left
    untouched so the full severity is preserved. Never guess exposure away.

Conservative on purpose: a unit counts as exposed unless we positively observe
it stopped-and-disabled, so a genuine risk is never hidden.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models import Finding
from .base import have, run

# systemctl is-active values that mean the unit is up (or coming up).
_ACTIVE_STATES = {"active", "activating", "reloading"}
# systemctl is-enabled values that positively mean "won't start on its own".
_DORMANT_ENABLE_STATES = {"disabled", "masked", "masked-runtime"}


class ServiceStateEnricher:
    """Annotate findings with whether their package's daemon is exposed."""

    name = "service-state"

    def __init__(self, config) -> None:  # config: vulnscanai.config.Config
        self.config = config
        self._unit_cache: Dict[str, List[str]] = {}

    def available(self) -> bool:
        return have("systemctl") and have("rpm")

    def _package_units(self, package: str) -> List[str]:
        """Service/socket unit basenames shipped by the package (cached)."""
        if package in self._unit_cache:
            return self._unit_cache[package]
        units: List[str] = []
        try:
            rc, out, _ = run(["rpm", "-ql", package], timeout=30)
        except Exception:  # noqa: BLE001
            rc, out = 1, ""
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if "/systemd/system/" not in line:
                    continue
                base = line.rsplit("/", 1)[-1]
                if not base.endswith((".service", ".socket")):
                    continue
                if "@." in base:
                    continue  # template unit; instances can't be queried here
                if base not in units:
                    units.append(base)
        self._unit_cache[package] = units
        return units

    def _systemctl(self, verb: str, unit: str) -> str:
        try:
            _rc, out, _ = run(["systemctl", verb, unit], timeout=10)
        except Exception:  # noqa: BLE001
            return ""
        out = out.strip()
        return out.splitlines()[0].strip() if out else ""

    def _unit_exposed(self, unit: str) -> bool:
        """True unless the unit is clearly stopped AND disabled/masked."""
        if self._systemctl("is-active", unit) in _ACTIVE_STATES:
            return True
        # Stopped: exposed unless we positively see a disabled/masked state.
        # Unknown/empty (e.g. a unit systemd doesn't recognise) -> exposed.
        return self._systemctl("is-enabled", unit) not in _DORMANT_ENABLE_STATES

    def _exposure(self, package: str) -> Tuple[str, List[str]]:
        units = self._package_units(package)
        if not units:
            return "no-service", []
        for unit in units:
            if self._unit_exposed(unit):
                return "active", units
        return "inactive", units

    def enrich(self, findings: List[Finding]) -> None:
        if not self.available():
            return
        for f in findings:
            # Only package findings, and don't clobber an already-set state.
            if not f.package or f.runtime_state:
                continue
            state, units = self._exposure(f.package)
            f.runtime_state = state
            if state == "inactive":
                f.raw["service_units"] = units
