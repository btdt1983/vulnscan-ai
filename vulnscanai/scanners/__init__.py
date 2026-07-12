# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Vulnerability scanner backends."""

from __future__ import annotations

from typing import Dict, Type

from .applicability import PatchedStateEnricher
from .base import Scanner
from .compliance import ComplianceScanner
from .container import ContainerScanner
from .dnf_rhsa import DnfRhsaScanner
from .effective_state import EffectiveStateScanner
from .exploit import ExploitEnricher
from .fips_posture import FipsPostureScanner
from .nvd import NvdEnricher
from .openscap import OpenScapScanner
from .oval import detect_distro, download_oval, is_oval_stale, oval_age_days
from .ports import PortScanner
from .runtime_state import ServiceStateEnricher
from .ssh_config import SshConfigScanner
from .systemd_security import SystemdSecurityScanner
from .webroot import WebrootScanner

# Registry of detection scanners (not enrichers).
SCANNERS: Dict[str, Type[Scanner]] = {
    DnfRhsaScanner.name: DnfRhsaScanner,
    OpenScapScanner.name: OpenScapScanner,
    SshConfigScanner.name: SshConfigScanner,
    SystemdSecurityScanner.name: SystemdSecurityScanner,
    PortScanner.name: PortScanner,
    WebrootScanner.name: WebrootScanner,
    ContainerScanner.name: ContainerScanner,
    EffectiveStateScanner.name: EffectiveStateScanner,
    FipsPostureScanner.name: FipsPostureScanner,
}

__all__ = [
    "Scanner", "DnfRhsaScanner", "OpenScapScanner", "SshConfigScanner",
    "SystemdSecurityScanner", "PortScanner", "WebrootScanner",
    "ContainerScanner", "EffectiveStateScanner", "FipsPostureScanner",
    "ComplianceScanner", "NvdEnricher", "ExploitEnricher",
    "PatchedStateEnricher", "ServiceStateEnricher", "SCANNERS",
    "download_oval", "detect_distro", "is_oval_stale", "oval_age_days",
]
