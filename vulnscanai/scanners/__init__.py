# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Vulnerability scanner backends."""

from __future__ import annotations

from typing import Dict, Type

from .base import Scanner
from .container import ContainerScanner
from .dnf_rhsa import DnfRhsaScanner
from .exploit import ExploitEnricher
from .nvd import NvdEnricher
from .openscap import OpenScapScanner
from .oval import detect_distro, download_oval
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
}

__all__ = [
    "Scanner", "DnfRhsaScanner", "OpenScapScanner", "SshConfigScanner",
    "SystemdSecurityScanner", "PortScanner", "WebrootScanner",
    "ContainerScanner", "NvdEnricher", "ExploitEnricher",
    "ServiceStateEnricher", "SCANNERS", "download_oval", "detect_distro",
]
