"""Vulnerability scanner backends."""

from __future__ import annotations

from typing import Dict, Type

from .base import Scanner
from .dnf_rhsa import DnfRhsaScanner
from .nvd import NvdEnricher
from .openscap import OpenScapScanner
from .oval import detect_distro, download_oval
from .ssh_config import SshConfigScanner

# Registry of detection scanners (not enrichers).
SCANNERS: Dict[str, Type[Scanner]] = {
    DnfRhsaScanner.name: DnfRhsaScanner,
    OpenScapScanner.name: OpenScapScanner,
    SshConfigScanner.name: SshConfigScanner,
}

__all__ = [
    "Scanner", "DnfRhsaScanner", "OpenScapScanner", "SshConfigScanner",
    "NvdEnricher", "SCANNERS", "download_oval", "detect_distro",
]
