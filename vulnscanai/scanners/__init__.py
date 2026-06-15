"""Vulnerability scanner backends."""

from __future__ import annotations

from typing import Dict, Type

from .base import Scanner
from .dnf_rhsa import DnfRhsaScanner
from .nvd import NvdEnricher
from .openscap import OpenScapScanner
from .oval import detect_distro, download_oval

# Registry of detection scanners (not enrichers).
SCANNERS: Dict[str, Type[Scanner]] = {
    DnfRhsaScanner.name: DnfRhsaScanner,
    OpenScapScanner.name: OpenScapScanner,
}

__all__ = [
    "Scanner", "DnfRhsaScanner", "OpenScapScanner", "NvdEnricher",
    "SCANNERS", "download_oval", "detect_distro",
]
