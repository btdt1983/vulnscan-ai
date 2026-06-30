# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Download and stage the OVAL security feed used by OpenSCAP.

OpenSCAP needs an OVAL definitions file describing known vulnerabilities for
the running distribution. This module detects the distro from
/etc/os-release, downloads the appropriate published feed (decompressing
.bz2/.gz on the fly), and writes it to <state_dir>/oval/ where the OpenSCAP
scanner looks for it.
"""

from __future__ import annotations

import bz2
import gzip
import os
import time
from typing import List, Optional, Tuple

from .. import http

# Per-distro candidate feed URLs. {major} is substituted with the major
# version. Tried in order; first that downloads wins. RHEL's feed is the
# fallback for unknown rebuilds.
_FEEDS = {
    "rhel": [
        "https://access.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2",
    ],
    "centos": [
        "https://access.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2",
    ],
    "almalinux": [
        "https://security.almalinux.org/oval/org.almalinux.alsa-{major}.xml.bz2",
    ],
    "rocky": [
        "https://download.rockylinux.org/pub/sig/{major}/security/x86_64/oval/rocky-{major}.oval.xml.bz2",
        "https://access.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2",
    ],
    "ol": [
        "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2",
    ],
    "oracle": [
        "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2",
    ],
    "fedora": [
        # Fedora does not publish a maintained OVAL feed; fall back to none.
    ],
}

_DEFAULT_FEEDS = [
    "https://access.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2",
]


def detect_distro() -> Tuple[str, str]:
    """Return (distro_id, major_version) from /etc/os-release."""
    distro_id, version = "rhel", "9"
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            data = {}
            for line in fh:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    data[k] = v.strip().strip('"')
        distro_id = (data.get("ID") or distro_id).lower()
        ver = data.get("VERSION_ID") or version
        version = ver.split(".")[0]
    except OSError:
        pass
    return distro_id, version


def candidate_urls(distro_id: str, major: str) -> List[str]:
    templates = _FEEDS.get(distro_id)
    if templates is None or (not templates and distro_id != "fedora"):
        templates = _DEFAULT_FEEDS
    return [t.format(major=major) for t in templates]


def _decompress(url: str, raw: bytes) -> bytes:
    if url.endswith(".bz2"):
        return bz2.decompress(raw)
    if url.endswith(".gz"):
        return gzip.decompress(raw)
    return raw


def download_oval(config, timeout: int = 180) -> Optional[str]:
    """Fetch the OVAL feed for this host. Returns the written path or None.

    Raises RuntimeError only when no candidate feed could be retrieved.
    """
    distro_id, major = detect_distro()
    urls = candidate_urls(distro_id, major)
    if not urls:
        raise RuntimeError(
            f"no OVAL feed is published for {distro_id} {major}; "
            "stage one manually under the oval/ directory"
        )
    oval_dir = os.path.join(config.state_dir, "oval")
    os.makedirs(oval_dir, mode=0o700, exist_ok=True)
    out_path = os.path.join(oval_dir, f"{distro_id}-{major}.oval.xml")

    errors = []
    for url in urls:
        try:
            raw = http.get_bytes(url, timeout=timeout)
            xml = _decompress(url, raw)
            with open(out_path, "wb") as fh:
                fh.write(xml)
            os.chmod(out_path, 0o600)
            return out_path
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {exc}")
            continue
    raise RuntimeError(
        "could not download an OVAL feed:\n  " + "\n  ".join(errors)
    )


def staged_oval_path(config) -> str:
    """Path where `download_oval` stages this host's OVAL feed."""
    distro_id, major = detect_distro()
    return os.path.join(config.state_dir, "oval", f"{distro_id}-{major}.oval.xml")


def oval_age_days(config) -> Optional[float]:
    """Age in days of the staged OVAL feed, or None if it isn't staged."""
    try:
        return (time.time() - os.path.getmtime(staged_oval_path(config))) / 86400.0
    except OSError:
        return None


def is_oval_stale(config, max_age_days: int) -> bool:
    """True if the staged OVAL feed is missing or older than max_age_days."""
    age = oval_age_days(config)
    return age is None or age > max_age_days
