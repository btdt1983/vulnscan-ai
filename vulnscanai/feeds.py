# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Vulnerability news / advisory feeds.

Aggregates recent vulnerability intelligence from well-known public sources into
a single normalised list (`NewsItem`) for the dashboard "Advisories" tab and for
scan-enrichment (exploited-in-the-wild + EPSS prioritisation):

  * CISA KEV  - Known Exploited Vulnerabilities (actively exploited; highest signal)
  * NVD       - recently published CVEs (NIST NVD API 2.0)
  * EPSS      - exploit-probability score per CVE (FIRST.org); enrichment lookup
  * distro    - the host distribution's own errata: AlmaLinux (RSS), Rocky Linux
                (Apollo/RESF JSON) and Oracle Linux (ELSA OVAL), picked by
                detect_distro() via the DISTRO_ERRATA registry

Everything is stdlib-only and goes through `http.py` (FIPS-hardened TLS, retry).
All feed URLs are FIXED constants — never user-supplied — so the dashboard can
never be coerced into fetching an arbitrary URL (no SSRF). Network failures are
soft: a feed that is down or malformed yields no items rather than raising, and
results are cached to the state dir so the tab still works offline / air-gapped.

The pure `parse_*` functions take already-decoded data and are unit-tested with
offline fixtures (no network).
"""

from __future__ import annotations

import bz2
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Set

from . import http

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Fixed feed endpoints (never user-supplied -> no SSRF).
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
# {major} / {year} are filled from detect_distro(); the host's own errata stream.
ALMA_ERRATA_RSS = "https://errata.almalinux.org/{major}/errata.rss"
ROCKY_APOLLO = "https://apollo.build.resf.org/v2/advisories"
ORACLE_OVAL = "https://linux.oracle.com/security/oval/com.oracle.elsa-{year}.xml.bz2"

# Map the many severity vocabularies (NVD baseSeverity, Red Hat/errata words)
# onto our four-level scale.
_SEV_MAP = {
    "critical": "critical",
    "high": "important", "important": "important",
    "medium": "moderate", "moderate": "moderate",
    "low": "low", "none": "low",
}


def _norm_sev(value: str) -> str:
    return _SEV_MAP.get((value or "").strip().lower(), "unknown")


def _cves(text: str) -> List[str]:
    """De-duplicated, upper-cased CVE ids found in free text, in order."""
    seen: Dict[str, None] = {}
    for m in _CVE_RE.findall(text or ""):
        seen.setdefault(m.upper(), None)
    return list(seen)


@dataclass
class NewsItem:
    """One normalised advisory / CVE news entry."""

    id: str
    source: str                    # kev | nvd | alma | rocky | ...
    title: str
    severity: str = "unknown"
    published: str = ""            # YYYY-MM-DD when known, else ""
    url: str = ""
    summary: str = ""
    cve_ids: List[str] = field(default_factory=list)
    exploited: bool = False        # listed in CISA KEV
    epss: Optional[float] = None   # 0.0-1.0 exploit probability (FIRST.org)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "NewsItem":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------- #
# Pure parsers (offline-testable: take decoded data, return NewsItems).
# --------------------------------------------------------------------------- #
def parse_kev(data: Dict, limit: int = 50) -> List[NewsItem]:
    """CISA Known Exploited Vulnerabilities JSON -> NewsItems (newest first)."""
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    out: List[NewsItem] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID", "")).upper()
        if not cve:
            continue
        name = v.get("vulnerabilityName") or cve
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        title = f"{vendor} {product}: {name}".strip(" :") if vendor else name
        ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        summary = v.get("shortDescription", "")
        if ransom:
            summary = "[known ransomware use] " + summary
        out.append(NewsItem(
            id=f"kev:{cve}", source="kev", title=title,
            severity="important", published=str(v.get("dateAdded", "")),
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            summary=summary, cve_ids=[cve], exploited=True))
    # KEV is roughly chronological; newest dateAdded first.
    out.sort(key=lambda i: i.published, reverse=True)
    return out[:limit]


def parse_nvd(data: Dict, limit: int = 50) -> List[NewsItem]:
    """NVD CVE API 2.0 response -> NewsItems."""
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    out: List[NewsItem] = []
    for entry in vulns or []:
        cve = (entry or {}).get("cve") or {}
        cid = str(cve.get("id", "")).upper()
        if not cid:
            continue
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        sev, score = _nvd_severity(cve.get("metrics") or {})
        published = str(cve.get("published", ""))[:10]
        title = f"{cid}: {desc[:90]}".rstrip()
        if score is not None:
            title = f"{cid} (CVSS {score}): {desc[:80]}".rstrip()
        out.append(NewsItem(
            id=f"nvd:{cid}", source="nvd", title=title, severity=sev,
            published=published,
            url=f"https://nvd.nist.gov/vuln/detail/{cid}",
            summary=desc, cve_ids=[cid]))
    out.sort(key=lambda i: i.published, reverse=True)
    return out[:limit]


def _nvd_severity(metrics: Dict):
    """Best CVSS (v3.1 > v3.0 > v2) -> (our-severity, base score)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            cdata = (arr[0] or {}).get("cvssData") or {}
            return (_norm_sev(cdata.get("baseSeverity", "")),
                    cdata.get("baseScore"))
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        m0 = arr[0] or {}
        return (_norm_sev(m0.get("baseSeverity", "")),
                (m0.get("cvssData") or {}).get("baseScore"))
    return ("unknown", None)


def parse_epss(data: Dict) -> Dict[str, float]:
    """FIRST.org EPSS response -> {CVE: probability 0.0-1.0}."""
    out: Dict[str, float] = {}
    rows = data.get("data") if isinstance(data, dict) else None
    for row in rows or []:
        cve = str(row.get("cve", "")).upper()
        try:
            score = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        if cve:
            out[cve] = score
    return out


def _safe_xml(text: str):
    """Parse untrusted feed XML, refusing a DTD/DOCTYPE.

    ElementTree never fetches external entities or DTDs, so classic XXE
    file-read is not possible; the residual risk is entity-expansion DoS
    ("billion laughs"), which requires a DOCTYPE. We reject any document that
    declares one (stdlib-only — no defusedxml dependency). Returns the root
    element, or None on a parse error / rejected DOCTYPE.
    """
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    # DOCTYPE/ENTITY are rejected above, so no entity expansion is possible.
    try:
        return ET.fromstring(text)  # nosec B314
    except ET.ParseError:
        return None


def parse_errata_rss(text: str, source: str, limit: int = 50) -> List[NewsItem]:
    """A distro errata RSS document -> NewsItems (AlmaLinux today)."""
    root = _safe_xml(text)
    if root is None:
        return []
    out: List[NewsItem] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        if not title:
            continue
        link = (item.findtext("link") or "").strip()
        desc = (item.findtext("description") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        # Severity word in the errata title, e.g. "ALSA-2026:1 Important: ...".
        sev = "unknown"
        for word in ("critical", "important", "moderate", "low"):
            if re.search(rf"\b{word}\b", title, re.I):
                sev = _norm_sev(word)
                break
        out.append(NewsItem(
            id=f"{source}:{title.split()[0]}", source=source, title=title,
            severity=sev, published=_rfc822_date(pub), url=link,
            summary=desc[:400], cve_ids=_cves(title + " " + desc)))
    return out[:limit]


def _rfc822_date(value: str) -> str:
    """Best-effort RFC-822 (RSS pubDate) -> YYYY-MM-DD; '' if unparseable."""
    if not value:
        return ""
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        return dt.strftime("%Y-%m-%d") if dt else ""
    except (TypeError, ValueError):
        return ""


def parse_rocky_apollo(data: Dict, major: str = "", limit: int = 50) -> List[NewsItem]:
    """Rocky Linux Apollo (RESF) advisories JSON -> NewsItems.

    Keeps advisories affecting `major` when known (else all). Severity arrives as
    e.g. "SEVERITY_IMPORTANT".
    """
    advs = data.get("advisories") if isinstance(data, dict) else None
    out: List[NewsItem] = []
    for a in advs or []:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name", "")).strip()
        if not name:
            continue
        products = a.get("affectedProducts") or []
        if major and products and not any(
                str(p).rstrip().endswith(major) for p in products):
            continue
        sev = _norm_sev(str(a.get("severity", "")).replace("SEVERITY_", ""))
        cves = [str(c.get("name", "")).upper()
                for c in (a.get("cves") or [])
                if isinstance(c, dict) and c.get("name")]
        out.append(NewsItem(
            id=f"rocky:{name}", source="rocky",
            title=f"{name} {a.get('synopsis', '')}".strip(), severity=sev,
            published=str(a.get("publishedAt", ""))[:10],
            url=f"https://errata.build.resf.org/{name}",
            summary=str(a.get("topic") or a.get("description") or "")[:400],
            cve_ids=list(dict.fromkeys(cves))))
    out.sort(key=lambda i: i.published, reverse=True)
    return out[:limit]


def _ln(elem) -> str:
    """Local (namespace-stripped) tag name of an XML element."""
    return elem.tag.rsplit("}", 1)[-1]


def parse_oracle_oval(text: str, major: str = "", limit: int = 50) -> List[NewsItem]:
    """Oracle Linux ELSA OVAL (patch definitions) -> NewsItems.

    Each `class="patch"` definition carries an ELSA title with its severity, the
    affected platform, the issue date and the CVE/ELSA references. Keeps the
    definitions affecting `major` when known.
    """
    root = _safe_xml(text)
    if root is None:
        return []
    out: List[NewsItem] = []
    for defn in root.iter():
        if _ln(defn) != "definition" or defn.get("class") != "patch":
            continue
        title = severity = issued = elsa_url = elsa_id = ""
        platforms: List[str] = []
        cves: List[str] = []
        for c in defn.iter():
            ln = _ln(c)
            if ln == "title" and c.text:
                title = c.text.strip()
            elif ln == "platform" and c.text:
                platforms.append(c.text.strip())
            elif ln == "severity" and c.text:
                severity = c.text.strip()
            elif ln == "issued":
                issued = c.get("date", "") or issued
            elif ln == "reference":
                src = (c.get("source") or "").upper()
                if src == "CVE" and c.get("ref_id"):
                    cves.append(c.get("ref_id", "").upper())
                elif src == "ELSA":
                    elsa_url = c.get("ref_url") or elsa_url
                    elsa_id = c.get("ref_id") or elsa_id
        if major and platforms and not any(p.rstrip().endswith(major) for p in platforms):
            continue
        sev = _norm_sev(severity)
        if sev == "unknown":
            m = re.search(r"\((critical|important|moderate|low)\)", title, re.I)
            if m:
                sev = _norm_sev(m.group(1))
        ident = elsa_id or (title.split(":", 1)[0].strip() if title else "")
        if not ident:
            continue
        out.append(NewsItem(
            id=f"oracle:{ident}", source="oracle", title=title or ident,
            severity=sev, published=(issued or "")[:10],
            url=elsa_url or f"https://linux.oracle.com/errata/{ident}.html",
            cve_ids=list(dict.fromkeys(cves))))
    out.sort(key=lambda i: i.published, reverse=True)
    return out[:limit]


# --------------------------------------------------------------------------- #
# Network fetchers (soft-failing wrappers around the parsers).
# --------------------------------------------------------------------------- #
def fetch_kev(cfg, limit: int = 50) -> List[NewsItem]:
    try:
        return parse_kev(http.get_json(KEV_URL, timeout=cfg.timeout), limit)
    except (http.HttpError, ValueError):
        return []


def fetch_nvd_recent(cfg, limit: int = 50, days: int = 7) -> List[NewsItem]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = (f"{cfg.nvd_api}?pubStartDate={start.strftime(fmt)}"
           f"&pubEndDate={now.strftime(fmt)}&resultsPerPage={min(limit, 200)}")
    headers = {"apiKey": cfg.nvd_api_key} if cfg.nvd_api_key else None
    try:
        return parse_nvd(http.get_json(url, headers=headers, timeout=cfg.timeout),
                         limit)
    except (http.HttpError, ValueError):
        return []


def _fetch_alma(cfg, major: str, limit: int) -> List[NewsItem]:
    raw = http.get_bytes(ALMA_ERRATA_RSS.format(major=major), timeout=cfg.timeout)
    return parse_errata_rss(raw.decode("utf-8", "replace"), "alma", limit)


def _fetch_rocky(cfg, major: str, limit: int) -> List[NewsItem]:
    url = f"{ROCKY_APOLLO}?page=0&limit={min(max(limit * 3, 30), 100)}"
    data = http.get_json(url, timeout=cfg.timeout)
    items = parse_rocky_apollo(data, major, limit)
    if not items and major:                         # nothing for this major -> show all
        items = parse_rocky_apollo(data, "", limit)
    return items


# Cap the decompressed OVAL so a malformed/hostile bz2 can't bomb memory; the
# real Oracle year feed is ~10-15 MB decompressed.
_MAX_OVAL_BYTES = 256 * 1024 * 1024


def _fetch_oracle(cfg, major: str, limit: int) -> List[NewsItem]:
    year = datetime.now(timezone.utc).year
    for yr in (year, year - 1):                      # early in the year, fall back
        try:
            raw = http.get_bytes(ORACLE_OVAL.format(year=yr),
                                 timeout=max(cfg.timeout, 60))
            # Bounded decompression (decompression-bomb guard).
            text = bz2.BZ2Decompressor().decompress(
                raw, _MAX_OVAL_BYTES).decode("utf-8", "replace")
        except (http.HttpError, OSError, ValueError):
            continue
        items = parse_oracle_oval(text, major, limit)
        if items:
            return items
    return []


# distro id (/etc/os-release ID) -> fetcher(cfg, major, limit). Each distro has
# its own native errata format (AlmaLinux RSS, Rocky Apollo JSON, Oracle OVAL).
DISTRO_ERRATA: Dict[str, Callable] = {
    "almalinux": _fetch_alma, "alma": _fetch_alma,
    "rocky": _fetch_rocky,
    "ol": _fetch_oracle, "oracle": _fetch_oracle, "oraclelinux": _fetch_oracle,
}
# NewsItem.source labels produced by the distro fetchers (for `news --source distro`).
DISTRO_SOURCES = {"alma", "rocky", "oracle"}


def fetch_distro_errata(cfg, limit: int = 50) -> List[NewsItem]:
    from .scanners.oval import detect_distro
    distro, major = detect_distro()
    fetch = DISTRO_ERRATA.get(distro)
    if fetch is None:
        return []
    try:
        return fetch(cfg, major, limit)
    except (http.HttpError, OSError, ValueError):
        return []

# News sources shown in the dashboard tab. name -> (label, fetch(cfg, limit)).
FEED_SOURCES: Dict[str, tuple] = {
    "kev": ("CISA Known Exploited Vulnerabilities", fetch_kev),
    "nvd": ("NVD recent CVEs", fetch_nvd_recent),
    "distro": ("Distribution errata", fetch_distro_errata),
}
DEFAULT_SOURCES = ["kev", "nvd", "distro"]


# --------------------------------------------------------------------------- #
# EPSS + KEV enrichment lookups (used by the scan enricher and the news tab).
# --------------------------------------------------------------------------- #
def epss_scores(cves: List[str], cfg, batch: int = 100) -> Dict[str, float]:
    """Look up EPSS probabilities for the given CVEs. Soft-fails to {}."""
    uniq = [c for c in dict.fromkeys(c.upper() for c in cves) if c]
    out: Dict[str, float] = {}
    for i in range(0, len(uniq), batch):
        chunk = uniq[i:i + batch]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        try:
            out.update(parse_epss(http.get_json(url, timeout=cfg.timeout)))
        except (http.HttpError, ValueError):
            continue
    return out


def kev_cve_set(cfg) -> Set[str]:
    """The full set of CVE ids in the CISA KEV catalog. Soft-fails to set()."""
    try:
        data = http.get_json(KEV_URL, timeout=cfg.timeout)
    except (http.HttpError, ValueError):
        return set()
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    return {str(v.get("cveID", "")).upper() for v in (vulns or []) if v.get("cveID")}


# --------------------------------------------------------------------------- #
# Aggregation + caching (offline-friendly).
# --------------------------------------------------------------------------- #
def _dedupe(items: List[NewsItem]) -> List[NewsItem]:
    """Collapse items that describe the same CVE, preferring the exploited one.

    KEV (exploited) wins over a plain NVD entry for the same CVE so the badge is
    not lost; otherwise the first occurrence is kept.
    """
    by_cve: Dict[str, NewsItem] = {}
    standalone: List[NewsItem] = []
    for it in items:
        key = it.cve_ids[0] if it.cve_ids else None
        if key is None:
            standalone.append(it)
            continue
        cur = by_cve.get(key)
        if cur is None or (it.exploited and not cur.exploited):
            by_cve[key] = it
    return list(by_cve.values()) + standalone


def fetch_all(cfg, sources: Optional[List[str]] = None,
              limit_per: int = 50) -> List[NewsItem]:
    """Fetch+merge the selected feed sources. Never raises (per-source soft-fail)."""
    chosen = sources or DEFAULT_SOURCES
    items: List[NewsItem] = []
    for name in chosen:
        spec = FEED_SOURCES.get(name)
        if spec is None:
            continue
        _label, fetch = spec
        try:
            items.extend(fetch(cfg, limit_per))
        except Exception:  # noqa: BLE001  (a source must never break the others)
            continue
    items = _dedupe(items)
    # Actively-exploited first, then newest, then by severity.
    from .models import severity_rank
    items.sort(key=lambda i: (i.exploited, i.published,
                              severity_rank(i.severity)), reverse=True)
    return items


def _cache_path(cfg) -> str:
    return os.path.join(cfg.state_dir, "news-cache.json")


def save_cache(cfg, items: List[NewsItem], fetched_at: str) -> None:
    cfg.ensure_state_dir()
    path = _cache_path(cfg)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"fetched_at": fetched_at,
                   "items": [i.to_dict() for i in items]}, fh)
    os.chmod(path, 0o600)


def load_cache(cfg):
    """Return (items, fetched_at) from the on-disk cache, or ([], '') if none."""
    try:
        with open(_cache_path(cfg), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return [], ""
    items = [NewsItem.from_dict(d) for d in data.get("items", [])]
    return items, str(data.get("fetched_at", ""))


def refresh_news(cfg, sources: Optional[List[str]] = None,
                 limit_per: int = 50):
    """Fetch fresh news and cache it. Returns (items, fetched_at).

    Falls back to the cached copy if every source came back empty (e.g. the host
    is offline), so a transient outage never blanks the tab.
    """
    items = fetch_all(cfg, sources, limit_per)
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not items:
        cached, when = load_cache(cfg)
        if cached:
            return cached, when
    save_cache(cfg, items, fetched_at)
    return items, fetched_at
