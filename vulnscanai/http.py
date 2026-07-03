# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Minimal HTTP helper built on the stdlib.

Uses urllib (no third-party dependency) over a FIPS-hardened TLS context so
the same code path works on an air-gapped or FIPS-locked host. All calls go
through here so retry/timeout/error behaviour is consistent.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from .fips import tls_context

DEFAULT_TIMEOUT = 30
USER_AGENT = "vulnscan-ai/0.1 (+https://example.invalid/vulnscan-ai)"
# Hard ceiling on a single response body, so a misbehaving/compromised feed
# origin can't drive unbounded memory use (the CISA KEV feed is a few MB).
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class HttpError(Exception):
    def __init__(self, status: int, message: str, body: str = ""):
        detail = f"HTTP {status}: {message}"
        # Surface the server's own error text (e.g. an API's "credit balance is
        # too low" message) instead of a bare "Bad Request" — that reason is
        # usually the only actionable part, and callers only render str(exc).
        reason = _error_reason(body)
        if reason:
            detail += f" — {reason}"
        super().__init__(detail)
        self.status = status
        self.body = body


def _error_reason(body: str, limit: int = 300) -> str:
    """Pull a human-readable reason out of a response body. Handles the common
    JSON error shapes ({"error": {"message": ...}}, {"error": "..."},
    {"message": ...}); falls back to the trimmed raw body."""
    body = (body or "").strip()
    if not body:
        return ""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict) and err.get("message"):
                return str(err["message"])[:limit]
            if isinstance(err, str) and err:
                return err[:limit]
            if data.get("message"):
                return str(data["message"])[:limit]
    except (ValueError, TypeError):
        pass
    return body[:limit]


def _request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 2,
) -> bytes:
    # Only ever speak HTTP(S): refuse file://, ftp://, data:, custom schemes —
    # so neither a config-supplied API base nor a feed URL can be turned into a
    # local-file read or other SSRF vector.
    if urlsplit(url).scheme not in ("http", "https"):
        raise HttpError(0, f"refusing non-HTTP(S) URL: {url}")
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    ctx = tls_context()
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            # Scheme is restricted to http/https above; TLS is the FIPS-hardened
            # context from fips.tls_context().
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # nosec B310
                body = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise HttpError(0, f"response exceeds {MAX_RESPONSE_BYTES} bytes")
                return body
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            # Retry on rate limit / transient server errors.
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                last_exc = exc
                continue
            raise HttpError(exc.code, exc.reason, body) from exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            # Covers connection refused/reset/DNS (URLError) and read timeouts
            # (socket.timeout) alike — e.g. a slow local model on CPU.
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            reason = getattr(exc, "reason", exc)
            raise HttpError(0, str(reason)) from exc
    raise HttpError(0, str(last_exc) if last_exc else "request failed")


def get_json(url: str, headers: Optional[Dict[str, str]] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Any:
    raw = _request("GET", url, headers=headers, timeout=timeout)
    return json.loads(raw.decode("utf-8"))


def get_bytes(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: int = 120) -> bytes:
    """Download a (possibly large) binary resource, e.g. a compressed feed."""
    return _request("GET", url, headers=headers, timeout=timeout)


def post_json(url: str, payload: Dict[str, Any],
              headers: Optional[Dict[str, str]] = None,
              timeout: int = DEFAULT_TIMEOUT) -> Any:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    body = json.dumps(payload).encode("utf-8")
    raw = _request("POST", url, headers=hdrs, data=body, timeout=timeout)
    return json.loads(raw.decode("utf-8"))
