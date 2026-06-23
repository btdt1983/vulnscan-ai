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

from .fips import tls_context

DEFAULT_TIMEOUT = 30
USER_AGENT = "vulnscan-ai/0.1 (+https://example.invalid/vulnscan-ai)"


class HttpError(Exception):
    def __init__(self, status: int, message: str, body: str = ""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


def _request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 2,
) -> bytes:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    ctx = tls_context()
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read()
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
