# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""AI provider abstraction.

Every provider takes a single prompt (system + user) and returns raw text.
The remediation module is responsible for building the prompt and parsing the
JSON the model returns, so providers stay thin and interchangeable.
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from .. import http


class ProviderError(Exception):
    pass


class AIProvider:
    name: str = "base"
    default_model: str = ""
    # Curated known model ids offered as a menu by the setup wizard (the setup
    # step also allows a custom id). Keep the recommended default first. Empty
    # means "no curated list" — the wizard falls back to a free-text prompt.
    known_models: List[str] = []
    # Environment variable that holds the API key for this provider.
    api_key_env: str = ""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: int = 60, effort: Optional[str] = None) -> None:
        self.model = model or self.default_model
        self.api_key = api_key or (os.environ.get(self.api_key_env) if self.api_key_env else None)
        self.timeout = timeout
        # Reasoning-effort hint (low|medium|high|xhigh|max). Only providers that
        # support it act on it; the rest ignore it.
        self.effort = effort

    def available(self) -> bool:
        """Whether this provider is usable (key present, etc.)."""
        if self.api_key_env:
            return bool(self.api_key)
        return True

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError

    def list_models(self) -> List[str]:
        """Model ids this account can currently use, via the vendor's own
        list-models endpoint. Lets `providers --verify` catch a configured
        default/selected model id that has quietly been retired, instead of
        only finding out on the next real API call. Providers that can't
        support this (no such endpoint) raise ProviderError.

        Deliberately single-page: every implementation below asks for the
        largest page size each API accepts (1000), confirmed live
        (2026-10-03, bogus-key probes) not to 400 on that value. None of
        these vendors' catalogs run anywhere near that size, so a second
        page is not expected in practice — but if a vendor ever does grow
        past it, a configured-but-older model id could fall off page one and
        get reported STALE while still actually live. Not following the
        cursor is a conscious choice (Anthropic's `has_more`/`last_id`,
        Gemini's `nextPageToken`), not an oversight."""
        raise ProviderError(f"{self.name} does not support live model verification")


def list_models_openai_compatible(provider_label: str, base_url: str, api_key: str,
                                  timeout: int) -> List[str]:
    """Shared GET {base_url}/models for the OpenAI-compatible chat providers
    (openai, mistral, deepseek, kimi all expose this same shape)."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        data = http.get_json(f"{base_url}/models", headers=headers, timeout=timeout)
    except http.HttpError as exc:
        raise ProviderError(f"{provider_label} API error: {exc}") from exc
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ProviderError(f"unexpected {provider_label} model-list response shape")
    return [m["id"] for m in items if isinstance(m, dict) and isinstance(m.get("id"), str)]


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response.

    Models sometimes wrap JSON in prose or ```json fences; be forgiving.
    """
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Scan for a '{' from which a complete JSON object decodes. raw_decode is
    # string/escape aware, unlike a naive brace counter — which miscounts braces
    # inside string values (e.g. an embedded `server { ... }` nginx config) and
    # then drops a legitimate plan.
    decoder = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            obj, _ = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            return obj
        idx = text.find("{", idx + 1)
    raise ProviderError("could not parse JSON from model response")
