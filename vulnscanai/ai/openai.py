# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""OpenAI / ChatGPT provider (optional).

Uses the Chat Completions API. Set OPENAI_API_KEY. Also works against any
OpenAI-compatible endpoint (e.g. a local gateway) via OPENAI_BASE_URL.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class OpenAIProvider(AIProvider):
    name = "openai"
    default_model = "gpt-5.6-terra"
    known_models = [
        "gpt-5.6-terra",                  # balanced default
        "gpt-5.6-sol",                    # frontier / hardest fixes
        "gpt-5.6-luna",                   # cheapest
    ]
    api_key_env = "OPENAI_API_KEY"

    @property
    def endpoint(self) -> str:
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        return f"{base}/chat/completions"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("OPENAI_API_KEY is not set")
        # No "temperature": the GPT-5 reasoning models reject any value other
        # than the default with a 400 ("does not support 0.1 with this model"),
        # which would break every remediation. They are deterministic enough for
        # JSON output without it, and an OpenAI-compatible gateway pointed at an
        # older model is happy with the default too.
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            data = http.post_json(self.endpoint, payload, headers=headers,
                                  timeout=self.timeout)
        except http.HttpError as exc:
            raise ProviderError(f"OpenAI API error: {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected OpenAI response shape") from exc
