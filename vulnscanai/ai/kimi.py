# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Moonshot Kimi provider (optional).

Kimi exposes an OpenAI-compatible Chat Completions API. Set MOONSHOT_API_KEY.
The K3 series fixes 'temperature' at 1.0 and returns an error for any other
value (Moonshot parameter reference, checked 2026-11-27), so none is sent.

The default endpoint is api.moonshot.cn. Moonshot's international docs
(platform.kimi.ai) give https://api.moonshot.ai/v1 instead: set
MOONSHOT_BASE_URL to that for an account created there.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError, list_models_openai_compatible


class KimiProvider(AIProvider):
    name = "kimi"
    default_model = "kimi-k3"
    known_models = [
        "kimi-k3",                        # default (previous-generation flagship)
        "kimi-k3.1-pro",                  # current flagship
        "kimi-k3.1-pro-highspeed",        # same model, faster serving
    ]
    api_key_env = "MOONSHOT_API_KEY"

    @property
    def endpoint(self) -> str:
        base = os.environ.get("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1").rstrip("/")
        return f"{base}/chat/completions"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("MOONSHOT_API_KEY is not set")
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
            raise ProviderError(f"Kimi API error: {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected Kimi response shape") from exc

    def list_models(self):
        if not self.api_key:
            raise ProviderError("MOONSHOT_API_KEY is not set")
        base = os.environ.get("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1").rstrip("/")
        return list_models_openai_compatible("Kimi", base, self.api_key, self.timeout)
