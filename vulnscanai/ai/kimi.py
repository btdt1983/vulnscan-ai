# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Moonshot Kimi provider (optional).

Kimi exposes an OpenAI-compatible Chat Completions API. Set MOONSHOT_API_KEY.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class KimiProvider(AIProvider):
    name = "kimi"
    default_model = "moonshot-v1-8k"
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
            "temperature": 0.1,
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
