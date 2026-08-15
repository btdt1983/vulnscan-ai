# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Moonshot Kimi provider (optional).

Kimi exposes an OpenAI-compatible Chat Completions API. Set MOONSHOT_API_KEY.
The legacy 'moonshot-v1-*' ids this provider used to default to are being sunset
(closed to new accounts already, platform sunset 2026-08-31), so the default is
now 'kimi-k3'. Point MOONSHOT_BASE_URL at the current host if the api.moonshot.cn
endpoint moves with the platform migration.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class KimiProvider(AIProvider):
    name = "kimi"
    default_model = "kimi-k3"
    known_models = [
        "kimi-k3",                        # flagship default
        "kimi-k2.7-code",                 # code-specialised
        "kimi-k2.6",                      # previous generation
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
