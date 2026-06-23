# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""DeepSeek provider (optional).

DeepSeek exposes an OpenAI-compatible Chat Completions API. Set DEEPSEEK_API_KEY.
The default model is the code-specialised 'deepseek-coder'; use 'deepseek-chat'
(general) or 'deepseek-reasoner' via --model / OLLAMA-style overrides as needed.
Point DEEPSEEK_BASE_URL at a gateway if you don't hit the public endpoint.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class DeepSeekProvider(AIProvider):
    name = "deepseek"
    default_model = "deepseek-coder"
    api_key_env = "DEEPSEEK_API_KEY"

    @property
    def endpoint(self) -> str:
        base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
        return f"{base}/chat/completions"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("DEEPSEEK_API_KEY is not set")
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
            raise ProviderError(f"DeepSeek API error: {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected DeepSeek response shape") from exc
