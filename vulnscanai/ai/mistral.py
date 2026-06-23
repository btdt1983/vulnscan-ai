# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Mistral AI provider (optional).

Mistral exposes an OpenAI-compatible Chat Completions API. Set MISTRAL_API_KEY.
The default model is the open-weights 'open-mixtral-8x7b'; other ids such as
'mistral-large-latest', 'mistral-small-latest' or 'open-mistral-7b' work via
--model. Point MISTRAL_BASE_URL at a gateway to override the endpoint.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class MistralProvider(AIProvider):
    name = "mistral"
    default_model = "open-mixtral-8x7b"
    api_key_env = "MISTRAL_API_KEY"

    @property
    def endpoint(self) -> str:
        base = os.environ.get("MISTRAL_BASE_URL", "https://api.mistral.ai/v1").rstrip("/")
        return f"{base}/chat/completions"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("MISTRAL_API_KEY is not set")
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
            raise ProviderError(f"Mistral API error: {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected Mistral response shape") from exc
