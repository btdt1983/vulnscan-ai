# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Google Gemini provider (optional). Set GEMINI_API_KEY."""

from __future__ import annotations

from .. import http
from .base import AIProvider, ProviderError


class GeminiProvider(AIProvider):
    name = "gemini"
    default_model = "gemini-2.0-flash"
    api_key_env = "GEMINI_API_KEY"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("GEMINI_API_KEY is not set")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.1},
        }
        try:
            data = http.post_json(url, payload, timeout=self.timeout)
        except http.HttpError as exc:
            raise ProviderError(f"Gemini API error: {exc}") from exc
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected Gemini response shape") from exc
