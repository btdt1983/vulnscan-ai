# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Google Gemini provider (optional). Set GEMINI_API_KEY.

Gemini 3 models deprecated the 'temperature'/'top_p'/'top_k' sampling
parameters (Google's own migration guidance: "strip temperature, top_p, and
top_k from generation configs") -- so this provider sends none of them, for
every model, rather than branch on generation. In their place,
'responseMimeType: application/json' asks the API to constrain output to
valid JSON directly (a real generateContent field, unrelated to the
deprecated sampling knobs) -- the same 'demand structured output at the API
level, don't just lower the temperature and hope' approach local.py already
uses for Ollama ("format": "json").

Gemini 3 also thinks by default. Google documents that thought tokens count
against max_output_tokens for their newer Interactions API, but does NOT
confirm the same for the classic generateContent endpoint this provider
calls, and Google's own generateContent code samples never set
maxOutputTokens either -- so it's left unset here too, matching the
behaviour that already works for Gemini 2.5. If truncated/empty JSON starts
showing up specifically for gemini-3.x models, this is the first place to
look.
"""

from __future__ import annotations

from .. import http
from .base import AIProvider, ProviderError


class GeminiProvider(AIProvider):
    name = "gemini"
    default_model = "gemini-3.8-flash"
    known_models = [
        "gemini-3.8-flash",               # balanced default, strongest on code/agents
        "gemini-2.5-pro",                 # deeper reasoning (no stable Gemini 3 Pro yet)
        "gemini-3.5-flash-lite",          # fastest / cheapest
    ]
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
            "generationConfig": {"responseMimeType": "application/json"},
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
