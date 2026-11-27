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

The API key goes in the 'x-goog-api-key' header, not the '?key=' query
string Google's own quickstart docs show -- a query-string key ends up in
request logs and, worse, in this tool's own error messages (http.HttpError
embeds the request URL verbatim). Confirmed live (2026-10-03, bogus key)
that the header form is accepted identically on both generateContent and
models.list -- byte-identical "API key not valid" error body either way.
"""

from __future__ import annotations

from .. import http
from .base import AIProvider, ProviderError


class GeminiProvider(AIProvider):
    name = "gemini"
    default_model = "gemini-3.8-flash"
    known_models = [
        "gemini-3.8-flash",               # balanced default, strongest on code/agents
        "gemini-4-hydrogen",              # Gemini 4, everyday coding/agentic work
        "gemini-3.5-flash-lite",          # fastest / cheapest
    ]
    api_key_env = "GEMINI_API_KEY"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("GEMINI_API_KEY is not set")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }
        headers = {"x-goog-api-key": self.api_key}
        try:
            data = http.post_json(url, payload, headers=headers, timeout=self.timeout)
        except http.HttpError as exc:
            raise ProviderError(f"Gemini API error: {exc}") from exc
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError) as exc:
            raise ProviderError("unexpected Gemini response shape") from exc

    def list_models(self):
        if not self.api_key:
            raise ProviderError("GEMINI_API_KEY is not set")
        url = "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000"
        headers = {"x-goog-api-key": self.api_key}
        try:
            data = http.get_json(url, headers=headers, timeout=self.timeout)
        except http.HttpError as exc:
            raise ProviderError(f"Gemini API error: {exc}") from exc
        items = data.get("models") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ProviderError("unexpected Gemini model-list response shape")
        out = []
        for m in items:
            name = m.get("name") if isinstance(m, dict) else None
            if isinstance(name, str) and name:
                # the API names models "models/gemini-3.8-flash"
                out.append(name.rsplit("/", 1)[-1])
        return out
