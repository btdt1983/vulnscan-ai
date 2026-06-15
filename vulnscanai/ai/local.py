"""Local / offline provider via an Ollama-compatible server.

For air-gapped or data-sensitive environments where nothing may leave the
host. Point OLLAMA_HOST at the local server (default http://127.0.0.1:11434)
and select a pulled model with OLLAMA_MODEL or --model. No API key required.

The tool only ever asks the model for a structured remediation object, so we
request Ollama's JSON-constrained output mode ("format": "json"), which makes
even small local models reliably emit parseable JSON.
"""

from __future__ import annotations

import os

from .. import http
from .base import AIProvider, ProviderError


class LocalProvider(AIProvider):
    name = "local"
    default_model = "llama3.1"
    api_key_env = ""  # no key needed

    def __init__(self, model=None, api_key=None, timeout: int = 60) -> None:
        super().__init__(model=model or os.environ.get("OLLAMA_MODEL"),
                         api_key=api_key, timeout=timeout)
        if not self.model:
            self.model = self.default_model
        # Local CPU inference (and the first-call model load) is far slower
        # than a cloud API, so be patient regardless of the global timeout.
        # Override with OLLAMA_TIMEOUT if needed.
        floor = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
        self.timeout = max(self.timeout, floor)

    @property
    def base_url(self) -> str:
        return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/api/chat"

    def available(self) -> bool:
        """True when a local Ollama server answers on its version endpoint."""
        try:
            http.get_json(f"{self.base_url}/api/version", timeout=3)
            return True
        except http.HttpError:
            return False

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            data = http.post_json(self.endpoint, payload, timeout=self.timeout)
        except http.HttpError as exc:
            if exc.status == 0:
                raise ProviderError(
                    f"cannot reach Ollama at {self.base_url} — is it running? "
                    f"start it with 'ollama serve' (or systemctl start ollama)"
                ) from exc
            if exc.status == 404 or "not found" in (exc.body or "").lower():
                raise ProviderError(
                    f"model '{self.model}' is not available locally — "
                    f"pull it first: 'ollama pull {self.model}'"
                ) from exc
            raise ProviderError(f"local model error: {exc}") from exc
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ProviderError("unexpected local model response shape") from exc
