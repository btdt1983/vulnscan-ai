"""AI provider abstraction.

Every provider takes a single prompt (system + user) and returns raw text.
The remediation module is responsible for building the prompt and parsing the
JSON the model returns, so providers stay thin and interchangeable.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional


class ProviderError(Exception):
    pass


class AIProvider:
    name: str = "base"
    default_model: str = ""
    # Environment variable that holds the API key for this provider.
    api_key_env: str = ""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: int = 60) -> None:
        self.model = model or self.default_model
        self.api_key = api_key or (os.environ.get(self.api_key_env) if self.api_key_env else None)
        self.timeout = timeout

    def available(self) -> bool:
        """Whether this provider is usable (key present, etc.)."""
        if self.api_key_env:
            return bool(self.api_key)
        return True

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response.

    Models sometimes wrap JSON in prose or ```json fences; be forgiving.
    """
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    raise ProviderError("could not parse JSON from model response")
