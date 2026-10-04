from __future__ import annotations

import json
import os
from typing import Any

import httpx


class ModelClient:
    def __init__(self, model: str, api_base: str | None = None, api_key: str | None = None,
                 timeout: int = 600):
        self.model = model
        self.api_base = (api_base or os.environ.get("OPENAI_BASE_URL") or
                         "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY must be set for model calls")

    def complete(self, prompt: str, max_tokens: int = 4096) -> str:
        response = httpx.post(
            self.api_base + "/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}],
                  "max_completion_tokens": max_tokens}, timeout=self.timeout,
        )
        response.raise_for_status()
        message = response.json()["choices"][0]["message"]
        content = message.get("content")
        if isinstance(content, list):
            return "".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
        return str(content or "")


def parse_object(text: str) -> dict[str, Any]:
    clean = text.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    value = json.loads(clean)
    if not isinstance(value, dict):
        raise ValueError("Model response must be a JSON object")
    return value
