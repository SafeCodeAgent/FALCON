"""Small configurable model transport; secrets are never written to artifacts."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def json_object(text: str) -> dict:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char == "{":
            try:
                value, _ = decoder.raw_decode(text[index:])
                if isinstance(value, dict): return value
            except json.JSONDecodeError:
                continue
    raise ValueError("model returned no JSON object")


class ModelClient:
    def __init__(self, model: str, *, base_url: str | None = None, api_key: str | None = None,
                 mode: str | None = None, timeout_s: int = 600):
        self.model = model
        self.base_url = (base_url or os.getenv("AV_API_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "").rstrip("/")
        self.api_key = api_key or os.getenv("AV_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY") or ""
        self.mode = mode or os.getenv("AV_API_MODE", "chat")
        self.timeout_s = timeout_s
        if self.mode not in {"chat", "responses"}: raise ValueError("API mode must be chat or responses")
        if not self.base_url or not self.api_key: raise ValueError("set AV_API_BASE_URL and AV_API_KEY")

    def complete(self, prompt: str) -> tuple[dict, str, dict]:
        if self.mode == "chat":
            url = self.base_url + "/chat/completions"
            body = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        else:
            url = self.base_url + "/responses"
            body = {"model": self.model, "input": prompt}
        req = urllib.request.Request(url, json.dumps(body).encode(), {
            "Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"model API returned HTTP {exc.code}: {exc.read(400).decode(errors='replace')}") from exc
        if self.mode == "chat":
            raw = payload["choices"][0]["message"].get("content") or ""
        else:
            raw = payload.get("output_text") or "".join(
                block.get("text", "") for item in payload.get("output", [])
                for block in item.get("content", []) if block.get("type") == "output_text")
        return json_object(raw), raw, payload.get("usage", {})
