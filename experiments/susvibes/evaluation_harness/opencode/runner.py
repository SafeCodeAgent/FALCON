"""OpenCode invocation with JSON event parsing and session continuation."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from evaluation_harness.common import command_from_template, run_command
from evaluation_harness.opencode.installer import VERSION, ensure_binary

if TYPE_CHECKING:
    from evaluation_harness.docker_workspace import DockerWorkspace


CONTAINER_BINARY = "/tmp/av-opencode/bin/opencode"


def _config(model: str, *, mode: str) -> tuple[str, str]:
    model_key = re.sub(r"[^A-Za-z0-9_.-]", "-", model.split("/")[-1]) or "model"
    provider = "av"
    config = {
        "$schema": "https://opencode.ai/config.json",
        "autoupdate": False,
        "share": "disabled",
        "enabled_providers": [provider],
        "provider": {
            provider: {
                "npm": "@ai-sdk/openai" if mode == "responses" else "@ai-sdk/openai-compatible",
                "name": "Model API",
                "options": {"baseURL": "{env:AV_AGENT_BASE_URL}",
                            "apiKey": "{env:AV_AGENT_API_KEY}"},
                "models": {model_key: {
                    "id": model, "name": model,
                    "limit": {"context": int(os.getenv("AV_OPENCODE_CONTEXT", "128000")),
                              "output": int(os.getenv("AV_OPENCODE_OUTPUT", "32000"))},
                }},
            },
        },
        "permission": {"webfetch": "deny", "websearch": "deny"},
    }
    return json.dumps(config, separators=(",", ":")), f"{provider}/{model_key}"


def prepare_runtime(runtime: DockerWorkspace, model: str) -> dict[str, str]:
    """Inject pinned OpenCode, set model provider, and isolate model traffic."""
    key = (os.getenv("AV_OPENCODE_API_KEY") or os.getenv("AV_API_KEY")
           or os.getenv("OPENAI_KEY") or os.getenv("OPENAI_API_KEY"))
    base_url = (os.getenv("AV_OPENCODE_API_BASE_URL") or os.getenv("AV_API_BASE_URL")
                or os.getenv("OPENAI_BASE_URL"))
    if not key or not base_url:
        raise ValueError("set an OpenCode model API base URL and key")
    musl = runtime.execute(["sh", "-c", "test -f /etc/alpine-release || "
                            "(ldd --version 2>&1 | grep -qi musl)"], timeout_s=10).returncode == 0
    binary = ensure_binary(musl=musl)
    created = runtime.execute(["mkdir", "-p", str(Path(CONTAINER_BINARY).parent)], timeout_s=10)
    if created.returncode:
        raise RuntimeError(f"Could not prepare OpenCode binary directory: {created.stderr[-500:]}")
    runtime.copy_file(binary, CONTAINER_BINARY)
    checked = runtime.execute([CONTAINER_BINARY, "--version"], timeout_s=30)
    if checked.returncode or VERSION not in checked.stdout + checked.stderr:
        raise RuntimeError("Task container cannot execute OpenCode 1.18.16")
    mode = os.getenv("AV_API_MODE", "chat")
    if mode not in {"chat", "responses"}:
        raise ValueError("AV_API_MODE must be chat or responses")
    path = "/responses" if mode == "responses" else "/chat/completions"
    relay_url = runtime.isolate_model_api(base_url, paths=(path,))
    generated, model_name = _config(model, mode=mode)
    return {
        "AV_AGENT_BASE_URL": relay_url,
        "AV_AGENT_API_KEY": key,
        "AV_OPENCODE_MODEL": os.getenv("AV_OPENCODE_MODEL", model_name),
        "OPENCODE_CONFIG_CONTENT": os.getenv("AV_OPENCODE_CONFIG_CONTENT", generated),
        "OPENCODE_DISABLE_AUTOUPDATE": "1",
        "OPENCODE_DISABLE_MODELS_FETCH": "1",
        "OPENCODE_DISABLE_SHARE": "1",
    }


def command_args(model: str, prompt: str, workspace: Path,
                 session_id: str = "") -> list[str]:
    checkout = os.getenv("AV_OPENCODE_SOURCE")
    if checkout:
        # Development only: run an OpenCode v1.18.16 source checkout with Bun on the host.
        source = Path(checkout).expanduser() / "packages" / "opencode"
        prefix = ["bun", "run", "--cwd", str(source), "--conditions=browser", "src/index.ts"]
    else:
        prefix = ["opencode"]
    args = prefix + ["run", "--auto", "--dir", str(workspace), "--model", model,
                     "--format", "json", "--title", "av-susvibes"]
    if session_id:
        args += ["--session", session_id]
    return args + [prompt]


def session_from_events(stdout: str) -> str:
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        value = item.get("sessionID") or item.get("session_id") or item.get("sessionId")
        if value:
            return str(value)
    return ""


def agent_turn(model: str, prompt: str, workspace: Path, timeout_s: int,
               *, session_id: str = "", command: list[str] | None = None,
               runtime: DockerWorkspace | None = None,
               agent_env: dict[str, str] | None = None) -> tuple[str, str]:
    actual_model = (agent_env or {}).get("AV_OPENCODE_MODEL", model) if runtime else model
    visible_workspace = Path(runtime.workdir) if runtime else workspace
    args = (command_from_template(command, model=model, prompt=prompt, workspace=visible_workspace,
                                  session_id=session_id)
            if command else command_args(actual_model, prompt, workspace, session_id))
    if runtime and not command:
        args = [CONTAINER_BINARY, "run", "--auto", "--dir", runtime.workdir,
                "--model", actual_model, "--format", "json", "--title", "av-susvibes"]
        if session_id:
            args += ["--session", session_id]
        args += [prompt]
    stdout = run_command(args, workspace, timeout_s, runtime=runtime, env=agent_env)
    return stdout, session_from_events(stdout) or session_id
