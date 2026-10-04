"""Claude Code invocation for the SusVibes outer repair loop.

Each call is a fresh `claude -p` session. The caller owns the no-test worktree,
patch extraction, security checks, and total 3,000-second task deadline.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from evaluation_harness.common import command_from_template, run_command

if TYPE_CHECKING:
    from evaluation_harness.docker_workspace import DockerWorkspace


ALLOWED_TOOLS = (
    "Bash", "Edit", "MultiEdit", "Write", "Read", "Glob", "Grep", "LS",
    "NotebookEdit", "NotebookRead", "TodoRead", "TodoWrite", "Agent",
)
DISALLOWED_TOOLS = ("WebFetch", "WebSearch")
SETUP_SCRIPT = Path(__file__).with_name("setup_cli.sh")


def prepare_runtime(runtime: DockerWorkspace, model: str) -> dict[str, str]:
    """Install the pinned CLI, then restrict the task container to its model API."""
    key = os.getenv("ANTHROPIC_AUTH_TOKEN") or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("set ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY for Claude Code")
    base_url = os.getenv("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
    runtime.copy_file(SETUP_SCRIPT, "/tmp/av-claude-setup.sh")
    setup = runtime.execute(["bash", "/tmp/av-claude-setup.sh"], timeout_s=1200)
    if setup.returncode:
        raise RuntimeError(f"Claude Code 1.0.128 setup failed: {setup.stderr[-1000:]}")
    relay_url = runtime.isolate_model_api(base_url,
                                          paths=("/v1/messages", "/v1/messages/count_tokens"))
    return {
        "ANTHROPIC_BASE_URL": relay_url,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY") or key,
        "ANTHROPIC_MODEL": model,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    }


def command_args(model: str, prompt: str) -> list[str]:
    return [
        "claude", "--verbose", "--output-format", "stream-json", "-p", prompt,
        "--model", model, "--allowedTools", *ALLOWED_TOOLS,
        "--disallowedTools", *DISALLOWED_TOOLS,
    ]


def result_event(stdout: str) -> dict | None:
    """Read the final structured result while ignoring non-JSON CLI log lines."""
    result = None
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("type") == "result":
            result = item
    return result


def agent_turn(model: str, prompt: str, workspace: Path, timeout_s: int,
               *, command: list[str] | None = None,
               runtime: DockerWorkspace | None = None,
               agent_env: dict[str, str] | None = None) -> tuple[str, str]:
    visible_workspace = Path(runtime.workdir) if runtime else workspace
    args = (command_from_template(command, model=model, prompt=prompt, workspace=visible_workspace)
            if command else command_args(model, prompt))
    if runtime and not command:
        args = ["bash", "-lc",
                'source /root/.nvm/nvm.sh >/dev/null 2>&1 || true; exec claude "$@"',
                "claude", *args[1:]]
    stdout = run_command(args, workspace, timeout_s, runtime=runtime, env=agent_env)
    if not command:
        result = result_event(stdout)
        if result and (result.get("is_error") or result.get("subtype") == "error"):
            raise RuntimeError("Claude Code reported an error in its result event")
    return stdout, ""  # The next repair starts a new session.
