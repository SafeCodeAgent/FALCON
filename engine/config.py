"""Configuration resolution for the attacker-verifier engine.

Configuration comes from three places, lowest priority first:

1. :data:`DEFAULTS` -- sensible values so the tools run with no setup.
2. A project config file (``.attacker-verifier/config.json`` at the repo root),
   if present.
3. An inline JSON override passed on the command line with ``--config-json``,
   which is how a skill forwards user-supplied settings.

Later sources are merged over earlier ones key by key (one level deep for the
``execution`` block), so a user only has to specify what they want to change.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

# The defaults below are the "just run it" settings described in the README.
DEFAULTS: Dict[str, Any] = {
    # Who proposes probes. "main" means the coding agent currently running the
    # skill does it inline; any other value names a subagent or model the skill
    # should delegate to.
    "attacker": "main",
    # Who judges traces the deterministic stage leaves undecided. Same meaning
    # as ``attacker``; "main" keeps it inline with the coding agent.
    "verifier": "main",
    # Number of probes requested per target, as a closed range.
    "probes_min": 5,
    "probes_max": 10,
    # Secure-code-generation only: how many attack -> verify -> repair cycles to
    # run before returning the best patch so far.
    "num_turns": 2,
    # Turn budget for the attacker per target: it explores and crafts probes for
    # up to this many turns, then returns its probes (compelled to return if it
    # has not; the target is skipped if it produces none).
    "attacker_max_turns": 20,
    # Upper bound on how many targets a single run attacks, so a large repo does
    # not expand without limit. Targets are ranked by security relevance first.
    "max_targets": 20,
    # Per-probe sandbox limits.
    "probe_timeout_s": 30,
    "probe_mem_mb": 1024,
    # Timeout for a delegated model/agent call, when the attacker or verifier is
    # not "main".
    "model_timeout_s": 600,
    # How probes are executed. mode is "host" (current session, no container) or
    # "docker". For docker, set either "image" (a fresh container per probe) or
    # "container" (exec into a running container); "workdir" is where the repo
    # is mounted/visible inside the container.
    "execution": {
        "mode": "host",
        "image": None,
        "container": None,
        "workdir": "/work",
        "python": "python3",
    },
}

PROJECT_CONFIG_RELPATH = os.path.join(".attacker-verifier", "config.json")


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge ``override`` onto ``base``, recursing one level into dict values."""
    out = dict(base)
    for key, value in override.items():
        if (
            key in out
            and isinstance(out[key], dict)
            and isinstance(value, dict)
        ):
            merged = dict(out[key])
            merged.update(value)
            out[key] = merged
        else:
            out[key] = value
    return out


def load_config(
    repo_root: str,
    inline_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the effective configuration for a run.

    ``repo_root`` is searched for the project config file. ``inline_json`` is an
    optional JSON string (from ``--config-json``) that wins over everything.
    """
    config = dict(DEFAULTS)
    config["execution"] = dict(DEFAULTS["execution"])

    project_path = os.path.join(repo_root, PROJECT_CONFIG_RELPATH)
    if os.path.isfile(project_path):
        try:
            with open(project_path, "r", encoding="utf-8") as handle:
                config = _deep_merge(config, json.load(handle) or {})
        except (ValueError, OSError) as exc:
            raise ConfigError(
                "could not read %s: %s" % (project_path, exc)
            ) from exc

    if inline_json:
        try:
            config = _deep_merge(config, json.loads(inline_json) or {})
        except ValueError as exc:
            raise ConfigError("invalid --config-json: %s" % exc) from exc

    _validate(config)
    return config


def _validate(config: Dict[str, Any]) -> None:
    lo, hi = config["probes_min"], config["probes_max"]
    if not (isinstance(lo, int) and isinstance(hi, int)) or lo < 1 or hi < lo:
        raise ConfigError(
            "probes_min/probes_max must be integers with 1 <= min <= max "
            "(got %r/%r)" % (lo, hi)
        )
    if config["num_turns"] < 1:
        raise ConfigError("num_turns must be >= 1")
    if config["max_targets"] < 1:
        raise ConfigError("max_targets must be >= 1")
    mode = config["execution"].get("mode")
    if mode not in ("host", "docker"):
        raise ConfigError("execution.mode must be 'host' or 'docker'")
    if mode == "docker" and not (
        config["execution"].get("image") or config["execution"].get("container")
    ):
        raise ConfigError(
            "execution.mode is 'docker' but neither 'image' nor 'container' is set"
        )


class ConfigError(Exception):
    """Raised when the resolved configuration is invalid."""
