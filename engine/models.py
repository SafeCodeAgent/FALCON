"""Read Claude Code's live model catalog.

Claude Code keeps the model list it offers (the same list its ``/model`` picker
shows) in a local cache under ``<config>/cache/model-catalog/``. Reading it here
means the attacker/verifier model choices always reflect the current models,
with no list hardcoded in this plugin: when Claude Code updates its models, this
function returns the new list automatically.

The Fable family is excluded from everything this module returns.
"""

from __future__ import annotations

import glob
import json
import os
from typing import Any, Dict, List, Optional

_FAMILIES = ("opus", "sonnet", "haiku")


def _config_dir() -> str:
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~"), ".claude")


def _catalog_file() -> Optional[str]:
    pattern = os.path.join(_config_dir(), "cache", "model-catalog", "*.json")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def _is_fable(model: Dict[str, Any]) -> bool:
    blob = (str(model.get("id", "")) + " " + str(model.get("name", ""))).lower()
    return "fable" in blob


def list_models() -> List[Dict[str, Any]]:
    """Return the live, non-Fable models as ``{id, name, quick_select, section}``.

    Returns an empty list if the catalog cannot be read; callers then fall back
    to the family aliases ``opus``/``sonnet``/``haiku``, which Claude Code always
    resolves to the latest model of each family.
    """
    path = _catalog_file()
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            catalog = json.load(handle)
        models = catalog["catalog"]["config"]["models"]
    except (OSError, ValueError, KeyError, TypeError):
        return []

    out: List[Dict[str, Any]] = []
    for model in models:
        if not isinstance(model, dict) or _is_fable(model):
            continue
        out.append(
            {
                "id": model.get("id"),
                "name": model.get("name"),
                "quick_select": bool(model.get("quick_select")),
                "section": model.get("section"),
            }
        )
    return out


def resolve(token: str) -> Optional[str]:
    """Resolve a user-facing model token to what the Agent tool's ``model`` takes.

    Accepts ``main coding agent`` (returns ``main``), a catalog name such as
    ``Opus 5.5``, a model id, or a family alias (``opus``/``sonnet``/``haiku``,
    resolved to the latest model of that family). Fable is never resolved.
    Returns the alias unchanged when the catalog is unavailable, so delegation
    still works offline. Returns ``None`` for an unknown or Fable token.
    """
    if not token:
        return None
    norm = token.strip().lower()
    if norm in ("main", "main coding agent", "inline"):
        return "main"
    if "fable" in norm:
        return None

    models = list_models()

    # Exact id match.
    for model in models:
        if norm == str(model.get("id", "")).lower():
            return model["id"]
    # Exact name match, ignoring spacing/case.
    squished = norm.replace(" ", "")
    for model in models:
        if squished == str(model.get("name", "")).lower().replace(" ", ""):
            return model["id"]
    # Family alias -> latest model of that family (quick_select first).
    if norm in _FAMILIES:
        family = [m for m in models if str(m.get("name", "")).lower().startswith(norm)]
        quick = [m for m in family if m.get("quick_select")]
        if quick:
            return quick[0]["id"]
        if family:
            return family[0]["id"]
        return norm  # no catalog: Agent tool accepts the bare alias
    return None
