"""Atomic per-task and batch checkpoints for resumable SusVibes inference."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staged = tempfile.mkstemp(prefix=".av-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, ensure_ascii=False, default=str)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(staged, path)
    finally:
        Path(staged).unlink(missing_ok=True)
