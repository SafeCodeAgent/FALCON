"""Loaded only by the `swe-agent` CLI launcher, before SWE-agent imports."""
import os
from pathlib import Path

if os.environ.get("AV_SWE_DATASET"):
    from av_susvibes.swe_gate import install
    install(Path(os.environ["AV_SWE_DATASET"]), os.environ["AV_SWE_MODEL"],
            Path(os.environ["AV_SWE_OUTPUT"]),
            max_rounds=int(os.environ.get("AV_SWE_ROUNDS", "5")))
