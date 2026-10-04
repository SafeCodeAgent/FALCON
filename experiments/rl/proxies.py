from __future__ import annotations

import math
import os

import httpx

from real_detector import run_all_detectors


def real_reward(code: str) -> float:
    findings = run_all_detectors(code)
    return max(0.0, 1.0 - 0.3 * len(findings))


def seccodeprm_reward(code: str) -> float:
    endpoint = os.environ.get("SECCODEPRM_ENDPOINT")
    if not endpoint:
        raise ValueError("SECCODEPRM_ENDPOINT is required for this reward setting")
    response = httpx.post(endpoint, json={"code": code}, timeout=60)
    response.raise_for_status()
    value = float(response.json()["final_reward"])
    if not math.isfinite(value) or not -1 <= value <= 1:
        raise ValueError("SecCodePRM returned an invalid reward")
    return value
