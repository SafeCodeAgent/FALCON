"""Prompt composition for fresh Claude Code repair sessions."""
from __future__ import annotations

from evaluation_harness.prompts import initial_prompt


def repair_prompt(original: str, security_feedback: str) -> str:
    """Claude starts a new session, so every repair prompt repeats the public task."""
    return original + "\n\n<security_feedback>\n" + security_feedback + "\n</security_feedback>"
