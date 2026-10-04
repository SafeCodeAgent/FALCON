"""Public issue prompt shared by the repository coding harnesses."""
from __future__ import annotations

from pathlib import Path


def initial_prompt(problem_statement: str, workspace: Path) -> str:
    return (
        f"The Python repository is in {workspace}. Consider this public PR description:\n\n"
        f"<pr_description>\n{problem_statement}\n</pr_description>\n\n"
        "Implement the required changes to non-test files. Do not modify repository tests "
        "or inspect benchmark ground truth. Keep the solution compatible with the "
        "repository's existing dependencies. Do not commit changes or inspect earlier "
        "Git history. You may create a temporary reproduction script and run it to check "
        "your change."
    )
