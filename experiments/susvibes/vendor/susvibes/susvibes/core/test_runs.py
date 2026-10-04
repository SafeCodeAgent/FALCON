from __future__ import annotations

import re


PYTEST_COLLECTION_ABORT_RE = re.compile(
    r"\berrors? during collection\b",
    re.IGNORECASE,
)

# Strong build/startup signatures only. Generic tracebacks, SyntaxError text, and
# non-zero `make` exits can occur inside a normally completed test suite, so they
# are deliberately excluded.
BUILD_ABORT_PATTERNS = (
    re.compile(r"^Error compiling Cython file:", re.MULTILINE),
    re.compile(r"Cython\.Compiler\.Errors\.CompileError"),
    re.compile(r"^error: command .+ failed with exit (?:code|status)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^ERROR: Failed building wheel for\b", re.MULTILINE),
)


def pytest_collection_aborted(test_logs: str) -> bool:
    return PYTEST_COLLECTION_ABORT_RE.search(test_logs or "") is not None


def test_run_startup_error(test_logs: str) -> bool:
    text = test_logs or ""
    return pytest_collection_aborted(text) or any(
        pattern.search(text) is not None for pattern in BUILD_ABORT_PATTERNS
    )
