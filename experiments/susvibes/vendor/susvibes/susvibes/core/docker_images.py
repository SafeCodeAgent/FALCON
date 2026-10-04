"""Helpers for restricting benchmark runs to Docker images already on the host."""

from __future__ import annotations

import subprocess
from collections.abc import Iterable


def _normalize_image_name(name: str) -> str:
    """Add Docker's implicit ``latest`` tag when a reference has no tag."""
    name = name.strip()
    if not name or "@" in name:
        return name
    last_component = name.rsplit("/", 1)[-1]
    return name if ":" in last_component else f"{name}:latest"


def get_local_docker_images() -> set[str]:
    """Return locally available tagged Docker image references without pulling."""
    try:
        result = subprocess.run(
            ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Docker is not installed or is not on PATH.") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        raise RuntimeError(f"Cannot list local Docker images: {detail}") from error

    return {
        _normalize_image_name(line)
        for line in result.stdout.splitlines()
        if line.strip() and not line.endswith(":<none>")
    }


def filter_records_by_local_images(
    records: Iterable[dict],
    *,
    image_field: str = "image_name",
) -> tuple[list[dict], list[dict]]:
    """Split dataset records into locally runnable and missing-image records."""
    local_images = get_local_docker_images()
    runnable, missing = [], []
    for record in records:
        image_name = record.get(image_field, "")
        target = runnable if _normalize_image_name(image_name) in local_images else missing
        target.append(record)
    return runnable, missing


def print_local_image_summary(runnable: list[dict], missing: list[dict]) -> None:
    print(
        f"Local Docker image filter: running {len(runnable)} instance(s), "
        f"skipping {len(missing)} instance(s) whose images are not pulled."
    )
    if missing:
        preview = ", ".join(record.get("instance_id", "unknown") for record in missing[:5])
        suffix = " ..." if len(missing) > 5 else ""
        print(f"Skipped: {preview}{suffix}")
