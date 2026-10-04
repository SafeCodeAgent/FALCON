"""Resolve a pinned OpenCode 1.18.16 standalone binary for task containers."""
from __future__ import annotations

import fcntl
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path


VERSION = "1.18.16"


def _compatible(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        with path.open("rb") as binary:
            if binary.read(4) != b"\x7fELF":
                return False
        result = subprocess.run([str(path), "--version"], capture_output=True,
                                text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and bool(re.search(r"(?<!\d)1\.18\.16(?!\d)", result.stdout + result.stderr))


def _target(musl: bool) -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "x64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"No OpenCode Linux binary for architecture {machine}")
    target = f"linux-{arch}"
    if arch == "x64":
        try:
            cpu = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        except OSError:
            cpu = ""
        if "avx2" not in cpu.lower().split():
            target += "-baseline"
    return target + ("-musl" if musl else "")


def ensure_binary(*, musl: bool = False) -> Path:
    explicit = os.getenv("AV_OPENCODE_BINARY")
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not _compatible(candidate):
            raise RuntimeError(f"AV_OPENCODE_BINARY is not a standalone OpenCode {VERSION} binary")
        return candidate
    installed = shutil.which("opencode")
    if installed and _compatible(Path(installed)):
        return Path(installed).resolve()
    target = _target(musl)
    destination = Path.home() / ".cache" / "attacker-verifier" / "opencode" / VERSION / target / "opencode"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.with_suffix(".lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if _compatible(destination):
            return destination
        url = ("https://github.com/anomalyco/opencode/releases/download/"
               f"v{VERSION}/opencode-{target}.tar.gz")
        with tempfile.TemporaryDirectory(prefix="av-opencode-") as tmp:
            archive = Path(tmp) / "release.tar.gz"
            urllib.request.urlretrieve(url, archive)
            with tarfile.open(archive, "r:gz") as bundle:
                members = [member for member in bundle.getmembers()
                           if member.isfile() and Path(member.name).name == "opencode"]
                if len(members) != 1:
                    raise RuntimeError("OpenCode release archive has an unexpected layout")
                source = bundle.extractfile(members[0])
                if source is None:
                    raise RuntimeError("OpenCode release archive contains no binary")
                staged = destination.with_name(f".opencode-{os.getpid()}.tmp")
                try:
                    with staged.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    staged.chmod(0o755)
                    os.replace(staged, destination)
                finally:
                    staged.unlink(missing_ok=True)
        if not _compatible(destination):
            raise RuntimeError(f"Downloaded OpenCode binary did not report version {VERSION}")
        return destination
