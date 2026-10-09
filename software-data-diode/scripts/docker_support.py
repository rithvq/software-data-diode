"""Locate Docker Desktop for per-user and system-wide Windows installs."""
import os
from pathlib import Path
import shutil


def docker_executable():
    executable = shutil.which("docker")
    if executable:
        return executable
    for base, suffix in ((os.getenv("LOCALAPPDATA", ""), "Programs/DockerDesktop/resources/bin/docker.exe"),
                         (os.getenv("ProgramFiles", ""), "Docker/Docker/resources/bin/docker.exe")):
        candidate = Path(base) / suffix
        try:
            if base and candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    raise RuntimeError("Docker CLI was not found. Install or open Docker Desktop and check PATH.")
