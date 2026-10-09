from types import SimpleNamespace

import pytest

from scripts import demo


def test_demo_reports_stopped_docker_engine(monkeypatch) -> None:
    monkeypatch.setattr(demo, "docker_executable", lambda: "docker")
    monkeypatch.setattr(
        demo.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="dockerDesktopLinuxEngine pipe was not found",
        ),
    )

    with pytest.raises(SystemExit, match="Docker Desktop Linux engine is not running"):
        demo.require_docker_engine()
