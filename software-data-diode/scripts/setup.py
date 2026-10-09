from __future__ import annotations

import os
from pathlib import Path
import secrets
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.generate_keys import main as generate_keys


REPLACEMENTS = {
    "POSTGRES_PASSWORD=replace-with-a-random-password": (
        "POSTGRES_PASSWORD=" + secrets.token_urlsafe(24)
    ),
    "OBSERVABILITY_TOKEN=replace-with-a-random-internal-token": (
        "OBSERVABILITY_TOKEN=" + secrets.token_urlsafe(32)
    ),
    "GRAFANA_ADMIN_PASSWORD=replace-this-password": (
        "GRAFANA_ADMIN_PASSWORD=" + secrets.token_urlsafe(24)
    ),
}


def main() -> int:
    os.chdir(PROJECT_ROOT)
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        content = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
        for placeholder, generated in REPLACEMENTS.items():
            content = content.replace(placeholder, generated)
        env_path.write_text(content, encoding="utf-8")
        print("Created .env with random local credentials")
    else:
        print("Kept existing .env")

    generate_keys(PROJECT_ROOT / "secrets")

    for directory in ("logs", "security-reports"):
        (PROJECT_ROOT / directory).mkdir(parents=True, exist_ok=True)
    print("Runtime directories are ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
