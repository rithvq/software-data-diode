import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.security.audit import verify_audit_log


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a Phase 2 audit log hash chain.")
    parser.add_argument("path", help="Path to a JSONL audit log")
    args = parser.parse_args()

    valid, message = verify_audit_log(args.path)
    print(message)
    raise SystemExit(0 if valid else 1)


if __name__ == "__main__":
    main()
