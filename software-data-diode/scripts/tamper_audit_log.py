from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.security import verify_audit_log


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tamper with a copy of a JSONL audit log and verify its hash chain."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.source, args.output)
    lines = args.output.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        record = json.loads(line)
        record["result"] = "TAMPERED_BY_CONTROLLED_TEST"
        lines[index] = json.dumps(record, sort_keys=True)
        break
    else:
        raise SystemExit("audit log contains no records")

    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    valid, reason = verify_audit_log(args.output)
    print(f"valid={str(valid).lower()} {reason}")
    return 1 if valid else 0


if __name__ == "__main__":
    raise SystemExit(main())
