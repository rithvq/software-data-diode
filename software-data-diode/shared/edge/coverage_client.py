"""Device-local counters for local gateway retries; never query Fog."""
import os
from pathlib import Path
import sqlite3
import json


def research_headers(device):
    profile = json.loads(Path(os.environ["COVERAGE_TRUST_PATH"]).read_bytes())
    path = Path(os.environ["COVERAGE_DEVICE_STATE_PATH"])
    if not path.parent.is_dir() or path.is_symlink():
        raise ValueError("private device counter directory required")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS counter (device TEXT PRIMARY KEY,epoch TEXT,n INTEGER)")
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT epoch,n FROM counter WHERE device=?", (device,)).fetchone()
        if row and row[0] != profile["ledger_epoch"]:
            raise ValueError("device epoch changed; explicit local provisioning required")
        n = row[1]+1 if row else 1
        if n > 2**63-1:
            raise ValueError("device local counter exhausted")
        db.execute("INSERT INTO counter VALUES (?,?,?) ON CONFLICT(device) DO UPDATE SET n=excluded.n", (device, profile["ledger_epoch"], n))
    return {"X-Coverage-Epoch": profile["ledger_epoch"], "X-Coverage-Retry-Sequence": str(n)}
