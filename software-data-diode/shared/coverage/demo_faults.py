"""Opt-in fixed N11 forward-link faults, never sender policy inputs."""
import hashlib
import json
import time
from collections import Counter
from pathlib import Path

from shared.edge.demo import require_demo
from shared.security.crypto import canonical_bytes


class DemoForwardFaults:
    def __init__(self, path="/logs/n11-plan.json", clock=time.time):
        require_demo()
        self.path, self.clock = Path(path), clock
        self.counts = Counter()
        self.events = []

    def transform(self, frame):
        if not self.path.exists():
            return frame
        if self.path.stat().st_size > 1024:
            raise ValueError("demo plan bound")
        plan = json.loads(self.path.read_bytes())
        if set(plan) != {"start", "run_id"} or type(plan["start"]) is not int or plan["start"] % 10:
            raise ValueError("invalid demo fault plan")
        stage = int((self.clock()-plan["start"])//10)
        raw, evidence = frame[:4] == b"RCR1", frame.startswith(b"{")
        action = None
        # Window n's RCCs seal at n+1. Negative raw in stage 4 passes;
        # its evidence alone is dropped at stage 5, not stage 3's RCCs.
        if stage == 3 and raw:
            action = "RAW_DROP"
        elif stage == 5 and evidence:
            action = "EVIDENCE_DROP"
        elif stage == 6 and evidence:
            action = "EVIDENCE_TAMPER"
        if action:
            self.counts[action] += 1
            if len(self.events) < 512:
                self.events.append({"time": self.clock(), "action": action,
                    "input_sha256": hashlib.sha256(frame).hexdigest(), "bytes": len(frame)})
            if action.endswith("DROP"):
                return None
            document = json.loads(frame)
            signature = document.get("signature")
            if not isinstance(signature, str):
                raise ValueError("expected signed evidence part")
            document["signature"] = ("A" if signature[0] != "A" else "B")+signature[1:]
            return canonical_bytes(document)
        return frame
