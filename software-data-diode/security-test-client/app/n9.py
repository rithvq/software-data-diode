"""Bounded N9 adversary. Only this disposable project's pinned allowlist is used."""
import argparse
import asyncio
import base64
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
from uuid import uuid4

import httpx

from shared.coverage.contracts import load_contract
from shared.coverage.transport import load_framer
from shared.security import load_private_key
from shared.security.n9_cases import mutations, unchecked_parts, run_model_campaign
from shared.security.n9_support import TargetAllowlist, Result, scope_fixture, export_results


class Capture:
    """Filtered Ethernet PCAP: bounded to 8 MiB and this test Fog address."""
    def __init__(self, path, fog_ip):
        self.path, self.fog_ip = path, fog_ip
        self.stop = threading.Event()
        self.counts = {"forward_udp": 0, "reverse_udp": 0, "reverse_tcp": 0, "reverse_icmp": 0}
        self.error, self.bytes = None, 0

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.socket.settimeout(.2)
        except OSError as exc:
            self.error = type(exc).__name__+": "+str(exc)
            return
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            with self.path.open("xb") as handle:
                handle.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                while not self.stop.is_set() and self.bytes < 8*1024*1024:
                    try:
                        packet = self.socket.recv(65535)
                    except socket.timeout:
                        continue
                    if len(packet) < 42 or packet[12:14] != b"\x08\x00":
                        continue
                    src, dst = socket.inet_ntoa(packet[26:30]), socket.inet_ntoa(packet[30:34])
                    if self.fog_ip not in {src, dst}:
                        continue
                    protocol = packet[23]
                    header = 14+(packet[14]&15)*4
                    if protocol == 17 and len(packet) >= header+8:
                        sport, dport = struct.unpack("!HH", packet[header:header+4])
                        if dst == self.fog_ip and dport == 9002:
                            self.counts["forward_udp"] += 1
                        if src == self.fog_ip:
                            self.counts["reverse_udp"] += 1
                    elif src == self.fog_ip:
                        if protocol == 6: self.counts["reverse_tcp"] += 1
                        if protocol == 1: self.counts["reverse_icmp"] += 1
                    stamp = time.time()
                    seconds = int(stamp)
                    handle.write(struct.pack("<IIII", seconds, int((stamp-seconds)*1e6), len(packet), len(packet)))
                    handle.write(packet)
                    self.bytes += len(packet)+16
        except OSError as exc:
            self.error = str(exc)

    def close(self):
        self.stop.set()
        if hasattr(self, "thread"):
            self.thread.join(2)
            self.socket.close()
        return {**self.counts, "captured_bytes": self.bytes, "error": self.error,
            "capture_scope": "TEST_DIODE_NAMESPACE_IPV4_TO_FROM_PINNED_FOG_ONLY",
            "truncated": self.bytes >= 8*1024*1024}


def send_frames(allow, frames):
    endpoint = allow.endpoint("fog-receiver", 9002)
    # No recv(), ACK, retry-on-response or receiver status query exists here.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for frame in frames:
            sender.sendto(frame, endpoint)
            time.sleep(.015)


def inject(allow, framer, root, operation):
    manifest = []
    if operation == "replay":
        old = json.loads((root/"injections.json").read_bytes())
        for row in old:
            if row["scenario"] == "reordered-valid-parts":
                send_frames(allow, tuple(base64.b64decode(f) for f in row["frames"]))
        return []
    index = int(time.time()//10)-2
    if operation == "outage":
        fixtures = [("database-outage-evidence", scope_fixture(framer,"edge-device-05",(12,),index-15))]
        cases = []
    else:
        _, _, _, _, cases = mutations(framer,index-8)
        fixtures = [("reordered-valid-parts", scope_fixture(framer,"edge-device-02",(95,),index)),
            ("fork-original", scope_fixture(framer,"edge-device-04",(0,),index-1)),
            ("fork-variant", scope_fixture(framer,"edge-device-04",(6,),index-1)),
            ("later-independent-gap", scope_fixture(framer,"edge-device-03",(9000,),index-2,previous="a"*64)),
            ("expired-capsule", scope_fixture(framer,"edge-device-01",(45,),index-40))]
        # A genuinely untrusted key, not merely a mutated signature string.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from shared.security.n9_support import fixture_framer
        other = fixture_framer(framer.contract,Ed25519PrivateKey.generate(),framer.profile.ledger_epoch)
        _,_,body,parts = scope_fixture(other,"edge-device-02",(95,),index-7)
        cases.append(("wrong-key",body,parts))
    for name, body, frames in cases:
        start = time.time()
        send_frames(allow, frames)
        manifest.append({"scenario":name,"expected":"REJECTED","body_digest":hashlib.sha256(body).hexdigest(),
            "frame_digests":[hashlib.sha256(f).hexdigest() for f in frames],"sent_at":start})
    for name, fixture in fixtures:
        scope, _, body, frames = fixture
        start = time.time()
        send_frames(allow, tuple(reversed(frames))+(frames[0],) if name=="reordered-valid-parts" else frames)
        if name=="reordered-valid-parts": send_frames(allow, frames)
        manifest.append({"scenario":name,"expected":"EXPIRED" if name=="expired-capsule" else "COMMITTED",
            "artifact_digest":scope.digest,"scope_id":scope.body.capsule_id,"device_id":scope.body.device_id,
            "window_index":scope.body.window_index,"sent_at":start,
            "frame_digests":[hashlib.sha256(f).hexdigest() for f in frames],
            "frames":[base64.b64encode(f).decode() for f in frames] if name=="reordered-valid-parts" else []})
    if operation != "outage":
        _,_,encoded,_ = scope_fixture(framer,"edge-device-02",(95,),index-3)
        for i in range(40):
            parts = unchecked_parts(encoded,framer,hashlib.sha256(uuid4().bytes).hexdigest())
            send_frames(allow, parts[:1])
        manifest.append({"scenario":"partial-assembly-flood-expiry","expected":"BOUNDED_EXPIRED","sent_at":time.time()})
        time.sleep(6)
    target = root/("outage-injections.json" if operation=="outage" else "injections.json")
    with target.open("x",encoding="utf-8") as handle:
        json.dump(manifest,handle,indent=2)
    return manifest


async def flood(allow, framer, root, operation):
    rows = []
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        url = allow.gateway_url("/telemetry")
        for critical_only in (False,True):
            name = (operation+"-critical-only") if critical_only else (operation+"-low-then-critical")
            start = time.perf_counter()
            before = (await client.get(allow.gateway_url("/metrics/runtime"))).json()
            sem = asyncio.Semaphore(12)
            async def submit(i):
                critical = critical_only or i>=80
                device = "edge-device-02" if critical else "edge-device-01"
                seq = (10000 if operation=="no-receiver" else 1000)+(500 if critical_only else 0)+i
                stamp = datetime.now(timezone.utc)
                payload = {"device_id":device,"timestamp":stamp.isoformat(),"telemetry_type":"system" if critical else "environmental",
                    "temperature":25,"humidity":50,"status":"critical" if critical else "normal",
                    "cpu_usage":95 if critical else None,"attributes":{"n9_run":os.environ["N9_RUN_ID"],
                        "n9_scenario":name,"n9_sent_us":int(stamp.timestamp()*1e6),"n9_index":i,"padding":"x"*5000}}
                async with sem:
                    response = await client.post(url,json=payload,headers={"X-Coverage-Epoch":framer.profile.ledger_epoch,
                        "X-Coverage-Retry-Sequence":str(seq)})
                return {"status":response.status_code,"critical":critical,"index":i,"reply":response.json(),
                    "sent_us":int(stamp.timestamp()*1e6),"elapsed":(datetime.now(timezone.utc)-stamp).total_seconds()}
            # Routine pressure first, then protected traffic in the same bounded run.
            first = await asyncio.gather(*(submit(i) for i in range(80)))
            rest = await asyncio.gather(*(submit(i) for i in range(80,200)))
            replies = first+rest
            await asyncio.sleep(12)
            after = (await client.get(allow.gateway_url("/metrics/runtime"))).json()
            accepted = sum(r["status"]==200 for r in replies)
            refused = sum(r["status"] in {409,429,503} for r in replies)
            state = after["coverage_admission"]
            passed = accepted>0 and accepted+refused==len(replies) and state["outbox_items"]<=256 and state["outbox_bytes"]<=4194304
            rows.append(Result(name,"LIVE_FINITE_CAPACITY","BOUNDED_ACCEPT_OR_REFUSE",
                "BOUNDED_ACCEPT_OR_REFUSE" if passed else "FAILED_OR_UNEXPECTED_HTTP",passed,None,"DOCKER_FAILURE",
                latency_seconds=time.perf_counter()-start,queue_data={"offered":len(replies),"accepted":accepted,"refused":refused,
                    "retry_conflicts":sum(r["status"]==409 for r in replies),"busy_or_capacity_refusals":sum(r["status"]==429 for r in replies),
                    "before":before,"after":after,"replies":replies},
                reason="HTTP durable admission outcomes; local dispatch is not receipt. Observer measures Fog receipt separately."))
    target = root/(operation+"-traffic.json")
    with target.open("x",encoding="utf-8") as handle: json.dump([asdict(r) for r in rows],handle,indent=2)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation",choices=("campaign","replay","outage","no-receiver"),default="campaign")
    operation = parser.parse_args().operation
    root = Path("/reports")
    allow = TargetAllowlist(json.loads(Path(os.environ["N9_ALLOWLIST"]).read_bytes()))
    if allow.project != os.environ["N9_PROJECT_NAME"]:
        raise ValueError("allowlist belongs to another project")
    fog_ip = allow.targets["fog-receiver"]["address"] if operation=="no-receiver" else allow.endpoint("fog-receiver",9002)[0]
    capture = Capture(root/(operation+".pcap"),fog_ip)
    capture.start()
    if os.getuid()==0:
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    if os.getuid()!=10001 or os.getgid()!=10001: raise RuntimeError("test actor did not drop privileges")
    rows = []
    try:
        key = load_private_key("/state/n9-key/private.pem")
        framer = load_framer("/run/coverage/profile.json",key.public_key(),"/app/config/rule_coverage.json",
            os.environ["COVERAGE_TRANSPORT_CONFIG"])
        framer.private_key = key
        if operation == "campaign":
            with tempfile.TemporaryDirectory(prefix="n9-model-") as state:
                model = run_model_campaign(state,load_contract("/app/config/rule_coverage.json"),key,
                    "/app/config/rule_coverage.json")
            export_results(root/"model",model,{"seed":909,"trials":120,"scope":"PURE_AND_PROCESS_CRASH_TESTS",
                "python":sys.version,"uid":os.getuid(),"gid":os.getgid(),
                "dependencies":{name:version(name) for name in ("httpx","pydantic","cryptography","fastapi")}})
            if not all(r.passed for r in model): raise RuntimeError("model campaign failure")
        if operation in {"campaign","outage","replay"}: inject(allow,framer,root,operation)
        if operation in {"campaign","no-receiver"}: rows = asyncio.run(flood(allow,framer,root,operation))
    finally:
        with (root/(operation+"-capture.json")).open("x",encoding="utf-8") as handle:
            json.dump(capture.close(),handle,indent=2)
    if not all(r.passed for r in rows): raise RuntimeError("live admission failure")
    print("N9 "+operation+" completed; no Fog response used by sender")


if __name__ == "__main__":
    main()
