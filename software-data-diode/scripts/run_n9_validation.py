"""Disposable, allowlisted local Docker validation. No baseline Compose operations."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import threading
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from shared.security.n9_support import Result, export_results, test_project


PG_SNAPSHOT = """
import json,os,psycopg
from psycopg.rows import dict_row
queries={
 'capsules':'SELECT artifact_digest,scope_id,received_at_us,verification FROM coverage_capsules ORDER BY persisted_at LIMIT 1000',
 'scopes':'SELECT scope_id,device_id,window_index,quarantined FROM coverage_scopes ORDER BY window_index LIMIT 1000',
 'outcomes':'SELECT timestamp_us,reason_code,details FROM coverage_outcomes ORDER BY timestamp_us LIMIT 1000',
 'conflicts':'SELECT scope_id,first_digest,second_digest FROM coverage_conflicts LIMIT 1000',
 'verdicts':'SELECT rule_id,window_index,verdict,verification_status,reasons FROM coverage_rule_verdicts ORDER BY window_index LIMIT 2000',
 'latency':"SELECT priority,payload->'attributes'->>'n9_scenario' AS scenario,COUNT(*) AS received,MIN((EXTRACT(EPOCH FROM received_at)*1000000-(payload->'attributes'->>'n9_sent_us')::bigint)/1000000) AS min_seconds,AVG((EXTRACT(EPOCH FROM received_at)*1000000-(payload->'attributes'->>'n9_sent_us')::bigint)/1000000) AS mean_seconds,MAX((EXTRACT(EPOCH FROM received_at)*1000000-(payload->'attributes'->>'n9_sent_us')::bigint)/1000000) AS max_seconds FROM accepted_telemetry WHERE payload->'attributes'->>'n9_scenario' IS NOT NULL GROUP BY priority,scenario",
 'tables':"SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
}
with psycopg.connect(os.environ['DATABASE_URL'],connect_timeout=3,row_factory=dict_row) as db:
 db.execute('SET statement_timeout=5000')
 print(json.dumps({name:list(db.execute(q)) for name,q in queries.items()},default=str))
"""


class Campaign:
    def __init__(self, docker, run, output):
        self.docker, self.run, self.output = docker,run,output
        self.project = test_project("software-data-diode-n9-"+run,run)
        self.env = {**os.environ,"N9_RUN_ID":run,"N9_PROJECT_NAME":self.project,
            "N9_OUTPUT_DIR":str(output),"N9_DB_PASSWORD":secrets.token_hex(24)}
        self.command = [docker,"compose","-p",self.project,"-f","docker-compose.n9.yml"]

    def call(self, args, *, compose=True, timeout=120, check=True, log=None, input_text=None):
        result = subprocess.run((self.command if compose else [self.docker])+args,cwd=ROOT,env=self.env,
            text=True,encoding="utf-8",errors="replace",capture_output=True,timeout=timeout,input=input_text)
        if log:
            (self.output/log).write_text(result.stdout+result.stderr,encoding="utf-8")
        if check and result.returncode:
            raise RuntimeError("Docker command failed: "+" ".join(args[:5])+"\n"+(result.stdout+result.stderr)[-3500:])
        return result

    def ids(self, own=False):
        args=["ps","-aq"]
        if own: args += ["--filter","label=com.docker.compose.project="+self.project]
        return self.call(args,compose=False).stdout.split()

    def inspect(self, ids):
        return json.loads(self.call(["inspect",*ids],compose=False).stdout) if ids else []

    def guard(self):
        test_project(self.project,self.run)
        containers=self.inspect(self.ids(own=True))
        for c in containers:
            if c["Config"]["Labels"].get("com.docker.compose.project") != self.project:
                raise ValueError("foreign container in test cleanup")
            if c["HostConfig"].get("PortBindings"):
                raise ValueError("N9 must not publish host ports")
            for mount in c["Mounts"]:
                if mount["Type"]=="volume" and not mount["Name"].startswith(self.project+"_"):
                    raise ValueError("foreign state volume mounted")
            for name in c["NetworkSettings"]["Networks"]:
                if name=="none" and c["HostConfig"]["NetworkMode"]=="none": continue
                if not name.startswith(self.project+"_"):
                    raise ValueError("foreign network mounted")
        return containers

    def ready(self, services, timeout=100):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            rows=self.guard()
            state={c["Config"]["Labels"].get("com.docker.compose.service"):c["State"] for c in rows}
            if all(state.get(s,{}).get("Health",{}).get("Status")=="healthy" for s in services): return
            if any(state.get(s,{}).get("Status")=="exited" for s in services): break
            time.sleep(2)
        self.call(["logs","--tail","80"],log="startup-failure.log",check=False)
        raise RuntimeError("N9 services did not become locally healthy")

    def local_json(self, service, code):
        return json.loads(self.call(["exec","-T",service,"python","-c",code]).stdout)

    def runtime(self, service):
        route="/research/status" if service=="fog-receiver" else "/metrics/runtime"
        return self.local_json(service,"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000"+route+"',timeout=3).read().decode())")

    def snapshot(self, name):
        document={"timestamp":datetime.now(timezone.utc).isoformat(),"fog":self.runtime("fog-receiver"),
            "diode":self.runtime("data-diode"),"gateway":self.runtime("edge-gateway"),
            "database":self.local_json("fog-receiver",PG_SNAPSHOT)}
        (self.output/(name+".json")).write_text(json.dumps(document,indent=2),encoding="utf-8")
        return document

    def client(self, operation):
        stopped=threading.Event()
        def sample():
            with (self.output/(operation+"-resources.jsonl")).open("x",encoding="utf-8") as handle:
                for _ in range(90):
                    if stopped.wait(2): break
                    ids=self.ids(own=True)
                    if not ids: continue
                    result=self.call(["stats","--no-stream","--format","{{json .}}",*ids],compose=False,timeout=15,check=False)
                    if result.returncode==0:
                        handle.write(json.dumps({"timestamp":datetime.now(timezone.utc).isoformat(),"samples":
                            [json.loads(line) for line in result.stdout.splitlines()]})+"\n")
                        handle.flush()
        sampler=threading.Thread(target=sample,daemon=True)
        sampler.start()
        try:
            self.call(["run","--rm","--no-deps","security-test-client","python","-m","app.n9","--operation",operation],
                timeout=300,log=operation+"-client.log")
        finally:
            stopped.set()
            sampler.join(20)
            if sampler.is_alive(): raise RuntimeError("bounded Docker resource sampler did not finish")

    def repository_checks(self, phase):
        source=(ROOT/("scripts/verify_"+phase+"_"+("persistence" if phase=="n6" else "rules")+".py")).read_text(encoding="utf-8")
        migrations={p.name:p.read_text(encoding="utf-8") for p in sorted((ROOT/"database/migrations").glob("*.sql"))}
        bundle=base64.b64encode(json.dumps(migrations).encode()).decode()
        code="import sys; sys.argv=['check','--migration-bundle',"+repr(bundle)+"]; exec(compile("+repr(source)+",'n9-"+phase+"-repository','exec'))"
        document=json.loads(self.call(["exec","-T","fog-receiver","python","-"],input_text=code).stdout)
        (self.output/(phase+"-repository.json")).write_text(json.dumps(document,indent=2),encoding="utf-8")
        return document


def protected_files():
    paths=[ROOT/".env",*sorted((ROOT/"secrets").glob("*.pem"))]
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}


def baseline_identity(containers):
    return {c["Id"]:{"image":c["Image"],"started":c["State"]["StartedAt"],"status":c["State"]["Status"],
        "mounts":sorted(c["Mounts"],key=lambda m:m["Destination"]),
        "networks":sorted(c["NetworkSettings"]["Networks"])} for c in containers}


def allocate_test_subnets(campaign):
    """Opt-in fallback for exhausted defaults; never prune or edit daemon settings."""
    names=campaign.call(["network","ls","-q"],compose=False).stdout.split()
    occupied=[]
    if names:
        for network in json.loads(campaign.call(["network","inspect",*names],compose=False).stdout):
            occupied.extend(ipaddress.ip_network(c["Subnet"]) for c in (network["IPAM"].get("Config") or []) if c.get("Subnet") and ":" not in c["Subnet"])
    if os.name=="nt":
        command=["powershell","-NoProfile","-Command","ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix)"]
        result=subprocess.run(command,text=True,encoding="utf-8",capture_output=True,check=True,timeout=20)
        routes=json.loads(result.stdout)
    else:
        result=subprocess.run(["ip","-j","-4","route","show","table","all"],text=True,capture_output=True,check=True,timeout=10)
        routes=[r["dst"] for r in json.loads(result.stdout) if r.get("dst")!="default"]
    occupied.extend(ipaddress.ip_network(r,strict=False) for r in routes if r!="0.0.0.0/0")
    pool=ipaddress.ip_network("10.0.0.0/8")
    chosen=next((n for n in pool.subnets(new_prefix=24) if not any(n.overlaps(other) for other in occupied)),None)
    if chosen is None: raise RuntimeError("no nonoverlapping local test subnet found")
    subnets=list(chosen.subnets(new_prefix=28))[:4]
    keys=("edge-network","diode-network","fog-ingress-network","fog-services-network")
    override={"networks":{key:{"ipam":{"config":[{"subnet":str(subnet)}]}} for key,subnet in zip(keys,subnets)}}
    path=campaign.output/"allocated-networks.yml"
    path.write_text(json.dumps(override,indent=2),encoding="utf-8")
    campaign.command += ["-f",str(path)]
    (campaign.output/"network-allocation.json").write_text(json.dumps({"chosen":str(chosen),"inspected_prefixes":[str(n) for n in occupied],
        "policy":"ephemeral internal /28 networks; observed Docker and host routes excluded; no daemon change"},indent=2),encoding="utf-8")


def cached_test_images(campaign, source):
    import re
    match=re.fullmatch(r"software-data-diode-n9-([a-f0-9]{12})",source)
    if not match: raise ValueError("cached image source must be an earlier isolated N9 project")
    test_project(source,match[1])
    model=json.loads(campaign.call(["config","--format","json"]).stdout)
    override={"services":{}}
    for service,definition in model["services"].items():
        if not definition.get("build"): continue
        image=json.loads(campaign.call(["image","inspect",source+"-"+service],compose=False).stdout)[0]
        volumes=[str(ROOT/"shared")+":/app/shared:ro"]
        if service=="security-test-client": volumes.append(str(ROOT/"security-test-client/app")+":/app/app:ro")
        override["services"][service]={"image":image["Id"],"volumes":volumes}
    path=campaign.output/"cached-images.yml"
    path.write_text(json.dumps(override,indent=2),encoding="utf-8")
    campaign.command += ["-f",str(path)]
    return {service:definition["image"] for service,definition in override["services"].items()}


def live_outcomes(output, final):
    results=[]
    db,fog=final["database"],final["fog"]
    for row in json.loads((output/"injections.json").read_bytes()):
        name=row["scenario"]
        matches=[o for o in db["outcomes"] if o["details"].get("input_digest") in row.get("frame_digests",[])]
        capsule=[c for c in db["capsules"] if c["artifact_digest"]==row.get("artifact_digest")]
        latency=None
        if matches: latency=max(0,min(o["timestamp_us"] for o in matches)/1e6-row["sent_at"])
        if row["expected"] in {"REJECTED","EXPIRED"}:
            actual=";".join(sorted({o["reason_code"] for o in matches})) or "NOT_RECORDED"
            passed=bool(matches)
            if name=="oversized-datagram":
                passed=fog.get("size_or_source_drops",0)>0
                actual="SIZE_OR_SOURCE_DROP" if passed else "NOT_OBSERVED"
            results.append(Result("docker-"+name,"LIVE_ARTIFACT_ATTACK",row["expected"],actual,passed,passed,"IN_SCOPE_ATTACK",
                latency_seconds=latency,reason="Observer matches submitted frame digests to durable Fog outcomes; not sender feedback"))
        elif name.startswith("fork-"):
            quarantined=any(s["scope_id"]==row["scope_id"] and s["quarantined"] for s in db["scopes"])
            passed=bool(capsule) and quarantined
            results.append(Result("docker-"+name,"SIGNED_SCOPE_FORK","QUARANTINED","QUARANTINED" if passed else "NOT_QUARANTINED",
                passed,passed,"IN_SCOPE_ATTACK",reason="Both valid signed bodies retained, unusable as definite coverage"))
        elif name=="partial-assembly-flood-expiry":
            reasons={o["reason_code"] for o in db["outcomes"]}
            passed="PARTIAL_ARTIFACT_CAPACITY" in reasons and "REASSEMBLY_EXPIRED" in reasons and fog["partial_artifacts"]==0
            results.append(Result("docker-partial-assemblies","BOUNDED_REASSEMBLY","CAPACITY_AND_EXPIRY",
                "CAPACITY_AND_EXPIRY" if passed else "NOT_OBSERVED",passed,None,"DOCKER_FAILURE",queue_data={
                    "partial_artifacts":fog["partial_artifacts"],"partial_bytes":fog["partial_bytes"],
                    "expired":fog["expired_partial_artifacts"]}))
        else:
            passed=len(capsule)==1
            if name=="later-independent-gap": passed=passed and capsule[0]["verification"]["continuity_status"]=="GAP"
            if name=="reordered-valid-parts": passed=passed and fog.get("duplicate_artifacts",0)>0
            results.append(Result("docker-"+name,"VALID_OR_REORDERED_EVIDENCE","ONE_DURABLE_CAPSULE",
                "ONE_DURABLE_CAPSULE" if passed else "NOT_COMMITTED",passed,None,"DOCKER_CORRECTNESS"))
    return results


def run(args):
    docker=args.docker or shutil.which("docker")
    if not docker:
        candidate=Path.home()/"AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"
        if candidate.exists(): docker=str(candidate)
    if not docker: raise RuntimeError("Docker CLI unavailable; no deployment created")
    run_id=secrets.token_hex(6)
    output=ROOT/"docs/novelty-roadmap/evidence/N9"/run_id
    output.mkdir(parents=True,exist_ok=False)
    campaign=Campaign(docker,run_id,output)
    start=datetime.now(timezone.utc).isoformat()
    before=baseline_identity(campaign.inspect(campaign.ids()))
    original_files=protected_files()
    rows=[]
    metadata={"project":campaign.project,"run_id":run_id,"seed":909,"started_at":start,
        "software_version":subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True).stdout.strip(),
        "source_sha256":{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
            [ROOT/"docker-compose.n9.yml",*sorted((ROOT/"shared/security").glob("n9*.py")),ROOT/"security-test-client/app/n9.py",Path(__file__),
             *sorted((ROOT/"config").glob("rule_coverage*.json"))]},
        "baseline_container_count":len(before),"application_feedback_used":False,
        "synthetic_attack_injection_bytes":"NOT_N4_SCHEDULED_WORK; separately recorded in PCAP"}
    created=False
    try:
        if campaign.ids(own=True): raise ValueError("N9 project already exists")
        if args.allocate_test_subnets: allocate_test_subnets(campaign)
        if args.cached_images_from: metadata["cached_images"]=cached_test_images(campaign,args.cached_images_from)
        config=json.loads(campaign.call(["config","--format","json"]).stdout)
        if any(s.get("ports") for s in config["services"].values()): raise ValueError("host port publication forbidden")
        if not all(n.get("internal") for n in config["networks"].values()): raise ValueError("non-isolated N9 network")
        created=True
        if not args.cached_images_from: campaign.call(["build"],timeout=600,log="build.log")
        services=[s for s in config["services"] if s!="security-test-client"]
        campaign.call(["up","-d","--no-build","--pull","never",*services],timeout=180,log="startup.log")
        campaign.ready(["edge-gateway","data-diode","fog-receiver","event-processor","fog-analytics","alert-engine","postgres"])
        containers=campaign.guard()
        by_service={c["Config"]["Labels"]["com.docker.compose.service"]:c for c in containers}
        networks={name:json.loads(campaign.call(["network","inspect",model["name"]],compose=False).stdout)[0]
            for name,model in config["networks"].items()}
        # Compose model keys need resolving to their actual project-scoped names.
        allow={"project":campaign.project,"run_id":run_id,"targets":{
            "edge-gateway":{"address":by_service["edge-gateway"]["NetworkSettings"]["Networks"][campaign.project+"_diode-network"]["IPAddress"],"ports":[8000]},
            "fog-receiver":{"address":by_service["fog-receiver"]["NetworkSettings"]["Networks"][campaign.project+"_fog-ingress-network"]["IPAddress"],"ports":[9002]}}}
        (output/"allowlist.json").write_text(json.dumps(allow,indent=2),encoding="utf-8")
        (output/"networks.json").write_text(json.dumps(networks,indent=2),encoding="utf-8")
        reverse=campaign.local_json("fog-receiver",REVERSE_PROBE)
        known={s:list(c["NetworkSettings"]["Networks"].values()) for s,c in by_service.items() if s.startswith("edge-")}
        addresses={s:[n["IPAddress"] for n in nets] for s,nets in known.items()}
        reverse += campaign.local_json("fog-receiver",REVERSE_IP_PROBE+"\nprobe("+repr(addresses)+")")
        memberships=not(set(by_service["fog-receiver"]["NetworkSettings"]["Networks"]) & set(by_service["edge-device-01"]["NetworkSettings"]["Networks"]))
        rows.append(Result("docker-reverse-path","APPLICATION_ISOLATION","ALL_EDGE_PROBES_FAIL",
            "ALL_EDGE_PROBES_FAIL" if all(r["failed"] for r in reverse) else "UNEXPECTED_ACCESS",memberships and all(r["failed"] for r in reverse),
            None,"DOCKER_ISOLATION",queue_data={"probes":reverse,"no_shared_edge_network":memberships}))
        campaign.snapshot("initial")
        for phase in ("n6","n7"):
            document=campaign.repository_checks(phase)
            rows.append(Result("docker-"+phase+"-transactions","POSTGRES_MIGRATIONS_FAILURE_RECOVERY","ALL_REPOSITORY_CHECKS_PASS",
                "ALL_REPOSITORY_CHECKS_PASS",True,None,"DOCKER_CORRECTNESS",queue_data=document))
        campaign.client("campaign")
        time.sleep(8)
        after=campaign.snapshot("after-campaign")
        rows.extend(Result(**r) for r in json.loads((output/"model/results.json").read_bytes())["results"])
        metadata["test_runtime"]=json.loads((output/"model/results.json").read_bytes())["metadata"]
        rows.extend(Result(**r) for r in json.loads((output/"campaign-traffic.json").read_bytes()))
        rows.extend(live_outcomes(output,after))
        stats=campaign.call(["stats","--no-stream","--format","{{json .}}",*campaign.ids(own=True)],compose=False).stdout
        (output/"docker-stats.jsonl").write_text(stats,encoding="utf-8")
        rows.append(Result("docker-resources","RESOURCE_MEASUREMENT","CONTAINER_STATS","CONTAINER_STATS",bool(stats.strip()),None,
            "DOCKER_MEASUREMENT",resource_data={"end_samples":[json.loads(line) for line in stats.splitlines()],
                "time_series_file":"campaign-resources.jsonl","bounded_samples":90},
            reason="Docker CPU/memory time series sampled during model, injections and live floods; bounded discrete samples, not continuous peak proof"))
        # Restart only this project's receiver; immutable retransmission must remain idempotent.
        campaign.call(["restart","fog-receiver"])
        campaign.ready(["fog-receiver"])
        campaign.client("replay")
        time.sleep(3)
        replay=campaign.snapshot("after-restart-replay")
        digest=next(r["artifact_digest"] for r in json.loads((output/"injections.json").read_bytes()) if r["scenario"]=="reordered-valid-parts")
        good=sum(c["artifact_digest"]==digest for c in replay["database"]["capsules"])==1 and replay["fog"].get("duplicate_artifacts",0)>0
        rows.append(Result("docker-replay-after-restart","DURABLE_REPLAY","IDEMPOTENT","IDEMPOTENT" if good else "FAILED",good,good,"IN_SCOPE_ATTACK"))
        campaign.call(["stop","-t","15","postgres"])
        campaign.client("outage")
        pending=campaign.runtime("fog-receiver")
        campaign.call(["start","postgres"])
        campaign.ready(["postgres"])
        time.sleep(8)
        recovered=campaign.snapshot("database-recovered")
        digest=json.loads((output/"outage-injections.json").read_bytes())[0]["artifact_digest"]
        good=pending["pending_evidence"]>0 and any(c["artifact_digest"]==digest for c in recovered["database"]["capsules"])
        rows.append(Result("docker-database-outage","DURABLE_SPOOL","PENDING_THEN_COMMITTED",
            "PENDING_THEN_COMMITTED" if good else "FAILED",good,None,"DOCKER_FAILURE",queue_data={"during_outage":pending,"after":recovered["fog"]}))
        sender_before=campaign.runtime("edge-gateway")
        campaign.call(["stop","-t","15","fog-receiver"])
        campaign.client("no-receiver")
        sender_after=campaign.runtime("edge-gateway")
        before_attempts=sender_before["coverage_udp"]["sender"].get("attempts",0)
        after_attempts=sender_after["coverage_udp"]["sender"].get("attempts",0)
        good=sender_after["coverage_udp"]["live"] and after_attempts>before_attempts
        rows.extend(Result(**r) for r in json.loads((output/"no-receiver-traffic.json").read_bytes()))
        rows.append(Result("docker-no-receiver-feedback","RECEIVER_UNAVAILABLE","SENDER_CONTINUES_LOCAL_ATTEMPTS",
            "SENDER_CONTINUES_LOCAL_ATTEMPTS" if good else "BLOCKED",good,None,"DOCKER_ISOLATION",queue_data={"before_attempts":before_attempts,"after_attempts":after_attempts},
            reason="Local attempted dispatch continues with stopped Fog; no receipt/delivery guarantee"))
        campaign.call(["start","fog-receiver"])
        campaign.ready(["fog-receiver"])
        final=campaign.snapshot("final")
        capture=json.loads((output/"campaign-capture.json").read_bytes())
        good=capture["error"] is None and capture["forward_udp"]>0 and capture["reverse_udp"]==capture["reverse_tcp"]==0
        rows.append(Result("docker-cross-boundary-packets","OBSERVED_DIRECTION","FORWARD_WITHOUT_APPLICATION_REPLIES",
            "FORWARD_WITHOUT_APPLICATION_REPLIES" if good else "FAILED_OR_CAPTURE_UNAVAILABLE",good,None,"DOCKER_ISOLATION",queue_data=capture,
            reason="Tested application behavior only. UDP/network/privileged host is not a physical diode; ICMP separately recorded."))
        latencies=final["database"]["latency"]
        good=any(x["priority"]=="CRITICAL" and x["scenario"].startswith("campaign-") for x in latencies)
        rows.append(Result("docker-critical-receipt-latency","RECEIPT_MEASUREMENT","CRITICAL_FOG_RECEIPTS",
            "CRITICAL_FOG_RECEIPTS" if good else "NO_RECEIPTS",good,None,"DOCKER_MEASUREMENT",queue_data={"measurements":latencies},
            reason="Client timestamp to persisted Fog receipt, seconds; refused/locally dropped inputs are excluded, not zero-latency receipts"))
        campaign.call(["logs","--tail","100"],log="final-services.log",check=False)
    except Exception as exc:
        (output/"failure-traceback.txt").write_text(traceback.format_exc(),encoding="utf-8")
        rows.append(Result("campaign-execution","HARNESS_OR_RUNTIME","COMPLETED",str(exc),False,None,"CHECK_FAILURE"))
        if created: campaign.call(["logs","--tail","80"],log="failure-services.log",check=False)
    finally:
        if created:
            try:
                campaign.guard()
                campaign.call(["down","--volumes","--remove-orphans","--timeout","15"],timeout=120,log="cleanup.log")
            except Exception as exc:
                rows.append(Result("test-cleanup","CLEANUP_GUARD","SCOPED_CLEANUP",str(exc),False,None,"CHECK_FAILURE",
                    reason="Cleanup refused or failed; no unvalidated fallback deletion attempted"))
        now=baseline_identity(campaign.inspect(list(before)))
        preserved=now==before and protected_files()==original_files
        metadata["baseline_changed_ids"]=[identity for identity in before if now.get(identity)!=before[identity]]
        rows.append(Result("baseline-preservation","STATE_PRESERVATION","UNCHANGED","UNCHANGED" if preserved else "CHANGED",preserved,None,"PRESERVATION",
            reason="Original container IDs/images/start states/mounts/network memberships and credentials/key bytes compared; no secret bytes exported"))
        metadata.update(ended_at=datetime.now(timezone.utc).isoformat(),baseline_preserved=preserved,
            test_containers_remaining=len(campaign.ids(own=True)))
        export_results(output,rows,metadata)
        print(str(output))
        print(f"N9: {sum(r.passed for r in rows)}/{len(rows)} scenarios passed")
    return 0 if all(r.passed for r in rows) else 1


REVERSE_PROBE="""
import json,socket
rows=[]
for name in ['edge-gateway',*[f'edge-device-{i:02d}' for i in range(1,6)]]:
 try: socket.gethostbyname(name); failed=False
 except OSError: failed=True
 rows.append({'service':name,'kind':'DNS','failed':failed})
 for port in (8000,9001):
  try:
   with socket.create_connection((name,port),timeout=.5): pass
   failed=False
  except OSError: failed=True
  rows.append({'service':name,'port':port,'kind':'TCP','failed':failed})
print(json.dumps(rows))
"""

REVERSE_IP_PROBE="""
import json,socket
def probe(addresses):
 rows=[]
 for service,ips in addresses.items():
  for ip in ips:
   try:
    with socket.create_connection((ip,8000),timeout=.5): pass
    failed=False
   except OSError: failed=True
   rows.append({'service':service,'address':ip,'port':8000,'kind':'KNOWN_IP_TCP','failed':failed})
 print(json.dumps(rows))
"""


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--docker",help="Local Docker executable path")
    parser.add_argument("--cached-images-from",help="Explicit earlier isolated N9 image project for offline use; current shared/test source mounted read-only")
    parser.add_argument("--allocate-test-subnets",action="store_true",help="Opt-in inspected nonoverlapping /28 subnets when Docker default pools are exhausted")
    raise SystemExit(run(parser.parse_args()))
