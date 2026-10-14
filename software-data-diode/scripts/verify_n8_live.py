"""Read-only deployed N8 API, metrics and mount checks on the coverage project."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.docker_support import docker_executable


PROBE = r'''
import json,time,urllib.request,urllib.error
checks=[]
def check(name,condition):
    if not condition:raise AssertionError(name)
    checks.append({'check':name,'passed':True})
def get(path):
    return json.load(urllib.request.urlopen('http://127.0.0.1:8000'+path,timeout=5))
def status(path):
    try:return urllib.request.urlopen('http://127.0.0.1:8000'+path,timeout=5).status
    except urllib.error.HTTPError as exc:return exc.code
check('Monitoring API ready',get('/ready')['status']=='ready')
overview=get('/api/coverage/overview')
check('accepted-ingress scope explicit',overview['observation_scope']=='accepted_normalized_gateway_ingress')
check('assurance not full raw recomputation',overview['assurance']=='AUTHENTICATED_SUMMARY' and overview['offline_recomputation']=='NOT_RUN_BY_DASHBOARD')
counts=overview['counts']
check('historical latest verdict counts partition opportunities',counts['opportunities']==counts['positive']+counts['negative']+counts['unknown'])
page=get('/api/coverage/verdicts?limit=3')
check('bounded live page',len(page['items'])<=3)
check('invalid page size rejected',status('/api/coverage/verdicts?limit=101')==422)
check('unknown rule returns empty page',not get('/api/coverage/verdicts?rule_id=n8-not-registered')['items'])
if page['next_cursor']:
    c=page['next_cursor']
    next_page=get('/api/coverage/verdicts?limit=3&before_window='+str(c['before_window'])+'&before_id='+c['before_id'])
    check('live keyset has no duplicate identities',not {i['decision_id'] for i in page['items']}.intersection(i['decision_id'] for i in next_page['items']))
if page['items']:
    identity=page['items'][0]['decision_id']
    detail=get('/api/coverage/decisions/'+identity)
    check('exact decision and revision history',detail['decision']['decision_id']==identity and bool(detail['history']))
    check('missing evidence does not become safe',detail['decision']['verdict']!='FALSE' or 'coverage_health' in detail['decision']['result'])
check('invalid capsule digest rejected',status('/api/coverage/capsules/not-a-digest')==422)
check('unknown capsule returns 404',status('/api/coverage/capsules/'+'0'*64)==404)
metrics=urllib.request.urlopen('http://127.0.0.1:8000/metrics',timeout=5).read().decode()
for name in ('coverage_metrics_available 1.0','coverage_evidence_received_bytes','coverage_pending_obligations','coverage_verification_failures','coverage_rule_windows{truth="UNKNOWN"}'):
    check('live metric '+name,name in metrics)
prometheus=None
try:
    for attempt in range(12):
        targets=json.load(urllib.request.urlopen('http://prometheus-fog:9090/api/v1/targets',timeout=5))
        matching=[t for t in targets['data']['activeTargets'] if t['labels'].get('job')=='monitoring-api']
        if matching and all(t['health']=='up' for t in matching):break
        time.sleep(2)
    check('Fog Prometheus scrapes Monitoring API',bool(matching) and all(t['health']=='up' for t in matching))
    result=json.load(urllib.request.urlopen('http://prometheus-fog:9090/api/v1/query?query=coverage_metrics_available',timeout=5))
    check('Prometheus stores coverage samples',any(r['value'][1]=='1' for r in result['data']['result']))
    prometheus={'targets':matching,'coverage_metrics_available':result['data']['result']}
except urllib.error.URLError:
    raise RuntimeError('start only the optional Fog collector before this verifier')
print(json.dumps({'checks':checks,'overview':overview,'page':page,'prometheus':prometheus},default=str))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to replace previous evidence")
    command = [docker_executable(), "compose", "-p", "software-data-diode-coverage",
        "-f", "docker-compose.yml", "-f", "docker-compose.coverage.yml", "--profile", "coverage"]
    result = subprocess.run([*command, "exec", "-T", "monitoring-api", "python", "-c", PROBE],
                            cwd=ROOT, capture_output=True, text=True, timeout=100)
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:])
    document = json.loads(result.stdout)
    ids = subprocess.run([*command, "ps", "-q", "monitoring-api", "dashboard"], cwd=ROOT,
                         capture_output=True, text=True, check=True, timeout=30).stdout.split()
    containers = json.loads(subprocess.run([docker_executable(), "inspect", *ids], cwd=ROOT,
        capture_output=True, text=True, check=True, timeout=30).stdout)
    memberships = {}
    for container in containers:
        service = container["Config"]["Labels"]["com.docker.compose.service"]
        if container["Config"]["Labels"]["com.docker.compose.project"] != "software-data-diode-coverage":
            raise RuntimeError("foreign project")
        networks = sorted(container["NetworkSettings"]["Networks"])
        if any("edge" in n or "diode-network" in n for n in networks):
            raise RuntimeError("dashboard/API attached outside Fog")
        mounts = [{"target": m["Destination"], "writable": m["RW"]} for m in container["Mounts"]]
        if service == "monitoring-api" and (len(mounts)!=1 or mounts[0] != {"target":"/app/config/rule_coverage.json","writable":False}):
            raise RuntimeError("unexpected Monitoring API mount")
        memberships[service] = {"networks": networks, "mounts": mounts, "ports": container["HostConfig"]["PortBindings"]}
    document["memberships"] = memberships
    document["mode"] = "LIVE_RESEARCH_POSTGRES_API_AND_PROMETHEUS"
    args.output.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"N8 live checks passed: {len(document['checks'])}; {args.output}")


if __name__ == "__main__":
    main()
