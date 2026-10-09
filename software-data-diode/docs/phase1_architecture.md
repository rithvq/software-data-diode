# Phase 1: Minimum Unidirectional Pipeline

This standalone baseline lives in `phase1/` and `docker-compose.phase1.yml`.
It preserves the full research system in the normal `docker-compose.yml`.
Always use `-f docker-compose.phase1.yml` for Phase 1 commands. There is exactly
one device, no adaptive intelligence, no database, and no dashboard.

## Architecture

```text
Edge Device -> Edge Gateway -> Unidirectional Gateway -> Fog Receiver
             /telemetry             /ingest                /receive
```

| Service | Logical networks | Responsibility |
| --- | --- | --- |
| edge-device | edge-network | Generate environmental telemetry |
| edge-gateway | edge-network, gateway-network | Validate, instrument, enqueue, forward |
| unidirectional-gateway | gateway-network, fog-network | Validate source, instrument, schedule, forward |
| fog-receiver | fog-network | Validate and record accepted telemetry |

All networks are internal Docker bridges. There are no published host ports.
Compose assigns subnets automatically, avoiding fixed subnet conflicts. Actual
network names have the `software-data-diode-phase1_` project prefix. Fog shares
neither the Edge network nor the gateway network. Neither gateway implements a
generic proxy, reverse transfer endpoint, or packet router.

Python 3.11 containers use FastAPI/Pydantic and HTTP. Each message preserves its
UUID `message_id`, `device_id`, timezone-aware `timestamp`, positive
`sequence_number`, and `payload` across all hops. Payload fields are temperature,
humidity, and status. Sequence numbers restart at one each device process lifetime.

## Run From PowerShell

Start Docker Desktop and wait for its Linux engine. Then:

```powershell
Set-Location "C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode"
docker info
docker compose -f docker-compose.phase1.yml config --quiet
docker compose -f docker-compose.phase1.yml up --build -d --wait
docker compose -f docker-compose.phase1.yml ps
python scripts/verify_phase1.py
```

The verifier needs only Python's standard library. Docker must be on PATH or
specified with `--docker "C:\path\to\docker.exe"`. It also detects the per-user
Docker Desktop installation under LOCALAPPDATA. No setup script, signing keys,
`.env` initialization, or full-profile startup is needed for this baseline.

View recent logs and gateway instrumentation without indefinitely occupying the terminal:

```powershell
docker compose -f docker-compose.phase1.yml logs --tail 30 edge-device fog-receiver
docker compose -f docker-compose.phase1.yml exec -T unidirectional-gateway python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
```

Inspect actual network membership:

```powershell
docker network inspect software-data-diode-phase1_edge-network
docker network inspect software-data-diode-phase1_gateway-network
docker network inspect software-data-diode-phase1_fog-network
```

When preserving in-flight telemetry matters, stop generation first, inspect both
gateways until their `queue_length` values are zero, then stop the remaining services:

```powershell
docker compose -f docker-compose.phase1.yml stop edge-device
docker compose -f docker-compose.phase1.yml exec -T edge-gateway python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
docker compose -f docker-compose.phase1.yml exec -T unidirectional-gateway python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
docker compose -f docker-compose.phase1.yml stop
```

Restart with `docker compose -f docker-compose.phase1.yml up -d --wait`.
Named log volumes persist; queues and counters do not. Avoid `down -v` unless
intentionally deleting Phase 1 logs. These commands do not target the full
system's project, database, or dashboard.

## Instrumentation and Interfaces

Both gateways write JSONL records to their own named volume under `/logs` and
expose bounded recent records through `/metrics/runtime`.

| Field | Meaning |
| --- | --- |
| arrival_timestamp | UTC handler arrival, before validation |
| queue_entry_timestamp | UTC queue admission after validation and policy evaluation |
| transmission_timestamp | UTC just before a transmission attempt; null before dispatch |
| message_size_bytes | Normalized UTF-8 JSON size, excluding HTTP/TCP overhead |
| queue_length | Waiting plus in-flight entries; after removal for transmitted events |

Records also contain service, event, message/device IDs, sequence number, attempt,
and reason. Events are `queued`, `transmission_attempt`, `retry`, and `transmitted`.
Arrival and queue-entry timestamps remain unchanged during retries. Fog appends
accepted messages with receipt instrumentation to `/logs/fog-received.jsonl`.
These are ordinary logs, not cryptographically tamper-evident audit logs.

`phase1/interfaces.py` defines replaceable Protocols:

- `InformationAnalyzer.analyze`: initially no derived information.
- `StateEstimator`: counts local arrival attempts, bytes, dispatch attempts, and queue length.
- `CongestionPredictor.predict`: initially NORMAL.
- `PolicyEngine.decide`: initially admits valid messages with available capacity.
- `Scheduler.enqueue/select`: initially FIFO in `phase1/components.py`.

Inject a `PipelineComponents` bundle into `Pipeline` or `create_app`.
Network code invokes interfaces and contains no FIFO operations. Tests substitute
a stack scheduler without changing HTTP handlers. No Fog metrics or policy
instructions feed these interfaces.

## Verification

`scripts/verify_phase1.py` checks running containers, not just configuration.
It waits for ten new received messages, checks unique IDs, one device, contiguous
FIFO sequences, and matching gateway timestamp/size records. It inspects actual
memberships using `docker inspect` and `docker network inspect`, then probes
from inside Fog:

- Edge device and Edge Gateway DNS names must not resolve.
- TCP connections to their actual container IPs on port 8000 must fail.
- An Edge-side positive control must reach the Edge Gateway health endpoint.
- Fog can reach the dual-homed Unidirectional Gateway, but its `/ingest` must
  reject reverse-direction requests with HTTP 403.

The device has no listener; its failed port probe alone is not proof of isolation.
The listening gateway control, raw-IP probes, and network membership together
establish segmentation. Results are saved to `phase1-results/verification.json`
and `phase1-results/network-inspection.json`. Failure produces a nonzero exit code.
Probes target only this local Compose project, never external systems.

In the existing project environment, run unit/API tests with:

```powershell
python -m pytest tests/test_phase1.py -q
```

Tests cover identity preservation, timestamps, lost-ack retries, duplicates,
conflicting UUIDs, bounded queues, schema/body-size/source validation, 100 concurrent
arrivals, background dispatch, bounded history, replaceable policy/scheduling,
and the network contract.

## Software-Isolation Limitations

This is a **software-defined, logically unidirectional application pipeline**,
not a physical data diode. TCP acknowledgements and HTTP acceptance/error
responses travel backward. Transport retries depend on those responses.
Do not describe this baseline as physically one-way or completely feedback-free.

Receivers compare the actual peer IP with Docker DNS for their configured
immediate upstream. Proxy headers are disabled. This is not cryptographic
authentication. Containers run non-root with dropped Linux capabilities,
read-only root filesystems, resource limits, and no Docker socket. A host/Docker
administrator or compromised gateway can nevertheless defeat software isolation.
Fog can reach the gateway's Fog-side interface; the ingress guard restricts its
normal API, not every covert channel or denial of service.

Queues have capacity 100, including the in-flight item. Queue-full responses
apply backpressure. Temporary failures retain the same message and retry in FIFO
order with bounded backoff. Lost acknowledgements may cause retransmission.
Duplicate suppression remembers the latest 1,000 completed IDs per process,
not an unlimited or durable exactly-once guarantee. Queued/unacknowledged data
can be lost on termination. Logs are not replayed as a durable queue. Log
volumes need monitoring/rotation for prolonged use; in-memory history is bounded.

Signing, TLS, durable queues, replay security, adaptive intelligence, multi-device
analytics, and benchmarking are outside this minimum deployment and remain
separate from the existing full system.
