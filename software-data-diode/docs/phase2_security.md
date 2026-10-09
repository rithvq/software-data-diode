# Phase 2: Secure Envelopes and Integrity

This is the second step of the standalone phased development track following
`docker-compose.phase1.yml`. It deliberately stops before information utility,
prediction, filtering, multi-Edge analytics, or benchmarking. Those capabilities
in the older full system are not evidence of completion of the new phases.

## Run

Start Docker Desktop's Linux engine. From the project directory:

```powershell
Set-Location "C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode"
docker info
docker compose -f docker-compose.phase2.yml run --build --rm key-init
docker compose -f docker-compose.phase2.yml up --build -d --wait
python scripts/verify_phase2.py
```

The verifier uses only the Python standard library on the host. A non-PATH Docker
executable can be supplied with `--docker "C:\path\to\docker.exe"`; per-user Docker
Desktop installations are detected automatically. All commands target only
`software-data-diode-phase2`. Phase 1 and the full application remain untouched.
This phase has no browser UI or host-published ports.

The setup job has no network and exits after creating a new key pair or checking
the existing pair. Repeating it preserves the signing identity. It refuses a
mismatched pair or an orphan public key, rather than silently rotating credentials.
Keys live in separate Docker named volumes, never the image or host source tree.

Inspect current status and security counters:

```powershell
docker compose -f docker-compose.phase2.yml ps
docker compose -f docker-compose.phase2.yml logs --tail 30 edge-device edge-gateway unidirectional-gateway fog-receiver
docker compose -f docker-compose.phase2.yml exec -T fog-receiver python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
docker compose -f docker-compose.phase2.yml exec -T fog-receiver python -m phase2.probe audit
```

Safely stop this phase with `docker compose -f docker-compose.phase2.yml stop`.
Restart with `docker compose -f docker-compose.phase2.yml up -d --wait`.
Persistent pending outboxes and sequence state survive container recreation.
Do not use `down -v` unless deliberately deleting keys, replay state, and audit
history. Back up/restore the device and receiver security volumes consistently;
restoring an older device counter against a newer receiver will trigger replay checks.

## Architecture and Trust Boundary

```text
Edge Device --unsigned source--> Edge Gateway --signed envelope-->
Unidirectional Gateway --unchanged signed envelope--> Fog Receiver
```

| Service | Networks | Keys and state |
| --- | --- | --- |
| edge-device | edge-network | Durable sequence and one pending source message; no signing key |
| edge-gateway | edge-network, gateway-network | Private key read-only; public key read-only; private state volume |
| unidirectional-gateway | gateway-network, fog-network | Public key only, read-only; private state volume |
| fog-receiver | fog-network | Public key only, read-only; private state volume |

There are three internal Docker bridges, no fixed subnets, no published ports,
no Docker socket, no reverse control API, and no Fog telemetry input to the
scheduler interfaces. Containers run as UID 10001, drop Linux capabilities, and
use read-only root filesystems. The sender-source guard from Phase 1 remains:
each HTTP ingress accepts only the Docker-resolved immediate upstream peer IP.
Uvicorn ignores forwarded-IP headers.

The Edge Gateway validates unsigned input and signs it. Both downstream services
independently validate the complete envelope before admission. The private key
never mounts into the diode, device, or Fog. The one-off key initializer is a
trusted operator setup job, not a network service.

## Envelope and Canonicalization

`phase2/models.py` extends the Phase 1 telemetry model with required fields:

```text
message_id, device_id, timestamp, sequence_number, payload
created_at, message_type, priority, base_priority, event_class, payload_size
supersession_key, aggregation_allowed, sampling_allowed, must_preserve
schema_version, payload_hash, signature
```

`timestamp` and `created_at` must identify the same timezone-aware creation time.
The sequence is a positive signed-64-bit integer, not a boolean/coerced string.
Payloads are JSON objects. Source message type supports environmental, system,
network, security, and industrial; this deployment generates only environmental
telemetry. Priority supports CRITICAL, HIGH, MEDIUM, LOW. Without transformations,
priority must equal base_priority. Unknown top-level fields are rejected.

`payload_size` is the canonical UTF-8 payload length, not network overhead.
SHA-256 hashes those payload bytes. Ed25519 signs canonical serialization of
**all normalized envelope fields except signature**, including the payload hash,
size, timestamps, sequence, priority, and every future-utility metadata flag.
No field used for later utility decisions is unsigned.

The canonical profile uses Pydantic-normalized JSON values, recursively sorted
object keys, compact separators, UTF-8, and unescaped Unicode. Array order stays
significant. Duplicate object keys, nonfinite numbers, extra fields, and invalid
types are rejected. This is a defined Python application profile, **not an RFC
8785/JCS interoperability claim**; another language must implement this same
normalization before interoperating. Existing `shared/security` cryptographic
helpers are reused, with strict parsing and the new schema in `phase2/security.py`.

Mandatory semantics are explicit: security-category and CRITICAL messages require
`must_preserve=true`. Mandatory messages cannot enable sampling, aggregation,
or supersession. These are schema guards and signed metadata, not a utility
algorithm. The Phase 2 FIFO performs no sampling, aggregation, or automatic
congestion dropping. Queue exhaustion returns retryable backpressure.

## Validation and Delivery

The order is rate limit, source check, bounded body read, schema/semantics, device
identity binding, payload size/hash/signature, duplicate/replay state, freshness,
capacity, durable acceptance, and forwarding. Identity binding currently permits
only `edge-device-01`. The rate limit is a per-service token bucket (20 messages/s,
burst 40), not per-device fairness. Body limit is 8192 bytes and canonical payload
limit is 4096 bytes. Defaults accept source times up to 120 seconds old or 10
seconds in the future. Synchronize clocks in any multi-host extension.

| Result | Handling |
| --- | --- |
| HASH_MISMATCH / INVALID_SIGNATURE | Reject, audit, count; no replay-state mutation |
| REPLAY_DETECTED | New UUID at an already accepted/lower per-device sequence; HTTP 409 |
| DUPLICATE_MESSAGE | Same UUID with different authenticated contents: HTTP 409 |
| DUPLICATE_MESSAGE, exact retry | Audit/count and HTTP 200, with no second admission/delivery |
| EXPIRED_MESSAGE | New stale/future message rejected; HTTP 400 |
| INVALID_SCHEMA / PAYLOAD_SIZE_MISMATCH | HTTP 422 |
| PAYLOAD_TOO_LARGE | HTTP 413 |
| RATE_LIMIT_EXCEEDED | HTTP 429 with Retry-After |
| QUEUE_FULL | HTTP 503 with Retry-After; sequence remains available to retry |
| UNAUTHORIZED_SOURCE / UNKNOWN_DEVICE | HTTP 403 |

Cryptographic checks precede duplicate acknowledgement. Known exact retries are
acknowledged even after their original freshness window because they cannot
cause a new delivery. Duplicate fingerprints persist across restarts and are
retained for the freshness window plus skew/margin; high-water sequence numbers
persist independently. Older IDs outside duplicate retention are still blocked
by sequence/freshness rules. SQLite security transactions also persist the
outbound envelope, so restart does not remember an admission while forgetting
its pending data. Device generation similarly persists its sequence and pending
source message before sending.

Transient failures, HTTP 408/429/5xx, and lost acknowledgements retry with backoff.
Permanent downstream 4xx responses are terminal rejections, audited separately
and never counted as delivered. This prevents an expired item blocking FIFO
forever. Mandatory status does not bypass integrity/freshness validation.
Long outages can expire messages; this phase does not guarantee lossless delivery.

## Audit and Metrics

Each receiving service has `/state/audit.jsonl`, a chained SHA-256 log containing
service, time, event, result/reason, IDs, and previous/current hashes. It records
validation decisions, duplicates, and transmission outcomes. A VALIDATED event
records validation, not proof of subsequent Fog delivery. Startup verifies the
existing chain and refuses to append if broken. SQLite counters and admission
state are authoritative for committed acceptance; file logging and SQLite do
not constitute a single distributed transaction.

`phase2.probe audit` copies the active log, verifies it, changes the first copied
record, and requires a first-broken-location report at line 1. Original logs are
not modified. The existing `scripts/verify_audit_log.py` also verifies exported logs.

`/metrics/runtime` retains Phase 1 arrival/queue-entry/transmission timestamps,
message size, queue length, and bounded recent records. It adds durable accepted
and transmitted message counters, terminal rejection counts, and per-reason
security counters. The live verifier exports JSON and CSV with scenario,
attack_type, expected_result, actual_result, detected, response_time (seconds),
timestamp, and HTTP status. These are controlled functional observations, not
statistical efficacy or performance conclusions. Utility metrics remain future work.

## Verification and Limits

`tests/test_phase2.py` covers cryptography, signed metadata, canonicalization,
malformed JSON, preservation constraints, key initialization, source guards,
rate/body/payload limits, persistence/restart, replay/duplicate distinctions,
queue recovery, retry handling, and audit tampering. The full suite must also pass.

`scripts/verify_phase2.py` reuses Phase 1's actual Docker network membership,
forward-delivery, and reverse-path checks. It adds key-mount inspection, Fog
verification of ten received signed envelopes, controlled attacks from the Edge
Gateway to the local diode, a bounded 80-request malformed-message flood,
audit-copy tampering, queue bounds, and continued valid traffic afterward.
Targets are fixed project service names; no external infrastructure is attacked.
Results appear in `phase2-results/`.

Security limitations:

- Software isolation is not a hardware data diode. TCP acknowledgements and HTTP
  status responses return to senders and inform transport retries. No claim of
  physically one-way TCP or completely feedback-free transport is made.
- Device-to-Edge input relies on the isolated network/source guard, not device
  certificates. A compromised trusted Edge peer or signing key can forge data.
- Ed25519 provides integrity/authenticity, not confidentiality; transport is HTTP.
- An unkeyed hash chain detects ordinary edits but cannot detect a privileged
  attacker rewriting the entire chain or deleting its tail without an external
  trusted checkpoint. The logs are tamper-evident, not tamper-proof.
- State/audit ownership assumes one worker per container; do not enable multiple
  Uvicorn workers. Volume deletion, rollback, full disk, and host compromise are
  outside crash/restart protection. Logs and retained database files need disk
  monitoring/retention; rate limiting does not eliminate disk-exhaustion threats.
- Sequence-based replay checks assume Phase 2 FIFO order. Later reordering
  schedulers require a bounded replay window instead of blindly reusing this rule.
- This phase has no key rotation/revocation protocol, TLS, PostgreSQL analytics,
  information utility calculation, prediction, or adaptive policy selection.

The next phase is the dedicated `information_utility/` module: component scores,
last-transmitted-state cache, category-specific novelty and TTLs, and safe
supersession. Prediction must remain deferred until its own phase.
