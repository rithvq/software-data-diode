# Threat Model

## Assets

1. Edge telemetry integrity.
2. Ed25519 private signing key.
3. Ed25519 public verification key.
4. Message sequence and replay state.
5. Fog Receiver acceptance decisions.
6. Tamper-evident audit logs.
7. Docker network segmentation.

## Trust Boundaries

```text
Edge Devices -> Edge Gateway -> Data Diode -> Fog Receiver -> Fog Processing
```

The Edge Gateway is the signing boundary. Raw telemetry exists only before this point. Signed envelopes cross the diode boundary. The Fog Receiver must verify everything it receives and must not trust the Data Diode blindly.

In normal profiles, the private key is mounted only into `edge-gateway`. The Fog
Receiver receives only the public key. The controlled `security-test` profile
also mounts the private key into its simulator so it can create valid replay
fixtures; that profile is not a deployment mode.

## Attacker Capabilities

An attacker may:

1. Send malformed telemetry to the Edge Gateway.
2. Modify payload fields, hashes, signatures, timestamps, or sequence numbers in transit.
3. Replay previously valid signed envelopes.
4. Reuse a previously accepted UUID.
5. Flood the Data Diode with excessive requests.
6. Edit audit log files after records are written.
7. Attempt direct network access from Fog to Edge.

## Attack Surfaces

1. `POST /telemetry` on Edge Gateway.
2. `POST /ingest` on Data Diode.
3. `POST /receive` on Fog Receiver.
4. Docker network attachments and DNS.
5. Mounted key files.
6. Audit log files.
7. Priority classification and filtering rules.
8. Data Diode queue and scheduler configuration.

## Mitigations

1. Pydantic schema validation rejects malformed messages.
2. Canonical JSON serialization prevents hash/signature mismatch due only to field order.
3. SHA-256 detects payload tampering.
4. Ed25519 signatures detect unauthorized envelope changes.
5. Fog Receiver freshness checks reject old or future-dated messages.
6. In-memory duplicate detection rejects repeated message IDs.
7. In-memory Fog replay detection rejects non-increasing per-device sequence
   numbers; the gateway persists its next counters across gateway restarts.
8. Data Diode request-size checks reject oversized payloads.
9. Data Diode token-bucket rate limiting rejects excessive request rates.
10. Audit logs chain records with `previous_log_hash` and `current_log_hash`.
11. Docker Compose separates `fog-ingress-network` from `fog-services-network`;
    only the Fog Receiver bridges them and no Fog service joins `edge-network`.
12. Data Diode ingress is reachable only through its internal network
    membership and can additionally enforce a configured source CIDR.
13. Bounded queues prevent unbounded memory growth.
14. Overflow handling preferentially retains higher-priority messages.
15. Adaptive aging and starvation boost prevent LOW messages from being queued forever.
16. FIFO baseline experiments make scheduler behavior measurable rather than anecdotal.

## Assumptions

1. The Edge Gateway is trusted to hold and protect the private key.
2. The host filesystem protects the generated `secrets/*.pem` files.
3. Docker Compose network configuration is not maliciously modified at runtime.
4. System clocks are reasonably synchronized.
5. In-memory Fog replay state is acceptable for this prototype.

## Residual Risks

1. Docker network isolation is software-controlled and can be changed by a privileged host user.
2. This is not a hardware data diode and does not provide physical one-way guarantees.
3. Replay and duplicate state is lost when the Fog Receiver restarts.
4. Audit logs are tamper-evident, not tamper-proof.
5. Private keys are file-based and not protected by an HSM or TPM.
6. There is no mutual TLS, per-device key identity, automatic key rotation, or
   persistent Data Diode queue.
7. A compromised Edge Gateway can sign malicious but structurally valid telemetry.
8. Incorrect priority/filtering rules can suppress useful low-priority telemetry.
9. In-memory scheduling and metrics state is lost on restart.
10. PostgreSQL contains security-sensitive operational data and must use a strong
    deployment password, encrypted storage, backups, and restricted host access.
11. Correlation and anomaly rules are explainable but can be evaded by values just
    below configured thresholds; rule changes must be reviewed and versioned.
12. Adaptive scheduling improves deterministic policy behavior, but it is not a
    substitute for formal real-time guarantees.

The complete limitation statement and deployment scope are maintained in
`docs/limitations.md`.
