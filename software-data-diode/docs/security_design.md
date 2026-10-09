# Security Design

## Controls

- Ed25519 signs a canonical representation of each secure envelope.
- SHA-256 binds the telemetry payload to `payload_hash`.
- Pydantic applies strict schema and size constraints before Fog processing.
- Timestamp freshness, UUID duplicate detection, and per-device monotonic
  sequences reject stale or replayed data.
- Token-bucket admission and egress controls protect the bounded diode queue.
- Priority-aware overflow can evict lower-priority entries for a higher-priority
  arrival; a LOW arrival cannot evict existing work.
- Each service emits structured JSON logs. Gateway, diode, and receiver audit
  files use a chained SHA-256 record format.
- Runtime signing keys and `.env` credentials are generated locally, ignored by
  version control, and mounted only where required.
- Containers run as UID/GID 10001, drop Linux capabilities, use
  `no-new-privileges`, read-only roots, bounded `/tmp`, and resource limits.

## Message Verification

```mermaid
flowchart TD
  A["Receive bytes"] --> B{"Schema valid?"}
  B -- No --> R1["INVALID_SCHEMA"]
  B -- Yes --> C{"Payload hash matches?"}
  C -- No --> R2["HASH_MISMATCH"]
  C -- Yes --> D{"Ed25519 signature valid?"}
  D -- No --> R3["INVALID_SIGNATURE"]
  D -- Yes --> E{"Timestamp fresh?"}
  E -- No --> R4["EXPIRED_MESSAGE"]
  E -- Yes --> F{"UUID unseen?"}
  F -- No --> R5["DUPLICATE_MESSAGE"]
  F -- Yes --> G{"Sequence advances?"}
  G -- No --> R6["REPLAY_DETECTED"]
  G -- Yes --> H["Audit ACCEPTED and forward"]
```

Rejections are audited locally before rejection metadata is persisted. If
PostgreSQL is offline, the security response and audit record are preserved and
the persistence error is logged.

## Controlled Attack Simulation

```mermaid
flowchart LR
  T["security-test-client\nsecurity-test profile"]
  T -->|"tamper / replay / malformed / flood"| D["Data Diode ingress"]
  T -->|"verification scenarios"| R["Fog Receiver ingress"]
  R -->|"probe only in test mode"| X["Fog-to-Edge DNS and ports"]
  X --> F["Expected: all fail"]
  T --> C["CSV + JSON evidence"]
  A["Copied audit log"] --> M["Modify earlier record"]
  M --> V["Hash-chain verifier"]
  V --> B["First broken line"]
```

The test client is attached only to the two intentional ingress networks. It
rejects targets other than the literal Compose hosts `data-diode` and
`fog-receiver`; no external system is targeted.

## Secret Handling

Run `python scripts/setup.py` to create random local credentials and signing
keys. Do not put `.env` or `secrets/*.pem` in a commit, image, report, or
screenshot. Rotate by stopping the stack, replacing `.env` values and both key
files, then rebuilding/restarting the affected services.

## Security Claim

This design demonstrates cryptographic integrity, replay resistance, bounded
resource use, audit tamper evidence, and Docker-network isolation. The Docker
host administrator remains in the trusted computing base and can reconfigure
networks or mounts.

