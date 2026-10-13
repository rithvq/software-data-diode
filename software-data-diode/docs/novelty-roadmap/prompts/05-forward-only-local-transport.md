# N5: Forward-Only Research Transport

Copy the entire prompt below into the coding agent. Complete earlier phases first.

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N5: FORWARD-ONLY RESEARCH TRANSPORT

Prerequisite: N4 produces immutable evidence/raw outbox work with valid budgets.

Goal: deploy a local research transport that can lose/reorder traffic without any receiver application feedback.

1. Add a selectable transport interface. Keep the existing HTTP mode for baseline and rollback. In RCCD mode, Data Diode sends UDP datagrams to Fog Receiver, with no ACK/NACK or receiver-response socket used by the sender.
2. Disable diode-to-Fog HTTP readiness polls, message-response retries and request/response observability export in this mode. Replace required Edge state export with bounded signed forward records included in the traffic budget. Internal Edge and internal Fog HTTP calls remain allowed.
3. Keep Data Diode a passive bounded forwarder. Gateway policy inputs must not include Fog readiness, status codes, processing latency, queue state or collector observations. Local send() success is recorded as attempted dispatch, not receipt.
4. Enforce 1,200-byte datagram payloads including signed envelope fields. Implement bounded authenticated parts when needed: artifact identity, part index/count, whole-body digest and signature binding. Bound part count, total bytes, partial assemblies and timeout. Missing parts must not trigger a reverse request.
5. Support optional fixed evidence repeats with identical signed bytes and local schedule. Charge all repeat/part bytes. Default choices must be explicit and experimentally ablatable.
6. Add a separate durable reorder-aware replay path for research envelopes. Do not weaken or silently reuse the existing highest-sequence-only verifier. Define bounded history, stale windows, retired epochs and duplicate identities.
7. Create docker-compose.coverage.yml as a minimal override of current services, with an isolated software-data-diode-coverage project, research mode flags, Edge-only ledger volume, separate state and loopback dashboard ports. Avoid fixed subnets and new infrastructure services.
8. Test drop, reorder, duplicate and delayed datagrams with a seeded local forward fault adapter. Verify Fog cannot resolve/connect to Edge application services and record actual memberships. Inspect cross-boundary packet captures or equivalent instrumentation to show the tested mode sends no application replies; distinguish that result from physical or privileged-host enforcement.
9. Add startup/config checks and correct local liveness/readiness semantics. Fog unavailability must expose stale coverage, not block an ACK-free sender waiting for readiness.

Acceptance: the research path runs locally, has bounded state, does not require receiver replies, and accurately labels attempts, receipt and software-isolation limits.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N5.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```
