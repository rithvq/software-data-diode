# N3: Signed Rule Coverage Capsules

Copy the entire prompt below into the coding agent. Complete earlier phases first.

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N3: SIGNED RULE COVERAGE CAPSULES

Prerequisite: N2 durable admission and recovery are verified.

Goal: create bounded, self-contained evidence for original accepted observations, using existing cryptographic primitives.

1. Introduce a separate versioned RCC artifact schema. Do not force evidence into a fake ordinary telemetry payload. Bind gateway/key identity, ledger epoch, immutable capsule identity, contract hash, device/window scope, ingress range, accepted count, time basis, closure reason, facts, limitations, reduction accounting and predecessor digest.
2. Accumulate matching/nonmatching/unresolved counts before policy transformation. Verify their sum equals the declared accepted count for each atomic condition. Include only the minimal sufficient facts needed by v1 predicates and bounded witness references. Do not derive threshold facts from an aggregate mean.
3. Keep semantic coverage separate from raw selection, raw dispatch, queue overflow and confirmed receipt. A committed exact predicate fact may represent a raw sample later dropped locally. It does not prove raw delivery.
4. Use canonical serialization, SHA-256 and Ed25519 with domain separation between contracts, telemetry and evidence. Sign every field used to determine scope, identity or meaning. Repeated artifacts must reuse identical signed bytes.
5. Provide a sender input commitment for offline audit, with explicitly named construction and canonical vectors. State that Fog cannot independently recompute withheld inputs from a digest alone. Online assurance is AUTHENTICATED_SUMMARY under a trusted gateway; offline raw recomputation is a distinct check.
6. Seal each window independently. Missing a predecessor marks chain continuity incomplete but does not automatically invalidate an independently usable later window. Detect two different signed bodies with the same immutable scope identity.
7. Define no-input, missing-metric, recovery, time-discontinuity and contract-transition artifacts. An empty capsule or heartbeat cannot certify no event when the contract requires observations.
8. Enforce hard serialization/record/list bounds. Specify bounded signed transport parts if a capsule does not fit the future 1,200-byte datagram limit.
9. Test canonical vectors, every meaningful field mutation, wrong keys, count contradictions, identity forks, recovery closures, redelivery and offline recomputation.

Acceptance: artifacts authenticate their exact declared scope, remain bounded, and clearly distinguish authenticated assertions from independently recomputed facts.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N3.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```
