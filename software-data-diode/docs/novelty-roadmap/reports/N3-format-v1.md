# N3 signed evidence format v1

Frozen 2026-10-13. Implementation: `shared/coverage/capsules.py`, `parts.py` and `sealing.py`.
This specifies authenticated assertions, not hidden-input proofs, raw delivery or established novelty.

## Scope and identity

RCC is a separate artifact, never an ordinary telemetry envelope with a fabricated payload.
`rccd-capsule-v1` declares one gateway, key ID, ledger epoch, contract hash and device/window.
Windows retain N1's UTC-aligned half-open 10 seconds; time basis is gateway ingress microseconds, not sensor time or physical simultaneity.
The contract hash references the preprovisioned immutable N1 profile, including units, binary64 interpretation, minimum samples and rule expressions.

The body signs protocol/kind, scope kind, gateway/key IDs, epoch, immutable capsule ID, contract hash/profile, device/window index/start/end, observation scope/time basis, closure reason, contiguous ingress range, accepted count, input commitment, facts, limitations, population completeness, accounting, predecessor digest, creation time and online assurance.
The ingress range and counts describe original normalized accepted observations, not outgoing transport sequences.

Let `C(x)` be the project's `canonical_bytes`: Python JSON, sorted object keys, no spaces, UTF-8, `ensure_ascii=False`, `allow_nan=False`, explicit model defaults and JSON-mode values. This is a project-specific format, **not RFC 8785**. Cross-language implementations must reproduce its number encoding and the vectors.
Digest strings are lowercase hexadecimal. Signatures/chunks use canonical padded standard base64.
Incoming duplicate keys, nonfinite numbers, unknown fields, noncanonical bytes and inconsistent partitions/scopes are rejected.

The capsule identity is:

```text
SHA256("RCCD-CAPSULE-IDENTITY-V1\0" ||
       C({gateway_id, ledger_epoch, device_id, window_index, contract_hash}))
```

Changing the key, facts, predecessor, creation time or accounting does not create a new identity for the same scope. Two different valid signed bodies under that identity are a fork, not a replacement.

## Signature and domain separation

All displayed domain strings below end in one literal NUL byte, not the two characters backslash and zero.

```text
body_digest = SHA256("RCCD-EVIDENCE-BODY-V1\0" || C(body))
unsigned = {algorithm: "Ed25519", signature_domain: "RCCD-EVIDENCE-V1",
            body: body, body_digest: hex(body_digest)}
signature = Ed25519.sign("RCCD-EVIDENCE-SIGN-V1\0" || C(unsigned))
artifact = C(unsigned plus signature: base64(signature))
artifact_digest = SHA256("RCCD-EVIDENCE-ARTIFACT-V1\0" || artifact)
```

The existing bare-canonical-JSON contract hash and ordinary telemetry signature preimages remain unchanged. Evidence signature/body/identity preimages have distinct literal domains, so telemetry or a contract digest is not accepted as evidence authentication.
Keys are supplied locally by `(gateway_id, signing_key_id)`; no network key discovery or trust-on-first-use.
Each referenced contract must already be provisioned and match its digest.

## Facts and raw accounting

For every atomic condition registered for the device:

```text
matching_count + nonmatching_count + unresolved_count = accepted_observation_count
```

Missing metrics or a telemetry type mismatch count as unresolved. Counts are calculated from the original accepted records before policy transformation, never thresholded aggregate means.
EXISTS and COUNT_GE need these exact bounded counts, the contract and coverage limitations; no raw numeric sample list is necessary.
Each fact optionally includes at most two unique matching ingress-sequence/input-hash references. These are disclosure references, not independently verified matching-value proofs.
The verifier requires exactly the locally registered per-device condition set.

The signed raw disposition snapshot partitions accepted records into `pending_policy`, `selected_raw`, `reduced_raw`, `dropped_raw` and `archived_local`.
`queue_overflow_drops` is a subset of `dropped_raw`, not an extra population.
`raw_dispatch_attempts` is a separate attempt counter, not a delivery assertion.
`confirmed_receipt_count` must be null and `receipt_assurance` is `NOT_OBSERVED`.
An exact committed fact can represent a sample dropped from the raw queue. It does not show raw dispatch or Fog receipt.
Later transmission statistics must not rewrite a sealed snapshot; any future separate accounting artifact needs its own schema and identity.

N3's local ledger sealer currently emits only N2's pending/locally archived states. It does not implement policy dispositions or queue accounting transitions.

## Original-input commitment

The named construction is **sha256-scope-seeded-input-fold-v1**.
Each original record has its whole normalized canonical ingress message and its N2 `input_hash = SHA256(canonical_input)`.
Require unique contiguous per-device ingress sequences, matching epoch/device, and ingress timestamps within the declared half-open window. Sort by ingress sequence.

```text
root_0 = SHA256("RCCD-INPUT-SEED-V1\0" || C(WindowIdentity))
leaf_i = SHA256("RCCD-INPUT-LEAF-V1\0" ||
                C({ledger_epoch, device_id, ingress_sequence,
                   ingress_utc_us, input_hash}))
root_i = SHA256("RCCD-INPUT-FOLD-V1\0" || root_(i-1) || leaf_i)
```

The fold concatenates raw 32-byte digests, not their hexadecimal encodings. `WindowIdentity` contains epoch, device, index and contract hash. Empty scopes commit to the seed; a digest alone cannot demonstrate absence of input.
Commitment record count, accepted count and ingress range must agree.

Online assurance is **AUTHENTICATED_SUMMARY**: a trusted gateway asserted the counts and scope.
Fog cannot independently recompute withheld inputs from the root or witness references.
Offline audit requires the disclosed canonical original records, verifies the signature first, then recomputes root/range and predicate counts using direct independent inequality branches.
It returns `RECOMPUTED`, `MISMATCH` or `INCOMPLETE_DISCLOSURE`, labeled **OFFLINE_RAW_RECOMPUTATION**.
It does not recompute raw dispatch/drop history, sensor truth, gateway-clock accuracy or original source generation.
A malicious authorized signer can publish internally consistent false counts; online authentication passes while complete disclosed-input auditing can detect the lie.

## Canonical vector

Authoritative values live in `tests/fixtures/coverage_capsule_v1.json`; the test constructs the full signed bytes from the fixed message/profile and separately checks seed/leaf/fold calculations.
The Ed25519 seed is public test-only bytes 0 through 31; it is not a deployment secret.

```text
gateway_id = gateway-vector
signing_key_id = test-vector-key
ledger_epoch = vector-epoch
device_id = edge-device-01
window_index = 0
contract_hash = 5ac9d246d40fc6a333c68fe984025d7f6169bec2fe3e85589c5af3cee51204bd
original = normalized EdgeTelemetryMessage(device_id=edge-device-01,
           timestamp=1970-01-01T00:00:00Z, temperature=45, humidity=50,
           status=normal, telemetry_type=environmental)
ingress_sequence = 1
ingress_utc_us = 1
created_at_utc_us = 10000000
input_hash = d229e56ce2a5ded520df9a28c0ccc4f6728c0e959d995d2ebb350ac3d0d1a31f
input_root = 2679457591c05b44127307408f5b9e55ab3ed028ac2351e6fd39716cebb5a80e
capsule_id = 3a107e027fb627f01d21d011b71ff190a193ba643c0d4975c392913dc3b2db0b
body_digest = 88381e0bc7002ed500b1b1dbf5db04d7920c471c393cda329be0d4d7c68741c7
signature = 1XC/szzzmZ9dwf/2zUmv9p8ew2vIdSf0RJ/dcQPdH8i/sBKgXNE/a1NpLHSFJHNMv0VnQ06HnHlppVy1M1N0BA==
artifact_digest = 651bd73aab999bba3355a0ac34dc6b8f8dc1777b10f41c6ff6319c6f35e7a878
artifact_length = 1738 bytes
```

## Closure, continuity and transition

Normal observed scopes use `WINDOW_END`. No-input artifacts use zero counts/null range and `NO_INPUT`, but minimum-sample requirements still produce UNKNOWN, not an absence certificate.
Startup limitations remain `STARTUP_PARTIAL`; interrupted/recovery/legacy closures require `INTERRUPTED`; clock-discontinuity closures require `CLOCK_DISCONTINUITY`.
Missing metrics remain unresolved facts rather than a fabricated normal value.
N3's pure no-input builder does not establish that the gateway ran during a historical window; the durable sealer refuses missing/unobserved scopes. No normal historical empty windows are synthesized.

Each window authenticates independently. A missing predecessor gives continuity `INCOMPLETE` without automatically rejecting the later window's independently usable facts.
A wrong-device/gateway/epoch or non-earlier predecessor gives `BROKEN`. The bounded inspector can resolve a gap after the parent arrives.
`COMPLETE` means the available declared chain terminates at a signed null predecessor; it is not proof that every historical window exists.
Window-chain continuity, signature verification, rule truth, coverage completeness and device health are separate results.

`rccd-transition-v1` / `RCC_CONTRACT_TRANSITION` signs gateway/key, epoch, previous/next hashes, effective index/start, time basis, creation time and `OPERATOR_PROVISIONING_REQUIRED`.
Its identity hashes `RCCD-TRANSITION-IDENTITY-V1\0` plus gateway, epoch, previous hash and effective index. Excluding next hash detects competing proposed next contracts at the same transition point.
Both contracts must already be provisioned; the artifact has no predicate facts and does not command live reconfiguration. N2's ledger stays pinned to its contract.

## Hard bounds and transport parts

| Material | v1 hard bound |
|---|---|
| Canonical signed logical artifact | 32,768 bytes |
| Conditions / witness references | 64 per capsule / 2 per condition |
| Coverage limitations / identifier length | 3 / 64 ASCII characters |
| Original inputs per scope / canonical scope bytes | 10,000 / 8 MiB |
| Pure input record / current N2 admission record | 65,536 bytes / 8,192 bytes |
| In-memory evidence inspection | 256 artifacts maximum; fail closed, no eviction |
| Optional signing journal | Default 256 artifacts and 4 MiB signed bytes; configurable up to 10,000 and 32 MiB, additionally subject to N2 SQLite cap |
| Journal public key bindings | 16; public bytes only |
| Signed part batch / raw chunk | 96 parts / at most 384 bytes |
| Future datagram serialized payload | At most 1,200 bytes |

Even the one-observation vector exceeds 1,200 bytes. `rccd-part-v1` / `RCC_PART` signs gateway/key, artifact ID/digest, index/count, logical byte total and base64 chunk under `RCCD-TRANSPORT-PART-SIGN-V1\0`.
The finite splitter deterministically chooses a fitting chunk size; impossible header/part-count budgets fail visibly.
Each part authenticates independently, and complete bounded reassembly must also verify logical digest and whole artifact signature/scope. Mixed IDs, differing signed chunks at one index and oversized frames fail.
Reordering and exact duplicates are accepted within the 96-entry batch bound; missing parts leave evidence unavailable.

This is a codec, not a deployed UDP sender/receiver or a promise of delivery. N5-N6 must bound live concurrent assemblies/bytes, expiry, replay retention, retransmission policy and datagram rate without receiver feedback.
Count part headers, signatures, repeated bytes and IP/UDP overhead when reserving the future link budget; the logical artifact size alone is not the transmission cost.
