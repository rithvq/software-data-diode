# N5 transport contract

Version: rccd-udp-v1. Local research only; not a hardware diode or established novelty.

## Modes and Boundaries

`DIODE_FORWARD_TRANSPORT=http` retains the existing HTTP deployment. `udp` requires the separately provisioned `software-data-diode-coverage` project and local trust, contract and transport configuration. The Gateway also requires coupled admission. The baseline Compose file is unchanged.

Device-to-Gateway HTTP remains inside Edge. Gateway-to-Diode and Diode-to-Fog use UDP ports 9001 and 9002, respectively. No UDP host port is published. The diode's HTTP health server is container-loopback-only in this deployment. Its research message/metrics HTTP routes are disabled. Research readiness is local process/intake readiness, not proof of downstream receipt or database processing.

Neither the sender socket API nor the receive protocol exposes an application reply operation. DNS resolution uses Docker's local resolver; its results only select a socket destination, never an admission/scheduling input. Failed/unresolved local sends still consume charged grants. ICMP, ARP, DNS and privileged host behavior are not a physical one-way guarantee.

## Authenticated Frames

Raw and forward-state frames have this network-byte-order header:

| Field | Bytes |
|---|---:|
| Magic: RCR1 raw / RCS1 state | 4 |
| Immutable artifact UUID | 16 |
| SHA-256 of complete canonical body | 32 |
| Part index / count | 2 / 2 |
| Complete-body byte count | 4 |
| Provisioned context lookup tag | 4 |
| Ed25519 part signature | 64 |

Total header: **128 bytes**, matching N4's configured raw-header allowance. The signature covers `RCCD-BINARY-PART-V1\0`, the entire canonical trust profile, the first 64 header bytes and the chunk. The context contains gateway/key IDs, approved epoch, contract hash and public-key fingerprint. The four-byte lookup tag is not the security boundary: signature verification binds the full context.

Chunks are at most 1,072 bytes with the default 1,200-byte datagram payload ceiling. Raw bodies retain the original telemetry signature/hash and outgoing UUID/sequence namespace; binary signatures bind their approved research epoch separately. No selected raw sequence proves original-input completeness.

RCC evidence retains N3's canonical signed JSON part format and independent capsule authentication. Complete-body digest, bounded part count, identity and all signature checks precede use. Logical raw/evidence records are at most 32 KiB, parts at most 96, forward state at most 8 KiB. N4's smaller 12 KiB raw bound also applies to outgoing work.

## Byte Accounting

Normal frame grants charge serialized payload plus 28 modeled IPv4/UDP bytes. Binary headers are now real serialized bytes, not extra fictional costs. N3 signed-part headers/signatures and each configured evidence repeat are included. Ethernet, encapsulation and IP options are not measured by this model.

Default evidence repeats: **2**, with identical stored signed bytes. Raw and state records have one scheduled copy. Repeat ablation requires explicit fresh/configuration-compatible research state.

The default state interval is 10 seconds. Its worst-case forward reservation is 9,824 bytes and packed-storage reservation 12,825 bytes, held before admitting telemetry work. Default five-device RCC reservation is 62,434 bytes per 10-second closure cycle. Total 72,258 bytes fits the configured evidence quantum of 131,072 bytes, including packetization slack. An underfunded combined configuration fails startup; state is not free.

The passive diode has a bounded FIFO queue and locally configured byte pacing. It does not add repeats, signatures, policy transformations or delivery retries. The two UDP hops each carry the scheduled bytes; total two-hop network traffic is not the single-hop budget.

An unresolved grant after a sender crash is already charged. Recovery records `LOCAL_ATTEMPT_UNCERTAIN` and consumes that cursor without a free retransmission. A later preconfigured evidence copy may repair a missing part. Neither successful socket calls nor uncertain grants are confirmed Fog receipts.

## Receive and Replay State

Only authorized local source addresses enter the bounded application queue. Part authentication precedes partial-assembly admission. Defaults: 256 queued frames, 32 partial artifacts, 1 MiB partial-frame bytes and five-second monotonic assembly expiry. Duplicates do not refresh expiry. Missing parts never cause a reverse request.

The Fog-only SQLite replay store has a separate writer lock, identity anchor, immutable trust/config binding, full transactions and bounded pages/history. Default sequence reorder width is 128 for raw/state records; evidence accepts a 30-window reorder history at the 300-second freshness setting. Artifact creation times must be within the freshness interval or at most 30 seconds ahead.

One epoch is explicitly approved. Unknown epochs fail authentication/provisioning. Local retirement persists a refusal flag; a changed profile or a missing anchored store cannot silently reset history. Multiple-epoch migration is not implemented in N5.

Same kind/identity and identical body is an idempotent duplicate. Different signed content with that identity, or a reused per-device sequence, is a conflict. Durable highwaters survive eligible-history pruning; older sequence/window identities remain refused. Pending internal Fog processing is never evicted to admit newer work. Full storage refuses admission rather than acknowledging nonexistent durability.

Verified raw/state work has bounded durable pending processing toward existing internal Fog services. Internal retries cannot influence the sender. N5 evidence remains in bounded local replay retention, without new PostgreSQL capsule/verdict tables. Existing telemetry processing can be at-least-once across crash boundaries; stronger downstream publication semantics are N6 prerequisites.

## Staleness and Limits

Fog reports per-device evidence age and stale/missing status separately from forward-state age. Empty or fresh state does not certify no event. `Coverage: NOT_EVALUATED_N5` is deliberate: N6/N7 rule persistence/evaluation and N8 coverage visualization are not implemented here.

Windows stay UTC-aligned and half-open. Sequential UTC/monotonic samples within the existing contract tolerance defer closure until both clocks cross; admission separately checks UTC membership. Larger jumps/regressions still halt and limit affected windows. Restart preserves identities, records interrupted scopes and does not invent historical normality.

N4 retains finite raw records and a 256-capsule signing cache by default. At five observed devices per window, the latter can fill after roughly 8.5 minutes of continuously observed windows. Admission then refuses unsupported additional obligations. Explicit export/retirement/compaction and later cache-retention work are needed for longer runs; no unlimited delivery or uptime claim is made.
