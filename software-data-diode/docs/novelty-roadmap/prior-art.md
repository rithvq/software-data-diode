# Prior-art assessment and invention candidate

Search date: 2026-10-13. This is a targeted technical search, not a professional patent search or legal opinion.

N0 expanded the initial search to full claim sets and publications. See the
[dated claim-level review and stop/go assessment](reports/N0-prior-art-review.md).

## Conclusion

Do not claim novelty in a software data diode, trusted-network integration, signatures, hash chains, priority scheduling, adaptive filtering, load prediction, signed manifests, authenticated aggregation, or three-valued monitoring by themselves.

The candidate worth investigating is their **specific coupling at irreversible reduction and byte admission**: maintaining exact facts for a restricted rule language, reserving bounded evidence capacity before reducing observations, forwarding independent window evidence without receiver feedback, and making Fog decisions conditional on the received evidence.

The search did not establish that this combination is new. Combining known mechanisms may be obvious even when no reviewed document describes the whole prototype. Its patent prospects remain unestablished.

## Relevant documents

These short descriptions concern technical disclosures, not current legal status, claim validity or infringement.

| Document | Relevant disclosure | Implication for the candidate |
|---|---|---|
| [CN107078970B - Data diode device](https://patents.google.com/patent/CN107078970B/en) | Transmitting-side traffic measurements support receiving-side load prediction and traffic limiting. | A broad feedback-free congestion-prediction claim overlaps directly. |
| [EP4437713A1 - Virtual data diode](https://patents.google.com/patent/EP4437713A1/en) | Software/virtual transfer, filter chains, logging and adaptive filtering. | Software-only deployment and intelligent filters are not sufficient distinctions. |
| [US9736121B2 - File manifest filter](https://patents.google.com/patent/US9736121B2/en) | File characteristics and manifests govern release across a one-way link. | A manifest or checksum beside a diode is an established building block. |
| [US11641327B2 - One-way consistency and integrity](https://patents.google.com/patent/US11641327B2/en) | Independent manifests and receiver processing checks over one-way connectivity. | No-feedback completeness gating is also established related work; see the N0 claim review. |
| [WO2026019937A1 - Erasure-coded diode transmission](https://patents.google.com/patent/WO2026019937A1/en) | Redundant encoded segments enable recovery over a diode. | Forward redundancy is related work; repetition/coding is not the proposed invention. |
| [Window-Aware Load Shedding, VLDB 2006](https://www.vldb.org/conf/2006/p799-tatbul.pdf) | Window-level shedding preserves correct subsets of aggregate query results. | Correct query results under selective shedding are not a new goal; compare evidence reservation specifically. |
| [Proof-Infused Streams, VLDB 2007](https://users.cs.utah.edu/~lifeifei/papers/authenstream.pdf) | Authentication of selection and aggregation answers over stream windows. | Verifiable compact stream answers have a long research history. |
| [Runtime Verification over Out-of-order Streams, 2019](https://people.inf.ethz.ch/basin/pubs/tocl19.pdf) | Sound three-valued monitoring accounts for delay, reordering and loss. | UNKNOWN and conservative reasoning over gaps are not novel alone. |
| [Rational Monitor with Imperfect Information](https://arxiv.org/abs/2408.11627) | Monitoring under imperfect information, including resource-aware observation choices. | Budget-aware monitoring also requires comparison. |
| [Verifiable Telemetry Ledgers, revision 11](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/11/) | Bounded ledger segments, durable admission, policy identity, continuity and explicit verification limits. | Ledger and scope controls are related. This is an individual Internet-Draft, not an adopted standard. |
| [Universal State Transcript specification](https://github.com/thelabmd/UST-Protocol/blob/main/spec/UST-1.0.md) | Signed gaps and observational coverage qualify no-event claims. | A broad signed-silence claim has substantial overlap. Pin publication history before making a legal assessment. |
| [P16 - Temporal evidence gap detection](https://aiep.dev/specs/p16_aiep_deterministic_temporal_evidence_gap_detection_os/) | Version-bound gap artifacts and completeness gates for downstream operations. | Generic gap evidence and fail-closed gating are already publicly described. No patent registration was verified for this page. |
| [Agent-Native Telemetry, 2026 preprint](https://arxiv.org/html/2608.16178v1) | Signed batches, scoped coverage and verified non-occurrence; its producer buffer uses collector acknowledgments. | Negative verification and compact evidence require close comparison. Investigate the different no-feedback admission mechanism; do not treat that difference as established patentability. |

The most important overlaps are query-aware shedding, authenticated stream queries, one-way manifest checks, missing-data monitoring, and scoped negative evidence. The candidate must demonstrate a concrete additional interaction, not just place those features on a dashboard.

## Proposed technical disclosure, for review

Working mechanism:

1. Locally provision a monitoring contract with exact predicate semantics, device scope, observation boundary, window width and resource limits.
2. At trusted gateway admission, durably record observation identity and update rule-sufficient facts before any reduction.
3. Reserve forward evidence bytes and bounded durable storage when admitting a reduction decision; evidence obligations influence routine-data admission.
4. Seal independently interpretable, signed window capsules binding the contract, original-ingress range, facts, coverage limitations and reduction accounting.
5. Send payloads and evidence over the forward application path without receiver acknowledgments or receiver-driven scheduling.
6. At Fog, authenticate and validate the disclosed scope, then give a definite rule result only when the received facts suffice. Otherwise retain UNKNOWN.
7. Measure the effect on correct decision yield, false definite results, evidence cost and critical-event latency at matched total byte budgets.

This is an outline of an invention candidate, not patent claims drafted for filing.

## Elements and overlap

| Element | Established or proposed | Further work |
|---|---|---|
| Forward-only transfer and network separation | Established | Describe the software isolation boundary accurately |
| Hashes, signatures and immutable identities | Established | Reuse tested code |
| Predicate summaries and three-valued evaluation | Established | Compare exact semantics against relevant papers |
| Durable closed-window coverage artifacts | Established related work | Compare the closest public specifications |
| Charging evidence capacity before irreversible telemetry reduction | Proposed narrow distinguishing interaction | Search claims and publications specifically for this coupling |
| Scheduling evidence obligations jointly with protected events and routine payloads | Proposed embodiment, not established novelty | Demonstrate a technical effect beyond independent queues |
| Independent Fog decisions without any reverse application query | Proposed integrated operating condition | Compare one-way monitoring and authenticated streaming designs |

The last three rows can still be anticipated or obvious. Neither a new acronym nor an application in Fog computing creates an inventive step.

## Search record

Representative queries used in this review:

- site:patents.google.com "data diode" "filtering" "adaptive"
- site:patents.google.com "data diode device" "network load prediction"
- site:patents.google.com "data diode" "manifest"
- "authenticated" "stream" "completeness" "aggregation" sensor
- "data diode" "predicate"
- "one-way" "telemetry" "omission" certificate
- "semantic" "completeness" "data diode"
- "signed" "telemetry" "suppression" "certificate"
- "query-aware" "data diode"
- "proof-carrying" "data diode"
- "data diode" "coverage certificate"
- "telemetry" "rule-preserving"
- "unidirectional" "semantic" "coverage" certificate
- "runtime verification" "three-valued" "missing" data monitoring

Sources were read through a web research tool. This folder does not reproduce their full texts. N0 reviewed the claim sets identified in its report, but patent families, prosecution histories, citations, non-English publications and unpublished applications were not exhaustively reviewed. Search snippets and a failed keyword search are not evidence that an idea is absent.

## Next search before filing

Ask a patent professional or the university technology-transfer office to compare the concrete method against full claims and literature, including classifications concerning network security, telemetry, stream processing and congestion control. Check patent families in the intended filing jurisdiction. Resolve the dated revision history of public repository specifications.

Keep patentability separate from freedom to operate. A potentially patentable improvement may still rely on another party's protected claims.

## Filing considerations

Patents generally require novelty, an inventive step and industrial applicability; public disclosure before filing can affect novelty depending on the jurisdiction. Review filing and publication order with faculty before publishing the implementation or paper. [WIPO patent FAQ](https://www.wipo.int/en/web/patents/faq_patents).

If filing in India, Section 3(k) excludes mathematical/business methods, computer programs per se and algorithms. A networking prototype therefore needs a jurisdiction-specific eligibility assessment; calling it a system or adding Docker does not settle eligibility. [Indian Patents Act, Section 3](https://ipindia.gov.in/acts/patent-act-1970/section-3).

A future disclosure should describe the measured technical behavior, identify actual human contributions and cite overlapping work honestly. Do not state that patent eligibility, novelty or legal clearance has been confirmed.
