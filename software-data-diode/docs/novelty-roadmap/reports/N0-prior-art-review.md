# N0 focused prior-art review

Reviewed 2026-10-13. This is a technical overlap assessment, not legal clearance.

## Decision

**GO for scoped research implementation. HOLD any assertion of patent novelty, eligibility or freedom to operate.**

A broad claim to a data diode that preserves monitoring decisions while suppressing telemetry is not defensible from this search. Known stream/query, signed-evidence and missing-information work overlaps substantially.

The narrower hypothesis to investigate is: atomically account for a durable rule-fact obligation and its bounded future forward-byte cost before admitting irreversible routine telemetry reduction, then evaluate independently scoped evidence without receiver application feedback.

No reviewed claim is asserted here to establish or defeat legal patentability of that full combination. Absence of a phrase in a claim is not a novelty test, and a combination of known features may be obvious.

## Claim/publication review

| Source and date/version | Reviewed scope and technical overlap | Remaining candidate distinction, not a finding of novelty |
|---|---|---|
| [CN107078970B](https://patents.google.com/patent/CN107078970B/en), published 2020-04-17; listed priority 2014-10-30 | Claim set 1-16; independent claims 1/5/7 and 9/13/15 address network/receiver load prediction and discard, pause or TCP-window control. Sender-local load control is directly related. | Original predicate obligations and their reserved disclosure cost are a different investigation target; load prediction itself is excluded from the novelty claim. Translation and family review remain incomplete. |
| [EP4437713A1](https://patents.google.com/patent/EP4437713A1/en), published 2024-10-02; listed priority 2021-11-23 | Claims 1-20, especially 1/9/16, concern processing nodes/protocol conversion in a virtual-network NIC; UDP/filter-chain dependents and broader filter/logging description are relevant. | Docker/software deployment and UDP conversion are established context. The B1 page could not be fetched in this session; no conclusion about its granted claims is made. |
| [US9736121B2](https://patents.google.com/patent/US9736121B2/en), published 2017-08-15; listed priority 2012-07-16 | Claims 1-27, including independent 1/10/21, cover manifest-characteristic authorization and one-way file transfer. | Registering policy/hash metadata beside a diode is not sufficient novelty. Predicate-scoped reduction obligations need a separate comparison. |
| [US11641327B2](https://patents.google.com/patent/US11641327B2/en), published 2023-05-02; listed priority 2020-10-19; A1 publication 2022-04-21 | Claims 1-20, especially independent 1/9/15, cover independent unit/aggregate manifests and receiving-side consistency checks before processing; description expressly excludes acknowledgments and auxiliary return networks. | Completeness evidence and processing gates without feedback overlap directly. These reviewed claims do not establish the proposed rule-fact/advance-byte admission coupling; that observation is not a novelty or noninfringement finding. |
| [WO2026019937A1](https://patents.google.com/patent/WO2026019937A1/en), published 2026-01-22; listed priority 2024-07-17 | Claims 1-20; independent 1/8/15 describe redundant segment generation and recovery. Claim 7 includes optional drop-rate feedback. | Forward redundancy alone is excluded. RCCD proposes facts rather than recovery of all original bytes; no-ACK evidence repeats remain ordinary transport machinery. |
| [Window-Aware Load Shedding](https://www.vldb.org/conf/2006/p799-tatbul.pdf), VLDB 2006 | Sections 1-3 describe window-level dropping to preserve correct subsets of aggregate query results under overload. | Query/window-aware reduction is established. Compare admission accounting for signed evidence costs, not just correct answers versus dropped tuples. |
| [Proof-Infused Streams](https://users.cs.utah.edu/~lifeifei/papers/authenstream.pdf), VLDB 2007 | Stream/query model and authentication methods cover selection and distributive aggregation with authenticated structures. | Signed exact predicate facts are not new alone. Trusted-summary assurance is weaker than independent recomputation of disclosed inputs and must be labeled. |
| [Out-of-order stream verification](https://people.inf.ethz.ch/basin/pubs/tocl19.pdf), author version dated 2019 | Sections 1-3 cover three-valued semantics, knowledge gaps and sound monitoring over unreliable/out-of-order streams. | UNKNOWN and conservative result preservation are established. The research question concerns admission/evidence cost and useful decision yield. |
| [Rational Monitor](https://arxiv.org/html/2408.11627v1), preprint v1 2024-08-21 | Imperfect-information monitoring and observation-budget choices. | Resource-aware monitoring is related; a networking use case alone does not establish an inventive step. |
| [Agent-Native Telemetry](https://arxiv.org/html/2608.16178v1), preprint v1 2026-08-17 | Sections 2-4 disclose scoped evidence, signed batches, acknowledgments, independent checkpoints and a negative-result completeness condition. | Complete negative evidence and compact capsules overlap closely. RCCD's claimed online assurance is limited to trusted summaries; lack of acknowledgments is an operating constraint, not automatically novelty. |
| [VTL revision 11](https://datatracker.ietf.org/doc/html/draft-elkhatabi-verifiable-telemetry-ledgers-11), published 2026-09-06 | Admission/closure/recovery and verification-scope sections define bounded durable artifacts; payload interpretation and safety decisions are outside its profile. | Durable closure and explicit assurance limits are established related work. This is an individual draft, not an adopted standard or patent. |
| [UST specification](https://github.com/thelabmd/UST-Protocol/blob/main/spec/UST-1.0.md), mutable repository reviewed 2026-10-13 | Stream/no-event discussion ties negative assertions to expected signed cadence, gaps and observational coverage. | A broad signed-silence claim overlaps. First public disclosure and exact commit history were not independently pinned. |
| [P16 temporal gap disclosure](https://aiep.dev/specs/p16_aiep_deterministic_temporal_evidence_gap_detection_os/), reviewed 2026-10-13 | Describes versioned gap artifacts and a downstream completeness gate. | Generic gap gating is excluded from the novelty claim. Patent registration and an independently verified publication date were not established. |

Publication/priority dates above are those displayed in the sources; they are not a legal priority determination. The granted EP text, complete patent-family prosecution history and jurisdiction-specific scope remain unresolved.

## Search expansion in N0

In addition to the initial roadmap queries, search terms included:

- "data diode" "evidence" "reservation"
- "telemetry" "predicate" "bandwidth reservation"
- "stream" "authenticated" "load shedding"
- "query preservation" "load shedding" stream
- "window-aware load shedding" "aggregation queries" pdf
- "evidence" "reservation" "telemetry" site:patents.google.com/patent
- "one-way" "manifest" "consistency" "integrity"

The window-aware paper and one-way consistency patent are additional substantive related work found during N0. Source fetches were sometimes intermittent; available primary copies were used. No finding is based solely on a search snippet or secondary summary.

## Narrowed research question

Does coupling irreversible reduction admission to explicit future evidence capacity improve correct definite decisions per byte, relative to the same predicate facts sent with a properly sized fixed periodic evidence reservation, when the forward path can lose traffic and cannot supply receiver feedback?

The fixed-reservation comparator is essential. V1 facts may have a small constant cost per window; if a fixed lane solves the problem equally well, incremental reservations may add no meaningful technical advance.

## Risks and next steps

The ingredients are individually well represented in prior work. The specific coupling still faces an obvious-combination objection; no measured technical advantage exists yet. Continue N1-N10 as a bounded research study and preserve negative findings.

Before filing, a qualified search should compare the concrete state transition/admission method against full families, relevant non-English literature and the filing jurisdiction's requirements. Check source revision histories and the university's ownership/publication policy. Do not use this report to assert novelty, legal eligibility, validity or noninfringement.
