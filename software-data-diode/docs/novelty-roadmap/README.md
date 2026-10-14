# Local novelty development roadmap

Prepared: 2026-10-13 (Asia/Calcutta).
Status: N0-N3 reported complete; N4 code verified but its report is missing. N5-N8 are implemented and verified, including N8 real PostgreSQL/API/scrape/network/browser checks. N9-N11 remain planned. Research mode remains opt-in and separate from HTTP. See N5-N8 for limits, including the inherited signing-retention cap.

Project: C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode

## Selected direction

**Rule-Coverage Data Diode (RCCD)**

Formal working title: **Rule-Preserving Telemetry Reduction and Evidence-Budgeted Forwarding for Software-Defined Unidirectional Gateways**.

The proposed factor is a coupled mechanism: before reducing an observation, the Edge Gateway maintains the facts needed for a preconfigured monitoring rule and reserves the forward bytes needed to disclose those facts. Fog uses authenticated, window-scoped evidence to issue TRUE, FALSE, or UNKNOWN. Missing evidence remains visible.

This is an invention candidate and an engineering research hypothesis. A targeted search found substantial related work. It did not establish novelty, an inventive step, patent eligibility, or freedom to operate. Do not describe it as the first such system or as a patentable invention established by this review.

## Why this belongs in this project

The current gateway already selects, samples, aggregates, supersedes and drops before signing. Its transport sequence numbers identify selected outgoing messages, not every original observation. Fog therefore cannot infer original observation coverage from those sequence numbers. Current anomaly and correlation paths consume received payloads and do not have a rule-specific coverage contract.

RCCD makes this gap the central research question:

> Under a fixed forward byte budget and without receiver feedback, can a gateway reduce telemetry while preserving useful, correct decisions about registered rules, and explicitly expose decisions that cannot be supported?

The product proposition is **less raw telemetry with explicit evidence for each monitoring decision**. Its value must be measured, including the cost of the evidence.

## Read first

- [Prior art and patent assessment](prior-art.md)
- [Technical specification and boundaries](design.md)
- [All copy-paste prompts in one file](prompts/ALL_PHASES.md)
- [N0 completion report and verification evidence](reports/N0.md)
- [N1 pure contracts, oracle and verification report](reports/N1.md)
- [N2 durable admission, bounded state and recovery report](reports/N2.md)
- [N3 signed capsules, offline audit and verification report](reports/N3.md)
- [N3 artifact, commitment and signed-part format](reports/N3-format-v1.md)
- [N5 local forward-only transport, checks and prerequisites](reports/N5.md)
- [N5 framing, budgets and replay semantics](reports/N5-transport-v1.md)
- [N6 durable Fog verification, PostgreSQL checks and limits](reports/N6.md)
- [N7 coverage-aware decisions, versioned history and idempotent alerts](reports/N7.md)
- [N8 coverage dashboard, metrics, local and live verification](reports/N8.md)
- [Frozen v1 contract and independent oracle definition](reports/N0-contract-v1.md)
- [Baseline modes and local integration checklist](reports/N0-integration.md)

## Development phases

The N prefix identifies a new research track. It does not renumber the existing Phase 1-8 work or the standalone Phase 1/2 deployments.

| Phase | Work | Completion evidence |
|---|---|---|
| N0 (complete) | Baseline, prior-art review and specification freeze | [Current implementation, test/Docker snapshot and frozen scope](reports/N0.md) |
| N1 (complete) | Rule contracts and three-valued semantics | [Independent oracle, golden hash and exhaustive contract tests](reports/N1.md) |
| N2 (complete) | Durable observation ledger before filtering | [Crash/rollback, retry, compaction and capacity checks](reports/N2.md) |
| N3 (complete) | Signed Rule Coverage Capsules | [Canonical vectors, immutable sealing, offline audit and bounded signed parts](reports/N3.md) |
| N4 (code verified) | Rule-preserving filtering and evidence budget reservations | 60 prerequisite tests; missing report recorded in [N5](reports/N5.md) |
| N5 (complete) | Forward-only research transport | [Local UDP deployment, bounded replay, no-reply observations and outage tests](reports/N5.md) |
| N6 (complete) | Fog evidence verification and persistence | [Typed assurance, conflict quarantine, transactional publication and real PostgreSQL/outage checks](reports/N6.md) |
| N7 (complete) | Coverage-aware correlation and alerts | [Scoped oracle comparisons, late evidence, conflicts, revision history and Alert Engine checks](reports/N7.md) |
| N8 (complete) | Fog-only coverage dashboard and metrics | [Interactive inspection, stable refresh, PostgreSQL and deployed checks](reports/N8.md) |
| N9 | Adversarial and invariant validation | Machine-readable local security and correctness reports |
| N10 | Repeated baseline and ablation experiments | Raw measurements, paired trials, uncertainty and regenerated figures |
| N11 | Local demo, packaging and invention disclosure | Reproducible demonstration and claims-to-evidence review |

## How to use the prompts

1. Open the project at the path above in your coding agent.
2. Read this roadmap and the specification.
3. Copy the complete fenced prompt for N0 from [ALL_PHASES.md](prompts/ALL_PHASES.md), or the individual prompt file.
4. Let the agent finish that phase and read its evidence and remaining limitations.
5. Continue with N1, then the subsequent phases in order. Each prompt explicitly limits work to its phase.
6. Do not paste all phases together. Later phases depend on tested contracts and artifacts from earlier ones.

The prompts are engineering instructions to paste into the coding agent. They are not PowerShell commands.

## Scope discipline

Keep the five devices, FastAPI services, existing signatures, existing security tests, PostgreSQL, Streamlit and reproducibility utilities. Extend their current responsibilities. Preserve the working deployment and baseline paths.

Replace unsafe interpretation of missing data in the research path. Add durable observation accounting, rule evidence, evidence-aware admission and receiver verification. Do not add blockchain, neural networks, cloud services, a new frontend framework, federated learning, or arbitrary agent infrastructure.

Use local Docker Compose on this Windows machine. Provision rules and keys through local operator configuration. Do not use AWS resources, a cloud deployment, remote experiment hosts or a Fog-to-Edge configuration channel.

## Stop/go decisions

- **N0:** If the coupled mechanism is directly anticipated or its distinction cannot be defended, record that result. Useful engineering can continue, but patent wording must narrow or the project must be repositioned as research.
- **N4:** If evidence does not fit the configured link and storage budgets, reject the configuration or expose unsupported windows. Do not silently assume evidence is free.
- **N9:** Any wrong definite answer within the stated trusted-ingress model is a correctness failure. Fix it before evaluating performance.
- **N10:** If simple summaries and signed heartbeats achieve the same decision yield and resource use, report that result. Do not hide the strongest baseline.
- **N11:** Discuss filing and publication order with your faculty and an appropriate patent professional before public disclosure. A completed prototype is not a patentability determination.

## Deliverables and current status

This folder contains the proposed design, prior-art assessment, twelve build prompts and N0-N3/N5-N8 reports and evidence. N4 provides coupled admission and byte accounting. N5 integrates isolated UDP, charged signed frames and bounded reorder/reassembly. N6 adds durable verification and PostgreSQL facts. N7 adds scoped three-valued rules, independent coverage health, revision history, checked original-witness disclosures and recoverable Alert Engine delivery. N8 adds opt-in inspection and metrics with local and real database/deployment evidence. Existing HTTP/standalone deployments remain preserved. Repeated comparative performance campaigns remain future work. The existing N4 signing-retention cap still requires a reviewed long-run retirement procedure; N8 does not reset it.

Future phase reports should live in docs/novelty-roadmap/reports/Nxx.md. New experimental artifacts should use new directories under experiments/results/coverage/ and must not overwrite prior results.
