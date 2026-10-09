# Eight-Phase Research Development Map

## Standalone Phased Track

The renewed phased implementation uses separate Compose projects so each step
can be verified independently: [Phase 1 pipeline](phase1_architecture.md) and
[Phase 2 security](phase2_security.md). Phase 2 stops at secure metadata; the next
step is a dedicated information-utility module without prediction. The older
full-system implementation map below is retained as historical context, not
certification that later phases of this renewed track have been completed.

## Historical Full System

This map supersedes the historical Phase 1-8 descriptions for the research mechanism.
The core decision engine exists from the architecture layer onward; it is not an
optional analytics feature. Historical services and experiments remain available.

| Phase | Research role | Implementation and evidence | Remaining validation |
|---|---|---|---|
| 1: Architecture | Define software-only directionality, local input boundary, policy queue and transport separation | `shared/traffic/information.py`, Edge gateway integration, Compose mode | Live Docker startup and routing in the target environment |
| 2: Integrity | Transform before signing; trace originals and aggregates; audit reasons and utility terms | `shared/models/telemetry.py`, signed source times, `shared/security/audit.py`, integration tests | Device authentication and durable replay-state threat review |
| 3: Research mechanism | Information analyzer, all eight utility terms, local estimator, predictive congestion, six actions, fairness | Configurable engine and `config/information_policy.json`; deterministic tests | Domain calibration, predictor error analysis and adversarial input modeling |
| 4: Fog | Five independent types, verify and persist transformed payloads, analyze/correlate on Fog | Existing five devices, receiver, PostgreSQL, event processor, analytics, alert engine | Interpret aggregate sample counts/windows in each domain-specific analytic |
| 5: Observability | Forward policy evidence to Fog; display utility/actions/local prediction | Gateway observability snapshot, monitoring store and Scheduler view | Visual inspection in a running Docker dashboard |
| 6: Security | Preserve event semantics, reject invalid inputs, audit tamper evidence, no receiver input to policy | Existing isolated security suite plus policy, flood, signing and hash-chain tests | Rerun container reverse-path and attack scenarios on deployed images |
| 7: Evaluation | Paired-seed baselines, reductions/scheduling/prediction ablations, local bandwidth step | `experiments/runners/information_benchmark.py`, raw traces, 5 trials, CIs and graphs | Longer runs, more seeds, real-network loss/CPU/memory, utility calibration and reconstruction fidelity |
| 8: Packaging | Central terminology, configurable deployment, reproducibility and honest claims | README, design specification, manuscript draft, read-only config mount | Live deployment certification, literature/prior-art study and independent research review |

Passing Python tests establishes software behavior covered by those tests. It does
not certify Docker network isolation, hardware diode equivalence, publication
readiness, or patentability. See `feedback_free_design.md` for the operational and
measurement definitions used by the code and report.
