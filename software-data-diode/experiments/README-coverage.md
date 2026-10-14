# N10 Coverage Experiments

This is a local research evaluation, not a novelty, patentability or universal
correctness claim. It leaves the baseline deployment, credentials and volumes alone.

## Run and Regenerate

Run from the `software-data-diode` directory using the existing virtual environment.
Each output directory must be new. The default matrix is bounded to twenty seconds
of virtual ingress plus a four-second deadline, five seeds, fourteen cases and
twelve arms (840 trials). Runtime is longer than virtual time, especially with
SQLite durable commits on Windows.

```powershell
.\.venv\Scripts\python.exe -m experiments.runners.run_coverage --output experiments/results/coverage/my-new-model-run --workers 4
```

The configuration is `experiments/workloads/coverage_workloads.json`. Five to ten
trials are supported; reported configurations require at least five. Invalid
contracts, underfunded evidence budgets and unsafe output identifiers fail before
the matrix starts. Change a copy of the configuration to declare another bounded
matrix, then pass `--config path/to/copy.json`. Use `--no-analysis` to separate
execution from plotting. Model execution in a Docker container is still simulation.
`--case recovery` and `--arm compact_summary` select declared subsets; their saved
configuration records the subset. Completed subsets can be copied into a fresh
bundle only when parameters, contracts, seeds and original/fault hashes match:

```powershell
.\.venv\Scripts\python.exe -m experiments.runners.bundle_coverage --config experiments/workloads/coverage_workloads.json --source path/to/first-run --source path/to/second-run --output experiments/results/coverage/my-new-bundle
```

The bundle retains the exact source manifest per case/trial/arm. It is not another
execution and does not silently claim identical source versions or admission scopes.

```powershell
.\.venv\Scripts\python.exe -m experiments.analysis.coverage_report experiments/results/coverage/my-new-model-run --output experiments/results/coverage/my-new-model-analysis
```

Default regeneration checks original input/fault hashes, admitted originals, real
signed frame costs, capacity pacing, fault application, independent oracle verdicts
and saved metrics before drawing figures. `--tables-only` uses the saved trial CSV
and does not perform that replay; it must not be described as independently verified.
Every figure has PNG, PDF, aggregate CSV and per-trial raw CSV companions.

Actual local transport replay is separate:

```powershell
.\.venv\Scripts\python.exe scripts/run_n10_udp.py --output experiments/results/coverage/my-new-udp-run
.\.venv\Scripts\python.exe -m experiments.analysis.coverage_udp_report experiments/results/coverage/my-new-udp-run --output experiments/results/coverage/my-new-udp-analysis
```

This creates ten fresh disposable Compose projects, two arms by five paired seeds,
with fresh PostgreSQL, trust and state. No host ports are published. The client runs
in the isolated gateway namespace and can send only to its pinned test diode IP and
UDP port. It cannot query Fog. Only host-side measurement queries read Fog afterward.
Cleanup verifies project ownership before removing that project's containers/volumes.
Do not manually apply `docker-compose.n10.yml` to the main project.

The live runner uses `docker-compose.n9.yml` plus the N10 override. For exhausted
Docker network pools, `--allocate-test-subnets` inspects current Docker networks and
host routes, then allocates separate internal test subnets without pruning networks
or changing the daemon. `--cached-images-from software-data-diode-n9-<run-id>` uses
existing explicit test image IDs and read-only current source mounts when registry
access is unavailable. Without that flag, the test images are built normally.
`--smoke` verifies orchestration using one pair and deliberately produces no
comparative confidence-interval report.
All existing containers are audited by default. Only explicitly named network-none
N10 model containers may be excluded using `--concurrent-model-container NAME`;
exclusions are recorded. Do not use this flag for a baseline service.

## Baselines and Ablations

| Arm | Meaning |
|---|---|
| `fifo_gap` | Unfiltered FIFO, signed original-ingress range closure, gap-aware exact monitoring |
| `legacy` | Current InformationEngine/native legacy analytics; conservative original-witness projection for the exact-rule comparison |
| `heartbeat` | Unfiltered FIFO plus authenticated ingress-range heartbeats; no deliberately weakened filtering |
| `compact_summary` | Strong ordinary summary: exact original counts with signed scope/range/limitations in compact N5 binary parts, fixed admission and no advance reservation |
| `fixed_summary` | Matched-format control: original predicate facts, actual RCC codec/repeats/service, no advance evidence reservation |
| `rccd` | Coupled N4 evidence admission and rule-preserving reduction |
| `always_unknown` | Zero-traffic UNKNOWN control; undefined efficiency is not reported as successful detection |
| `no_semantics` | Unsafe mean-as-original predicate claims, test harness only |
| `no_advance` | Advance reservation removed; intentionally identical to the fixed-summary baseline |
| `no_service` | Owned lane quotas removed; bounded frame round robin with hard total pacing |
| `no_repeats` | One evidence/control transmission instead of the default two |
| `no_recovery` | Modeled pending work loss, actual N4 unsupported-fact restart refusal, subsequent admission outage and observer-cache loss |

FIFO and heartbeat intentionally coincide under this frozen closed-window contract:
both have strong authenticated tail barriers, rather than relying on a missing last
sequence to certify absence. This equivalence is disclosed, not hidden.
FIFO is the raw candidate discipline; all arms use the common byte-lane server.
It is not one undifferentiated global wire queue across protected, routine and
evidence classes. Compact summaries omit RCC witness/commitment/chain metadata,
not original predicate semantics, signatures, declared scope or count constraints.
They are a harness baseline, not a new deployed Fog artifact schema.

## Declared Comparison Model

- Same original offered trace, contract/device set, time-indexed seeded fault field,
  capacity/deadline schedule, 64 raw candidates, 256 outbox items, 4 MiB outbox and
  32 MiB ledger bound per arm. Different admission scopes are recorded explicitly.
- Nominal load is based on a 6,500-byte reference size, not measured NIC occupancy.
  Retained actual signed/framed byte totals disclose the resulting true cost.
- Small-link trials use 16 KiB/s (one paired case uses 32 KiB/s), **50% evidence,
  25% protected and 25% routine service**. This is an explicitly funded research
  parameter choice, not the deployment's 10% evidence default. Configuring that
  default at 16 KiB/s is rejected as underfunded for these frozen contracts.
- Raw provenance is added only to serialized signed output, not to policy stream
  attributes. Its signature/framing cost is charged to every raw arm.
- Fixed summaries cannot attach the production N5 framer unchanged. Both summary
  arms use the actual N4 chunk/header interface and external N5 encoding, with
  an assertion that every frame's charged size matches its serialized bytes.
- Every transmitted frame, signed control, header, repeat and 28-byte IPv4/UDP
  overhead is charged. Ethernet/tunnel/NIC overhead is not measured.
- The global model serializer applies the capacity step; the sender's configured
  N4 estimator remains nominal. This is a test model, not dynamic live link sensing.
- Signed observer processing occurs after sender scheduling. No Fog outcome,
  collector statistic or receiver readiness feeds a sender decision.
- Recovery removes pending work in a harness ablation; it does not simulate every
  operating-system crash. N9 retains the separate real process-crash checks.
- Unsupported recovered facts cause an admission outage, not a bypass of N4's
  fail-closed guard. The resulting accepted-scope divergence is explicitly recorded.
- Durations avoid the inherited 256 signing-retention cap. Long-running retirement
  and the missing N4 phase report remain prerequisites for broader studies.

Actual UDP trials replay precomputed N4 artifacts through the production passive
diode and Fog receiver into PostgreSQL. They measure transport/durable receipt
behavior, **not native online gateway admission throughput or policy CPU**. Real
parts may expire or miss deadlines even without a seeded loss adapter. Paired
relative traces have different aligned UTC origins, ephemeral epochs and keys.
Socket instrumentation records no Fog UDP sends; it is not physical isolation or
a new packet-capture proof. Concurrent host workloads affect latency/resources.

## Statistics and Interpretation

The independent N1 full accepted-ingress oracle is the reference. Upstream loss and
local refusal remain separately recorded and are not called false rule decisions.
UNKNOWN is neither FALSE nor successful detection. Evidence facts authenticate a
trusted sender assertion; signatures do not prove hidden observations are truthful.

Per case/arm: mean, median, sample SD, sample count and two-sided Student-t 95%
interval. Paired effects use one within-seed difference per trial, not packets or
rule windows as independent samples. The existing conservative t table gives
2.776 for five trials (four degrees of freedom). Small, bounded/discrete samples
make the normal-mean approximation descriptive; intervals are not proofs.
Missing samples are omitted with `n` shown. Workload/fault strata are not pooled.
Descriptive intervals can cross physical/logical bounds; they are not negative
delay or error measurements. Identical plotted series can overlap; raw/paired
tables retain every baseline identity.
See [Data Dictionary](analysis/coverage_data_dictionary.md) for denominators,
units, counters and scope. Report simple-summary ties/wins and negative outcomes.

Results and limitations from the implementation campaign are in
[N10 Report](../docs/novelty-roadmap/reports/N10.md).
