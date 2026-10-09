# Phase 7 Experimental Evaluation

Phase 7 provides a configuration-driven, repeated-trial benchmark for the Edge
filter and data-diode scheduler. It uses the production `EdgeFilter`,
`BoundedMessageQueue`, and `AdaptiveScheduler` implementations in a deterministic
discrete-event harness. This makes runs fast, repeatable, and independent of host
network timing.

## Directory Layout

```text
experiments/
  workloads/phase7_workloads.json
  runners/benchmark.py
  runners/run_phase7.py
  analysis/analyze.py
  results/phase7/
```

The workload JSON is the source of truth for seeds, duration, capacity, queue
size, filtering parameters, configurations, load levels, bursts, and priority
distributions. The runner rejects configurations with fewer than five trials.

## Compared Configurations

| ID | Filtering | Scheduler | Interpretation |
|---|---:|---|---|
| `baseline_a_direct` | no | FIFO | Direct Edge forwarding into a FIFO diode |
| `baseline_b_fifo` | yes | FIFO | Filtered FIFO diode baseline |
| `adaptive_only` | no | adaptive | Scheduling ablation |
| `proposed` | yes | adaptive | Filtering and adaptive scheduling |

Every workload/trial arrival sequence is generated once and reused across all
four configurations. This paired design avoids giving one configuration an
easier random traffic trace.

## Workloads

The default capacity is 40 messages/s over 30 simulated seconds:

| Workload | Offered load | Special behavior |
|---|---:|---|
| A - Light | 25% | Standard priority mix |
| B - Moderate | 50% | Standard priority mix |
| C - Near saturation | 90% | Standard priority mix |
| D - Overload | 150% | Standard priority mix |
| E - Burst | 50% base | 3x rate from 40% to 60% of the run |
| F - Critical-event storm | 90% | 35% HIGH and 25% CRITICAL before tagged events |

Arrivals follow seeded Poisson processes. Detectable anomaly and attack events
are explicitly tagged and assigned HIGH and CRITICAL priority respectively.

## Run

Install the development requirements once:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run all 120 default trials: six workloads, four configurations, and five seeds.

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py
```

Use a different fully recorded configuration or result directory:

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --config experiments\workloads\phase7_workloads.json --output-dir experiments\results\phase7
```

To persist the manifest and analysis references to the existing PostgreSQL
experiment table, set `DATABASE_URL` and add `--persist-to-database`.

## Outputs

```text
configuration.json
experiment_manifest.json
raw_trials.csv
message_metrics.csv
queue_timeseries.csv
aggregate_statistics.csv
scheduler_comparison.csv
experiment_summary.md
figures/*.csv
figures/*.png
figures/*.pdf
```

`experiment_manifest.json` records the experiment ID, base and trial seeds,
software version, source/config SHA-256 fingerprint, environment, and UTC start
and completion timestamps. Each trial row also records its seed, configuration,
software version, and timestamps.

Regenerate every table and graph from retained raw CSV data:

```powershell
.\.venv\Scripts\python.exe -m experiments.analysis.analyze --result-dir experiments\results\phase7
```

## Statistics

For each workload/configuration/metric group the analyzer reports:

- arithmetic mean
- median
- sample standard deviation
- two-sided 95% Student-t confidence interval

Scheduler latency and starvation comparisons use the paired unfiltered FIFO and
adaptive-only arms, isolating the scheduler. Queue-overflow reduction compares
direct FIFO with the full proposed arm. Positive improvement percentages indicate
a lower measured value in the compared adaptive/proposed arm; negative values
indicate an increase.

LOW starvation counts scheduled LOW messages that are dropped or wait longer
than the configured threshold. Fairness is Jain's fairness index over per-priority
delivery ratios.

## Measurement Boundary

Latency, queueing, throughput, drops, and bandwidth are simulated-time results
from the production filtering and scheduling algorithms. CPU utilization uses
Python process CPU time divided by wall time, and peak memory uses `tracemalloc`.
Those resource values characterize the in-process benchmark, not the entire
Docker deployment.

Anomaly and attack detection latency is the end-to-end simulated delay until a
tagged detectable event reaches Fog; detection is modeled as immediate at Fog.
The detection-rate graph therefore measures whether tagged security events
survive filtering, congestion, and queue admission. Cryptographic detection
correctness and wall-clock response are evaluated separately by Phase 6.

The generated report states measurements and confidence intervals without
automatically claiming that the proposed system is better.
