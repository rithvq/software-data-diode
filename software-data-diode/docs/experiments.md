# Experiments

## Current Research Evaluation

The current mechanism is described in [Feedback-free design](feedback_free_design.md).
Run `python -m experiments.runners.information_benchmark --output <new-directory>`
for the production information-policy engine, seven workloads, seven configurations,
five paired trials, prediction/reduction/scheduling ablations, and a bandwidth step.
Raw decisions and traces are retained. Regenerate plots with
`python -m experiments.analysis.information_report <directory>`.

The results are modeled policy outcomes. Estimated bytes exclude protocol overhead;
sample representation can include aggregates. The new runner does not label message
preservation as attack/anomaly detection or runner CPU time as container CPU usage.

## Historical Phase 7 Evaluation

The remainder describes the earlier filter/scheduler experiment. It does not
evaluate the new eight-term utility mechanism. Its detection metrics are simulated
delivery proxies, not executions of the Fog detectors or proof of detection accuracy.

The reproducible Phase 7 framework is in `experiments/`. It runs the production
filter and scheduler in a deterministic discrete-event harness and retains raw
data for every graph.

## Matrix

The four configurations are direct forwarding + FIFO, filtering + FIFO,
adaptive scheduling only, and adaptive scheduling + filtering. Six workloads
cover 25%, 50%, 90%, 150%, a 3x burst, and a HIGH/CRITICAL storm. Every
configuration uses five repeated seeded trials and paired arrival traces.

Run:

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py
```

Regenerate analysis from existing raw data:

```powershell
.\.venv\Scripts\python.exe -m experiments.analysis.analyze --result-dir experiments\results\phase7
```

## Statistical Method

For each workload/configuration/metric group, analysis reports mean, median,
sample standard deviation, and two-sided 95% Student-t confidence intervals.
Measured metrics include throughput, p50/p95/p99 latency, priority latency,
queue wait and utilization, drops, process CPU, peak Python memory, bandwidth
saving, detection latency, fairness, and starvation.

## Retained Evidence

`experiments/results/phase7/` contains the manifest, exact configuration,
trial/message/queue CSV files, aggregate tables, scheduler comparison, Markdown
summary, and ten PNG/PDF figures with a same-named source CSV.

The completed 120-trial run used seed `20260902`. Its proposed configuration
measured 48.5% to 67.3% bandwidth saving across the six workloads. In the
unfiltered scheduler comparison, CRITICAL p95 improvement ranged from 6.1% at
light load to 97.9% in overload; adaptive LOW starvation matched FIFO in these
traces. These are simulation-harness measurements, not claims about arbitrary
hardware or networks. See `experiments/results/phase7/experiment_summary.md`
for all confidence intervals and objective results.

The longer methodology and measurement-boundary discussion remains in
`docs/phase7_experiments.md`.
