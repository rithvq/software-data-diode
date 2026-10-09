# Feedback-Free Information Preservation for Software-Defined Unidirectional Edge-Fog Gateways

Status: method and evaluation draft; not a publication-ready paper or novelty claim.

## Abstract

We investigate locally controlled information preservation when an Edge-to-Fog
gateway cannot consume receiver-generated application feedback. The software
prototype combines telemetry-specific novelty, operational criticality, freshness,
security relevance, waiting time, starvation prevention, transmission cost, and
obsolescence in an explainable utility function. A deterministic predictor estimates
future local queue pressure. A policy selects sending, delaying, aggregation,
sampling, supersession, or dropping before payload signing. Fog verifies the signed
output and performs storage, analytics, alerting, and visualization. The evaluation
framework compares the same implemented policy under paired workload traces and
local capacity changes. Simulation and testbed measurements are explicitly separated.

## System and Contribution

The target is a software-defined, logically enforced unidirectional communication
gateway, not a hardware data diode. TCP acknowledgements are compatible with the
definition. Fog application acknowledgements and resource/control feedback are
excluded from the adaptive policy's input interface. The proposed contribution is
the integrated local information-preservation mechanism. Priority queues, filtering,
cryptography, and Fog analytics are supporting components, not independently claimed
novelties. See `feedback_free_design.md` for the implemented equations and boundaries.

## Research Hypotheses

1. Utility with local pressure prediction may improve critical-event preservation
   or latency relative to FIFO at matched offered load and configured capacity.
2. Aggregation, sampling, and supersession may reduce estimated transmitted bytes
   while retaining important state changes; they can also reduce information fidelity.
3. Waiting credit and oldest-overdue selection may improve service for admitted
   LOW/MEDIUM messages, with a possible cost to critical-message latency.
4. Density selection during severe pressure may help or hurt different workloads;
   it must be compared separately rather than assumed optimal.

## Method

The implementation uses five telemetry types and configurable normalization scales.
Unseen streams, unusual events, security spikes, and high-novelty transitions are
protected from lossy reductions. Non-event state may be summarized, sampled, or
superseded under congestion. The predictor extrapolates local queue pressure from
arrival rate, configured service capacity, bursts, and queue growth. Selection is
deterministic given configuration, the input trace, and local clock observations.
The policy cannot know whether a locally dispatched state reached Fog.

Aggregation occurs before signing and retains counts, extrema, means, observation
windows, and bounded lists of source IDs. Sequence and envelope timestamp allocation
occur after scheduling. Original sample times remain signed payload metadata.

## Evaluation Protocol

The benchmark uses at least five paired seeds per workload/configuration. Seven
workloads include light to overload, bursts, a critical storm, and a local capacity
step. Comparators include FIFO and priority aging; ablations isolate scheduling,
reduction, and prediction, with a separate density strategy. Full resolved settings,
source SHA-256 fingerprints, workload traces, decision evidence, queue histories,
raw trial CSVs and timestamps are retained. Statistics include mean, median, sample
standard deviation and Student-t 95% confidence intervals.

The current runner measures a discrete-event service model using the production
policy implementation. It does not execute the Fog detector, so message preservation
is never called security or anomaly detection accuracy. Estimated serialized bytes
exclude packet headers and retransmissions. Runner CPU time is not container CPU
utilization. Summarized representation does not establish exact signal reconstruction.

## Results

Use the generated `experiment_summary.md` and raw CSV files for actual trial values.
The report deliberately does not declare the proposal superior. Do not transfer
simulation effects into claims of measured physical-network performance. Paired
comparisons, longer durations, sensitivity to weights/thresholds, burst distributions,
predictor calibration, fault injection, and information reconstruction error remain
necessary before a research publication submission.

## Threats to Validity and Related Work

The configured capacity model omits transport backpressure, retransmission cost,
wireless loss, receiver loss, and restart recovery. FIFO tail-drop and utility-aware
admission differ as part of the treatment; the policy's aggregate gains cannot be
attributed to its scheduling term alone. The existing simulations do not authenticate
individual devices. Software isolation depends on a trusted host and Docker setup.

A systematic review of information/value-aware scheduling, age of information,
Edge data reduction, unidirectional gateways, predictive admission control, and
software isolation is still required. No invented citations, prior-art clearance,
patentability statement, or conference acceptance claim is supplied in this draft.
