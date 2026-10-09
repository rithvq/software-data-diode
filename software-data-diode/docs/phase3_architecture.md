# Phase 3 Architecture

## Goal

Phase 3 adds adaptive scheduling, traffic prioritization, congestion awareness, bounded queues, edge data reduction, and reproducible FIFO-vs-adaptive experiments.

The secure one-way flow remains:

```text
Edge Device -> Edge Gateway -> Software Data Diode -> Fog Receiver
```

## Priority Classification

Priority rules are centralized in `shared/traffic/priority.py`.

Default rules:

```text
intrusion/security/attack event -> CRITICAL
temperature >= 38.0 -> HIGH
temperature >= 34.0 -> MEDIUM
CPU or memory >= 85.0 -> MEDIUM
warning/abnormal/degraded status -> MEDIUM
routine telemetry -> LOW
```

The selected priority is included in the signed envelope. Any later modification of priority invalidates the Ed25519 signature.

## Edge Filtering

The Edge Gateway applies filtering before signing:

1. Duplicate filtering based on recent device/payload fingerprints.
2. Change-based filtering for low-priority telemetry.
3. Sampling for low-priority telemetry when a configured congestion state is active.
4. Aggregation of filtered low-value samples.

CRITICAL messages bypass filtering and aggregation.

## Adaptive Scheduler

The diode uses `BoundedMessageQueue` plus either FIFO or `AdaptiveScheduler`.

Score formula:

```text
Score =
    Wp * Priority
  + Wa * WaitingAge
  + Wu * Urgency
  + Wc * CongestionFactor
  + Ws * StarvationFactor
  - Wb * EstimatedTransmissionCost
```

Terms:

```text
Priority: Numeric value for CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1.
WaitingAge: Seconds the message has waited in the diode queue.
Urgency: Deterministic signal from priority and payload conditions.
CongestionFactor: Queue-utilization state multiplied by message priority.
StarvationFactor: Waiting-time boost after the starvation threshold.
EstimatedTransmissionCost: Signed estimate of message byte cost.
```

The effective priority increases with waiting time:

```text
Effective Priority = Original Priority + Waiting-Time Boost
```

This is what lets old LOW messages eventually outrank fresh higher-priority work.

## Congestion States

The diode monitors:

```text
queue length
queue utilization
incoming rate
outgoing rate
recent latency
processing load
```

Default states:

```text
NORMAL: queue utilization < 50%
ELEVATED: queue utilization >= 50%
CONGESTED: queue utilization >= 75%
CRITICAL: queue utilization >= 90%
```

## Queue Overflow

The queue is bounded by `MAX_QUEUE_SIZE`.

Overflow behavior:

```text
LOW incoming message: drop if the queue is full.
MEDIUM/HIGH/CRITICAL incoming message: evict a lower-priority queued message if one exists.
CRITICAL message: retained whenever lower-priority capacity can be recovered.
```

Every drop generates metrics and a tamper-evident audit event.

## Experiments

Run:

```powershell
python scripts/run_experiments.py --output-dir experiments/results
```

Scenarios:

```text
normal_load
near_capacity
overload
critical_burst
```

Each scenario is run with:

```text
fifo
adaptive
```

Output formats:

```text
JSON: experiments/results/phase3_results.json
CSV:  experiments/results/phase3_results.csv
```

The output supports these research questions:

1. Does adaptive scheduling reduce CRITICAL latency?
2. What is the effect on LOW-priority latency?
3. Does starvation prevention eventually transmit old LOW messages?
4. How many bytes are filtered at the edge?
5. How does queue occupancy change?
6. Does behavior remain stable under burst traffic?
