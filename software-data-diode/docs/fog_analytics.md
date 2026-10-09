# Fog Analytics

## Processing Pipeline

The Fog Receiver accepts only verified envelopes. The Event Processor converts
them into Fog events, persists accepted telemetry, and forwards them to the
Analytics Engine. Analytics persists anomalies and correlated security events;
the Alert Engine stores the resulting alerts.

## Explainable Detection

Rules are loaded from `config/anomaly_rules.json`:

| Detector | Decision |
|---|---|
| Threshold | A named metric exceeds its configured maximum |
| Moving average deviation | Current value differs from the prior window mean by the configured ratio |
| Z-score | Absolute z-score exceeds the configured threshold after enough history |

The detectors retain bounded per-device, per-metric windows. An anomaly records
the detector, observed value, expected value, score, severity, and an
explanation. No neural network or opaque model is required.

## Cross-Device Correlation

Rules in `config/correlation_rules.json` specify telemetry type, metric,
operator, threshold, time window, cooldown, alert type, and severity. The
default rules detect:

- network packet spike + high system CPU + failed security logins
- elevated environmental temperature + excessive industrial vibration

Each matched condition contributes message, device, metric, value, and timestamp
evidence. A cooldown prevents repeated alerts from the same continuing event.

## Severity and Persistence

Alerts use `INFO`, `WARNING`, `HIGH`, or `CRITICAL` and include:
`alert_id`, timestamp, source devices, type, severity, evidence, and description.
PostgreSQL migrations create accepted telemetry, rejected metadata, security
events, anomalies, alerts, experiment metadata, performance metrics, and
observability snapshot tables.

## Failure Semantics

- Database health is part of Fog readiness.
- Accepted telemetry is not acknowledged by the Event Processor until its main
  telemetry row is stored.
- Persistence and downstream failures return an explicit 502 or 503 and emit a
  structured error log.
- Auxiliary performance metrics are best-effort and cannot change a completed
  business result.
- A security rejection remains rejected and audit-recorded when rejection
  metadata cannot be stored.

