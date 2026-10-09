# Phase 4 Architecture

## Runtime Flow

```text
edge-device-01 (environmental) --+
edge-device-02 (system) ---------+
edge-device-03 (network) --------+--> Edge Gateway --> Software Data Diode
edge-device-04 (security) --------+                         |
edge-device-05 (industrial) ------+                         v
                                                  Fog Receiver
                                                       |
                                                       v
                                                Event Processor
                                                       |
                                                       v
                                             Fog Analytics Engine
                                                  |          |
                                                  v          v
                                             PostgreSQL  Alert Engine
                                                              |
                                                              v
                                                         PostgreSQL
```

The Fog Receiver also writes rejection metadata directly to PostgreSQL. Invalid or
untrusted envelopes never enter the Event Processor.

## Responsibility Boundary

### Edge

- Edge devices generate domain-specific telemetry from independent configurations.
- The Edge Gateway validates, filters, aggregates, deduplicates, and assigns priority.
- The gateway signs each accepted envelope and tracks health, activity, rates,
  filtering, priority counts, and sequence numbers independently per device.

### Software Data Diode

- Accepts traffic only from the diode-side subnet.
- Applies a bounded queue, adaptive scheduling, congestion monitoring, and egress
  rate control.
- Bridges the diode network to Fog ingress without joining either Edge or Fog
  processing networks.

### Fog

- The receiver verifies hashes, signatures, freshness, duplicates, and replay state.
- The Event Processor persists accepted telemetry and creates trusted Fog events.
- Fog Analytics runs threshold, moving-average deviation, and z-score detection.
- Configurable correlation rules combine evidence across devices and time windows.
- The Alert Engine stores complete INFO, WARNING, HIGH, and CRITICAL alerts.
- PostgreSQL stores telemetry, rejections, anomalies, security events, alerts,
  experiment metadata, and performance metrics.

## Network Isolation

```text
edge-network         edge devices + Edge Gateway
diode-network        Edge Gateway + Software Data Diode
fog-ingress-network  Software Data Diode + Fog Receiver
fog-services-network Fog Receiver + Event Processor + Analytics + Alerts + PostgreSQL
```

All networks are Docker `internal` networks. Docker allocates available subnets at
startup to avoid collisions with VPNs and existing Docker projects. Only the
required bridge service joins each adjacent pair. PostgreSQL and Fog Analytics are
not addressable from the diode, Edge Gateway, or Edge devices.

This is a software-enforced one-way architecture. It demonstrates protocol and
network separation, but it is not equivalent to a hardware data diode.

## Explainable Analytics

Rules live in:

```text
config/anomaly_rules.json
config/correlation_rules.json
```

Threshold findings identify the configured bound. Moving-average findings include
the recent expected value and deviation ratio. Z-score findings include the mean and
score. Every anomaly records its detector, source message, metric, observed value,
expected value, severity, and explanation.

The default cross-device security rule requires all of the following within 60
seconds:

```text
network packets_per_second >= 8000
system cpu_usage >= 90
security failed_logins >= 5
```

It creates a CRITICAL `POTENTIAL_SECURITY_INCIDENT` alert with evidence from all
source messages. Rule cooldowns suppress repeated alerts from the same evidence
pattern.

## Persistence

PostgreSQL initializes from `database/migrations/001_phase4_schema.sql`. The named
volume `fog-postgres-data` retains records across container restarts. Migrations in
`docker-entrypoint-initdb.d` run when a new database volume is first initialized.
The `device_telemetry_summary` and `alert_severity_summary` database views prepare
stable aggregates for a later visualization layer without moving visualization into
the Edge or transport tiers.
