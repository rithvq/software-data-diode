# Phase 5 Observability

## Trust-Zone Design

The dashboard is a Fog consumer. It is attached only to `fog-services-network` and
its only application dependency is `monitoring-api`.

```text
Edge Gateway -- authenticated snapshot --> Data Diode
Data Diode   -- forward-only snapshot ---> Fog Receiver --> PostgreSQL
                                                        --> Monitoring API
                                                        --> Streamlit
```

No dashboard code contains an Edge Gateway or Data Diode address. Component health
for those tiers is inferred from recent snapshots that already crossed the diode in
the permitted direction. Fog component health is checked locally from the
Monitoring API.

Prometheus is split by trust zone:

```text
prometheus-edge: diode-network only; scrapes Edge Gateway and Data Diode
prometheus-fog:  fog-services-network only; scrapes Fog services
```

Both collectors also expose only their read APIs to the isolated
`observability-control-network`, where optional Grafana runs. This avoids a shared
application network between Edge and Fog.

## Streamlit Views

- Architecture: live Edge nodes, gateway, diode, and Fog component health.
- KPIs: generation, acceptance, rejection, rates, latency, queue, active nodes,
  alerts, and filtering.
- Scheduler: throughput and drops by priority, latency, queue waiting time,
  congestion, and score distributions.
- Security: rejection categories and tamper-evident audit-chain state.
- Fog analytics: latest anomalies, severity, active alerts, timelines, and telemetry
  trends.

The dashboard refreshes every three seconds by default. Empty, unavailable, and
healthy states are explicit.

## Metrics

Every HTTP service exposes Prometheus text format at `/metrics`. Important series:

```text
messages_received_total
messages_forwarded_total
messages_rejected_total
queue_size
queue_wait_seconds
end_to_end_latency_seconds
signature_failures_total
replay_attempts_total
filtered_bytes_total
transmitted_bytes_total
scheduler_score
dropped_messages_total
service_health
audit_log_valid
```

Histograms preserve distributions for p95 calculations instead of publishing only
precomputed averages.

## Grafana Provisioning

Grafana is optional through the `observability` Compose profile. Datasources and
dashboards are loaded from `observability/grafana` without manual UI setup:

```text
System Health
Throughput
Security
Scheduler Performance
Edge and Fog Workload
```

## Structured Logging

`shared/observability/logging.py` emits JSON logs to standard output. The message ID
is reused as the correlation ID after the gateway creates the signed envelope, so a
single message can be followed through gateway, diode, receiver, event processor,
analytics, and alert creation.

The observability snapshot token authenticates the internal metrics route. Replace
the development default through `OBSERVABILITY_TOKEN` outside local demonstrations.
