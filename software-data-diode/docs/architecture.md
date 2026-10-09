# Final Architecture

The current research mode is specified in [Feedback-free design](feedback_free_design.md).
It is a software-defined, logically enforced unidirectional communication gateway.
TCP acknowledgements are permitted; Fog application feedback does not drive its policy.

## Responsibility Boundaries

| Layer | Responsibilities |
|---|---|
| Edge devices | Generate domain telemetry with independent rates, seeds, and traffic profiles |
| Edge Gateway | Validate, track devices, analyze information, estimate local pressure, predict congestion, score utility, choose six actions, queue, then sign |
| Software Data Diode | Forward signed research output in FIFO order through bounded transport, rate-limit, audit; legacy adaptive scheduling remains available separately |
| Fog Receiver | Verify schema, hash, signature, timestamp, UUID, and sequence |
| Fog services | Persist events, detect anomalies, correlate devices, create alerts |
| Observability | Prepare Fog-side dashboard data and scrape zone-local metrics |

The dashboard reads only the Fog-side `monitoring-api`. It has no Edge or diode
network attachment.

## Full Architecture

```mermaid
flowchart TB
  subgraph EDGE["EDGE ZONE"]
    E1["Edge 01\nEnvironmental"]
    E2["Edge 02\nSystem"]
    E3["Edge 03\nNetwork"]
    E4["Edge 04\nSecurity"]
    E5["Edge 05\nIndustrial"]
    GW["Edge Gateway\nInformation utility / Prediction / Policy\nQueue / Transform / Sign"]
    E1 --> GW
    E2 --> GW
    E3 --> GW
    E4 --> GW
    E5 --> GW
  end

  subgraph DIODE["SOFTWARE DATA DIODE"]
    DD["Bounded FIFO Transport\nRate Limiter\nAudit Chain"]
  end

  subgraph FOG["FOG ZONE"]
    FR["Fog Receiver\nCryptographic Verification"]
    EP["Event Processor"]
    DB[("PostgreSQL")]
    FA["Fog Analytics\nAnomaly + Correlation"]
    AE["Alert Engine"]
    API["Monitoring API"]
    UI["Streamlit Dashboard"]
    FR --> EP
    EP --> DB
    EP --> FA
    FA --> DB
    FA --> AE
    AE --> DB
    DB --> API --> UI
  end

  subgraph OBS["OBSERVABILITY CONTROL"]
    PF["Fog Prometheus"]
    PE["Edge-side Prometheus"]
    G["Grafana"]
    PF --> G
    PE --> G
  end

  GW --> DD --> FR
  PE -. scrape .-> GW
  PE -. scrape .-> DD
  PF -. scrape .-> FR
  PF -. scrape .-> EP
  PF -. scrape .-> FA
  PF -. scrape .-> AE
```

## Trust Boundaries

```mermaid
flowchart LR
  subgraph EN["edge-network (internal)"]
    ED["5 Edge devices"] --> GW["Gateway"]
  end
  subgraph DN["diode-network (internal)"]
    GW --> DD["Data Diode"]
    PE["Prometheus Edge"] -. scrape .-> GW
    PE -. scrape .-> DD
  end
  subgraph FI["fog-ingress-network (internal)"]
    DD --> FR["Fog Receiver"]
  end
  subgraph FS["fog-services-network (internal)"]
    FR --> FP["Fog processing"]
    FP --> DB[("PostgreSQL")]
    DB --> DASH["Monitoring API / Dashboard"]
    PF["Prometheus Fog"] -. scrape .-> FP
  end
  subgraph OC["observability-control-network (internal)"]
    PE --> G["Grafana"]
    PF --> G
  end
```

The Data Diode is the only normal service attached to both `diode-network` and
`fog-ingress-network`. The Fog Receiver is not attached to `edge-network` or
`diode-network`, so Docker DNS and routing do not provide a Fog-to-Edge path.

## Message Data Flow

```mermaid
sequenceDiagram
  participant E as Edge device
  participant G as Edge Gateway
  participant D as Data Diode
  participant R as Fog Receiver
  participant P as Event Processor
  participant A as Fog Analytics
  participant DB as PostgreSQL
  participant L as Alert Engine

  E->>G: Raw telemetry
  G->>G: Validate, filter, prioritize, sequence, sign
  G->>D: Secure envelope
  D->>D: Rate-limit, enqueue, schedule
  D->>R: Forward-only delivery
  R->>R: Schema, hash, signature, freshness, replay checks
  R->>P: Verified envelope
  P->>DB: Accepted telemetry
  P->>A: Fog event
  A->>DB: Anomaly / security event
  A->>L: Alert
  L->>DB: Stored alert
```

## Traceability

`message_id` is generated at the gateway and reused as `correlation_id` in JSON
logs. `device_id`, sequence number, priority, audit entries, database rows, and
Prometheus labels preserve a message's origin across the forward path.
