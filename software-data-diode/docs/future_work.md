# Future Work

## Security and Assurance

- Replace the software boundary with a hardware data diode or FPGA transmitter
  and receiver while retaining the envelope protocol.
- Use per-device identities, hardware-backed keys, certificate rotation, and
  remote attestation.
- Add image signing, SBOM generation, vulnerability scanning, and admission
  policy checks to CI.
- Replace broad in-network CIDRs with authenticated workload identity and
  deployment-specific network policy.
- Commission an independent threat-model review and protocol fuzzing campaign.

## Reliability

- Persist diode queues and replay windows without introducing a reverse
  acknowledgment path.
- Define explicit delivery semantics, dead-letter handling, and disaster
  recovery for Fog storage.
- Support horizontally partitioned gateways and analytics with deterministic
  device ownership.
- Add longer fault-injection and soak tests for restart, disk-full, clock-skew,
  and partial-network failures.

## Analytics and Research

- Calibrate thresholds from domain-labelled data and report false-positive and
  false-negative rates.
- Compare Isolation Forest against deterministic methods without making it a
  required dependency.
- Repeat benchmarks on Linux hosts and representative Edge hardware, recording
  Docker-wide CPU, memory, disk, and network utilization.
- Add paired significance tests and effect sizes where distribution assumptions
  are justified.
- Evaluate scheduler sensitivity across weights, queue capacities, and priority
  distributions.

## Operations and UI

- Add authenticated read-only dashboard access, alert acknowledgement, and
  retention controls.
- Export OpenTelemetry traces while preserving zone isolation.
- Package environment-specific Compose overlays or Kubernetes manifests only
  after equivalent one-way network policy tests exist.

