# Limitations

The system is a **software-defined/logically enforced unidirectional gateway
prototype**.

It demonstrates architectural isolation and security mechanisms but cannot
provide the absolute physical unidirectionality guarantees associated with
hardware data diodes.

Specific limits:

- A privileged Docker host administrator can alter networks, mounts, images,
  clocks, traffic, and secrets.
- Docker `internal` networks provide logical segmentation, not an optical or
  electrical one-way boundary.
- The gateway and diode expose HTTP software endpoints and therefore inherit
  operating-system, container-runtime, dependency, and application risks.
- Private keys are local files, not hardware-backed keys. All simulated devices
  currently share the gateway signing identity.
- Queue contents, replay state, device registry state, and analytics windows are
  in memory and reset on service restart.
- Delivery is at-most-best-effort across process failure; there is no durable
  message broker or end-to-end acknowledgment ledger.
- Readiness probes test immediate dependencies, not full semantic correctness.
- Resource limits are Compose controls and depend on Docker host support.
- The default CIDRs are broad inside isolated Docker networks. Production
  deployment would require stable addresses or authenticated service identity.
- Phase 7 latency and resource values come from a deterministic in-process
  simulation. They do not represent wire-speed hardware-diode performance.
- Anomaly methods are explainable but basic, and fixed thresholds require domain
  calibration. Correlation state is local to one analytics process.
- The Streamlit and Grafana interfaces are local demonstration tools without a
  complete multi-user authorization model.
- Security tests validate known scenarios and cannot prove absence of
  vulnerabilities.

Accordingly, this project is suitable for education, architecture research, and
controlled local evaluation. It is not a substitute for certified hardware in a
high-assurance deployment.

