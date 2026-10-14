# N10 Data Dictionary

All model metrics are one row per independent trial/arm/case. Five rows, not the
packets or eighteen rule windows inside them, are the repeated-trial sample.
Actual UDP rows are a distinct measurement scope and must never be pooled with
model rows. Synthetic threshold values are the frozen demonstration contract.

## Identity and Retained Files

| File/Field | Meaning |
|---|---|
| `configuration.json`, `contract.json` | Full declared workload settings and immutable typed rule meaning |
| `start-manifest.json`, `manifest.json` | Seed/configuration, source SHA-256 map, revision, dependency versions, timestamps and execution scope |
| Bundle manifest `parents`, `pair_sources` | Exact source manifest/run per case/trial/arm; bundling is not another execution or a claim of identical source versions |
| `original_trace.jsonl.gz` | Generated input, relative `at_us`, source ID, priority, canonical message and upstream-delivery bit |
| `fault_schedule.jsonl.gz` | Seeded absolute millisecond field; loss/delay uniforms indexed by transmitted completion time |
| `*-accepted.jsonl.gz` | Exactly the durably admitted original inputs, ingress sequence/epoch/time and source ID; oracle scope |
| `*-artifacts.jsonl.gz` | Immutable signed raw/state/evidence frames, base64 encoded once per artifact |
| `*-forward.jsonl.gz` | Frame part, repeat flag, size, start/finish/arrival, drop outcome and fault slot |
| `*-queue.jsonl.gz` | Sampled local outbox items/bytes, reserved wire bytes and pending obligations |
| `*-context.json` | Public trust profile/key, UTC origin, local restart events and trial accounting/resource metrics |
| `*-verdicts.csv` | Rule/window oracle truth, observed truth, deadline, first definite time and UNKNOWN duration |
| `trace_hash`, `fault_hash` | Paired input/fault fingerprints; unequal values reject pairing |
| `accepted_trace_hash` | Accepted populations excluding epoch namespace; divergences disclosed in paired tables |
| `statistics.csv` | Independent-trial summary per metric/case/arm, including observed n and missing samples |
| `paired_differences.csv` | RCCD minus comparator, within-seed samples and accepted-scope equality count |
| Figure `-raw.csv` / `.csv` | Per-trial samples / aggregated plotted points, adjacent to PNG and PDF |
| `postgres_receipts.json` | Actual committed Fog rows with stored original receiver timestamps and signed parts |
| `resources.jsonl` | Bounded host-side Docker snapshots; independent of sender policy |
| `actual_attempts.jsonl.gz` | Actual send-only UDP attempts and planned/actual wall-clock send times |

Capsule counts remain **AUTHENTICATED_SUMMARY**, not independently checked physical
facts. Oracle recomputation uses retained originals only for offline experiment
validation; those originals are not magically available to live Fog or sender policy.
No production credentials or private signing keys are exported.

## Model Metrics

| Metric | Unit / denominator / interpretation |
|---|---|
| `opportunities` | Contract rules times declared ingress windows, including no-input/missing-device opportunities |
| `correct_definite`, `decision_yield` | Correct TRUE/FALSE count by deadline; yield divides by **all opportunities**, including oracle UNKNOWN |
| `false_false`, `false_true` | Counts of observed FALSE/oracle TRUE and observed TRUE/oracle FALSE respectively |
| `wrong_definite` | Any observed definite contradicting the oracle, including a definite answer when oracle is UNKNOWN; cannot be hidden by the two narrower error counts |
| `unknown_rate`, `deadline_misses` | UNKNOWN/all opportunities at deadline; missing evidence is not a negative finding |
| `unknown_duration_seconds` | Mean UNKNOWN time from window closure to its deadline, capped by that deadline; not continuous-time physical event duration |
| `decisions_per_kib` | Correct definite count / (`wire_bytes`/1024); null if no forward bytes |
| `incident_recall` | Correct TRUE `incident-correlation` windows / oracle-positive incident windows; null if none |
| `positive_rule_recall` | Correct TRUE windows / oracle-positive windows across all rules; separate from incident recall |
| `incident_opportunities`, `positive_opportunities` | Positive incident / all-positive-rule denominator counts |
| `latency_p50/p95/p99_seconds` | Interpolated quantiles of exact-original raw receipt minus accepted ingress time; not lost/reduced samples |
| `critical_latency_*`, `high/medium/low_latency_*` | Same quantiles within priority; null when that priority has no exact raw receipts; sample counts retained |
| `decision_latency_*` | First-ever observed definite time minus window closure, clamped at zero for early positive witnesses; a final UNKNOWN can retain earlier definite history, while never-definite windows have no sample |
| `queue_wait_*` | First local attempted frame start minus ingress of that raw work; attempted work only, not a delivery guarantee |
| `raw_detail_availability`, `raw_receipts` | Unique exactly received original identities / accepted identities (and count); aggregates excluded; historical receipt availability, not a promise of post-crash cache retention |
| `generated`, `upstream_lost`, `admission_refused`, `accepted` | Generated, before-admission loss, local refusal and committed accepted counts, respectively; different scopes |
| `refusal_reasons` | Local refusal reason/count JSON, not Fog feedback |
| `generated_bytes` | Compact sorted canonical input JSON bytes before signing, including upstream-lost generated inputs |
| `raw_bytes` | Attempted signed raw UDP payload bytes, including signed envelope and transport headers/parts |
| `evidence_bytes`, `state_bytes` | Attempted signed RCC or compact predicate-summary / local-state or range-heartbeat UDP bytes, repeats included; compact summaries use signed STATE-format parts classified as logical evidence |
| `wire_bytes` | All attempted UDP bytes plus modeled 28-byte IPv4/UDP overhead per attempted part, including dropped/repeated frames |
| `repeat_bytes` | Wire-byte subset for configured repetitions after the first; **do not add it again** to wire totals |
| `framing_bytes` | Attempted raw/state fixed signed headers plus RCC signed part envelopes; subset of UDP bytes, not additional cost |
| `evidence_fraction` | `evidence_bytes` / all attempted UDP payload bytes; includes RCC/compact-summary repeats but excludes ordinary heartbeat/local-state bytes from numerator |
| `bandwidth_saving` | (`generated_bytes` - `wire_bytes`)/`generated_bytes`; a fraction, not percent; can be negative, and includes explicitly different generation/forward scopes |
| `modeled_capacity_bytes`, `budget` | Integral of byte-capacity schedule over ingress+deadline / nominal bytes per second |
| `charged_local_bytes` | N4 locally charged grants; includes an unfinished canceled grant that need not appear in completed attempted wire bytes |
| `lost_frames`, `cancelled_charged_grants` | Injected dropped frames / grants unable to finish within the bounded run |
| `raw_dropped_originals`, `raw_reduced_originals` | Durable final local original dispositions; not inferred receive loss |
| `queue_max_items/bytes`, `queue_average_items` | Maximum and arithmetic mean of sampled outbox snapshots; mean is **not** a continuous-time integral |
| `outbox_final_bytes`, `unsupported_scopes` | Remaining bounded local work and evidence limitations at stop |
| `storage_bytes` | Final SQLite accounting (including durable auxiliary files according to existing ledger status); not total host disk use |
| `runner_cpu_seconds/percent`, `runner_wall_seconds` | Model process CPU / wall and 100*CPU/wall; common ledger, signing and harness overhead included; not native gateway CPU |
| `runner_sampled_rss_bytes` | Maximum observed process RSS, not a guaranteed instantaneous peak; worker imports/order/contention matter |
| `runner_peak_python_bytes` | Optional tracemalloc Python heap maximum; null when disabled (default); not zero memory |
| `receiver_rejections` | Model observer parse/verification rejections, not attack detection rate |
| `native_legacy_anomalies/alerts` | Actual legacy received-payload detector/correlation output counts; not exact RCC rule decisions |

Zero opportunities, generated bytes or accepted originals give null corresponding
ratios. Zero forward bytes give null efficiency/evidence fraction. No positive
incidents and no received priority samples give null recall/latency. Count zero and
missing sample are distinct. SD uses `n-1`; CI is unavailable for fewer than two
metric samples. Quantiles within a trial are not additional repeated trials.
Descriptive t intervals can cross physical/logical bounds; they are not negative
delay measurements or exact bounded-proportion intervals. Compact-arm and repaired
recovery batches retain separate source/timing provenance, additionally confounding
model CPU comparisons through batch/import/host contention.

## Actual UDP Metrics

`measurement_scope` is `ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY`, not simulation and not
online policy throughput. Yield uses signed facts/raw originals observed by stored
receiver timestamps before the same four-second deadline. A PostgreSQL row is
required for this analysis; its timestamp is not commit completion latency.
`paired_relative_trace_hash` removes absolute input timestamps only; relative
times, generated messages, priority and upstream-delivery outcomes remain paired.

`attempted_udp_bytes` sums actual socket attempts. `attempted_model_wire_bytes`
adds 28 bytes per attempt; it is not a NIC capture measurement. `send_errors` and
schedule slip describe sender-local attempts, not Fog receipt. Critical latency
uses exactly persisted, nonaggregate raw originals. Fog queue/spool/partial
measurements are snapshots, not claimed peaks. `fog_udp_reply_calls=0` is observed
socket instrumentation, not enforcement against a privileged host administrator.

Docker CPU percent can exceed 100% for multiple cores. Live resource analysis
uses snapshots inside each replay interval, yielding one mean CPU and observed
maximum memory per service/trial. Startup/preparation samples are excluded.
Five trial aggregates, not individual scrapes, enter resource confidence intervals.
Missing or failed scrapes are explicitly counted. Memory units are parsed as
decimal or binary as displayed. Concurrent baseline/model workloads are a limitation.
