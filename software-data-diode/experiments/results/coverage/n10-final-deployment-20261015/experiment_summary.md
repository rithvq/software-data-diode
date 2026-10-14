# N10 Actual Docker/UDP Artifact Replay

Separate five paired trials per arm; not online policy performance.
Gateway sender cannot resolve/query Fog; all actual frames pass the passive diode. Local send success is not receipt.

| Arm | Metric | n | Mean | Median | SD | 95% CI |
|---|---|---:|---:|---:|---:|---|
| rccd | decision_yield | 5 | 0.70000 | 0.72222 | 0.1009216784699164 | [0.5747092743818365, 0.8252907256181634] |
| rccd | unknown_rate | 5 | 0.30000 | 0.27778 | 0.10092167846991638 | [0.17470927438183653, 0.42529072561816345] |
| rccd | raw_detail_availability | 5 | 0.91861 | 0.97368 | 0.09079528765939804 | [0.8058863535642603, 1.031324686458156] |
| rccd | critical_latency_p95_seconds | 4 | 1.05842 | 0.99671 | 0.549845519141785 | [0.18361254795392068, 1.9332209898630808] |
| rccd | attempted_model_wire_bytes | 5 | 353590.40000 | 350464.00000 | 23160.092957499113 | [324837.9565604653, 382342.8434395348] |
| fixed_summary | decision_yield | 5 | 0.70000 | 0.66667 | 0.07453559924999299 | [0.6074666666666666, 0.7925333333333333] |
| fixed_summary | unknown_rate | 5 | 0.30000 | 0.33333 | 0.07453559924999299 | [0.20746666666666666, 0.3925333333333333] |
| fixed_summary | raw_detail_availability | 5 | 0.91861 | 0.97368 | 0.09079528765939804 | [0.8058863535642603, 1.031324686458156] |
| fixed_summary | critical_latency_p95_seconds | 4 | 1.12636 | 1.12003 | 0.532382961200692 | [0.2793383979653864, 1.973380980505988] |
| fixed_summary | attempted_model_wire_bytes | 5 | 353661.60000 | 350992.00000 | 23220.137807515268 | [324834.6129842761, 382488.58701572387] |

RCCD minus fixed-summary yield paired difference: {"n": 5, "mean": 0.0, "median": 0.05555555555555547, "stddev": 0.0785674201318386, "ci95_low": -0.09753869760697131, "ci95_high": 0.09753869760697131}

CPU/memory raw Docker time series and real PostgreSQL receipt timestamps are retained per trial. UDP/IP wire overhead is modeled, not a NIC packet-capture measurement.
No superiority or patentability inference is automatic. Actual absolute UTC origins differ; aligned relative original traces are paired explicitly.
