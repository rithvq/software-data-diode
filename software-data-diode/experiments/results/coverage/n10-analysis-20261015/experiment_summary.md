# N10 Coverage Experiment Summary

Measurement scope: bounded discrete-event simulation using N4 admission, N5 signing/framing and independent accepted-ingress oracle. Not measured Docker/UDP throughput.
840 trials; 5 paired seeds per arm/case. Workloads and fault strata are not pooled.
CI method: two-sided Student-t interval on independent trial means or within-seed differences; conservative tabulated quantile. Packet/rule observations within one trial are not independent replicates.
Small n and discrete bounded yields limit normal-mean interval accuracy; intervals are descriptive, not proofs. Missing denominators/priority samples are NA and lower metric n is shown.
Experimental service shares: evidence 50%, protected 25%; these are not the deployment's 10% evidence default.
All wire costs include signed envelopes, real signed transport parts, controls, UDP/IP model overhead and charged repeats. Common local state is charged to all transmitting arms.
FIFO and heartbeat have authenticated original ingress range closures. Fixed summaries preserve original predicates and use the same codec, repeats, queues and lane service as RCCD, without advance reservation.
compact_summary is the stronger low-cost ordinary summary: exact original counts, signed epoch/contract/device/window/range and limitations, encoded in N5 binary signed parts without RCC commitment/witness/chain overhead. It is a harness baseline, not a deployed Fog schema.
Legacy uses the actual InformationEngine and native anomaly/correlation algorithms; exact-rule yield is a conservative original-witness projection, not a relabeling of legacy anomalies as exact coverage.
no_semantics is an intentionally unsafe test-only aggregate-mean assertion. Its errors are disclosed, not deployed. Always-UNKNOWN has zero traffic and undefined decisions/KiB, not an advantage.
Receiver evaluation and fault observations are performed after sender scheduling; none are policy inputs.
Raw offered traces are paired. Admission scopes can diverge; paired_differences.csv records accepted-scope equality and differences are not silently described as identical admitted populations.
Model CPU/RSS/storage includes common experimental ledger/bookkeeping, not native service resource performance. Subprocess contention/order/imports can affect those measurements.

| Case | Arm | Correct yield mean | UNKNOWN mean | Wrong FALSE total | Wrong TRUE total | Wire bytes mean |
|---|---|---:|---:|---:|---:|---:|
| light | fifo_gap | 0.8333 | 0.1667 | 0 | 0 | 97012.6 |
| light | legacy | 0.0556 | 0.9444 | 0 | 0 | 82022.2 |
| light | heartbeat | 0.8333 | 0.1667 | 0 | 0 | 97012.6 |
| light | compact_summary | 0.8333 | 0.1667 | 0 | 0 | 97199.4 |
| light | fixed_summary | 0.8000 | 0.2000 | 0 | 0 | 162830.2 |
| light | rccd | 0.8000 | 0.2000 | 0 | 0 | 162830.2 |
| light | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| light | no_semantics | 0.8000 | 0.2000 | 0 | 0 | 162361.4 |
| light | no_advance | 0.8000 | 0.2000 | 0 | 0 | 162830.2 |
| light | no_service | 0.8000 | 0.2000 | 0 | 0 | 162830.2 |
| light | no_repeats | 0.8333 | 0.1667 | 0 | 0 | 120538.6 |
| light | no_recovery | 0.8000 | 0.2000 | 0 | 0 | 162830.2 |
| moderate | fifo_gap | 1.0000 | 0.0000 | 0 | 0 | 182166.2 |
| moderate | legacy | 0.0111 | 0.9889 | 0 | 0 | 164318.2 |
| moderate | heartbeat | 1.0000 | 0.0000 | 0 | 0 | 182166.2 |
| moderate | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 182410.2 |
| moderate | fixed_summary | 0.8889 | 0.1111 | 0 | 0 | 260276.6 |
| moderate | rccd | 0.8889 | 0.1111 | 0 | 0 | 260276.6 |
| moderate | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| moderate | no_semantics | 0.8889 | 0.1111 | 0 | 0 | 260222.2 |
| moderate | no_advance | 0.8889 | 0.1111 | 0 | 0 | 260276.6 |
| moderate | no_service | 0.8889 | 0.1111 | 0 | 0 | 260276.6 |
| moderate | no_repeats | 1.0000 | 0.0000 | 0 | 0 | 210408.4 |
| moderate | no_recovery | 0.8889 | 0.1111 | 0 | 0 | 260276.6 |
| near_capacity | fifo_gap | 0.9333 | 0.0667 | 0 | 0 | 310588.2 |
| near_capacity | legacy | 0.1333 | 0.8667 | 0 | 0 | 294332.0 |
| near_capacity | heartbeat | 0.9333 | 0.0667 | 0 | 0 | 310588.2 |
| near_capacity | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 310832.2 |
| near_capacity | fixed_summary | 0.7000 | 0.3000 | 0 | 0 | 353588.8 |
| near_capacity | rccd | 0.7000 | 0.3000 | 0 | 0 | 353588.8 |
| near_capacity | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| near_capacity | no_semantics | 0.6778 | 0.3222 | 0 | 0 | 353616.8 |
| near_capacity | no_advance | 0.7000 | 0.3000 | 0 | 0 | 353588.8 |
| near_capacity | no_service | 0.6667 | 0.3333 | 0 | 0 | 353464.0 |
| near_capacity | no_repeats | 1.0000 | 0.0000 | 0 | 0 | 332087.4 |
| near_capacity | no_recovery | 0.7000 | 0.3000 | 0 | 0 | 353588.8 |
| overload | fifo_gap | 0.4222 | 0.5778 | 0 | 0 | 381745.8 |
| overload | legacy | 0.3444 | 0.6556 | 0 | 0 | 381546.6 |
| overload | heartbeat | 0.4222 | 0.5778 | 0 | 0 | 381745.8 |
| overload | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 381381.8 |
| overload | fixed_summary | 0.7333 | 0.2667 | 0 | 0 | 381669.6 |
| overload | rccd | 0.7333 | 0.2667 | 0 | 0 | 381669.6 |
| overload | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| overload | no_semantics | 0.6556 | 0.3444 | 0 | 0 | 381641.4 |
| overload | no_advance | 0.7333 | 0.2667 | 0 | 0 | 381669.6 |
| overload | no_service | 0.6889 | 0.3111 | 0 | 0 | 381494.4 |
| overload | no_repeats | 0.9333 | 0.0667 | 0 | 0 | 380906.0 |
| overload | no_recovery | 0.7333 | 0.2667 | 0 | 0 | 381669.6 |
| burst | fifo_gap | 1.0000 | 0.0000 | 0 | 0 | 261762.2 |
| burst | legacy | 0.1444 | 0.8556 | 0 | 0 | 243914.2 |
| burst | heartbeat | 1.0000 | 0.0000 | 0 | 0 | 261762.2 |
| burst | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 262006.2 |
| burst | fixed_summary | 0.7778 | 0.2222 | 0 | 0 | 327229.0 |
| burst | rccd | 0.7778 | 0.2222 | 0 | 0 | 327229.0 |
| burst | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| burst | no_semantics | 0.8000 | 0.2000 | 0 | 0 | 327278.6 |
| burst | no_advance | 0.7778 | 0.2222 | 0 | 0 | 327229.0 |
| burst | no_service | 0.7778 | 0.2222 | 0 | 0 | 327259.4 |
| burst | no_repeats | 0.9778 | 0.0222 | 0 | 0 | 290500.4 |
| burst | no_recovery | 0.7778 | 0.2222 | 0 | 0 | 327229.0 |
| critical_storm | fifo_gap | 1.0000 | 0.0000 | 0 | 0 | 280800.0 |
| critical_storm | legacy | 0.0556 | 0.9444 | 0 | 0 | 262950.8 |
| critical_storm | heartbeat | 1.0000 | 0.0000 | 0 | 0 | 280800.0 |
| critical_storm | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 281044.0 |
| critical_storm | fixed_summary | 0.7778 | 0.2222 | 0 | 0 | 343164.0 |
| critical_storm | rccd | 0.7778 | 0.2222 | 0 | 0 | 343164.0 |
| critical_storm | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| critical_storm | no_semantics | 0.7889 | 0.2111 | 0 | 0 | 342704.0 |
| critical_storm | no_advance | 0.7778 | 0.2222 | 0 | 0 | 343164.0 |
| critical_storm | no_service | 0.7222 | 0.2778 | 0 | 0 | 343051.2 |
| critical_storm | no_repeats | 1.0000 | 0.0000 | 0 | 0 | 309482.6 |
| critical_storm | no_recovery | 0.7778 | 0.2222 | 0 | 0 | 343164.0 |
| loss_10 | fifo_gap | 0.2111 | 0.7889 | 0 | 0 | 182166.2 |
| loss_10 | legacy | 0.0111 | 0.9889 | 0 | 0 | 164318.2 |
| loss_10 | heartbeat | 0.2111 | 0.7889 | 0 | 0 | 182166.2 |
| loss_10 | compact_summary | 0.9778 | 0.0222 | 0 | 0 | 182410.2 |
| loss_10 | fixed_summary | 0.8556 | 0.1444 | 0 | 0 | 260276.6 |
| loss_10 | rccd | 0.8556 | 0.1444 | 0 | 0 | 260276.6 |
| loss_10 | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| loss_10 | no_semantics | 0.8444 | 0.1444 | 1 | 0 | 260222.2 |
| loss_10 | no_advance | 0.8556 | 0.1444 | 0 | 0 | 260276.6 |
| loss_10 | no_service | 0.8444 | 0.1556 | 0 | 0 | 260276.6 |
| loss_10 | no_repeats | 0.6778 | 0.3222 | 0 | 0 | 210408.4 |
| loss_10 | no_recovery | 0.8556 | 0.1444 | 0 | 0 | 260276.6 |
| loss_25 | fifo_gap | 0.0556 | 0.9444 | 0 | 0 | 182166.2 |
| loss_25 | legacy | 0.0111 | 0.9889 | 0 | 0 | 164318.2 |
| loss_25 | heartbeat | 0.0556 | 0.9444 | 0 | 0 | 182166.2 |
| loss_25 | compact_summary | 0.9667 | 0.0333 | 0 | 0 | 182410.2 |
| loss_25 | fixed_summary | 0.6667 | 0.3333 | 0 | 0 | 260276.6 |
| loss_25 | rccd | 0.6667 | 0.3333 | 0 | 0 | 260276.6 |
| loss_25 | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| loss_25 | no_semantics | 0.6556 | 0.3333 | 1 | 0 | 260222.2 |
| loss_25 | no_advance | 0.6667 | 0.3333 | 0 | 0 | 260276.6 |
| loss_25 | no_service | 0.6667 | 0.3333 | 0 | 0 | 260276.6 |
| loss_25 | no_repeats | 0.3444 | 0.6556 | 0 | 0 | 210408.4 |
| loss_25 | no_recovery | 0.6667 | 0.3333 | 0 | 0 | 260276.6 |
| burst_loss | fifo_gap | 0.2222 | 0.7778 | 0 | 0 | 310588.2 |
| burst_loss | legacy | 0.1333 | 0.8667 | 0 | 0 | 294332.0 |
| burst_loss | heartbeat | 0.2222 | 0.7778 | 0 | 0 | 310588.2 |
| burst_loss | compact_summary | 0.6333 | 0.3667 | 0 | 0 | 310832.2 |
| burst_loss | fixed_summary | 0.4667 | 0.5333 | 0 | 0 | 353588.8 |
| burst_loss | rccd | 0.4667 | 0.5333 | 0 | 0 | 353588.8 |
| burst_loss | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| burst_loss | no_semantics | 0.4556 | 0.5444 | 0 | 0 | 353616.8 |
| burst_loss | no_advance | 0.4667 | 0.5333 | 0 | 0 | 353588.8 |
| burst_loss | no_service | 0.4333 | 0.5667 | 0 | 0 | 353464.0 |
| burst_loss | no_repeats | 0.6333 | 0.3667 | 0 | 0 | 332087.4 |
| burst_loss | no_recovery | 0.4667 | 0.5333 | 0 | 0 | 353588.8 |
| evidence_loss | fifo_gap | 0.9333 | 0.0667 | 0 | 0 | 310588.2 |
| evidence_loss | legacy | 0.1333 | 0.8667 | 0 | 0 | 294332.0 |
| evidence_loss | heartbeat | 0.9333 | 0.0667 | 0 | 0 | 310588.2 |
| evidence_loss | compact_summary | 0.1333 | 0.8667 | 0 | 0 | 310832.2 |
| evidence_loss | fixed_summary | 0.1333 | 0.8667 | 0 | 0 | 353588.8 |
| evidence_loss | rccd | 0.1333 | 0.8667 | 0 | 0 | 353588.8 |
| evidence_loss | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| evidence_loss | no_semantics | 0.1333 | 0.8667 | 0 | 0 | 353616.8 |
| evidence_loss | no_advance | 0.1333 | 0.8667 | 0 | 0 | 353588.8 |
| evidence_loss | no_service | 0.1333 | 0.8667 | 0 | 0 | 353464.0 |
| evidence_loss | no_repeats | 0.1333 | 0.8667 | 0 | 0 | 332087.4 |
| evidence_loss | no_recovery | 0.1333 | 0.8667 | 0 | 0 | 353588.8 |
| reorder_delay | fifo_gap | 0.1889 | 0.8111 | 0 | 0 | 310588.2 |
| reorder_delay | legacy | 0.1111 | 0.8889 | 0 | 0 | 294332.0 |
| reorder_delay | heartbeat | 0.1889 | 0.8111 | 0 | 0 | 310588.2 |
| reorder_delay | compact_summary | 0.7556 | 0.2444 | 0 | 0 | 310832.2 |
| reorder_delay | fixed_summary | 0.2000 | 0.8000 | 0 | 0 | 353588.8 |
| reorder_delay | rccd | 0.2000 | 0.8000 | 0 | 0 | 353588.8 |
| reorder_delay | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| reorder_delay | no_semantics | 0.1778 | 0.8222 | 0 | 0 | 353616.8 |
| reorder_delay | no_advance | 0.2000 | 0.8000 | 0 | 0 | 353588.8 |
| reorder_delay | no_service | 0.2444 | 0.7556 | 0 | 0 | 353464.0 |
| reorder_delay | no_repeats | 0.1667 | 0.8333 | 0 | 0 | 332087.4 |
| reorder_delay | no_recovery | 0.2000 | 0.8000 | 0 | 0 | 353588.8 |
| capacity_step | fifo_gap | 0.4667 | 0.5333 | 0 | 0 | 239033.0 |
| capacity_step | legacy | 0.1333 | 0.8667 | 0 | 0 | 238535.2 |
| capacity_step | heartbeat | 0.4667 | 0.5333 | 0 | 0 | 239033.0 |
| capacity_step | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 239024.0 |
| capacity_step | fixed_summary | 0.2556 | 0.7444 | 0 | 0 | 239307.6 |
| capacity_step | rccd | 0.2556 | 0.7444 | 0 | 0 | 239307.6 |
| capacity_step | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| capacity_step | no_semantics | 0.2556 | 0.7444 | 0 | 0 | 238999.6 |
| capacity_step | no_advance | 0.2556 | 0.7444 | 0 | 0 | 239307.6 |
| capacity_step | no_service | 0.2667 | 0.7333 | 0 | 0 | 239242.0 |
| capacity_step | no_repeats | 0.5222 | 0.4778 | 0 | 0 | 238622.2 |
| capacity_step | no_recovery | 0.2556 | 0.7444 | 0 | 0 | 239307.6 |
| recovery | fifo_gap | 0.1000 | 0.9000 | 0 | 0 | 129306.2 |
| recovery | legacy | 0.1111 | 0.8889 | 0 | 0 | 114387.2 |
| recovery | heartbeat | 0.1000 | 0.9000 | 0 | 0 | 129306.2 |
| recovery | compact_summary | 0.1556 | 0.8444 | 0 | 0 | 118380.8 |
| recovery | fixed_summary | 0.1111 | 0.8889 | 0 | 0 | 116987.0 |
| recovery | rccd | 0.1111 | 0.8889 | 0 | 0 | 116987.0 |
| recovery | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| recovery | no_semantics | 0.1111 | 0.8889 | 0 | 0 | 116987.0 |
| recovery | no_advance | 0.1111 | 0.8889 | 0 | 0 | 116987.0 |
| recovery | no_service | 0.1111 | 0.8889 | 0 | 0 | 114955.4 |
| recovery | no_repeats | 0.1111 | 0.8889 | 0 | 0 | 115232.4 |
| recovery | no_recovery | 0.0000 | 1.0000 | 0 | 0 | 89923.6 |
| moderate_double_budget | fifo_gap | 1.0000 | 0.0000 | 0 | 0 | 182166.2 |
| moderate_double_budget | legacy | 0.0111 | 0.9889 | 0 | 0 | 164318.2 |
| moderate_double_budget | heartbeat | 1.0000 | 0.0000 | 0 | 0 | 182166.2 |
| moderate_double_budget | compact_summary | 1.0000 | 0.0000 | 0 | 0 | 182410.2 |
| moderate_double_budget | fixed_summary | 1.0000 | 0.0000 | 0 | 0 | 260276.6 |
| moderate_double_budget | rccd | 1.0000 | 0.0000 | 0 | 0 | 260276.6 |
| moderate_double_budget | always_unknown | 0.0000 | 1.0000 | 0 | 0 | 0.0 |
| moderate_double_budget | no_semantics | 1.0000 | 0.0000 | 0 | 0 | 260222.2 |
| moderate_double_budget | no_advance | 1.0000 | 0.0000 | 0 | 0 | 260276.6 |
| moderate_double_budget | no_service | 1.0000 | 0.0000 | 0 | 0 | 260276.6 |
| moderate_double_budget | no_repeats | 1.0000 | 0.0000 | 0 | 0 | 210408.4 |
| moderate_double_budget | no_recovery | 1.0000 | 0.0000 | 0 | 0 | 260276.6 |

## Fixed summaries versus coupled admission

These are actual paired observations, not an automatic superiority claim:

| Case | RCCD minus fixed-summary yield | Paired 95% CI | Equal accepted scopes |
|---|---:|---|---:|
| light | 0.0000 | [0.0000, 0.0000] | 5/5 |
| moderate | 0.0000 | [0.0000, 0.0000] | 5/5 |
| near_capacity | 0.0000 | [0.0000, 0.0000] | 5/5 |
| overload | 0.0000 | [0.0000, 0.0000] | 5/5 |
| burst | 0.0000 | [0.0000, 0.0000] | 5/5 |
| critical_storm | 0.0000 | [0.0000, 0.0000] | 5/5 |
| loss_10 | 0.0000 | [0.0000, 0.0000] | 5/5 |
| loss_25 | 0.0000 | [0.0000, 0.0000] | 5/5 |
| burst_loss | 0.0000 | [0.0000, 0.0000] | 5/5 |
| evidence_loss | 0.0000 | [0.0000, 0.0000] | 5/5 |
| reorder_delay | 0.0000 | [0.0000, 0.0000] | 5/5 |
| capacity_step | 0.0000 | [0.0000, 0.0000] | 5/5 |
| recovery | 0.0000 | [0.0000, 0.0000] | 5/5 |
| moderate_double_budget | 0.0000 | [0.0000, 0.0000] | 5/5 |

Across these separate case means: RCCD higher 0, equal 14, lower 0. Ordinary summaries that match or beat RCCD are explicitly retained.
No pooled effect, patentability, universal zero-error guarantee or applicability to untested settings follows. Long-run signing-retention and N4 documentation limits remain.
Real Docker/UDP replay, if run, is stored and summarized separately; simulation does not certify that implementation.

## Compact Ordinary Summaries

| Case | RCCD minus compact yield | Paired 95% CI | Equal accepted scopes |
|---|---:|---|---:|
| light | -0.0333 | [-0.1259, 0.0592] | 5/5 |
| moderate | -0.1111 | [-0.2086, -0.0136] | 5/5 |
| near_capacity | -0.3000 | [-0.4154, -0.1846] | 5/5 |
| overload | -0.2667 | [-0.3993, -0.1340] | 5/5 |
| burst | -0.2222 | [-0.3685, -0.0759] | 5/5 |
| critical_storm | -0.2222 | [-0.3513, -0.0932] | 5/5 |
| loss_10 | -0.1222 | [-0.2636, 0.0191] | 5/5 |
| loss_25 | -0.3000 | [-0.4430, -0.1570] | 5/5 |
| burst_loss | -0.1667 | [-0.2356, -0.0977] | 5/5 |
| evidence_loss | 0.0000 | [0.0000, 0.0000] | 5/5 |
| reorder_delay | -0.5556 | [-0.8090, -0.3021] | 5/5 |
| capacity_step | -0.7444 | [-0.8789, -0.6100] | 5/5 |
| recovery | -0.0444 | [-0.1678, 0.0789] | 5/5 |
| moderate_double_budget | 0.0000 | [0.0000, 0.0000] | 5/5 |
RCCD higher 0, equal 2, lower 12 separate case means than compact summaries. A richer artifact is not automatically a better byte-efficiency tradeoff.
