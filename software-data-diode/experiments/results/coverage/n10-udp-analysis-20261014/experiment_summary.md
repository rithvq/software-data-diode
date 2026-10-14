# N10 Actual Docker/UDP Replay

Five paired trials per arm. Recomputed from signed artifacts and retained PostgreSQL receipts, separately from simulation.
Sender admission and schedule are precomputed using N4; only transport/receiver persistence are actual live measurements. Not native online gateway throughput.
The receipt time is the stored receiver timestamp, not a database-commit completion measurement. Local send success is not receipt.
Docker resource snapshots are reduced to one sample mean CPU / observed maximum memory per trial within replay time; snapshots are not independent replicates.
Different aligned UTC origins and ephemeral epochs/keys are declared; relative traces are paired. No synthetic packet faults are claimed in this live matrix.

| Arm | Metric | n | Mean | Median | Sample SD | 95% Student-t CI |
|---|---|---:|---:|---:|---:|---|
| rccd | decision_yield | 5 | 0.7222222222222222 | 0.7222222222222222 | 0.1111111111111111 | [0.5842816732102352, 0.8601627712342093] |
| rccd | unknown_rate | 5 | 0.2777777777777778 | 0.2777777777777778 | 0.11111111111111112 | [0.13983722876579077, 0.41571832678976484] |
| rccd | raw_detail_availability | 5 | 0.9186055200112082 | 0.9736842105263158 | 0.09079528765939804 | [0.8058863535642603, 1.031324686458156] |
| rccd | critical_latency_p95_seconds | 4 | 1.104348400235176 | 1.0418101608753205 | 0.5228261687826611 | [0.27253196570196225, 1.9361648347683897] |
| rccd | attempted_model_wire_bytes | 5 | 353427.2 | 350464 | 23068.020292170717 | [324789.06154650485, 382065.3384534952] |
| rccd | data_diode_sample_mean_cpu_percent | 5 | 10.8616 | 11.306000000000001 | 1.6026505545501804 | [8.871965523678844, 12.851234476321155] |
| rccd | data_diode_sample_max_memory_bytes | 5 | 57472450.56 | 57325649.92 | 787933.5255107 | [56494258.71215493, 58450642.40784507] |
| rccd | fog_receiver_sample_mean_cpu_percent | 5 | 32.0008 | 31.232 | 6.886777562837356 | [23.45110709852903, 40.55049290147097] |
| rccd | fog_receiver_sample_max_memory_bytes | 5 | 77393297.40799999 | 75549900.8 | 5970139.074959543 | [69981579.05289948, 84805015.7631005] |
| rccd | postgres_sample_mean_cpu_percent | 5 | 32.1684 | 31.76 | 2.198919461917601 | [29.438518579709488, 34.89828142029051] |
| rccd | postgres_sample_max_memory_bytes | 5 | 42540728.32 | 41901096.96 | 2787920.851159503 | [39079622.32470183, 46001834.31529817] |
| fixed_summary | decision_yield | 5 | 0.7 | 0.7222222222222222 | 0.1009216784699164 | [0.5747092743818365, 0.8252907256181634] |
| fixed_summary | unknown_rate | 5 | 0.3 | 0.2777777777777778 | 0.10092167846991638 | [0.17470927438183653, 0.42529072561816345] |
| fixed_summary | raw_detail_availability | 5 | 0.9186055200112082 | 0.9736842105263158 | 0.09079528765939804 | [0.8058863535642603, 1.031324686458156] |
| fixed_summary | critical_latency_p95_seconds | 4 | 1.0854759246110917 | 1.0198521614074707 | 0.5068052403703861 | [0.27914878718180736, 1.8918030620403758] |
| fixed_summary | attempted_model_wire_bytes | 5 | 353660 | 351100 | 23198.500231696013 | [324859.8752760663, 382460.1247239337] |
| fixed_summary | data_diode_sample_mean_cpu_percent | 5 | 13.045533333333333 | 13.26 | 3.4247454049737605 | [8.79383198083809, 17.297234685828577] |
| fixed_summary | data_diode_sample_max_memory_bytes | 5 | 53953429.504 | 54830039.04 | 5580752.579512178 | [47025120.831538245, 60881738.176461756] |
| fixed_summary | fog_receiver_sample_mean_cpu_percent | 5 | 33.43566666666667 | 31.514 | 3.6200488333108933 | [28.9415029550127, 37.92983037832064] |
| fixed_summary | fog_receiver_sample_max_memory_bytes | 5 | 76072091.648 | 74763468.8 | 3620651.0877376855 | [71577180.25858954, 80567003.03741047] |
| fixed_summary | postgres_sample_mean_cpu_percent | 5 | 37.48546666666667 | 37.989999999999995 | 1.9355176970401362 | [35.08258930289747, 39.88834403043587] |
| fixed_summary | postgres_sample_max_memory_bytes | 5 | 42825940.992 | 43725619.2 | 1688555.7638999936 | [40729658.21001252, 44922223.77398748] |

RCCD minus fixed-summary decision-yield paired mean: 0.022222222222222254; 95% CI [-0.15089179287251872, 0.19533623731696323].
No superiority claim is implied. Attempted wire bytes add a modeled 28-byte IPv4/UDP overhead, not captured NIC traffic.
Fog socket instrumentation recorded zero UDP sends; UDP/shared-host bidirectionality remains a limitation.
