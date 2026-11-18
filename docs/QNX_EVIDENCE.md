# QNX Neutrino 8.0 Technical Evidence Matrix

This document maps every QNX-specific capability used in **PDX Guardian** directly to its source file, kernel/C API, and reproducible verification command.

---

### 1. QNX Capability -> Source -> Verification Map

| QNX 8.0 Capability | Source File & Key Symbols | How to Verify on QNX 8.0 | Observed Evidence Artifact |
|---|---|---|---|
| **QNX Resource Manager** (`/dev/pdxguardian`) | `qnx/guardian-gate/guardian_gate.c`<br>`dispatch_create()`, `iofunc_func_init()`, `resmgr_attach()`, `dispatch_block()`, `dispatch_handler()` | Boot QNX 8.0 QEMU, start `guardian_gate.elf`, run `ls -l /dev/pdxguardian` and `gate_submit.elf` | `evidence/week2/qnx_week2_results.json`<br>`evidence/week3/qnx_week3_results.json` |
| **QNX POSIX/C Client I/O** (`open`/`write`/`read` to Resource Manager) | `qnx/guardian-gate/gate_submit.c`<br>Writes binary `[manifest \| payload]` to `/dev/pdxguardian`, reads JSON receipt | `./gate_submit.elf /dev/pdxguardian manifest.bin fw.bin` | `evidence/week1/prodocux_evidence_verification.json` |
| **CPU Core Pinning** (`_NTO_TCTL_RUNMASK`) | `qnx/ecu-simulator/jitter_bench.c`<br>`ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)runmask)` | Run `jitter_bench.elf` and inspect `ecu_affinity_ok` / `worker_affinity_ok` or `pidin` | `evidence/week4/qnx_week4_jitter.json` |
| **Real-Time Priority Scheduling** (`SCHED_FIFO` / `SCHED_RR`) | `qnx/ecu-simulator/jitter_bench.c`<br>`pthread_setschedparam(..., SCHED_FIFO, 50)` (ECU) vs `SCHED_RR, 10` (worker) | Inspect `ecu_actual_policy`, `ecu_actual_priority`, or `pidin -p <pid> sched` | `evidence/week4/qnx_week4_jitter.json` |
| **Absolute Monotonic Timers** | `qnx/ecu-simulator/jitter_bench.c`<br>`clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)` for `10 ms` loop | Run `scripts/run_week4_e2e.py` (3 scenarios x 3 rounds x 10,000 samples) | `evidence/week4/qnx_week4_jitter.json` |
| **Crash-Safe Hash-Chained Journal on `fs-qnx6`** | `qnx/journal/pdx_journal.c`, `pdx_journal.h`<br>`fsync`-checked append, SHA-256 chain verification, monotonic version anchor | `T07` (`tmp`), `T07B` (`after-rename`), `T07C` (`after-version`) `SIGKILL` tests + `T09` persist error | `evidence/week3/qnx_week3_results.json` |
| **Ed25519 + SHA-256 Verification** | `portable/verifier/pdx_crypto_openssl.c`<br>OpenSSL 3 `EVP_DigestVerify` (Ed25519) & `EVP_Digest` (SHA-256) | `T01` (valid), `T02` (`DENY_HASH`), `T03` (`DENY_SIGNATURE`), `T06` (`DENY_HW_REV`) | `evidence/week3/qnx_week3_results.json` |
| **QNX 8.0 Target Service (Dual-Host)** | `tests/qnx_dual_host/qnx_target_service.c`<br>Cross-host OTA target service inside QNX 8.0 | `python tests/qnx_dual_host/run_qnx_dual_host.py` | `evidence/qnx_dual_host/qnx_dual_host_results.json` |
| **QNX 8.0 Cooperative Fleet Node** | `tests/dsx_air_fleet/qnx_veh_host.c`<br>Cross-compiled with `qcc -Vgcc_ntox86_64 -O2 -lsocket -lm` | `uname -a` -> `QNX localhost 8.0.0 ... x86_64` + `run_qnx_3guest.py --binary` | `tests/dsx_air_fleet/out_qnx_3guest_bin/qnx_3guest_results.json` |

---

### 2. Pre-Frozen Jitter Thresholds vs. Measured QEMU TCG Results

Before running Week 4 (`evidence/week4/qnx_week4_jitter.json`), native-hardware real-time thresholds were frozen in `docs/ARCHITECTURE.md` (`deadline_misses = 0`, `p50 <= 50 µs`, `p99 <= 250 µs`, `max <= 1500 µs`). Under **QEMU `-smp 2` TCG software emulation** (3 rounds x 10,000 samples = 30,000 samples per scenario), all three arms failed the native-hardware thresholds (`thresholds_passed: false`), with `idle` as the baseline (`p50 = 789.71 µs`, `p99 = 1,350.61 µs`, `max = 18,696.00 µs`, `3` misses). Because TCG emulation noise is on the same order as the scheduling effect, `separated-vcpu` showed higher median `p50/p99` than `idle` and `same-vcpu` despite a lower worst-case `max` (`11,208.44 µs` vs `127,841.20 µs`):

| Scenario (30,000 samples) | Deadline Misses | `p50` Median (µs) | `p99` Median (µs) | Worst `max` (µs) | Pre-Frozen Gate |
|---|---:|---:|---:|---:|---|
| `idle` (TCG baseline, no worker) | 3 | 789.71 | 1,350.61 | 18,696.00 | **FAIL** (TCG emulation) |
| `same-vcpu` (CPU0 FIFO 50 vs CPU0 RR 10) | 17 | 607.16 | 1,489.91 | 127,841.20 | **FAIL** (TCG + CPU0 contention) |
| `separated-vcpu` (CPU0 FIFO 50 vs CPU1 RR 10) | 2 | 1,263.63 | 1,943.18 | 11,208.44 | **FAIL** (TCG emulation) |

Under **nested `/dev/kvm` on a 1-OCPU (2-SMT-thread) cloud VM** (`evidence/week4/qnx_week4_jitter_kvm.json`, `-enable-kvm -cpu host -smp 2 -m 512M`, `35 s` post-boot settle):

| Scenario (30,000 samples) | Deadline Misses | `p50` Median (µs) | `p99` Median (µs) | Worst `max` (µs) | Pre-Frozen Gate |
|---|---:|---:|---:|---:|---|
| `idle` (nested KVM baseline) | 12 | 874.67 | 1,035.89 | 21,701.99 | **FAIL** (nested cloud KVM) |
| `same-vcpu` (CPU0 FIFO 50 vs CPU0 RR 10) | 13,194 | 2,546.67 | 63,508.78 | 79,553.18 | **FAIL** (1-OCPU + `fsync` I/O) |
| `separated-vcpu` (CPU0 FIFO 50 vs CPU1 RR 10) | 9,059 | 594.72 | 61,370.46 | 78,650.54 | **FAIL** (4.3x lower `p50`; tail unimproved) |

Follow-up diagnostic on nested `/dev/kvm` (`evidence/week4/qnx_week4_jitter_kvm_diag.json`, 3,000 samples each) isolating `ClockPeriod(100 µs)` vs default `1 ms` tick and `--no-fsync` (CPU-only SHA-256):

| Diagnostic Arm (3,000 samples) | Misses | `p50` (µs) | `p99` (µs) | Worst `max` (µs) | Takeaway |
|---|---:|---:|---:|---:|---|
| `idle` (default 1 ms tick) | 1 | 1,036.80 | 1,166.89 | 18,934.63 | Quantized to QNX 1 ms tick |
| `idle --clock-period-ns 100000` (100 µs tick) | 1 | **450.81** | **598.41** | 12,788.96 | **2.3x** lower `p50` (hypervisor floor remains) |
| `same-vcpu --no-fsync` (100 µs tick) | 1,171 | 2,506.63 | 45,004.02 | 63,436.24 | 39% misses on shared SMT core |
| `separated-vcpu --no-fsync` (100 µs tick) | 479 | **636.58** | 44,306.86 | 56,153.94 | **16%** misses (down from 30% w/ `fsync`) |

---

### 3. Fleet-Scale Compute: Dedicated QNX Node vs. Shared-Host Contention

In the OCI Intra-Region (`0.22 ms` LAN) 3-QNX-Guest KVM experiment (`tests/dsx_air_fleet/out_oci_lan/qnx_oci_lan_results.json`), `qnx-zone-a/b` shared a `1-OCPU / 952 MiB` VM with SUMO, while `qnx-zone-c` ran on a dedicated QNX KVM VM:

| QNX Guest Node | Placement | 60 veh `p99` | 150 veh `p99` | 300 veh `p99` | 600 veh `p99` | Collisions / Unsafe |
|---|---|---:|---:|---:|---:|---|
| `qnx-zone-a` | Shared VM1 (with SUMO + zone-b) | 30.89 ms | 81.99 ms | 84.88 ms | 85.27 ms | `0 / 0` |
| `qnx-zone-b` | Shared VM1 (with SUMO + zone-a) | 33.78 ms | 75.86 ms | 82.93 ms | 84.12 ms | `0 / 0` |
| `qnx-zone-c` | Dedicated VM2 (`-smp 2 -m 512M`) | **1.83 ms** | **4.55 ms** | **6.94 ms** | **8.79 ms** | `0 / 0` |

*Note: Fleet compute latency (`ms`) measures cooperative `DrivingIntentV2` zone evaluation and is distinct from `/dev/pdxguardian` / `jitter_bench` 10 ms ECU control-loop wakeup jitter (`µs`).*

---

### 4. Complete Evidence & Reproducibility Index

| Claim / Scope | Evidence Artifact(s) | Verification / Replay Command |
|---|---|---|
| Portable C policy & OpenSSL 3 Ed25519/SHA-256 (`T01`–`T06`, `T08`) | `simulator/fixtures/week3/*` | `gcc -Wall -Wextra -Werror -O2 -Iportable/include portable/manifest/pdx_manifest.c portable/verifier/pdx_crypto_openssl.c portable/tests/test_portable_fixtures.c -lcrypto -o /tmp/test_portable && /tmp/test_portable` |
| Host rejection, A/B slot & ProDocuX bundle checks (8 tests) | `evidence/week2/qnx_week2_results.json` | `python host/tests/test_week2_host_rejections.py` |
| Week 1–3 OTA gate, `T01`–`T10` fault injection & crash reconciliation | `evidence/week1/prodocux_evidence_verification.json`<br>`evidence/week2/prodocux_evidence_verification.json`<br>`evidence/week3/qnx_week3_results.json` | `python3 scripts/run_week2_e2e.py` / `scripts/run_week3_e2e.py` (with QSTI image) |
| Week 4 `SCHED_FIFO`/`SCHED_RR` jitter (QEMU TCG & nested `/dev/kvm`) | `evidence/week4/qnx_week4_jitter.json`<br>`evidence/week4/qnx_week4_jitter_kvm.json`<br>`evidence/week4/prodocux_jitter_verification.json` | `python3 scripts/run_week4_e2e.py` (with QSTI image) |
| Fair KVM-vs-KVM OS A/B (JSON & Binary OP `'B'`, identical `-smp 2 -m 512M`) | `tests/dsx_air_fleet/out_qnx_vs_ubuntu/qnx_vs_ubuntu_kvm_results.json`<br>`tests/dsx_air_fleet/out_qnx_vs_ubuntu/qnx_vs_ubuntu_kvm_binary_results.json` | Run `qnx_veh_host.c` inside identical KVM guests (`200 -> 20` vehicles/zone) |
| Cross-host & dual-VM idempotent reconciliation (`409 Conflict` host API) | `evidence/oci_dual_vm/oci_dual_vm_results_v2.json`<br>`evidence/qnx_dual_host/qnx_dual_host_results.json`<br>`evidence/qnx_oci_bidirectional/prodocux_qnx_oci_bundle_verification.json` | `python tests/qnx_dual_host/run_qnx_dual_host.py` |
| Fleet-scale QNX 8.0 simulation (`60 -> 600` vehicles, `0` collisions) | `tests/dsx_air_fleet/out_qnx_ladder/qnx_ladder_results.json`<br>`tests/dsx_air_fleet/out_qnx_3guest_bin/qnx_3guest_results.json`<br>`tests/dsx_air_fleet/out_qnx_crosshost_600/qnx_crosshost_results.json`<br>`tests/dsx_air_fleet/out_oci_lan/qnx_oci_lan_results.json` | Open `docs/hackathon_dashboard.html` or run `python tests/dsx_air_fleet/run_qnx_3guest.py --counts 60 150 300 600 --binary` |
| Pure SUMO baseline (no QNX toolchain required) | `tests/dsx_air_fleet/out_sumo_baseline/sumo_baseline_results.json` | `python tests/dsx_air_fleet/run_sumo_baseline.py` |
