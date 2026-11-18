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
| **QNX 8.0 Cooperative Fleet Node** | `tests/dsx_air_fleet/qnx_veh_host.c`<br>Cross-compiled with `qcc -Vgcc_ntox86_64 -O2 -lsocket -lm` | `uname -a` -> `QNX localhost 8.0.0 ... x86_64` + `run_qnx_3guest.py --binary` | `tests/dsx_air_fleet/out_qnx_3guest_bin/qnx_3guest_results.json` |

---

### 2. Pre-Frozen Jitter Thresholds vs. Measured QEMU TCG Results

Before running Week 4 (`evidence/week4/qnx_week4_jitter.json`), native-hardware real-time thresholds were frozen in `docs/ARCHITECTURE.md` (`deadline_misses = 0`, `p50 <= 50 µs`, `p99 <= 250 µs`, `max <= 1500 µs`). Under **QEMU `-smp 2` TCG software emulation** (3 rounds x 10,000 samples = 30,000 samples per scenario), all three arms failed the native-hardware thresholds (`thresholds_passed: false`), while `separated-vcpu` reduced worst-case spike latency by **11.4x** vs `same-vcpu`:

| Scenario (30,000 samples) | Deadline Misses | `p50` Median (µs) | `p99` Median (µs) | Worst `max` (µs) | Pre-Frozen Gate |
|---|---:|---:|---:|---:|---|
| `idle` (no worker) | 3 | 789.71 | 1,350.61 | 18,696.00 | **FAIL** (TCG emulation) |
| `same-vcpu` (CPU0 FIFO 50 vs CPU0 RR 10) | 17 | 607.16 | 1,489.91 | 127,841.20 | **FAIL** (TCG + CPU0 contention) |
| `separated-vcpu` (CPU0 FIFO 50 vs CPU1 RR 10) | 2 | 1,263.63 | 1,943.18 | 11,208.44 | **FAIL** (TCG; 11.4x lower max) |

---

### 3. Fleet-Scale Compute: Dedicated QNX Node vs. Shared-Host Contention

In the OCI Intra-Region (`0.22 ms` LAN) 3-QNX-Guest KVM experiment (`tests/dsx_air_fleet/out_oci_lan/qnx_oci_lan_results.json`), `qnx-zone-a/b` shared a `1-OCPU / 952 MiB` VM with SUMO, while `qnx-zone-c` ran on a dedicated QNX KVM VM:

| QNX Guest Node | Placement | 60 veh `p99` | 150 veh `p99` | 300 veh `p99` | 600 veh `p99` | Collisions / Unsafe |
|---|---|---:|---:|---:|---:|---|
| `qnx-zone-a` | Shared VM1 (with SUMO + zone-b) | 30.89 ms | 81.99 ms | 84.88 ms | 85.27 ms | `0 / 0` |
| `qnx-zone-b` | Shared VM1 (with SUMO + zone-a) | 33.78 ms | 75.86 ms | 82.93 ms | 84.12 ms | `0 / 0` |
| `qnx-zone-c` | Dedicated VM2 (`-smp 2 -m 512M`) | **1.83 ms** | **4.55 ms** | **6.94 ms** | **8.79 ms** | `0 / 0` |

*Note: Fleet compute latency (`ms`) measures cooperative `DrivingIntentV2` zone evaluation and is distinct from `/dev/pdxguardian` / `jitter_bench` 10 ms ECU control-loop wakeup jitter (`µs`).*
