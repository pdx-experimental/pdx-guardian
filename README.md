# PDX Guardian
## QNX-Native Update Gate & Crash-Safe Evidence Plane

*Verify before activation. Reconcile after interruption. Preserve the evidence.*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/pdx-experimental/pdx-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/pdx-experimental/pdx-guardian/actions/workflows/ci.yml)
[![Target](https://img.shields.io/badge/Target-QNX_Neutrino_8.0-red.svg)](https://blackberry.qnx.com/)
[![Engine](https://img.shields.io/badge/Orchestrator-PDX_Artifact_Engine_0.3.0a12-green.svg)](https://pypi.org/project/pdx-artifact-engine/)

---

### Overview

**PDX Guardian** is a QNX Neutrino 8.0 native Resource Manager (`/dev/pdxguardian`) that sits in front of vehicle firmware activation—enforcing cryptographic verification, anti-rollback, and stationary-vehicle policy **before** any slot is touched, logging transitions to an `fsync`-checked SHA-256 hash-chained journal on `fs-qnx6`, and recovering deterministically after `SIGKILL` or persistence failures.

Instead of embedding heavy Python orchestrators inside the vehicle RTOS, PDX Guardian separates:
1. **QNX 8.0 Native Update Gate (`qnx/guardian-gate/guardian_gate.c`, `/dev/pdxguardian`)**: Performs Ed25519 signature verification, SHA-256 integrity checks, anti-rollback, hardware-revision matching (`DENY_HW_REV`), vehicle-speed gating (`DENY_NOT_STATIONARY`), fail-closed journal recovery, and `SCHED_FIFO` / `SCHED_RR` priority isolation.
2. **Host Lifecycle & Audit Plane (`host/`, `pdx-artifact-engine`, `prodocux`)**: Drives external lifecycles, idempotent cross-host reconciliation (host-side HTTP `409 Conflict` on conflicting operation IDs), and tamper-evident `prodocux.evidence_bundle` receipts.
3. **Scale-Out Fleet Validation (`tests/dsx_air_fleet/qnx_veh_host.c`)**: Applies the same fail-closed philosophy across 60–600 cooperative vehicles in SUMO 1.28+ simulation.

---

### Pre-Frozen Jitter Thresholds vs. Measured Results (Week 4, QEMU TCG)

Before running `jitter_bench.c` (`qnx/ecu-simulator/jitter_bench.c`), native-hardware thresholds were frozen in [ARCHITECTURE.md](docs/ARCHITECTURE.md) (`deadline_misses = 0`, `p50 <= 50 µs`, `p99 <= 250 µs`, `max <= 1500 µs`). Under **QEMU `-smp 2` TCG software emulation** (3 rounds × 10,000 samples = 30,000 samples per arm, `evidence/week4/qnx_week4_jitter.json`), **all 3 arms failed the native-hardware thresholds** due to host OS scheduling and TCG JIT translation noise—with `idle` as the baseline (`p50 = 789.71 µs`, `p99 = 1,350.61 µs`, `max = 18,696.00 µs`, `3` misses). Because TCG emulation noise is on the same order as the scheduling effect, `separated-vcpu` showed higher median `p50/p99` than `idle` and `same-vcpu` despite a lower worst-case `max` (`11,208.44 µs` vs `127,841.20 µs`):

| Arm (30,000 samples each) | Deadline Misses | `p50` Median | `p99` Median | Worst `max` | Pre-Frozen Gate |
|---|---:|---:|---:|---:|---|
| `idle` (TCG baseline, no worker) | 3 | 789.71 µs | 1,350.61 µs | 18,696.00 µs | **FAIL** (QEMU TCG) |
| `same-vcpu` (CPU0 FIFO 50 vs CPU0 RR 10) | 17 | 607.16 µs | 1,489.91 µs | 127,841.20 µs | **FAIL** (TCG + CPU0 contention) |
| `separated-vcpu` (CPU0 FIFO 50 vs CPU1 RR 10) | 2 | 1,263.63 µs | 1,943.18 µs | 11,208.44 µs | **FAIL** (TCG emulation) |

We also re-ran `jitter_bench.elf` under **nested `/dev/kvm` on a 1-OCPU (2-SMT-thread) cloud VM** (`evidence/week4/qnx_week4_jitter_kvm.json`, `35 s` post-boot settle). Under nested cloud virtualization and virtualized `fsync()` block I/O, all 3 arms still failed the bare-metal thresholds (`idle`: `12` misses, `p50 = 874.67 µs`, `p99 = 1,035.89 µs`, `max = 21,701.99 µs`; `same-vcpu`: `13,194` misses, `p50 = 2,546.67 µs`, `p99 = 63,508.78 µs`; `separated-vcpu`: `9,059` misses, `p50 = 594.72 µs`, `p99 = 61,370.46 µs`)—while `separated-vcpu` cut `p50` by **4.3×**, the `p99` tail (`61.4 ms` vs `63.5 ms`) remained disturbed on the 1-OCPU nested VM. A follow-up diagnostic (`evidence/week4/qnx_week4_jitter_kvm_diag.json`, 3,000 samples) isolated two causes: (1) calling `ClockPeriod(100 µs)` instead of QNX's default `1 ms` tick halved `idle` latency (`p50 = 1,036.80 → 450.81 µs`, `p99 = 1,166.89 → 598.41 µs`), and (2) running `--no-fsync` (CPU-only SHA-256) cut `separated-vcpu` misses from `30%` to `16%` (`479/3,000` vs `1,171/3,000` on `same-vcpu`, `p99 = 44.31 ms`). Thus `/dev/pdxguardian` **is designed to isolate** update work, while physical bare-metal SoC hardware is required to validate sub-millisecond `µs` targets.

---

### Threat Model & Fault-Injection Coverage (`T01–T10`, QNX 8.0 QEMU)

All 10 fault-injection and recovery cases in `evidence/week3/qnx_week3_results.json` passed on QNX 8.0 QEMU (`SLOT_A` / `SLOT_B` are **simulated** slot directories; in production QNX deployments, `/dev/pdxguardian` is designed to gate the platform's native A/B partition switcher):

| Threat / Fault | Enforcing Mechanism | Test Case & Observed Decision |
|---|---|---|
| Tampered firmware payload | OpenSSL 3 SHA-256 (`pdx_crypto_openssl.c`) | `T02` -> `DENY_HASH` |
| Forged / bad signature | OpenSSL 3 Ed25519 (`pdx_crypto_openssl.c`, software-held key; HSM/TPM next) | `T03` -> `DENY_SIGNATURE` |
| Version rollback / replay | Monotonic version anchor (`pdx_journal.c`) | `T04`, `T08` -> `DENY_ROLLBACK` |
| Hardware revision mismatch | Policy check (`g_vehicle_state.current_hw_revision`) | `T06` -> `DENY_HW_REV` |
| Update while vehicle moving | Stationary interlock (`vehicle_speed_kmh == 0`) | `T05` -> `DENY_NOT_STATIONARY` |
| `SIGKILL` mid-commit (3 points) | `fsync` journal reconciliation (`tmp`, `after-rename`, `after-version`) | `T07`/`T07B` -> `RECONCILED_ABORTED`; `T07C` -> `RECONCILED_ACTIVATED` |
| Persistence write failure | Fail-closed uncertain lock | `T09`, `T09b` -> `UNKNOWN_OUTCOME` (`UNCERTAIN_*_LOCKED`) |
| Tampered on-disk journal | SHA-256 chain verification on startup | `T10` -> `BLOCKED_JOURNAL_TAMPERED` |

*Regulatory context: PDX Guardian provides machine-verifiable evidence artifacts that can support **ISO 24089** and **UNECE R155/R156** software-update audit workflows; it is a virtualized demonstration, not a formal ASIL or regulatory certification.*

---

### Fleet-Scale Validation (60 → 600 Vehicles, Simulation)

To evaluate QNX 8.0 behavior at fleet scale (`tests/dsx_air_fleet/qnx_veh_host.c`, SUMO 1.28+ simulation):
- **Safety Invariants in Simulation**: Across Single-Guest QNX TCG, 3-Independent-QNX-Guest, Cross-Host `1000 km` WAN, and OCI Intra-Region KVM (`0.22 ms` LAN), every QNX run recorded **0 collisions**, **0 unsafe commands**, **100% stale-packet rejection** (`20–200` dropped), and **100% 2-stage recovery** (`8/8` to `17/17` vehicles).
- **Dedicated QNX Node vs. Shared-Host Contention** (`out_oci_lan/qnx_oci_lan_results.json`, `60 → 600` vehicles):
  - `qnx-zone-c` (dedicated QNX KVM VM, `-smp 2 -m 512M`): `p99 = 1.83 → 4.55 → 6.94 → 8.79 ms`
  - `qnx-zone-a / b` (shared `1-OCPU / 952 MiB` VM running SUMO + 2 QNX guests): `p99 = 85.27 ms` / `84.12 ms` at 600 vehicles (difference is host CPU contention, not QNX overhead).
- **Fair KVM-vs-KVM Guest A/B (`out_qnx_vs_ubuntu/qnx_vs_ubuntu_kvm_results.json` & `qnx_vs_ubuntu_kvm_binary_results.json`, identical `-enable-kvm -cpu host -smp 2 -m 512M`, `35 s` settle, `200 → 20` vehicles/zone)**:
  - **JSON `STEP_BATCH`**: From `20–100` vehicles/zone, QNX 8.0.0 KVM (`p99 = 72.84–82.45 ms`) and Ubuntu 24.04 KVM (`p99 = 63.58–66.62 ms`) sit in the same QEMU SLIRP range; at `200` vehicles/zone, Ubuntu KVM stays at `p50 = 8.67 ms / p99 = 70.96 ms` while QNX KVM reaches `p50 = 87.13 ms / p99 = 174.06 ms`.
  - **Binary Protocol (`OP 'B'`)**: Switching to compact binary framing drops QNX KVM `200/zone` `RTT p50` by **8.3×** (`87.13 → 10.55 ms`, `p99 = 88.26 ms`). While QEMU SLIRP TCP `RTT` remains lower on Linux (`1.80 ms` vs `10.55 ms` `p50` at `200/zone`), **in-guest compute (`clock_gettime`) is faster on QNX 8.0.0 across all 4 scales** (`p50 = 9.0 / 18.0 / 40.0 / 131.0 µs` on QNX vs `13.0 / 47.0 / 67.0 / 187.0 µs` on Ubuntu 24.04). QNX's primary value remains deterministic RTOS isolation (`/dev/pdxguardian`), priority scheduling, and `fs-qnx6` crash recovery.

*(Fleet compute latency in `ms` is distinct from `/dev/pdxguardian` control-loop wakeup jitter in `µs`.)*

---

### Provenance & AI Disclosure

- **Built New for QNX Global Hackathon 2026**: `qnx/` (Resource Manager `/dev/pdxguardian`, `fs-qnx6` journal, `jitter_bench.c`), `portable/` (binary manifest ABI, policy gate, OpenSSL 3 Ed25519/SHA-256 verifier), `host/fleet-controller/`, `scripts/` (QEMU E2E runners), `tests/qnx_dual_host/`, `tests/dsx_air_fleet/`, and `docs/hackathon_dashboard.html`.
- **Pre-Existing Host-Side Libraries**: `pdx-artifact-engine==0.3.0a12` and `prodocux==0.3.0rc11` (used strictly on the host side for receipt verification and evidence bundling; see [ENGINE_BOUNDARY.md](docs/ENGINE_BOUNDARY.md)).
- **AI Role & Fail-Closed Stance**: AI coding assistants were used during development, and any future AI audit summarization remains strictly **off-vehicle on the host plane**—AI never participates in in-vehicle `/dev/pdxguardian` activation decisions.

---

### Judge Quickstart, QNX Evidence & Documentation

- **[QNX 8.0 Technical Evidence Matrix](docs/QNX_EVIDENCE.md)** *(Exact APIs, files, verification commands, and threshold tables)*
- **[Interactive Comparison & Replay Dashboard](docs/hackathon_dashboard.html)** *(Zero dependencies — open directly in any browser)*
- **[30-Minute QNX Resource Manager Codelab](docs/CODELAB.md)**
- [Deployment & Judge Quickstart Guide](docs/DEPLOYMENT.md) | [System Architecture](docs/ARCHITECTURE.md) | [Security Model](docs/SECURITY.md)

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
