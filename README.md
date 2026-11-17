# PDX Guardian
## Evidence-Driven Vehicle Update & Recovery

*Verify before activation. Reconcile after interruption. Preserve the evidence.*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/Target-QNX_Neutrino_8.0-red.svg)](https://blackberry.qnx.com/)
[![Engine](https://img.shields.io/badge/Orchestrator-PDX_Artifact_Engine_0.3.0a12-green.svg)](https://pypi.org/project/pdx-artifact-engine/)

---

### Overview

**PDX Guardian** is an evidence-driven vehicle software update gate and recovery infrastructure targeting the **QNX Global Hackathon 2026** (Automotive & Mobility / Best Use of QNX-specific Technologies).

Instead of porting heavy Python runtimes into the vehicle RTOS, PDX Guardian introduces a clean, resilient separation:
1. **Vehicle Safety Gate (QNX 8.0 C/C++ Native `/dev/pdxguardian`)**: Enforces pre-activation policy, Ed25519 signature verification, anti-rollback guarantees, `fsync`-checked fail-closed journal recovery (including simulated persistence failure locking and post-restart reconciliation), and priority-scheduled control (`SCHED_FIFO` / `SCHED_RR`; QEMU TCG jitter is reported honestly as a virtualized benchmark).
2. **Cooperative Fleet Safety & Partition Recovery (QNX 8.0 Native `qnx_veh_host.elf`)**: Executes vehicle intent exchange (`DrivingIntentV2`), stale-replay rejection, local stopping-distance fallback during network partitions, and 2-stage recovery across 60–600 vehicles and 3 intersections (`j1 / j2 / j3`).
3. **Orchestrator & Auditing (Host Python + ProDocuX)**: Drives external lifecycles, SUMO traffic environments, and tamper-evident `prodocux.evidence_bundle` verification packages.

---

### Key Findings & Evidence Scope (Lower-Bound Guarantee)

- **Safety Invariants Hold Everywhere (60 → 600 Vehicles)**: Across Single-Guest QNX TCG, 3-Independent-QNX-Guest (JSON & Binary), Cross-Host 1000 km WAN, and OCI Intra-Region KVM (`0.22 ms` LAN), every QNX run recorded **0 collisions**, **0 unsafe commands**, **100% stale-packet rejection** (`20–200` dropped), and **100% 2-stage recovery coverage** (`8/8` to `17/17` vehicles in recovery denominator).
- **Virtualized Lower Bound vs Independent-ECU Scaling**: In the OCI Intra-Region 600-vehicle KVM run, `qnx-zone-a/b` shared a 1-OCPU / 952 MiB host with SUMO (`qnx_compute p99 = 84.1–85.3 ms`), whereas the dedicated QNX node `qnx-zone-c` achieved **`p99 = 8.79 ms`** (`1.83 → 4.55 → 6.94 → 8.79 ms` across `60 → 600` vehicles). This directly demonstrates that under dedicated per-vehicle QNX ECU compute and low-latency automotive networking (`0.22 ms` intra-DC vs `91.5 ms` 1000 km WAN), the framework operates well within a `100 ms` real-time cycle.

---

### Interactive Visualization & Experiment Replay

- **[QNX 8.0.0 Interactive Comparison & Full-Duration Replay Dashboard](docs/hackathon_dashboard.html)** *(Zero external dependencies — open directly in any browser to compare architectures across 60–600 vehicles, view Same-Hardware Ubuntu 24.04 vs QNX 8.0.0 A/B benchmarks, and replay/compare any archived 3-intersection run side-by-side.)*

### Project Documentation & Reproducibility

- [System Architecture](docs/ARCHITECTURE.md)
- [Deployment & Judge Quickstart Guide](docs/DEPLOYMENT.md)
- [Security Model & Durability](docs/SECURITY.md)
- [Engine Boundary & Capabilities](docs/ENGINE_BOUNDARY.md)
- [Manifest Binary ABI Specification](portable/include/pdx_manifest.h)

---

### License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
