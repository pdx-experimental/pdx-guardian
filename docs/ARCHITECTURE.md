# PDX Guardian: Architecture Specification
## Gate 0 System Architecture Specification (Freeze Baseline)

**Version**: v1.2 (Gate 0 Baseline)  
**Tagline**: *Verify before activation. Reconcile after interruption. Preserve the evidence.*  

---

### 1. System Architecture

The system strictly enforces the authority boundary between the **Host Orchestrator (Python)** and the **Vehicle Target (QNX C/C++ Native)**:

```text
[Host Orchestrator: Ubuntu / Python 3.10+ (container) or 3.12 (CI & Host)]
  ├── pdx-artifact-engine (0.3.0a12): External Operation Lifecycle, Step Receipts, Checkpoint CAS
  ├── ProDocuX (0.3.0rc11): Deterministic Render, Evidence Verification, PDF Report
  └── Fleet Controller: Binary Signed Manifest Dispatch (160 Bytes)
            |
            | Wire Protocol: Raw Socket / Serial / IPC Bridge
            v
[Vehicle Target: QNX Neutrino RTOS 8.0]
  ├── /dev/pdxguardian (Resource Manager, Mid-Priority)
  │     ├── Binary ABI Unpack (pdx_manifest.h)
  │     ├── Ed25519 Signature Verification (OpenSSL 3 / qcrypto)
  │     ├── Anti-rollback Monotonic Version Check
  │     └── Stationary Condition Gate (Speed == 0)
  ├── Simulated ECU (ecu_control: High-Priority 50, FIFO)
  │     └── 10ms Control Loop, CLOCK_MONOTONIC, Deadline Miss & Jitter Tracker
  └── Update Worker (update_worker: Low-Priority 10, RR)
        ├── Simulated Slot A / Slot B Staging
        ├── Power-Safe COW Write (fs-qnx6)
        └── Local Journal Hash Chain (seq, prev_hash, op_id, entry_hash)
```

---

### 2. Core Components & Responsibility Boundaries

1. **`portable/` (Portable Verification Core)**:
   * Written in standard C99/C11.
   * Contains the frozen `pdx_manifest.h` ABI (96-byte payload + 64-byte Ed25519 signature).
   * Zero external dynamic library dependencies, ensuring identical binary parsing across QNX and Linux mock environments.
2. **`qnx/guardian-gate/` (Vehicle Native Admission Gate)**:
   * Registers the native QNX Resource Manager (`/dev/pdxguardian`).
   * Communicates with clients over native QNX IPC (`MsgSend`, `MsgReceive`, `MsgReply`).
   * Invokes QNX 8.0 built-in OpenSSL 3 / `qcrypto` for Ed25519 signature verification and SHA-256 hashing.
3. **`qnx/ecu-simulator/` (Real-Time Control Simulator)**:
   * Simulates a periodic vehicle real-time control service (e.g., steering/braking monitor).
   * Runs a fixed 10 ms period timed via `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)`.
   * Supports both `same-vcpu` and `separated-vcpu` scheduling configurations, recording cycle jitter and deadline miss counts.
4. **`qnx/journal/` & `qnx/ecu-simulator/jitter_bench.c` (Journal, Simulated Slot Staging & Worker Load)**:
   * Writes update payloads to the inactive simulated slot (`SLOT_A` / `SLOT_B` alternating) inside `qnx/guardian-gate/guardian_gate.c`.
   * Appends monotonic SHA-256 hash-chained journal records (`qnx/journal/pdx_journal.c`).
   * If interrupted (`SIGKILL` or persistence I/O error), automatically reconciles on restart from the durable journal.
   * `jitter_bench.c` runs the representative `SCHED_RR` priority-10 worker load (SHA-256 + `fsync` I/O) against the `SCHED_FIFO` priority-50 `10 ms` ECU loop.

---

### 3. Real-Time Scheduling & Pre-Frozen Benchmark Thresholds

For virtualized QEMU benchmark runs, the following acceptance thresholds are pre-frozen before measurement:
* **Sample Size**: $N \ge 10,000$ cycles (excluding the first 1,000 warm-up cycles).
* **Deadline Miss Count**: **0** (zero cycles exceeding the 10 ms period).
* **p50 Jitter**: $\le 50\,\mu s$.
* **p99 Jitter**: $\le 250\,\mu s$.
* **Max Jitter**: $\le 1,500\,\mu s$.
* **Disclaimer**: *Demonstration Benchmark on Virtualized Environment, Not an ASIL Certification Guarantee.*
