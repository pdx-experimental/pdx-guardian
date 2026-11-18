# Codelab: Build a Cryptographic, Crash-Safe OTA Gate Resource Manager on QNX 8.0

**Estimated time:** 30 minutes  
**Target:** QNX Neutrino 8.0 (`x86_64`)  
**What you will build:** A native QNX Resource Manager (`/dev/pdxguardian`) that verifies Ed25519-signed firmware manifests before staging, logs transitions to an `fsync`-checked SHA-256 hash-chained journal on `fs-qnx6`, recovers deterministically after `SIGKILL`, and isolates real-time `SCHED_FIFO` control loops from update workers.

---

### Prerequisites
- QNX SDP 8.0 (`qcc`, `qnxsdp-env.bat` or `qnxsdp-env.sh`)
- QEMU (`qemu-system-x86_64`) + a QNX 8.0 QSTI image (`disk-qemu.qcow2`)
- Repository checkout: `https://github.com/pdx-experimental/pdx-guardian`

---

### Step 1: Define a Portable, Zero-Trust Manifest ABI (`5 min`)
Inspect `portable/include/pdx_manifest.h` and `portable/include/pdx_gate_policy.h`.  
Instead of parsing JSON inside the vehicle RTOS, PDX Guardian uses a fixed binary header (`pdx_manifest_t`) verified in C before any slot is touched:
- Magic & ABI version check
- SHA-256 payload digest (`payload_sha256`)
- Ed25519 signature (`signature[64]`)
- Anti-rollback floor (`target_version > current_active_version`)
- Hardware revision match (`hw_revision == current_hw_revision`)
- Operational safety interlock (`vehicle_speed_kmh == 0`)

---

### Step 2: Verify Signatures & Digests with OpenSSL 3 (`5 min`)
Open `portable/verifier/pdx_crypto_openssl.c`.  
It wraps OpenSSL `EVP_DigestVerify` (Ed25519) and `EVP_Digest` (SHA-256) with strict bounds checking and zero dynamic heap surprises on the verification path.

---

### Step 3: Build the Fail-Closed Hash-Chained Journal (`7 min`)
Open `qnx/journal/pdx_journal.c`.  
Before staging firmware into `SLOT_A` or `SLOT_B`, `guardian_gate.c` records `BEGIN_STAGE` to the journal with `fsync()`. Each entry hashes the previous `journal_hash`, creating a tamper-evident chain:
- If `guardian_gate` receives `SIGKILL` mid-staging (`tmp` or `after-rename`), startup recovery detects the incomplete `BEGIN_STAGE` and reconciles to `RECONCILED_ABORTED` without corrupting the active slot.
- If `SIGKILL` happens after version commit (`after-version`), recovery reconciles to `RECONCILED_ACTIVATED`.
- If the journal file is tampered with on disk, `chain_valid` becomes `0` and the gate locks fail-closed (`BLOCKED_JOURNAL_TAMPERED`).

---

### Step 4: Expose `/dev/pdxguardian` as a QNX Resource Manager (`8 min`)
Open `qnx/guardian-gate/guardian_gate.c`:
1. Create a dispatch handle with `dispatch_create()`.
2. Initialize `iofunc_attr_t` and `resmgr_io_funcs_t` (`guardian_io_read`, `guardian_io_write`).
3. Attach `/dev/pdxguardian` via `resmgr_attach(dpp, &resmgr_attr, "/dev/pdxguardian", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr)`.
4. Enter `dispatch_block(ctp)` / `dispatch_handler(ctp)`.

Cross-compile both the Resource Manager and the CLI client (`qnx/guardian-gate/gate_submit.c`) using `qcc`:
```cmd
call <QNX_SDP_ROOT>\qnxsdp-env.bat
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include -Iqnx\journal ^
  -o qnx\guardian-gate\guardian_gate.elf ^
  qnx\guardian-gate\guardian_gate.c qnx\journal\pdx_journal.c ^
  portable\manifest\pdx_manifest.c portable\verifier\pdx_crypto_openssl.c -lcrypto
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include ^
  -o qnx\guardian-gate\gate_submit.elf qnx\guardian-gate\gate_submit.c
```

---

### Step 5: Isolate Real-Time Control (`SCHED_FIFO` vs `SCHED_RR`) (`5 min`)
Open `qnx/ecu-simulator/jitter_bench.c` to see how QNX-native `ThreadCtl(_NTO_TCTL_RUNMASK, ...)` pins `ecu_control` (`SCHED_FIFO`, priority `50`, `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME)`) onto CPU0 while `update_worker` (`SCHED_RR`, priority `10`) runs SHA-256 + `fsync` I/O on CPU1 (`separated-vcpu`).

Compile and run the full automated QNX 8.0 QEMU verification suites (`run_week2_e2e.py`, `run_week3_e2e.py`, `run_week4_e2e.py`) as documented in `docs/DEPLOYMENT.md`.
