# Codelab: Build a Cryptographic, Crash-Safe OTA Gate Resource Manager on QNX 8.0

**Estimated time:** 30 minutes  
**Target:** QNX Neutrino 8.0 (`x86_64`)  
**What you will build:** Starting from a minimal ~55-line QNX Resource Manager skeleton, you will progressively add OpenSSL 3 Ed25519/SHA-256 verification, an `fsync`-checked SHA-256 hash-chained journal on `fs-qnx6`, and `SIGKILL` crash reconciliation—then compare your build against `qnx/guardian-gate/guardian_gate.c` and run it inside QNX 8.0 QEMU.

---

### Prerequisites
- **QNX SDP 8.0 & QSTI QEMU Image**: Obtain via **QNX Everywhere** at [qnx.com](https://blackberry.qnx.com/) (provides `qcc` and `disk-qemu.qcow2`).
- **QEMU**: `qemu-system-x86_64` on Linux or Windows.
- **Repository checkout**: `git clone https://github.com/pdx-experimental/pdx-guardian`

---

### Step 1: Start with a Minimal QNX Resource Manager Skeleton (`5 min`)
Create `mini_gate.c` that registers `/dev/pdxguardian` using QNX's `dispatch_create()` and `resmgr_attach()`, echoing a JSON status line on `read()`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/resmgr.h>

static int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
    const char *reply = "{\"gate\":\"pdxguardian\",\"status\":\"READY\"}\n";
    size_t len = strlen(reply);
    if (ocb->offset >= (off_t)len) { MsgReply(ctp->rcvid, 0, NULL, 0); return _RESMGR_NOREPLY; }
    size_t n = len - (size_t)ocb->offset;
    if (n > msg->i.nbytes) n = msg->i.nbytes;
    MsgReply(ctp->rcvid, n, reply + ocb->offset, n);
    ocb->offset += n;
    return _RESMGR_NOREPLY;
}

int main(void) {
    dispatch_t *dpp = dispatch_create();
    resmgr_attr_t rattr = {0};
    rattr.nparts_max = 1;
    rattr.msg_max_size = 65536;
    iofunc_attr_t attr;
    iofunc_attr_init(&attr, S_IFCHR | 0666, NULL, NULL);
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t ifuncs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cfuncs, _RESMGR_IO_NFUNCS, &ifuncs);
    ifuncs.read = io_read;
    if (resmgr_attach(dpp, &rattr, "/dev/pdxguardian", _FTYPE_ANY, 0, &cfuncs, &ifuncs, &attr) == -1) {
        perror("resmgr_attach");
        return EXIT_FAILURE;
    }
    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while ((ctp = dispatch_block(ctp)) != NULL) { dispatch_handler(ctp); }
    return EXIT_SUCCESS;
}
```

---

### Step 2: Add Portable Policy & OpenSSL 3 Ed25519/SHA-256 Verification (`7 min`)
Rather than parsing JSON inside the RTOS, PDX Guardian shares a fixed binary header (`pdx_signed_manifest_t` in `portable/include/pdx_manifest.h`) across Linux and QNX:
1. `pdx_evaluate_manifest_policy()` (`portable/manifest/pdx_manifest.c`) checks magic, schema, anti-rollback version floor, hardware revision, and `vehicle_speed_kmh == 0`.
2. `pdx_verify_crypto_openssl()` (`portable/verifier/pdx_crypto_openssl.c`) validates the Ed25519 signature over the manifest payload and the SHA-256 digest of the firmware bytes using OpenSSL 3 `EVP_DigestVerify` and `EVP_Digest`.

You can run this exact C verifier on Linux first (without QNX) using the repository's CI test:
```bash
gcc -Wall -Wextra -Werror -O2 -Iportable/include \
  portable/manifest/pdx_manifest.c portable/verifier/pdx_crypto_openssl.c \
  portable/tests/test_portable_fixtures.c -lcrypto -o /tmp/test_portable
/tmp/test_portable
```
Expected output:
```text
[PASS] T01 valid v11 -> ALLOW
[PASS] T02 tampered payload -> DENY_HASH
[PASS] T03 bad signature -> DENY_SIGNATURE
[PASS] T04 rollback v09 -> DENY_ROLLBACK
[PASS] T06 hw_revision mismatch -> DENY_HW_REV
[PASS] T05 non-stationary -> DENY_NOT_STATIONARY
[PASS] T08 sequence replay -> DENY_ROLLBACK
ALL 7 PORTABLE C FIXTURE TESTS PASSED.
```

---

### Step 3: Add the `fsync` Hash-Chained Journal & `SIGKILL` Recovery (`8 min`)
Compare `mini_gate.c` with the full `qnx/guardian-gate/guardian_gate.c` and `qnx/journal/pdx_journal.c`:
- Before writing to the inactive simulated slot (`SLOT_A` or `SLOT_B`), `guardian_gate.c` appends `BEGIN_STAGE` to the `fs-qnx6` journal with `fsync()`.
- Each entry hashes the previous `journal_hash`, forming a tamper-evident chain.
- If `SIGKILL` arrives mid-staging (`tmp` or `after-rename`), startup recovery reconciles to `RECONCILED_ABORTED`; if after version commit (`after-version`), it reconciles to `RECONCILED_ACTIVATED`. If the journal is tampered with on disk, the gate locks fail-closed (`BLOCKED_JOURNAL_TAMPERED`).

---

### Step 4: Cross-Compile for QNX 8.0 & Test Inside QEMU (`5 min`)

**On Linux:**
```bash
source <QNX_SDP_ROOT>/qnxsdp-env.sh
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable/include -Iqnx/journal \
  -o qnx/guardian-gate/guardian_gate.elf \
  qnx/guardian-gate/guardian_gate.c qnx/journal/pdx_journal.c \
  portable/manifest/pdx_manifest.c portable/verifier/pdx_crypto_openssl.c -lcrypto
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable/include \
  -o qnx/guardian-gate/gate_submit.elf qnx/guardian-gate/gate_submit.c
```

**On Windows (`cmd`):**
```cmd
call <QNX_SDP_ROOT>\qnxsdp-env.bat
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include -Iqnx\journal ^
  -o qnx\guardian-gate\guardian_gate.elf ^
  qnx\guardian-gate\guardian_gate.c qnx\journal\pdx_journal.c ^
  portable\manifest\pdx_manifest.c portable\verifier\pdx_crypto_openssl.c -lcrypto
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include ^
  -o qnx\guardian-gate\gate_submit.elf qnx\guardian-gate\gate_submit.c
```

Inside the QNX 8.0 QEMU guest (after transferring the `.elf` files and `simulator/fixtures/week3/`), verify the Resource Manager and test valid, tampered, and crash-recovery cases:
```sh
uname -a
./guardian_gate.elf --pubkey 7d1f0d1f1133b05f65e075aa4a687d8bccc31efd521db6fcc72e34bea7b3f8fa &
ls -l /dev/pdxguardian

# 1. Valid update -> ALLOW
./gate_submit.elf /dev/pdxguardian t01_manifest_v11.bin t01_fw_v11.bin
# Expected JSON: {"operation_id":"op-wk3-t01-valid-v11","decision":"ALLOW","slot_status":"STAGED_AND_ACTIVATED_SLOT_B",...}

# 2. Tampered firmware -> DENY_HASH
./gate_submit.elf /dev/pdxguardian t02_manifest_v12.bin t02_fw_v12_tampered.bin
# Expected JSON: {"operation_id":"op-wk3-t02-tamper-v12","decision":"DENY_HASH","slot_status":"UNCHANGED_SLOT_B",...}

# 3. Simulated SIGKILL mid-staging + restart reconciliation
./guardian_gate.elf --simulate-crash tmp --pubkey 7d1f0d1f1133b05f65e075aa4a687d8bccc31efd521db6fcc72e34bea7b3f8fa &
./gate_submit.elf /dev/pdxguardian t07_manifest_v12.bin t07_fw_v12.bin
# Restart guardian_gate.elf and query status:
./gate_submit.elf /dev/pdxguardian --status
# Expected JSON: {"status_query":true,...,"reconcile_performed":true,"reconciled_state":"RECONCILED_ABORTED",...}
```

---

### Step 5: Inspect Real-Time Priority Scheduling (`5 min`)
Open `qnx/ecu-simulator/jitter_bench.c` to see how `ThreadCtl(_NTO_TCTL_RUNMASK, ...)` pins a 10 ms `SCHED_FIFO` (prio 50) ECU control loop on CPU0 using `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)` while a representative `SCHED_RR` (prio 10) worker runs SHA-256 + `fsync` I/O on CPU1. Run the full automated Week 2–4 suites via `docs/DEPLOYMENT.md`.
