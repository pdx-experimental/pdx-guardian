# PDX Guardian: Security & Threat Model
## Gate 0 Security Model & Durability Specification (Security Boundary)

**Version**: v1.2 (Gate 0 Baseline)  

---

### 1. Threat Model & Trust Boundaries (Honest Boundary Disclosure)

This project is an automotive OTA gate and recovery prototype governed by the following documented boundaries:
1. **Non-Safety-Critical Certification**: Demonstrates admission control and crash recovery for non-safety-critical vehicle services; does not claim ISO 26262 ASIL certification.
2. **Physical & Root Access Limits**: Does not defend against attackers with physical debug probes (JTAG) or system `root` privileges. Hardware Root of Trust (TPM/HSM) integration is deferred to production roadmaps.
3. **User-Space Crash vs. Sudden Power Cut**: `SIGKILL` tests validate recovery from worker process crashes and abnormal user-space termination, which is explicitly distinguished from physical hardware power-cut testing.
4. **Simulated Update Slots**: File-backed Slot A / Slot B directories without vehicle bootloader integration are formally designated as "Simulated Update Slots" rather than hardware-level firmware bank switching.

---

### 2. Cryptographic Standards

* **Algorithms**: Ed25519 digital signature verification + SHA-256 integrity hashing.
* **Libraries**:
  * QNX 8.0 Target: Uses QNX-provided **OpenSSL 3 (`libcrypto`)**; custom non-standard cryptographic implementations are prohibited.
  * Host / Portable Core: Uses OpenSSL 3 / standard RFC 8032-compatible libraries.
* **Signature Coverage**:
  * Signatures strictly cover the first 96 bytes of the `pdx_manifest.h` payload (magic, schema version, target version, sequence ID, hardware revision, stationary requirement, operation ID, and payload SHA-256).

---

### 3. Local Journal Hash Chain & Crash Consistency

* **Journal Hash Chain Structure**:
  Each journal entry records:
  `{ sequence_id, prev_hash[32], operation_id[32], target_slot, status, entry_sha256[32] }`
  ensuring any tampering or truncation breaks hash-chain verification and causes fail-closed startup.
* **Durability Write Protocol (Gate 0 Verified on `fs-qnx6`)**:
  * Write staging file completely and call `fsync(fd)` (verified return `0`).
  * Perform atomic rename `rename(tmp, target)` (verified return `0`).
  * **Directory Sync Measurement (QNX 8.0 `/data` on `fs-qnx6`)**: `fs_probe.elf` verified `file fsync() = 0`, `atomic rename() = 0`, and `dir fsync() = 0 (errno=0: No error)`, backed by `fs-qnx6` Power-Safe Copy-on-Write (COW) transaction semantics.
