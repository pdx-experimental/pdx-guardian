# PDX Guardian: Engine Capability & Boundary Alignment
## Gate 0 External Dependency & Capability Matrix

**Review Date**: 2026-11-12  
**Pinned Versions**: `pdx-artifact-engine==0.3.0a12` | `prodocux==0.3.0rc11`  

---

### 1. Local Python Environment & PyPI Version Pinning (Gate 0 Verified)

* **PDX Artifact Engine**: `pdx-artifact-engine==0.3.0a12`
  * Wheel: `pdx_artifact_engine-0.3.0a12-py3-none-any.whl`
  * SHA-256: `1ac34e04702029d8b0dd4819d579284a7660ea077fad8ad3489fb5e6b9211a77`
  * URL: `https://files.pythonhosted.org/packages/10/48/0d422c6362bd5b94e0f78ff6deb72b9ab941c562bf276479cd474f91bd66/pdx_artifact_engine-0.3.0a12-py3-none-any.whl`
  * Verified Path: `.venv\Lib\site-packages\pdx_artifact_engine\__init__.py` (`import pdx_artifact_engine` succeeded)
* **ProDocuX**: `prodocux==0.3.0rc11`
  * Wheel: `prodocux-0.3.0rc11-py3-none-any.whl`
  * SHA-256: `8fe9c12bb2c61ada8c3372417cad9b887d21f1b1fdde49eb808058943ce0da5f`
  * URL: `https://files.pythonhosted.org/packages/7f/06/29a0e9931358500a03c278fad71d9c73c1a3d492cb08b1b183fc32b9160c/prodocux-0.3.0rc11-py3-none-any.whl`
  * Verified Path: `.venv\Lib\site-packages\prodocux_kernel\__init__.py` (`import prodocux_kernel` succeeded)
* Policy Alignment: Strictly pinned to published PyPI releases; unpublished source builds (`a13` / `rc12`) are excluded.

---

### 2. pdx-artifact-engine 0.3.0a12 Capability Matrix

Per the official `0.3.0a12` metadata and contracts, the capabilities and boundaries used by this project are:

| PDX Engine Native Capability (0.3.0a12) | Public Contract Status | PDX Guardian Usage | Boundary & Constraint Declaration |
| :--- | :--- | :--- | :--- |
| **External Operation Lifecycle** | `Available (core)` | `host/pdx-adapter/` manages vehicle OTA operation lifecycles | Strictly uses public states: `submitted`, `pending`, `completed`, `failed`, `unknown_outcome`, `timed_out`, `cancelled` |
| **Reconciliation Mechanism** | `Available (core)` | Triggers `reconcile_required=true` when state is `unknown_outcome` | `reconcile` is a coordination action, not a lifecycle state |
| **Checkpoint CAS** | `Available (core)` | Writes replayable checkpoints on state transitions | Preserves atomicity between host dispatch state and local state |
| **Step Receipts** | `Available (0.3.0a5+)` | Produces SHA-256 execution receipts per update step | Serves as raw evidence for ProDocuX audit verification |
| **Product-neutral Provenance Export** | `Published (0.3.0a9)` | Exports provenance metadata | Enables independent third-party verification of signatures and dependencies |
| **Deterministic Block Extraction & Render** | `Available (alpha)` | Generates vehicle update and security audit reports | Invokes `prodocux_kernel` verification and deterministic PDF rendering |

---

### 3. Host Adapter Boundary & Non-Deceptive Declaration

1. **Strict Semantic Mapping**: `host/pdx-adapter/` acts solely as a translator between QNX vehicle-side evidence (Journal Hash Chain, Simulated Slot A/B, Ed25519 verification receipts) and `0.3.0a12` external operation lifecycle contracts.
2. **No Fabricated Engine Claims**: If a vehicle scenario requires governance semantics beyond `0.3.0a12`, the system must remain in `blocked` or `unknown_outcome` rather than synthesizing custom local logic and claiming native engine support.
