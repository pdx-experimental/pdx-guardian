# PDX Guardian: Deployment & Reproducibility Guide
## Toolchain, Clean-Checkout Setup, and Verification Commands

### 1. Toolchain Division
* **QNX 8.0 Cross-Compilation**:
  * Uses local QNX SDP 8.0 (`qnxsdp-env.bat` + `qcc -Vgcc_ntox86_64`) to compile native QNX x86_64 ELF binaries.
* **Host Orchestrator & Verification Container**:
  * Python 3.12+ virtual environment with pinned PyPI dependencies (`pdx-artifact-engine==0.3.0a12`, `prodocux==0.3.0rc11`).
  * `docker/Dockerfile.qnx-builder` (Ubuntu 22.04 + `qemu-system-x86`) to orchestrate QNX 8.0 QSTI (`disk-qemu.qcow2`) end-to-end runs.

---

### 2. Clean-Checkout Reproduction Steps

#### Step A: Install Pinned Host Python Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install pdx-artifact-engine==0.3.0a12 prodocux==0.3.0rc11
```

#### Step B: Cross-Compile QNX 8.0 Native Binaries
Run from a Windows shell with QNX SDP 8.0 installed (replace `<QNX_SDP_ROOT>` with your QNX SDP 8.0 directory):
```cmd
call <QNX_SDP_ROOT>\qnxsdp-env.bat
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include -Iqnx\journal ^
  -o qnx\guardian-gate\guardian_gate.elf ^
  qnx\guardian-gate\guardian_gate.c qnx\journal\pdx_journal.c ^
  portable\manifest\pdx_manifest.c portable\verifier\pdx_crypto_openssl.c -lcrypto
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 -Iportable\include ^
  -o qnx\guardian-gate\gate_submit.elf qnx\guardian-gate\gate_submit.c
qcc -Vgcc_ntox86_64 -Wall -Wextra -O2 ^
  -o qnx\ecu-simulator\jitter_bench.elf qnx\ecu-simulator\jitter_bench.c -lcrypto -lm
```

#### Step C: Build Builder Container & Generate Fixtures
```powershell
docker build -t pdx-guardian-builder:latest -f docker\Dockerfile.qnx-builder .
.\.venv\Scripts\python.exe host\fleet-controller\build_week2_fixtures.py
.\.venv\Scripts\python.exe host\fleet-controller\build_week3_fixtures.py
```

#### Step D: Execute QNX 8.0 QEMU E2E Tests & Host ProDocuX Pipelines
> **QSTI Container Mount Requirement**: The W2/W3/W4 runners expect the QSTI disk image at `/qemu/qemu/output/disk-qemu.qcow2` inside the container (e.g., if `disk-qemu.qcow2` is at `<QNX_QEMU_DIR>/qemu/output/disk-qemu.qcow2`, mount `<QNX_QEMU_DIR>` to `/qemu`).

```powershell
# Week 2: Cryptographic Gate, A/B Slot Separation & Crash Recovery (generates evidence/week2/qnx_week2_results.json)
docker run --rm -v ${PWD}:/workspace -v <QNX_QEMU_DIR>:/qemu `
  pdx-guardian-builder:latest python3 /workspace/scripts/run_week2_e2e.py
.\.venv\Scripts\python.exe host\run_week2_pipeline.py

# Week 3: T01-T10 Fault Injection, Crash/Persistence-Error Recovery & Fail-Closed Journal
docker run --rm -v ${PWD}:/workspace -v <QNX_QEMU_DIR>:/qemu `
  pdx-guardian-builder:latest python3 /workspace/scripts/run_week3_e2e.py
.\.venv\Scripts\python.exe host\run_week3_pipeline.py

# Week 4: 3-Arm Interleaved Jitter Benchmark (idle, same-vcpu, separated-vcpu)
docker run --rm -v ${PWD}:/workspace -v <QNX_QEMU_DIR>:/qemu `
  pdx-guardian-builder:latest python3 /workspace/scripts/run_week4_e2e.py
.\.venv\Scripts\python.exe host\run_week4_pipeline.py

# Host Rejection & A/B Slot Unit Tests (requires evidence/week2/qnx_week2_results.json from Week 2 above)
.\.venv\Scripts\python.exe host\tests\test_week2_host_rejections.py
```

---

### 3. QSTI QEMU Target Configuration & Acceleration Disclosure
* **Core Launch Arguments**:
  * `-cpu max -smp 2 -m 2G -display none -monitor none -snapshot`
  * Disk: `-drive file=disk-qemu.qcow2,if=ide,format=qcow2`
  * Networking: `-netdev user,id=net0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=net0`
* **Honest Virtualization Acceleration Disclosure**:
  * Inside Windows Docker Desktop (WSL2) containers, `/dev/kvm` is unavailable, so QEMU executes in **TCG (Tiny Code Generator) software emulation mode**.
  * Functional tests, QNX IPC, cryptographic verification, crash recovery, and state reconciliation are all faithfully reproduced under TCG. **Hard real-time jitter metrics measured without KVM/hardware acceleration are reported strictly as a virtualized demonstration benchmark, not a production real-time guarantee.**

---

### 4. Reproducing QNX 8.0.0 Multi-Vehicle Fleet & Cross-Host Benchmarks

#### Step E1: Quick Offline Review or Pure SUMO Baseline (No QNX Image Required)
1. **Interactive Dashboard**: Open `docs/hackathon_dashboard.html` directly in any browser (zero external dependencies).
2. **Pure SUMO 1.28+ Baseline** (requires `sumo` + `traci` installed locally):
```powershell
python tests\dsx_air_fleet\run_sumo_baseline.py
```

#### Step E2: Cross-Compile `qnx_veh_host.elf` & Configure Target Paths
With QNX SDP 8.0 installed at `<QNX_SDP_ROOT>`:
```cmd
call <QNX_SDP_ROOT>\qnxsdp-env.bat
qcc -Vgcc_ntox86_64 -O2 -Wall -Wextra -o tests\dsx_air_fleet\qnx_veh_host.elf tests\dsx_air_fleet\qnx_veh_host.c -lsocket -lm
```
Set environment variables pointing to your local `qemu-system-x86_64` binary and QNX 8.0 QEMU image (`disk-qemu.qcow2`). If your QNX guest uses non-default credentials (QSTI defaults to `root`/`root`), also set `PDX_QNX_USER` and `PDX_QNX_PASS`:
```powershell
$env:PDX_QEMU_BIN  = "<PATH_TO_QEMU_SYSTEM_X86_64>"
$env:PDX_QNX_QCOW2 = "<PATH_TO_DISK_QEMU_QCOW2>"
# Optional if your QNX guest differs from QSTI defaults:
# $env:PDX_QNX_USER = "root"
# $env:PDX_QNX_PASS = "root"
```

#### Step E3: Run Local QNX 8.0.0 Fleet Ladders (60 → 150 → 300 → 600 Vehicles)
```powershell
# 1. Single QNX Guest (3 zone processes) 60->600 ladder + 600v 3-arm paired experiment
python tests\dsx_air_fleet\run_qnx_ladder.py --counts 60 150 300 600 --no-pace

# 2. 3 Independent QNX Guests (1:1 wall-clock, binary protocol + clock_gettime compute)
python tests\dsx_air_fleet\run_qnx_3guest.py --counts 60 150 300 600 --binary

# 3. 3 Independent QNX Guests medium-traffic 3-arm paired baseline (60v & 150v)
python tests\dsx_air_fleet\run_qnx_3guest_paired.py
```

#### Step E4: Optional Remote / OCI Cloud KVM & Same-Hardware A/B Benchmarks
To reproduce cross-host or intra-region KVM runs on two Ubuntu 24.04 `/dev/kvm` hosts (`qemu-system-x86` + `sumo` installed, `disk-uncomp.qcow2` staged in the remote user's `$HOME` directory), configure SSH targets via environment variables. Note that the remote runners target the default cloud-image `ubuntu@` account with `StrictHostKeyChecking=no`, which is intended **strictly for ephemeral/disposable test VMs**:
```powershell
$env:PDX_OCI_VM1_IP  = "<VM1_IP>"
$env:PDX_OCI_VM2_IP  = "<VM2_IP>"
$env:PDX_OCI_VM1_KEY = "<PATH_TO_VM1_SSH_KEY>"
$env:PDX_OCI_VM2_KEY = "<PATH_TO_VM2_SSH_KEY>"

# Same-hardware Ubuntu 24.04 Native vs QNX 8.0.0 KVM A/B (35s post-boot + 200->20 steady-state)
python tests\dsx_air_fleet\bench_qnx_vs_ubuntu.py

# Cross-host 3-QNX-Guest WAN experiment (60->600)
python tests\dsx_air_fleet\run_qnx_crosshost.py --counts 60 150 300 600 --no-pace

# Intra-region KVM dual-host run (executed on VM1, targeting VM1 + VM2 QNX+KVM)
# python3 run_oci_lan_qnx.py --counts 60 150 300 600
```
