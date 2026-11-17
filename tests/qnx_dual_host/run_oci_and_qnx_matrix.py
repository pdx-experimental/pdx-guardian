#!/usr/bin/env python3
"""
Runs the complete cross-host QNX + OCI verification matrix:
  1. OCI Dual-VM (OCI VM1 <-> OCI VM2): Cases A, B, C (VM2 restart + state preservation), D (409 conflict)
  2. Direction 1 (OCI VM1 Host -> Local QNX 8.0 QEMU Target): Cases A, B, C (QNX restart), D (409 conflict)
  3. Direction 2 (Local QNX 8.0 QEMU Client -> OCI VM2 Target): Cases A, B, D
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
QEMU_BIN = Path(os.environ.get("PDX_QEMU_BIN", shutil.which("qemu-system-x86_64") or "qemu-system-x86_64"))
QNX_QCOW2 = Path(os.environ.get("PDX_QNX_QCOW2", "disk-qemu.qcow2"))

VM1_IP = os.environ.get("PDX_OCI_VM1_IP", "198.51.100.1")
VM2_IP = os.environ.get("PDX_OCI_VM2_IP", "198.51.100.2")
KEY_VM1 = os.environ.get("PDX_OCI_VM1_KEY", "~/.ssh/oci_vm1.key")
KEY_VM2 = os.environ.get("PDX_OCI_VM2_KEY", "~/.ssh/oci_vm2.key")
PUBKEY_HEX = "7d1f0d1f1133b05f65e075aa4a687d8bccc31efd521db6fcc72e34bea7b3f8fa"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def start_http_server(root: Path, port: int) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(QuietHandler, directory=str(root))
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def read_until(sock: socket.socket, markers: List[bytes], timeout: float = 90.0) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if any(m in buf for m in markers):
                return buf
        except socket.timeout:
            continue
    return buf


def ssh_run(key: str, ip: str, cmd: str, timeout: int = 90) -> str:
    res = subprocess.run(
        ["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", f"ubuntu@{ip}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    if res.returncode != 0:
        raise RuntimeError(f"ssh failed ({res.returncode}) on {ip}: stdout={res.stdout} stderr={res.stderr}")
    return res.stdout


def scp_up(key: str, ip: str, local_path: Path, remote_path: str) -> None:
    subprocess.run(
        ["scp", "-i", key, "-o", "StrictHostKeyChecking=no", str(local_path), f"ubuntu@{ip}:{remote_path}"],
        check=True, capture_output=True, text=True, timeout=30,
    )


def wait_http_ok(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.4)
    raise RuntimeError(f"Timed out waiting for {url}")


def start_vm2_target(reset_state: bool) -> subprocess.Popen:
    # Kill any prior oci_target_service and allow private VCN subnet 10.0.0.0/24 -> 8080
    ssh_run(KEY_VM2, VM2_IP, "pkill -f '[o]ci_target_service.py' || true; sudo iptables -C INPUT -s 10.0.0.0/24 -p tcp --dport 8080 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -s 10.0.0.0/24 -p tcp --dport 8080 -j ACCEPT")
    reset_flag = " --reset-state" if reset_state else ""
    cmd = (
        f"python3 ~/oci_target_service.py --bind 0.0.0.0 --port 8080 "
        f"--state-dir /tmp/oci_target_state --gate-bin ~/pdx-oci-target/oci_portable_gate "
        f"--pubkey-hex {PUBKEY_HEX}{reset_flag}"
    )
    return subprocess.Popen(
        ["ssh", "-i", KEY_VM2, "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM2_IP}", cmd],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def main() -> int:
    # Upload latest oci_v2_suite.py to VM1 and oci_target_service.py to VM2
    scp_up(KEY_VM1, VM1_IP, REPO_ROOT / "tests" / "oci_dual_vm" / "oci_v2_suite.py", "~/pdx-oci-host/oci_v2_suite.py")
    scp_up(KEY_VM2, VM2_IP, REPO_ROOT / "tests" / "oci_dual_vm" / "oci_target_service.py", "~/oci_target_service.py")

    # =========================================================================
    # 1. OCI Dual-VM (VM1 <-> VM2 via SSH tunnel)
    # =========================================================================
    vm2_proc = start_vm2_target(reset_state=True)
    tun_l = subprocess.Popen(["ssh", "-i", KEY_VM2, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-N", "-L", "18091:127.0.0.1:8080", f"ubuntu@{VM2_IP}"], stdin=subprocess.DEVNULL)
    tun_r_oci = subprocess.Popen(["ssh", "-i", KEY_VM1, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-N", "-R", "18088:127.0.0.1:18091", f"ubuntu@{VM1_IP}"], stdin=subprocess.DEVNULL)
    try:
        wait_http_ok("http://127.0.0.1:18091/health", 25.0)
        ab_cmd = "for i in $(seq 1 20); do curl -sf http://127.0.0.1:18088/health >/dev/null && break; sleep 0.5; done; python3 ~/pdx-oci-host/oci_v2_suite.py --target-url http://127.0.0.1:18088 --phase ab"
        ab_json = json.loads(ssh_run(KEY_VM1, VM1_IP, ab_cmd))

        # Restart VM2 target WITHOUT --reset-state
        vm2_proc.terminate()
        vm2_proc.wait(timeout=5)
        vm2_proc = start_vm2_target(reset_state=False)
        wait_http_ok("http://127.0.0.1:18091/health", 25.0)
        cd_json = json.loads(ssh_run(KEY_VM1, VM1_IP, "python3 ~/pdx-oci-host/oci_v2_suite.py --target-url http://127.0.0.1:18088 --phase cd"))

        oci_dual_res = {
            "environment": f"Dual OCI VMs (VM1 {VM1_IP} <-> VM2 {VM2_IP}, Ubuntu 24.04)",
            "target_health": ab_json["target_health"],
            "cases": ab_json["cases"] + cd_json["cases"],
        }
        c_a, c_b, c_c, c_d = oci_dual_res["cases"]
        oci_checks = [
            {"name": "case_a_drop_after_commit_reconciled", "passed": c_a["reconciled_committed"] is True and c_a["active_version"] == 11 and c_a["write_count_after_replay"] == 1},
            {"name": "case_b_drop_before_commit_no_write", "passed": c_b["reconciled_committed"] is False and c_b["write_count"] == 1},
            {"name": "case_c_vm2_restart_preserves_state_and_idempotent", "passed": c_c["health_after_restart"].get("active_version") == 11 and c_c["health_after_restart"].get("write_count") == 1 and c_c["idempotent_replay_flag"] is True and c_c["write_count_after_restart_replay"] == 1},
            {"name": "case_d_conflicting_payload_rejected_409", "passed": c_d["http_status"] == 409 and c_d["write_count_unchanged"] == 1},
        ]
        oci_verif = {
            "schema": "prodocux.oci_dual_vm.verification.v2",
            "status": "pass" if all(ch["passed"] for ch in oci_checks) else "fail",
            "passed": sum(1 for ch in oci_checks if ch["passed"]),
            "total": len(oci_checks),
            "checks": oci_checks,
        }
        ev_oci = REPO_ROOT / "evidence" / "oci_dual_vm"
        (ev_oci / "oci_dual_vm_results_v2.json").write_text(json.dumps(oci_dual_res, indent=2), encoding="utf-8")
        (ev_oci / "prodocux_oci_verification_v2.json").write_text(json.dumps(oci_verif, indent=2), encoding="utf-8")
    finally:
        tun_r_oci.terminate()
        tun_l.terminate()
        vm2_proc.terminate()

    # =========================================================================
    # 2 & 3. Bidirectional Local QNX 8.0 QEMU <-> OCI VMs
    # =========================================================================
    httpd = start_http_server(REPO_ROOT, 18080)
    qemu_proc = subprocess.Popen([
        str(QEMU_BIN), "-cpu", "max", "-smp", "2", "-m", "2G", "-display", "none", "-monitor", "none", "-snapshot",
        "-drive", f"file={QNX_QCOW2},if=ide,format=qcow2",
        "-netdev", "user,id=net0,hostfwd=tcp::12222-:22,hostfwd=tcp::18090-:8080",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", "tcp:127.0.0.1:14321,server,nowait",
    ])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(30):
        try:
            sock.connect(("127.0.0.1", 14321))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)

    # Reset VM2 state for Direction 2 (QNX Client -> OCI VM2 Target)
    vm2_proc2 = start_vm2_target(reset_state=True)
    tun_l2 = subprocess.Popen(["ssh", "-i", KEY_VM2, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-N", "-L", "18091:127.0.0.1:8080", f"ubuntu@{VM2_IP}"], stdin=subprocess.DEVNULL)
    tun_r_qnx = subprocess.Popen(["ssh", "-i", KEY_VM1, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-N", "-R", "18090:127.0.0.1:18090", f"ubuntu@{VM1_IP}"], stdin=subprocess.DEVNULL)

    try:
        read_until(sock, [b"login:"], timeout=90.0)
        time.sleep(1.0)
        # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
        qnx_user = os.environ.get("PDX_QNX_USER", "root")
        qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
        sock.sendall(f"{qnx_user}\n".encode("ascii"))
        read_until(sock, [b"Password:"], timeout=15.0)
        time.sleep(0.5)
        sock.sendall(f"{qnx_pass}\n".encode("ascii"))
        read_until(sock, [b"# ", b"$ "], timeout=20.0)

        setup_qnx = (
            "mkdir -p /data/pdx_qnx\n"
            "cd /data/pdx_qnx\n"
            "curl -sS http://10.0.2.2:18080/tests/oci_dual_vm/oci_portable_gate_qnx.elf -o /data/pdx_qnx/oci_portable_gate_qnx.elf && "
            "curl -sS http://10.0.2.2:18080/tests/qnx_dual_host/qnx_target_service.elf -o /data/pdx_qnx/qnx_target_service.elf && "
            "curl -sS http://10.0.2.2:18080/tests/qnx_dual_host/qnx_host_client.elf -o /data/pdx_qnx/qnx_host_client.elf && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t01_manifest_v11.bin -o /data/pdx_qnx/t01_m.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t01_fw_v11.bin -o /data/pdx_qnx/t01_fw.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07_manifest_v12.bin -o /data/pdx_qnx/t07_m.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week3/t07_fw_v12.bin -o /data/pdx_qnx/t07_fw.bin && "
            "chmod +x /data/pdx_qnx/*.elf && echo QNX_FILES_OK\n"
        )
        sock.sendall(setup_qnx.encode("ascii"))
        read_until(sock, [b"QNX_FILES_OK"], timeout=40.0)

        # Start QNX Target Service
        sock.sendall(
            f"/data/pdx_qnx/qnx_target_service.elf --port 8080 --state-dir /data/pdx_qnx_state "
            f"--gate-bin /data/pdx_qnx/oci_portable_gate_qnx.elf --pubkey-hex {PUBKEY_HEX} > /tmp/qnx_svc.log 2>&1 &\n".encode("ascii")
        )
        wait_http_ok("http://127.0.0.1:18090/health", 25.0)
        d1_cmd = "for i in $(seq 1 20); do curl -sf http://127.0.0.1:18090/health >/dev/null && break; sleep 0.5; done; python3 ~/pdx-oci-host/oci_v2_suite.py --target-url http://127.0.0.1:18090 --phase ab"
        # Direction 1: OCI VM1 Host -> Local QNX 8.0 QEMU Target
        d1_ab = json.loads(ssh_run(KEY_VM1, VM1_IP, d1_cmd))
        # Restart QNX target service
        sock.sendall(
            f"slay -f qnx_target_service.elf 2>/dev/null; sleep 2\n"
            f"/data/pdx_qnx/qnx_target_service.elf --port 8080 --state-dir /data/pdx_qnx_state "
            f"--gate-bin /data/pdx_qnx/oci_portable_gate_qnx.elf --pubkey-hex {PUBKEY_HEX} > /tmp/qnx_svc2.log 2>&1 &\n"
            f"sleep 1; echo QNX_RESTART_OK\n".encode("ascii")
        )
        read_until(sock, [b"QNX_RESTART_OK"], timeout=20.0)
        wait_http_ok("http://127.0.0.1:18090/health", 15.0)
        d1_cd = json.loads(ssh_run(KEY_VM1, VM1_IP, "python3 ~/pdx-oci-host/oci_v2_suite.py --target-url http://127.0.0.1:18090 --phase cd"))
        dir1_res = {
            "direction": "OCI_VM1_Host_to_Local_QNX_8_0_Target",
            "target_health": d1_ab["target_health"],
            "cases": d1_ab["cases"] + d1_cd["cases"],
        }

        # Direction 2: Local QNX 8.0 QEMU Client -> OCI VM2 Target
        wait_http_ok("http://127.0.0.1:18091/health", 20.0)
        sock.sendall(b"/data/pdx_qnx/qnx_host_client.elf --host 10.0.2.2 --port 18091 --m1 /data/pdx_qnx/t01_m.bin --fw1 /data/pdx_qnx/t01_fw.bin --m7 /data/pdx_qnx/t07_m.bin --fw7 /data/pdx_qnx/t07_fw.bin; echo QNX_CLIENT_\"\"DONE\n")
        cli_raw = read_until(sock, [b"\nQNX_CLIENT_DONE", b"\r\nQNX_CLIENT_DONE"], timeout=40.0).decode("utf-8", "replace")
        dir2_res: Dict[str, Any] = {}
        for line in cli_raw.splitlines():
            s_line = line.strip()
            if s_line.startswith("QNX_CLIENT_RESULT "):
                dir2_res = json.loads(s_line.split("QNX_CLIENT_RESULT ", 1)[1])
                break

        ev_bi = REPO_ROOT / "evidence" / "qnx_oci_bidirectional"
        ev_bi.mkdir(parents=True, exist_ok=True)
        (ev_bi / "oci_to_qnx_results.json").write_text(json.dumps(dir1_res, indent=2), encoding="utf-8")
        (ev_bi / "qnx_to_oci_results.json").write_text(json.dumps(dir2_res, indent=2), encoding="utf-8")

        d1_a, d1_b, d1_c, d1_d = dir1_res["cases"]
        bi_checks = [
            {"name": "oci_dual_vm_4_of_4_pass", "passed": oci_verif["status"] == "pass"},
            {"name": "dir1_target_is_qnx_8_0", "passed": dir1_res["target_health"].get("sysname") == "QNX"},
            {"name": "dir1_oci_to_qnx_cases_abcd_pass", "passed": d1_a["reconciled_committed"] is True and d1_b["reconciled_committed"] is False and d1_c["idempotent_replay_flag"] is True and d1_d["http_status"] == 409},
            {"name": "dir2_client_is_qnx_8_0", "passed": dir2_res.get("client_os") == "QNX"},
            {"name": "dir2_qnx_to_oci_cases_abd_pass", "passed": dir2_res.get("case_a", {}).get("status", {}).get("committed") is True and dir2_res.get("case_a", {}).get("replay", {}).get("write_count") == 1 and dir2_res.get("case_b", {}).get("status", {}).get("committed") is False and dir2_res.get("case_d", {}).get("http_status") == 409},
        ]
        bi_verif = {
            "schema": "prodocux.qnx_oci_matrix.summary.v1",
            "note": "Python bidirectional matrix summary (5/5 includes OCI->OCI 4/4). Distinct from verify_evidence_bundle.",
            "status": "pass" if all(ch["passed"] for ch in bi_checks) else "fail",
            "passed": sum(1 for ch in bi_checks if ch["passed"]),
            "total": len(bi_checks),
            "checks": bi_checks,
        }
        (ev_bi / "prodocux_qnx_oci_verification.json").write_text(json.dumps(bi_verif, indent=2), encoding="utf-8")

        import hashlib
        import prodocux_kernel
        from prodocux_kernel.verification import verify_evidence_bundle
        from prodocux_kernel.verification.evidence_models import (
            EvidenceBundleRequestV1,
            EvidenceCheck,
            EvidenceDocument,
            EvidenceItem,
            EvidenceRuleSet,
            ExtractionIdentity,
            PdfPageLocator,
            SourceReferenceV1,
        )

        bi_bytes = json.dumps({"oci_to_qnx": dir1_res, "qnx_to_oci": dir2_res}, indent=2).encode("utf-8")
        bi_sha = hashlib.sha256(bi_bytes).hexdigest()
        doc_id = "doc-qnx-oci-bidirectional"
        src_ref = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1",
            source_sha256=bi_sha,
            media_type="application/json",
            locator=PdfPageLocator(kind="pdf_page", page=1),
            snippet="Bidirectional QNX 8.0 <-> OCI VM cross-host evidence",
            extraction=ExtractionIdentity(
                method="host_supplied",
                extractor_id="pdx-guardian-qnx-oci-matrix",
                extractor_version=prodocux_kernel.__version__,
            ),
            truncated=False,
        )
        req = EvidenceBundleRequestV1(
            schema_version="prodocux_evidence_bundle_request_v1",
            request_id=f"req-{bi_sha[:16]}",
            rule_set=EvidenceRuleSet(id="pdx-guardian-qnx-oci-bidirectional", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-qnx-oci-bidirectional-v1").hexdigest()),
            documents=[EvidenceDocument(document_id=doc_id, source_sha256=bi_sha, media_type="application/json")],
            evidence=[
                EvidenceItem(evidence_id="ev-d1-os", document_id=doc_id, field_name="oci_to_qnx.sysname", value_type="string", value=str(dir1_res["target_health"].get("sysname", "")), confidence=1.0, source_reference=src_ref),
                EvidenceItem(evidence_id="ev-d1-wc", document_id=doc_id, field_name="oci_to_qnx.case_c.write_count", value_type="number", value=d1_c["write_count_after_restart_replay"], confidence=1.0, source_reference=src_ref),
                EvidenceItem(evidence_id="ev-d1-409", document_id=doc_id, field_name="oci_to_qnx.case_d.http_status", value_type="number", value=d1_d["http_status"], confidence=1.0, source_reference=src_ref),
                EvidenceItem(evidence_id="ev-d2-os", document_id=doc_id, field_name="qnx_to_oci.client_os", value_type="string", value=str(dir2_res.get("client_os", "")), confidence=1.0, source_reference=src_ref),
                EvidenceItem(evidence_id="ev-d2-wc", document_id=doc_id, field_name="qnx_to_oci.case_a.write_count", value_type="number", value=dir2_res["case_a"]["replay"]["write_count"], confidence=1.0, source_reference=src_ref),
                EvidenceItem(evidence_id="ev-d2-409", document_id=doc_id, field_name="qnx_to_oci.case_d.http_status", value_type="number", value=dir2_res["case_d"]["http_status"], confidence=1.0, source_reference=src_ref),
            ],
            checks=[
                EvidenceCheck(check_id="chk-d1-qnx", kind="equality", evidence_ids=["ev-d1-os"], expected="QNX"),
                EvidenceCheck(check_id="chk-d1-wc", kind="numeric_range", evidence_ids=["ev-d1-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-d1-409", kind="numeric_range", evidence_ids=["ev-d1-409"], minimum=409.0, minimum_inclusive=True, maximum=409.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-d2-qnx", kind="equality", evidence_ids=["ev-d2-os"], expected="QNX"),
                EvidenceCheck(check_id="chk-d2-wc", kind="numeric_range", evidence_ids=["ev-d2-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-d2-409", kind="numeric_range", evidence_ids=["ev-d2-409"], minimum=409.0, minimum_inclusive=True, maximum=409.0, maximum_inclusive=True),
            ],
        )
        bundle_ver = verify_evidence_bundle(req)
        bundle_dict = bundle_ver if isinstance(bundle_ver, dict) else bundle_ver.model_dump(mode="json")
        (ev_bi / "prodocux_qnx_oci_bundle_verification.json").write_text(json.dumps(bundle_dict, indent=2), encoding="utf-8")

        print(json.dumps({"oci_dual_vm_matrix": oci_verif, "qnx_oci_bidirectional_summary": bi_verif, "prodocux_bundle_verification": bundle_dict}, indent=2))
        return 0 if (oci_verif["status"] == "pass" and bi_verif["status"] == "pass" and bundle_dict.get("status") == "pass") else 1
    finally:
        tun_r_qnx.terminate()
        tun_l2.terminate()
        vm2_proc2.terminate()
        sock.close()
        qemu_proc.terminate()
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
