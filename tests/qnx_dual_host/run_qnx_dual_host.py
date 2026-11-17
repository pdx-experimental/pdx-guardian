#!/usr/bin/env python3
"""
Local Dual-Host E2E Runner: Host Orchestrator <-> QNX 8.0 QEMU Target Service.
Boots QNX 8.0 in QEMU, launches qnx_target_service.elf + oci_portable_gate_qnx.elf
inside QNX Neutrino, and executes 4 cross-host fault/reconciliation/restart cases:
  - Case A: drop_after_commit -> unknown_outcome -> reconcile -> idempotent replay
  - Case B: drop_before_commit -> unknown_outcome -> reconcile -> 0 new writes
  - Case C: QNX target process restart -> durable state preserved -> idempotent replay
  - Case D: Same operation_id with conflicting payload -> 409 Conflict rejected
"""

from __future__ import annotations

import argparse
import base64
import functools
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
QEMU_BIN = Path(os.environ.get("PDX_QEMU_BIN", shutil.which("qemu-system-x86_64") or "qemu-system-x86_64"))
QNX_QCOW2 = Path(os.environ.get("PDX_QNX_QCOW2", "disk-qemu.qcow2"))


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


def http_json(method: str, url: str, payload: Dict[str, Any] | None = None) -> tuple[int, Dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, {"raw": raw}


def run_reconcile_suite(target_url: str, fixtures_dir: Path) -> Dict[str, Any]:
    t01_m = (fixtures_dir / "t01_manifest_v11.bin").read_bytes()
    t01_fw = (fixtures_dir / "t01_fw_v11.bin").read_bytes()
    t07_m = (fixtures_dir / "t07_manifest_v12.bin").read_bytes()
    t07_fw = (fixtures_dir / "t07_fw_v12.bin").read_bytes()

    _, health = http_json("GET", f"{target_url}/health")
    results: Dict[str, Any] = {"target_health": health, "cases": []}

    # Case A: drop_after_commit
    t_a0 = time.perf_counter()
    err_a = None
    try:
        http_json("POST", f"{target_url}/submit", {
            "operation_id": "op-wk3-t01-valid-v11",
            "manifest_b64": base64.b64encode(t01_m).decode("ascii"),
            "firmware_b64": base64.b64encode(t01_fw).decode("ascii"),
            "drop_mode": "drop_after_commit",
        })
        raise AssertionError("Expected connection drop in Case A")
    except Exception as exc:
        err_a = f"{type(exc).__name__}: {exc}"

    _, st_a = http_json("GET", f"{target_url}/status?op_id=op-wk3-t01-valid-v11")
    code_a_replay, rep_a = http_json("POST", f"{target_url}/submit", {
        "operation_id": "op-wk3-t01-valid-v11",
        "manifest_b64": base64.b64encode(t01_m).decode("ascii"),
        "firmware_b64": base64.b64encode(t01_fw).decode("ascii"),
        "drop_mode": "none",
    })
    conv_a_ms = round((time.perf_counter() - t_a0) * 1000.0, 2)
    results["cases"].append({
        "case": "A_drop_after_commit",
        "operation_id": "op-wk3-t01-valid-v11",
        "transport_error": err_a,
        "reconciled_committed": st_a.get("committed"),
        "active_version": st_a.get("active_version"),
        "active_slot": st_a.get("active_slot"),
        "write_count_after_reconcile": st_a.get("write_count"),
        "idempotent_replay_http": code_a_replay,
        "idempotent_replay_flag": rep_a.get("idempotent_replay"),
        "write_count_after_replay": rep_a.get("write_count"),
        "convergence_ms": conv_a_ms,
    })

    # Case B: drop_before_commit
    t_b0 = time.perf_counter()
    err_b = None
    try:
        http_json("POST", f"{target_url}/submit", {
            "operation_id": "op-wk3-t07-crash-v12",
            "manifest_b64": base64.b64encode(t07_m).decode("ascii"),
            "firmware_b64": base64.b64encode(t07_fw).decode("ascii"),
            "drop_mode": "drop_before_commit",
        })
        raise AssertionError("Expected connection drop in Case B")
    except Exception as exc:
        err_b = f"{type(exc).__name__}: {exc}"
    _, st_b = http_json("GET", f"{target_url}/status?op_id=op-wk3-t07-crash-v12")
    conv_b_ms = round((time.perf_counter() - t_b0) * 1000.0, 2)
    results["cases"].append({
        "case": "B_drop_before_commit",
        "operation_id": "op-wk3-t07-crash-v12",
        "transport_error": err_b,
        "reconciled_committed": st_b.get("committed"),
        "active_version": st_b.get("active_version"),
        "active_slot": st_b.get("active_slot"),
        "write_count": st_b.get("write_count"),
        "convergence_ms": conv_b_ms,
    })

    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-port", type=int, default=18080)
    ap.add_argument("--target-port", type=int, default=18090)
    ap.add_argument("--serial-port", type=int, default=14321)
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "evidence" / "qnx_dual_host"))
    ap.add_argument("--keep-alive", action="store_true", help="Keep QEMU running after local test for OCI reverse-tunnel")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fixtures_dir = REPO_ROOT / "simulator" / "fixtures" / "week3"
    meta = json.loads((fixtures_dir / "fixtures_meta.json").read_text(encoding="utf-8"))
    pubkey_hex = meta["public_key_hex"]

    httpd = start_http_server(REPO_ROOT, args.http_port)
    qemu_cmd = [
        str(QEMU_BIN),
        "-cpu", "max", "-smp", "2", "-m", "2G",
        "-display", "none", "-monitor", "none", "-snapshot",
        "-drive", f"file={QNX_QCOW2},if=ide,format=qcow2",
        "-netdev", f"user,id=net0,hostfwd=tcp::12222-:22,hostfwd=tcp::{args.target_port}-:8080",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", f"tcp:127.0.0.1:{args.serial_port},server,nowait",
    ]
    proc = subprocess.Popen(qemu_cmd)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(30):
        try:
            sock.connect(("127.0.0.1", args.serial_port))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        proc.terminate()
        httpd.shutdown()
        raise RuntimeError("Failed to connect to QEMU serial")

    transcript = b""
    try:
        b1 = read_until(sock, [b"login:"], timeout=90.0)
        transcript += b1
        time.sleep(1.0)
        # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
        qnx_user = os.environ.get("PDX_QNX_USER", "root")
        qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
        sock.sendall(f"{qnx_user}\n".encode("ascii"))
        b2 = read_until(sock, [b"Password:"], timeout=15.0)
        transcript += b2
        time.sleep(0.5)
        sock.sendall(f"{qnx_pass}\n".encode("ascii"))
        b3 = read_until(sock, [b"# ", b"$ "], timeout=20.0)
        transcript += b3

        setup_cmd = (
            f"mkdir -p /data/pdx_qnx\n"
            f"cd /data/pdx_qnx\n"
            f"curl -sS http://10.0.2.2:{args.http_port}/tests/oci_dual_vm/oci_portable_gate_qnx.elf -o /data/pdx_qnx/oci_portable_gate_qnx.elf && "
            f"curl -sS http://10.0.2.2:{args.http_port}/tests/qnx_dual_host/qnx_target_service.elf -o /data/pdx_qnx/qnx_target_service.elf && "
            f"chmod +x /data/pdx_qnx/oci_portable_gate_qnx.elf /data/pdx_qnx/qnx_target_service.elf\n"
            f"/data/pdx_qnx/qnx_target_service.elf --port 8080 --state-dir /data/pdx_qnx_state --gate-bin /data/pdx_qnx/oci_portable_gate_qnx.elf --pubkey-hex {pubkey_hex} > /tmp/qnx_svc.log 2>&1 &\n"
        )
        sock.sendall(setup_cmd.encode("ascii"))
        b4 = read_until(sock, [b"# "], timeout=15.0)
        sock.sendall(b"cat /tmp/qnx_svc.log; echo CHECK_READY\n")
        b4 += read_until(sock, [b"QNX_TARGET_READY", b"CHECK_READY"], timeout=15.0)
        transcript += b4

        target_url = f"http://127.0.0.1:{args.target_port}"
        for _ in range(15):
            try:
                http_json("GET", f"{target_url}/health")
                break
            except Exception:
                time.sleep(0.5)
        res = run_reconcile_suite(target_url, fixtures_dir)

        # Case C: QNX target restart + state preservation + idempotent replay
        restart_cmd = (
            f"slay -f qnx_target_service.elf 2>/dev/null; sleep 2\n"
            f"/data/pdx_qnx/qnx_target_service.elf --port 8080 --state-dir /data/pdx_qnx_state --gate-bin /data/pdx_qnx/oci_portable_gate_qnx.elf --pubkey-hex {pubkey_hex} > /tmp/qnx_svc2.log 2>&1 &\n"
            f"sleep 1; echo QNX_RESTART_OK\n"
        )
        sock.sendall(restart_cmd.encode("ascii"))
        b5 = read_until(sock, [b"QNX_RESTART_OK"], timeout=20.0)
        transcript += b5

        health_after: Dict[str, Any] = {}
        for _ in range(10):
            try:
                _, health_after = http_json("GET", f"{target_url}/health")
                break
            except Exception:
                time.sleep(0.5)
        t01_m = (fixtures_dir / "t01_manifest_v11.bin").read_bytes()
        t01_fw = (fixtures_dir / "t01_fw_v11.bin").read_bytes()
        code_c, rep_c = http_json("POST", f"{target_url}/submit", {
            "operation_id": "op-wk3-t01-valid-v11",
            "manifest_b64": base64.b64encode(t01_m).decode("ascii"),
            "firmware_b64": base64.b64encode(t01_fw).decode("ascii"),
            "drop_mode": "none",
        })
        res["cases"].append({
            "case": "C_qnx_restart_and_replay",
            "health_after_restart": health_after,
            "replay_http": code_c,
            "idempotent_replay_flag": rep_c.get("idempotent_replay"),
            "write_count_after_restart_replay": rep_c.get("write_count"),
        })

        # Case D: Conflicting payload with same operation_id -> 409 Conflict
        code_d, rep_d = http_json("POST", f"{target_url}/submit", {
            "operation_id": "op-wk3-t01-valid-v11",
            "manifest_b64": base64.b64encode(t01_m).decode("ascii"),
            "firmware_b64": base64.b64encode(t01_fw + b"TAMPER").decode("ascii"),
            "drop_mode": "none",
        })
        _, st_d = http_json("GET", f"{target_url}/status?op_id=op-wk3-t01-valid-v11")
        res["cases"].append({
            "case": "D_conflicting_payload_rejected",
            "http_status": code_d,
            "error": rep_d.get("error"),
            "write_count_unchanged": st_d.get("write_count"),
        })

        # Case E: Disk/state_save failure -> 500, no state mutation, restart preserves version/slot/firmware hash
        import hashlib
        t07_m = (fixtures_dir / "t07_manifest_v12.bin").read_bytes()
        t07_fw = (fixtures_dir / "t07_fw_v12.bin").read_bytes()
        expected_fw_sha256 = hashlib.sha256(t01_fw).hexdigest()
        code_e, rep_e = http_json("POST", f"{target_url}/submit", {
            "operation_id": "op-wk3-t07-persist-err-v12",
            "manifest_b64": base64.b64encode(t07_m).decode("ascii"),
            "firmware_b64": base64.b64encode(t07_fw).decode("ascii"),
            "drop_mode": "inject_state_save_error",
        })
        _, health_e = http_json("GET", f"{target_url}/health")
        _, st_e = http_json("GET", f"{target_url}/status?op_id=op-wk3-t07-persist-err-v12")

        # Restart QNX target service after state_save failure & verify on-disk firmware hash
        restart_e_cmd = (
            f"slay -f qnx_target_service.elf 2>/dev/null; sleep 2\n"
            f"/data/pdx_qnx/qnx_target_service.elf --port 8080 --state-dir /data/pdx_qnx_state --gate-bin /data/pdx_qnx/oci_portable_gate_qnx.elf --pubkey-hex {pubkey_hex} > /tmp/qnx_svc3.log 2>&1 &\n"
            f"sleep 1; openssl dgst -sha256 /data/pdx_qnx_state/slot_SLOT_B_fw.bin; echo QNX_ERR_RESTART_\"\"OK\n"
        )
        sock.sendall(restart_e_cmd.encode("ascii"))
        b_e = read_until(sock, [b"\nQNX_ERR_RESTART_OK", b"\r\nQNX_ERR_RESTART_OK"], timeout=20.0)
        transcript += b_e
        b_e_str = b_e.decode("utf-8", "replace")
        slot_b_fw_sha256 = ""
        for ln in b_e_str.splitlines():
            if "slot_SLOT_B_fw.bin" in ln and "=" in ln:
                slot_b_fw_sha256 = ln.split("=", 1)[1].strip()

        health_after_e: Dict[str, Any] = {}
        for _ in range(10):
            try:
                _, health_after_e = http_json("GET", f"{target_url}/health")
                break
            except Exception:
                time.sleep(0.5)

        res["cases"].append({
            "case": "E_state_save_failure_rollback_and_restart",
            "http_status": code_e,
            "error": rep_e.get("error"),
            "committed_resp": rep_e.get("committed"),
            "status_committed": st_e.get("committed"),
            "active_version_after": health_e.get("active_version"),
            "active_slot_after": health_e.get("active_slot"),
            "write_count_after": health_e.get("write_count"),
            "health_after_restart": health_after_e,
            "expected_slot_b_fw_sha256": expected_fw_sha256,
            "actual_slot_b_fw_sha256": slot_b_fw_sha256,
            "slot_b_fw_hash_match": (slot_b_fw_sha256 == expected_fw_sha256),
        })

        # Build matrix verification summary + ProDocuX EvidenceBundle verification
        c_a, c_b, c_c, c_d, c_e = res["cases"]
        checks = [
            {"name": "target_os_is_qnx", "passed": res["target_health"].get("sysname") == "QNX"},
            {"name": "case_a_drop_after_commit_reconciled", "passed": c_a["reconciled_committed"] is True and c_a["active_version"] == 11 and c_a["active_slot"] == "SLOT_B" and c_a["write_count_after_replay"] == 1},
            {"name": "case_b_drop_before_commit_no_write", "passed": c_b["reconciled_committed"] is False and c_b["active_version"] == 11 and c_b["write_count"] == 1},
            {"name": "case_c_qnx_restart_preserves_state_and_idempotent", "passed": c_c["health_after_restart"].get("active_version") == 11 and c_c["health_after_restart"].get("write_count") == 1 and c_c["idempotent_replay_flag"] is True and c_c["write_count_after_restart_replay"] == 1},
            {"name": "case_d_conflicting_payload_same_op_id_rejected_409", "passed": c_d["http_status"] == 409 and c_d["write_count_unchanged"] == 1},
            {"name": "case_e_state_save_failure_500_restart_and_fw_hash_intact", "passed": c_e["http_status"] == 500 and c_e["error"] == "persist_failed" and c_e["committed_resp"] is False and c_e["status_committed"] is False and c_e["active_version_after"] == 11 and c_e["active_slot_after"] == "SLOT_B" and c_e["write_count_after"] == 1 and c_e["health_after_restart"].get("active_version") == 11 and c_e["health_after_restart"].get("active_slot") == "SLOT_B" and c_e["health_after_restart"].get("write_count") == 1 and c_e["slot_b_fw_hash_match"] is True},
        ]
        verif = {
            "schema": "prodocux.qnx_dual_host.matrix.v1",
            "status": "pass" if all(ch["passed"] for ch in checks) else "fail",
            "passed": sum(1 for ch in checks if ch["passed"]),
            "total": len(checks),
            "checks": checks,
        }
        res_bytes = json.dumps(res, indent=2).encode("utf-8")
        (out_dir / "qnx_dual_host_results.json").write_bytes(res_bytes)

        import hashlib
        import prodocux_kernel
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
        from prodocux_kernel.verification import verify_evidence_bundle

        doc_sha = hashlib.sha256(res_bytes).hexdigest()
        doc_id = "doc-qnx-dual-host"
        src_ref = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1",
            source_sha256=doc_sha,
            media_type="application/json",
            locator=PdfPageLocator(kind="pdf_page", page=1),
            snippet="Local Host <-> QNX 8.0.0 QEMU dual-host reconciliation & fault matrix",
            extraction=ExtractionIdentity(
                method="host_supplied",
                extractor_id="pdx-guardian-qnx-dual-host",
                extractor_version=prodocux_kernel.__version__,
            ),
            truncated=False,
        )
        ev_items = [
            EvidenceItem(evidence_id="ev-sysname", document_id=doc_id, field_name="target_health.sysname", value_type="string", value=str(res["target_health"].get("sysname", "")), confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-a-wc", document_id=doc_id, field_name="case_a.write_count_after_replay", value_type="number", value=c_a["write_count_after_replay"], confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-b-wc", document_id=doc_id, field_name="case_b.write_count", value_type="number", value=c_b["write_count"], confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-c-wc", document_id=doc_id, field_name="case_c.write_count_after_restart_replay", value_type="number", value=c_c["write_count_after_restart_replay"], confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-d-code", document_id=doc_id, field_name="case_d.http_status", value_type="number", value=c_d["http_status"], confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-e-code", document_id=doc_id, field_name="case_e.http_status", value_type="number", value=c_e["http_status"], confidence=1.0, source_reference=src_ref),
            EvidenceItem(evidence_id="ev-e-wc", document_id=doc_id, field_name="case_e.write_count_after", value_type="number", value=c_e["write_count_after"], confidence=1.0, source_reference=src_ref),
        ]
        req = EvidenceBundleRequestV1(
            schema_version="prodocux_evidence_bundle_request_v1",
            request_id=f"req-{doc_sha[:16]}",
            rule_set=EvidenceRuleSet(id="pdx-guardian-qnx-dual-host", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-qnx-dual-host-v1").hexdigest()),
            documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
            evidence=ev_items,
            checks=[
                EvidenceCheck(check_id="chk-qnx-os", kind="equality", evidence_ids=["ev-sysname"], expected="QNX"),
                EvidenceCheck(check_id="chk-a-wc", kind="numeric_range", evidence_ids=["ev-a-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-b-wc", kind="numeric_range", evidence_ids=["ev-b-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-c-wc", kind="numeric_range", evidence_ids=["ev-c-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-d-409", kind="numeric_range", evidence_ids=["ev-d-code"], minimum=409.0, minimum_inclusive=True, maximum=409.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-e-500", kind="numeric_range", evidence_ids=["ev-e-code"], minimum=500.0, minimum_inclusive=True, maximum=500.0, maximum_inclusive=True),
                EvidenceCheck(check_id="chk-e-wc", kind="numeric_range", evidence_ids=["ev-e-wc"], minimum=1.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True),
            ],
        )
        bundle_ver = verify_evidence_bundle(req)
        bundle_dict = bundle_ver if isinstance(bundle_ver, dict) else bundle_ver.model_dump(mode="json")

        (out_dir / "qnx_dual_host_matrix.json").write_text(json.dumps(verif, indent=2), encoding="utf-8")
        (out_dir / "prodocux_qnx_dual_host_verification.json").write_text(json.dumps(bundle_dict, indent=2), encoding="utf-8")
        (out_dir / "qnx_serial_transcript.log").write_bytes(transcript)
        print(json.dumps({"results": res, "matrix_checks": verif, "prodocux_bundle_verification": bundle_dict}, indent=2))

        if args.keep_alive:
            print("KEEP_ALIVE: QNX 8.0 target listening on http://127.0.0.1:18090 (Ctrl+C to stop)")
            while True:
                time.sleep(5)
        return 0 if (verif["status"] == "pass" and bundle_dict.get("status") == "pass") else 1
    except Exception:
        try:
            sock.sendall(b"cat /tmp/qnx_svc.log; echo ---SVC2---; cat /tmp/qnx_svc2.log; echo ---DB---; cat /data/pdx_qnx_state/target_state.db; echo DBG_DONE\n")
            print(read_until(sock, [b"DBG_DONE"], timeout=5.0).decode("utf-8", "replace"))
        except Exception:
            pass
        raise
    finally:
        sock.close()
        proc.terminate()
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
