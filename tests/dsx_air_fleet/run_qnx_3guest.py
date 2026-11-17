#!/usr/bin/env python3
"""
3 Independent QNX 8.0.0 QEMU Guests Distributed Fleet Experiment.
Boots 3 separate QNX 8.0.0 QEMU VMs (qnx-zone-a, qnx-zone-b, qnx-zone-c),
each with its own vCPU/RAM budget (-smp 2 -m 1G), its own QNX kernel, and
its own qnx_veh_host.elf process, communicating over real UDP gateways while
SUMO supplies the traffic environment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
import socket

from run_qnx_ladder import (
    QEMU_BIN,
    QNX_QCOW2,
    QNX_ZONES,
    read_until,
    run_qnx_arm,
    start_http_server,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
SRC_ROOT = REPO_ROOT / "src"
for p in (str(REPO_ROOT), str(SRC_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)


def boot_qnx_guest(hid: str, h_rx: int, q_rx: int, h_rpc: int, q_rpc: int, serial_port: int, http_port: int) -> tuple[subprocess.Popen, socket.socket]:
    cmd = [
        str(QEMU_BIN),
        "-cpu", "max", "-smp", "2", "-m", "1G",
        "-display", "none", "-monitor", "none", "-snapshot",
        "-drive", f"file={QNX_QCOW2},if=ide,format=qcow2",
        "-netdev", (
            f"user,id=net0,"
            f"hostfwd=tcp::{h_rpc}-:{q_rpc},"
            f"hostfwd=udp::{h_rx}-:{q_rx}"
        ),
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", f"tcp:127.0.0.1:{serial_port},server,nowait",
    ]
    proc = subprocess.Popen(cmd)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(40):
        try:
            sock.connect(("127.0.0.1", serial_port))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        proc.terminate()
        raise RuntimeError(f"Failed to connect to QNX guest {hid} serial port {serial_port}")

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

    sock.sendall((
        f"mkdir -p /data/pdx_qnx_fleet && "
        f"curl -sS http://10.0.2.2:{http_port}/qnx_veh_host.elf -o /data/pdx_qnx_fleet/qnx_veh_host.elf && "
        f"chmod +x /data/pdx_qnx_fleet/qnx_veh_host.elf && echo QNX_BIN_\"\"OK\n"
    ).encode("ascii"))
    read_until(sock, [b"QNX_BIN_OK\r\n", b"QNX_BIN_OK\n"], timeout=30.0)
    return proc, sock


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", nargs="+", type=int, default=[60, 150])
    ap.add_argument("--seed", type=int, default=101)
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "out_qnx_3guest"))
    ap.add_argument("--no-pace", action="store_true")
    ap.add_argument("--binary", action="store_true")
    ap.add_argument("--http-port", type=int, default=18181)
    ap.add_argument("--serial-base", type=int, default=14331)
    args = ap.parse_args()

    fleet_dir = Path(__file__).resolve().parent
    out_base = Path(args.out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server(fleet_dir, args.http_port)
    procs: List[subprocess.Popen] = []
    zone_socks: Dict[str, socket.socket] = {}
    guest_info: Dict[str, Any] = {}

    try:
        for idx, (hid, zid, h_rx, q_rx, h_rpc, q_rpc, _) in enumerate(QNX_ZONES):
            sp = args.serial_base + idx
            proc, sock = boot_qnx_guest(hid, h_rx, q_rx, h_rpc, q_rpc, sp, args.http_port)
            procs.append(proc)
            zone_socks[hid] = sock
            guest_info[hid] = {"qemu_pid": proc.pid, "vcpu": 2, "ram": "1G", "serial_port": sp, "zone_id": zid}

        results: List[Dict[str, Any]] = []
        for n_veh in args.counts:
            res = run_qnx_arm(
                zone_socks,
                args.http_port,
                fleet_dir,
                n_veh,
                args.seed,
                "cooperative",
                True,
                out_base / f"qnx_3guest_{n_veh}v",
                not args.no_pace,
                use_binary=args.binary,
            )
            results.append(res)

        summary = {
            "target_os": "3 Independent QNX 8.0.0 x86pc QEMU Guests",
            "guest_topology": guest_info,
            "seed": args.seed,
            "pace_wall_clock": not args.no_pace,
            "runs": results,
        }
        (out_base / "qnx_3guest_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

        checks = []
        for r in results:
            nv = r["n_vehicles"]
            q_ok = all(v.get("os") == "QNX" and str(v.get("release", "")).startswith("8.0") for v in r["qnx_hosts"].values())
            checks.append({"name": f"3guest_{nv}v_hosts_are_qnx_8_0", "passed": q_ok})
            checks.append({"name": f"3guest_{nv}v_zero_collisions", "passed": r["collisions"] == 0})
            checks.append({"name": f"3guest_{nv}v_all_trips_completed", "passed": r["completed_trips"] == nv})
            checks.append({"name": f"3guest_{nv}v_zero_unsafe_cmds", "passed": r["unsafe_cmds_detected"] == 0})
            checks.append({"name": f"3guest_{nv}v_tx_gw_rx_reconciled", "passed": r["tx_gw_rx_reconciled"]})
            checks.append({"name": f"3guest_{nv}v_recovery_coverage_complete", "passed": r["recovery_coverage_complete"]})

        passed_n = sum(1 for c in checks if c["passed"])
        matrix = {
            "schema": "prodocux.qnx_3guest.matrix.v1",
            "status": "pass" if passed_n == len(checks) else "fail",
            "passed": passed_n,
            "total": len(checks),
            "checks": checks,
        }
        (out_base / "qnx_3guest_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

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
        summary_path = out_base / "qnx_3guest_results.json"
        summary_bytes = summary_path.read_bytes()
        doc_sha = hashlib.sha256(summary_bytes).hexdigest()
        doc_id = "doc-qnx-3guest"
        sr = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1",
            source_sha256=doc_sha,
            media_type="application/json",
            locator=PdfPageLocator(kind="pdf_page", page=1),
            snippet="3 Independent QNX 8.0.0 QEMU Guests",
            extraction=ExtractionIdentity(
                method="host_supplied",
                extractor_id="pdx-guardian-qnx-3guest",
                extractor_version=prodocux_kernel.__version__,
            ),
            truncated=False,
        )
        ev_items, ev_checks = [], []
        for r in results:
            nv = r["n_vehicles"]
            q_ok = str(all(v.get("os") == "QNX" and str(v.get("release", "")).startswith("8.0") for v in r["qnx_hosts"].values()))
            ev_items.extend([
                EvidenceItem(evidence_id=f"ev-{nv}-qnx", document_id=doc_id, field_name=f"runs.{nv}.all_qnx", value_type="string", value=q_ok, confidence=1.0, source_reference=sr),
                EvidenceItem(evidence_id=f"ev-{nv}-col", document_id=doc_id, field_name=f"runs.{nv}.collisions", value_type="number", value=r["collisions"], confidence=1.0, source_reference=sr),
                EvidenceItem(evidence_id=f"ev-{nv}-trip", document_id=doc_id, field_name=f"runs.{nv}.completed_trips", value_type="number", value=r["completed_trips"], confidence=1.0, source_reference=sr),
                EvidenceItem(evidence_id=f"ev-{nv}-rcov", document_id=doc_id, field_name=f"runs.{nv}.recovery_coverage_complete", value_type="string", value=str(r["recovery_coverage_complete"]), confidence=1.0, source_reference=sr),
            ])
            ev_checks.extend([
                EvidenceCheck(check_id=f"chk-{nv}-qnx", kind="equality", evidence_ids=[f"ev-{nv}-qnx"], expected="True"),
                EvidenceCheck(check_id=f"chk-{nv}-col", kind="numeric_range", evidence_ids=[f"ev-{nv}-col"], minimum=0.0, minimum_inclusive=True, maximum=0.0, maximum_inclusive=True),
                EvidenceCheck(check_id=f"chk-{nv}-trip", kind="numeric_range", evidence_ids=[f"ev-{nv}-trip"], minimum=float(nv), minimum_inclusive=True, maximum=float(nv), maximum_inclusive=True),
                EvidenceCheck(check_id=f"chk-{nv}-rcov", kind="equality", evidence_ids=[f"ev-{nv}-rcov"], expected="True"),
            ])
        req = EvidenceBundleRequestV1(
            schema_version="prodocux_evidence_bundle_request_v1",
            request_id=f"req-{doc_sha[:16]}",
            rule_set=EvidenceRuleSet(
                id="pdx-guardian-qnx-3guest",
                version="1.0.0",
                sha256=hashlib.sha256(b"pdx-guardian-qnx-3guest-v1").hexdigest(),
            ),
            documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
            evidence=ev_items,
            checks=ev_checks,
        )
        b = verify_evidence_bundle(req)
        bundle_ver = b if isinstance(b, dict) else b.model_dump(mode="json")
        (out_base / "prodocux_qnx_3guest_bundle_verification.json").write_text(
            json.dumps(bundle_ver, indent=2), encoding="utf-8"
        )
        print(json.dumps({"summary": summary, "matrix_checks": matrix, "prodocux_bundle_verification": bundle_ver}, indent=2))
        if matrix["status"] != "pass" or bundle_ver.get("status") != "pass":
            sys.exit(1)
    finally:
        for s in zone_socks.values():
            try:
                s.close()
            except Exception:
                pass
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5.0)
            except Exception:
                pass
        httpd.shutdown()


if __name__ == "__main__":
    main()
