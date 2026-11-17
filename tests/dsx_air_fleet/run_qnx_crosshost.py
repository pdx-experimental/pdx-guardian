#!/usr/bin/env python3
"""
Cross-Physical-Host 3-QNX-Guest Distributed Fleet Experiment:
  - Zone A (qnx-zone-a): Local Windows QNX 8.0.0 QEMU (-smp 2 -m 1G)
  - Zone B (qnx-zone-b): OCI VM1 (PDX_OCI_VM1_IP) QNX 8.0.0 QEMU + KVM (-smp 2 -m 512M)
  - Zone C (qnx-zone-c): OCI VM2 (PDX_OCI_VM2_IP) QNX 8.0.0 QEMU + KVM (-smp 2 -m 512M)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

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

import os
VM1_IP = os.environ.get("PDX_OCI_VM1_IP", "198.51.100.1")
VM2_IP = os.environ.get("PDX_OCI_VM2_IP", "198.51.100.2")
KEY_VM1 = os.environ.get("PDX_OCI_VM1_KEY", "~/.ssh/oci_vm1.key")
KEY_VM2 = os.environ.get("PDX_OCI_VM2_KEY", "~/.ssh/oci_vm2.key")

REMOTE_BRIDGE_PY = """
import socket, struct, sys, threading
tcp_in_port = int(sys.argv[1])
udp_to_qnx_port = int(sys.argv[2])
udp_from_qnx_port = int(sys.argv[3])
tcp_out_port = int(sys.argv[4])

def tcp_to_udp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", tcp_in_port))
    srv.listen(4)
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        conn, _ = srv.accept()
        def handle(c):
            try:
                while True:
                    hdr = b""
                    while len(hdr) < 4:
                        ch = c.recv(4 - len(hdr))
                        if not ch: return
                        hdr += ch
                    (n,) = struct.unpack(">I", hdr)
                    buf = bytearray()
                    while len(buf) < n:
                        ch = c.recv(n - len(buf))
                        if not ch: return
                        buf.extend(ch)
                    us.sendto(bytes(buf), ("127.0.0.1", udp_to_qnx_port))
            except Exception:
                pass
            finally:
                c.close()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

def udp_to_tcp():
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.bind(("0.0.0.0", udp_from_qnx_port))
    conn = None
    while True:
        data, _ = us.recvfrom(65535)
        frame = struct.pack(">I", len(data)) + data
        for _ in range(2):
            if conn is None:
                try:
                    conn = socket.create_connection(("127.0.0.1", tcp_out_port), timeout=5.0)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    conn = None
                    break
            try:
                conn.sendall(frame)
                break
            except Exception:
                try: conn.close()
                except Exception: pass
                conn = None

threading.Thread(target=tcp_to_udp, daemon=True).start()
udp_to_tcp()
"""


def start_local_udp_tcp_bridge(udp_listen: int, tcp_target: int, tcp_listen: int, udp_target: int) -> None:
    def udp_to_tcp() -> None:
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        us.bind(("127.0.0.1", udp_listen))
        conn = None
        while True:
            data, _ = us.recvfrom(65535)
            frame = struct.pack(">I", len(data)) + data
            for _ in range(2):
                if conn is None:
                    try:
                        conn = socket.create_connection(("127.0.0.1", tcp_target), timeout=5.0)
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except Exception:
                        conn = None
                        break
                try:
                    conn.sendall(frame)
                    break
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None

    def tcp_to_udp() -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", tcp_listen))
        srv.listen(4)
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            conn, _ = srv.accept()
            def handle(c: socket.socket) -> None:
                try:
                    while True:
                        hdr = b""
                        while len(hdr) < 4:
                            ch = c.recv(4 - len(hdr))
                            if not ch:
                                return
                            hdr += ch
                        (n,) = struct.unpack(">I", hdr)
                        buf = bytearray()
                        while len(buf) < n:
                            ch = c.recv(n - len(buf))
                            if not ch:
                                return
                            buf.extend(ch)
                        us.sendto(bytes(buf), ("127.0.0.1", udp_target))
                except Exception:
                    pass
                finally:
                    c.close()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=udp_to_tcp, daemon=True).start()
    threading.Thread(target=tcp_to_udp, daemon=True).start()


def connect_and_login_qnx(serial_port: int, hid: str, http_port: int, timeout_login: float = 130.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(60):
        try:
            sock.connect(("127.0.0.1", serial_port))
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    else:
        raise RuntimeError(f"Failed to connect to QNX {hid} serial port {serial_port}")

    read_until(sock, [b"login:"], timeout=timeout_login)
    time.sleep(3.0)
    # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
    qnx_user = os.environ.get("PDX_QNX_USER", "root")
    qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
    sock.sendall(f"{qnx_user}\n".encode("ascii"))
    read_until(sock, [b"Password:"], timeout=20.0)
    time.sleep(0.5)
    sock.sendall(f"{qnx_pass}\n".encode("ascii"))
    read_until(sock, [b"# ", b"$ "], timeout=25.0)

    sock.sendall((
        f"mkdir -p /data/pdx_qnx_fleet && "
        f"curl -sS http://10.0.2.2:{http_port}/qnx_veh_host.elf -o /data/pdx_qnx_fleet/qnx_veh_host.elf && "
        f"chmod +x /data/pdx_qnx_fleet/qnx_veh_host.elf && echo QNX_BIN_\"\"OK\n"
    ).encode("ascii"))
    read_until(sock, [b"QNX_BIN_OK\r\n", b"QNX_BIN_OK\n"], timeout=45.0)
    return sock


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", nargs="+", type=int, default=[60])
    ap.add_argument("--seed", type=int, default=101)
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "out_qnx_crosshost"))
    ap.add_argument("--no-pace", action="store_true")
    ap.add_argument("--binary", action="store_true")
    ap.add_argument("--http-port", type=int, default=18181)
    args = ap.parse_args()

    fleet_dir = Path(__file__).resolve().parent
    out_base = Path(args.out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server(fleet_dir, args.http_port)

    # Start local UDP<->TCP bridges for Zone B (VM1) and Zone C (VM2)
    start_local_udp_tcp_bridge(19102, 19112, 20102, 20002)
    start_local_udp_tcp_bridge(19103, 19113, 20103, 20003)

    procs: List[subprocess.Popen] = []
    zone_socks: Dict[str, socket.socket] = {}

    try:
        # 1. Start Local QNX Guest A
        hid_a, _, h_rx_a, q_rx_a, h_rpc_a, q_rpc_a, _ = QNX_ZONES[0]
        procs.append(subprocess.Popen([
            str(QEMU_BIN),
            "-cpu", "max", "-smp", "2", "-m", "1G",
            "-display", "none", "-monitor", "none", "-snapshot",
            "-drive", f"file={QNX_QCOW2},if=ide,format=qcow2",
            "-netdev", f"user,id=net0,hostfwd=tcp::{h_rpc_a}-:{q_rpc_a},hostfwd=udp::{h_rx_a}-:{q_rx_a}",
            "-device", "virtio-net-pci,netdev=net0",
            "-serial", "tcp:127.0.0.1:14331,server,nowait",
        ]))

        import base64
        b64_bridge = base64.b64encode(REMOTE_BRIDGE_PY.encode("utf-8")).decode("ascii")

        # 2. Start OCI VM1 QNX+KVM Guest B + SSH tunnel
        remote_cmd_b = (
            "pkill -f '[q]emu-system-x86_64.*8092' || true\n"
            "pkill -f '[q]nx_bridge_b.py' || true\n"
            f"echo {b64_bridge} | base64 -d > /tmp/qnx_bridge_b.py\n"
            "nohup python3 /tmp/qnx_bridge_b.py 19112 9102 20002 20102 </dev/null >/tmp/bridge_b.log 2>&1 &\n"
            "nohup qemu-system-x86_64 -enable-kvm -cpu max -smp 2 -m 512M "
            "-display none -monitor none -snapshot "
            "-drive file=disk-uncomp.qcow2,if=ide,format=qcow2 "
            "-netdev user,id=net0,hostfwd=tcp:127.0.0.1:8092-:8092,hostfwd=udp:127.0.0.1:9102-:9102 "
            "-device virtio-net-pci,netdev=net0 "
            "-serial tcp:127.0.0.1:14332,server,nowait </dev/null >/tmp/qemu_b.log 2>&1 &\n"
            "sleep 2\n"
            "echo REMOTE_B_STARTED\n"
        )
        subprocess.run(
            ["ssh", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM1_IP}", "bash -s"],
            input=remote_cmd_b.encode("utf-8"), check=True, timeout=30,
        )
        procs.append(subprocess.Popen([
            "ssh", "-N", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=10", "-o", "ExitOnForwardFailure=yes",
            "-L", "14332:127.0.0.1:14332",
            "-L", "18092:127.0.0.1:8092",
            "-L", "19112:127.0.0.1:19112",
            "-R", f"{args.http_port}:127.0.0.1:{args.http_port}",
            "-R", "20102:127.0.0.1:20102",
            f"ubuntu@{VM1_IP}",
        ]))

        # 3. Start OCI VM2 QNX+KVM Guest C + SSH tunnel
        remote_cmd_c = (
            "pkill -f '[q]emu-system-x86_64.*8093' || true\n"
            "pkill -f '[q]nx_bridge_c.py' || true\n"
            f"echo {b64_bridge} | base64 -d > /tmp/qnx_bridge_c.py\n"
            "nohup python3 /tmp/qnx_bridge_c.py 19113 9103 20003 20103 </dev/null >/tmp/bridge_c.log 2>&1 &\n"
            "nohup qemu-system-x86_64 -enable-kvm -cpu max -smp 2 -m 512M "
            "-display none -monitor none -snapshot "
            "-drive file=disk-uncomp.qcow2,if=ide,format=qcow2 "
            "-netdev user,id=net0,hostfwd=tcp:127.0.0.1:8093-:8093,hostfwd=udp:127.0.0.1:9103-:9103 "
            "-device virtio-net-pci,netdev=net0 "
            "-serial tcp:127.0.0.1:14333,server,nowait </dev/null >/tmp/qemu_c.log 2>&1 &\n"
            "sleep 2\n"
            "echo REMOTE_C_STARTED\n"
        )
        subprocess.run(
            ["ssh", "-i", KEY_VM2, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM2_IP}", "bash -s"],
            input=remote_cmd_c.encode("utf-8"), check=True, timeout=30,
        )
        procs.append(subprocess.Popen([
            "ssh", "-N", "-i", KEY_VM2, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=10", "-o", "ExitOnForwardFailure=yes",
            "-L", "14333:127.0.0.1:14333",
            "-L", "18093:127.0.0.1:8093",
            "-L", "19113:127.0.0.1:19113",
            "-R", f"{args.http_port}:127.0.0.1:{args.http_port}",
            "-R", "20103:127.0.0.1:20103",
            f"ubuntu@{VM2_IP}",
        ]))

        time.sleep(2.0)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as pool:
            fa = pool.submit(connect_and_login_qnx, 14331, "qnx-zone-a", args.http_port, 120.0)
            fb = pool.submit(connect_and_login_qnx, 14332, "qnx-zone-b", args.http_port, 160.0)
            fc = pool.submit(connect_and_login_qnx, 14333, "qnx-zone-c", args.http_port, 160.0)
            zone_socks["qnx-zone-a"] = fa.result()
            zone_socks["qnx-zone-b"] = fb.result()
            zone_socks["qnx-zone-c"] = fc.result()

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
                out_base / f"crosshost_{n_veh}v",
                not args.no_pace,
                use_binary=args.binary,
            )
            results.append(res)

        summary = {
            "target_os": "Cross-Physical-Host 3 QNX 8.0.0 Guests (Local Windows + OCI VM1 KVM + OCI VM2 KVM)",
            "host_placement": {
                "qnx-zone-a": "Local Windows QEMU QNX 8.0.0 (-smp 2 -m 1G)",
                "qnx-zone-b": f"OCI VM1 ({VM1_IP}) QEMU+KVM QNX 8.0.0 (-smp 2 -m 512M)",
                "qnx-zone-c": f"OCI VM2 ({VM2_IP}) QEMU+KVM QNX 8.0.0 (-smp 2 -m 512M)",
            },
            "seed": args.seed,
            "pace_wall_clock": not args.no_pace,
            "runs": results,
        }
        (out_base / "qnx_crosshost_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

        checks = []
        for r in results:
            nv = r["n_vehicles"]
            q_ok = all(v.get("os") == "QNX" and str(v.get("release", "")).startswith("8.0") for v in r["qnx_hosts"].values())
            checks.append({"name": f"crosshost_{nv}v_hosts_are_qnx_8_0", "passed": q_ok})
            checks.append({"name": f"crosshost_{nv}v_zero_collisions", "passed": r["collisions"] == 0})
            checks.append({"name": f"crosshost_{nv}v_all_trips_completed", "passed": r["completed_trips"] == nv})
            checks.append({"name": f"crosshost_{nv}v_zero_unsafe_cmds", "passed": r["unsafe_cmds_detected"] == 0})
            checks.append({"name": f"crosshost_{nv}v_tx_gw_rx_reconciled", "passed": r["tx_gw_rx_reconciled"]})
            checks.append({"name": f"crosshost_{nv}v_recovery_coverage_complete", "passed": r["recovery_coverage_complete"]})

        passed_n = sum(1 for c in checks if c["passed"])
        matrix = {
            "schema": "prodocux.qnx_crosshost.matrix.v1",
            "status": "pass" if passed_n == len(checks) else "fail",
            "passed": passed_n,
            "total": len(checks),
            "checks": checks,
        }
        (out_base / "qnx_crosshost_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

        import prodocux_kernel
        from prodocux_kernel.verification import verify_evidence_bundle
        from prodocux_kernel.verification.evidence_models import (
            EvidenceBundleRequestV1, EvidenceCheck, EvidenceDocument, EvidenceItem,
            EvidenceRuleSet, ExtractionIdentity, PdfPageLocator, SourceReferenceV1,
        )
        summary_bytes = (out_base / "qnx_crosshost_results.json").read_bytes()
        doc_sha = hashlib.sha256(summary_bytes).hexdigest()
        doc_id = "doc-qnx-crosshost"
        sr = SourceReferenceV1(
            schema_version="prodocux_source_reference_v1", source_sha256=doc_sha, media_type="application/json",
            locator=PdfPageLocator(kind="pdf_page", page=1), snippet="Cross-Physical-Host 3 QNX 8.0.0 Guests",
            extraction=ExtractionIdentity(method="host_supplied", extractor_id="pdx-guardian-qnx-crosshost", extractor_version=prodocux_kernel.__version__),
            truncated=False,
        )
        ev_items, ev_checks = [], []
        for r in results:
            nv = r["n_vehicles"]
            q_ok = str(len(r["qnx_hosts"]) == 3 and all(v.get("os") == "QNX" for v in r["qnx_hosts"].values()))
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
            schema_version="prodocux_evidence_bundle_request_v1", request_id=f"req-{doc_sha[:16]}",
            rule_set=EvidenceRuleSet(id="pdx-guardian-qnx-crosshost", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-qnx-crosshost-v1").hexdigest()),
            documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
            evidence=ev_items, checks=ev_checks,
        )
        b = verify_evidence_bundle(req)
        bundle_ver = b if isinstance(b, dict) else b.model_dump(mode="json")
        (out_base / "prodocux_qnx_crosshost_bundle_verification.json").write_text(json.dumps(bundle_ver, indent=2), encoding="utf-8")
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
        for key, ip, pat in [(KEY_VM1, VM1_IP, "[8]092|[q]nx_bridge_b"), (KEY_VM2, VM2_IP, "[8]093|[q]nx_bridge_c")]:
            try:
                subprocess.run(
                    ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{ip}", f"pkill -f '{pat}' || true"],
                    timeout=10,
                )
            except Exception:
                pass
        httpd.shutdown()


if __name__ == "__main__":
    main()
