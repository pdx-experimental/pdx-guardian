#!/usr/bin/env python3
"""
Dual-Pillar Coexistence E2E Benchmark (QNX 8.0 QEMU -smp 2)
Runs BOTH pillars simultaneously inside a single QNX 8.0.0 guest:
  1. In-Motion Cooperative Driving-Plan Exchange (qnx_veh_host.elf, N=50/zone, binary STEP_BATCH + UDP DrivingIntentV2)
  2. Stationary-Interlocked OTA Gate (/dev/pdxguardian via guardian_gate.elf + gate_submit.elf)

Phases (after 35s post-boot settle; default --iters 600):
  - Captures `mount` (fs-qnx6) and `pidin` (io-sock / active processes) evidence.
  - Phase 1 (Baseline 1): In-motion STEP_BATCH (600 iters, 100 warmup) with OTA gate idle.
  - Phase 2 (Concurrent In-Motion OTA Rejection): In-motion STEP_BATCH (600 iters, 10 warmup) while
    guardian_gate.elf (--speed 72) processes 10 signed OTA submissions (all fail-closed),
    with host wall-clock timestamps proving overlap with the STEP_BATCH window.
  - Phase 3 (Baseline 2, Post-OTA Steady-State): In-motion STEP_BATCH (600 iters, 20 warmup) with OTA gate idle.
  - Phase 4 (Parked Activation): Vehicle parked (--speed 0), valid signed OTA (t01_m.bin)
    is admitted (ALLOW, active_ver=11) with hash-chained journal verified.
"""

from __future__ import annotations

import argparse
import http.server
import json
import math
import os
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


def make_handler(workspace_dir: Path):
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(workspace_dir), **kwargs)

        def log_message(self, format, *args):
            pass

    return QuietHandler


def start_http_server(workspace_dir: Path, port: int = 18080) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", port), make_handler(workspace_dir))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def read_until(sock: socket.socket, markers: list[bytes], timeout: float = 120.0) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                buf += chunk
                if any(m in buf for m in markers):
                    return buf
        except socket.timeout:
            continue
    raise TimeoutError(f"Timed out waiting for markers {markers}")


def send_msg(conn: socket.socket, obj: dict) -> None:
    b = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack(">I", len(b)) + b)


def recv_msg(conn: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c:
            raise ConnectionError("EOF")
        hdr += c
    (n,) = struct.unpack(">I", hdr)
    buf = bytearray()
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            raise ConnectionError("EOF")
        buf.extend(c)
    return bytes(buf)


def pack_step_batch(sim_ms: int, n_vehs: int = 50) -> bytes:
    def pad32(s: str) -> bytes:
        b = s.encode("utf-8")[:31]
        return b + b"\x00" * (32 - len(b))

    def pad8(s: str) -> bytes:
        b = s.encode("utf-8")[:7]
        return b + b"\x00" * (8 - len(b))

    peers_buf = bytearray()
    for j in range(10):
        peers_buf.extend(pad32(f"veh-{j:03d}"))
        peers_buf.extend(pad32("j1_s_in"))
        peers_buf.extend(pad8("j1"))
        peers_buf.extend(struct.pack("<iidd", 1 if (j % 5 == 0) else 0, 1 if (j % 7 == 0) else 0, 8.0, 15.0 + (j % 10)))
    peers_bytes = bytes(peers_buf)

    parts = [b"B", struct.pack("<iiiii", sim_ms, 7500, 0, 1, n_vehs), pad32("veh-000"), pad32("veh-000")]
    for i in range(n_vehs):
        parts.append(pad32(f"veh-{i:03d}"))
        parts.append(pad32("j1_w_in"))
        parts.append(pad8("j1"))
        parts.append(struct.pack("<iiiidd", 1 if (i % 4 == 0) else 0, 0, 1, 10, 9.5, 12.0 + (i % 15)))
        parts.append(peers_bytes)
    return b"".join(parts)


def pct(vals: list[float], p: float) -> float:
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((p / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 3)


def run_step_batch_phase(port: int, n_vehs: int, iters: int, warmup: int) -> dict:
    conn = None
    for _ in range(60):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=10.0)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            pl = pack_step_batch(0, n_vehs)
            conn.sendall(struct.pack(">I", len(pl)) + pl)
            resp = recv_msg(conn)
            if resp[:1] == b"R":
                break
            conn.close()
            conn = None
        except (OSError, ConnectionError):
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            time.sleep(0.5)
    if conn is None:
        raise RuntimeError(f"Cannot connect to qnx_veh_host on port {port}")

    try:
        for w in range(warmup):
            pl = pack_step_batch(w * 100, n_vehs)
            conn.sendall(struct.pack(">I", len(pl)) + pl)
            recv_msg(conn)

        t_start = time.time()
        compute_us: list[float] = []
        os_name = ""
        os_rel = ""
        for k in range(iters):
            pl = pack_step_batch((warmup + k) * 100, n_vehs)
            conn.sendall(struct.pack(">I", len(pl)) + pl)
            resp = recv_msg(conn)
            if resp[:1] != b"R" or len(resp) < 49:
                raise RuntimeError(f"Unexpected binary response len={len(resp)}")
            if not os_name:
                os_name = resp[1:17].split(b"\x00", 1)[0].decode("utf-8", "replace")
                os_rel = resp[17:33].split(b"\x00", 1)[0].decode("utf-8", "replace")
            c_us = struct.unpack("<q", resp[41:49])[0]
            compute_us.append(float(c_us))
        t_end = time.time()

        send_msg(conn, {"op": "GET_SUMMARY"})
        summary = json.loads(recv_msg(conn).decode("utf-8"))
        nodes = summary.get("nodes", {})
        tx_total = sum(n.get("tx_count", 0) for n in nodes.values())
        stale_dropped = sum(n.get("stale_dropped", 0) for n in nodes.values())
        return {
            "os": os_name,
            "release": os_rel,
            "n_vehs_per_zone": n_vehs,
            "fleet_equiv": n_vehs * 3,
            "iters": iters,
            "window_start_epoch_s": round(t_start, 3),
            "window_end_epoch_s": round(t_end, 3),
            "compute_p50_us": pct(compute_us, 50),
            "compute_p95_us": pct(compute_us, 95),
            "compute_p99_us": pct(compute_us, 99),
            "compute_max_us": round(max(compute_us), 3),
            "tx_total": tx_total,
            "stale_dropped": stale_dropped,
        }
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--qemu-bin", default="qemu-system-x86_64")
    parser.add_argument("--accel", default="tcg", choices=["tcg", "whpx", "kvm"])
    parser.add_argument("--cpu", default="max")
    parser.add_argument("--n-vehs", type=int, default=50)
    parser.add_argument("--iters", type=int, default=600)
    args = parser.parse_args()

    workspace_dir = Path(args.workspace).resolve()
    meta_path = workspace_dir / "simulator" / "fixtures" / "week2" / "fixtures_meta.json"
    pubkey_hex = json.loads(meta_path.read_text(encoding="utf-8"))["public_key_hex"]

    out_dir = workspace_dir / "evidence" / "coexistence"
    out_dir.mkdir(parents=True, exist_ok=True)
    httpd = start_http_server(workspace_dir, 18080)

    qemu_cmd = [
        args.qemu_bin,
        "-accel", args.accel,
        "-cpu", args.cpu,
        "-smp", "2",
        "-m", "2G",
        "-display", "none",
        "-monitor", "none",
        "-snapshot",
        "-drive", f"file={args.disk},if=ide,format=qcow2",
        "-netdev", "user,id=net0,hostfwd=tcp::18091-:8091",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", "tcp:127.0.0.1:4321,server,nowait",
    ]
    print(f"[Coexistence E2E] Starting QNX 8.0 QEMU (-accel {args.accel}, -smp 2)...", flush=True)
    proc = subprocess.Popen(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    sock = None
    for _ in range(40):
        try:
            sock = socket.create_connection(("127.0.0.1", 4321), timeout=2.0)
            break
        except OSError:
            time.sleep(0.5)
    if sock is None:
        proc.terminate()
        httpd.shutdown()
        raise RuntimeError("Failed to connect to QEMU serial port 4321")

    chunks: list[bytes] = []
    try:
        out = read_until(sock, [b"login:", b"# "], timeout=180.0)
        chunks.append(out)
        if b"login:" in out:
            time.sleep(1.5)
            qnx_user = os.environ.get("PDX_QNX_USER", "root")
            qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
            sock.sendall(f"{qnx_user}\n".encode("ascii"))
            out = read_until(sock, [b"# ", b"Password:"], timeout=30.0)
            chunks.append(out)
            if b"Password:" in out:
                time.sleep(0.5)
                sock.sendall(f"{qnx_pass}\n".encode("ascii"))
                out = read_until(sock, [b"# ", b"$ "], timeout=30.0)
                chunks.append(out)

        setup_cmd = (
            "mkdir -p /tmp/coex /data/pdx_guardian && cd /tmp/coex && "
            "curl -sf http://10.0.2.2:18080/qnx/guardian-gate/guardian_gate.elf -o guardian_gate.elf && "
            "curl -sf http://10.0.2.2:18080/qnx/guardian-gate/gate_submit.elf -o gate_submit.elf && "
            "curl -sf http://10.0.2.2:18080/tests/dsx_air_fleet/qnx_veh_host.elf -o qnx_veh_host.elf && "
            "curl -sf http://10.0.2.2:18080/simulator/fixtures/week2/t01_manifest_v11.bin -o t01_m.bin && "
            "curl -sf http://10.0.2.2:18080/simulator/fixtures/week2/t01_fw_v11.bin -o t01_fw.bin && "
            "curl -sf http://10.0.2.2:18080/simulator/fixtures/week2/t05_manifest_v12.bin -o t05_m.bin && "
            "curl -sf http://10.0.2.2:18080/simulator/fixtures/week2/t05_fw_v12.bin -o t05_fw.bin && "
            "chmod +x guardian_gate.elf gate_submit.elf qnx_veh_host.elf && "
            "echo '[' > /tmp/coex/specs.json && "
            "i=0; while [ $i -lt 50 ]; do "
            "  vid=$(printf 'veh-%03d' $i); "
            "  sep=','; [ $i -eq 49 ] && sep=''; "
            "  echo \"{\\\"vehicle_id\\\":\\\"$vid\\\",\\\"zone_id\\\":\\\"zone-a\\\",\\\"silent\\\":false}$sep\" >> /tmp/coex/specs.json; "
            "  i=$((i+1)); "
            "done && echo ']' >> /tmp/coex/specs.json && "
            "./qnx_veh_host.elf --host-id qnx-coex --zone-id zone-a --rx-port 9101 --rpc-port 8091 "
            "--gw-ip 127.0.0.1 --gw-port 9101 --specs-json /tmp/coex/specs.json --mode cooperative >/tmp/coex/veh.log 2>&1 & "
            "sleep 35 && "
            "printf '===QNX_%s===\\n' 'MOUNT' && mount && "
            "printf '===QNX_%s===\\n' 'PIDIN' && pidin -F '%a %b %N' | grep -E --color=never 'io-sock|qnx_veh|devb|slogger' && "
            "printf 'COEX_%s\\n' 'READY'\n"
        ).encode("ascii")
        sock.sendall(setup_cmd)
        setup_out = read_until(sock, [b"COEX_READY"], timeout=120.0)
        chunks.append(setup_out)
        setup_text = setup_out.decode("utf-8", errors="replace")

        print("[Coexistence E2E] Phase 1: Baseline 1 In-Motion STEP_BATCH (OTA idle)...", flush=True)
        phase1 = run_step_batch_phase(18091, args.n_vehs, args.iters, warmup=100)

        print("[Coexistence E2E] Phase 2: Concurrent In-Motion STEP_BATCH + speed=72 km/h OTA attempts...", flush=True)
        ota_inmotion_cmd = (
            "./guardian_gate.elf --pubkey " + pubkey_hex + " --version 10 --speed 72 >/tmp/coex/gate72.log 2>&1 & "
            "G72_PID=$!; waitfor /dev/pdxguardian 15; "
            "printf 'GATE72_%s\\n' 'READY'; "
            "k=1; while [ $k -le 10 ]; do "
            "  echo \"---ATTEMPT_${k}---\"; ./gate_submit.elf t05_m.bin t05_fw.bin; sleep 0.08; k=$((k+1)); "
            "done; "
            "./gate_submit.elf --status; "
            "kill $G72_PID 2>/dev/null; wait $G72_PID 2>/dev/null; "
            "printf 'PHASE2_OTA_%s\\n' 'DONE'\n"
        ).encode("ascii")
        sock.sendall(ota_inmotion_cmd)
        chunks.append(read_until(sock, [b"GATE72_READY"], timeout=45.0))
        ota_dispatch_epoch = round(time.time(), 3)
        phase2 = run_step_batch_phase(18091, args.n_vehs, args.iters, warmup=10)
        p2_out = read_until(sock, [b"PHASE2_OTA_DONE"], timeout=60.0)
        ota_complete_epoch = round(time.time(), 3)
        chunks.append(p2_out)
        p2_text = p2_out.decode("utf-8", errors="replace")

        print("[Coexistence E2E] Phase 3: Baseline 2 In-Motion STEP_BATCH (Post-OTA idle steady-state)...", flush=True)
        phase3_b2 = run_step_batch_phase(18091, args.n_vehs, args.iters, warmup=20)

        print("[Coexistence E2E] Phase 4: Parked (speed=0 km/h) OTA Activation...", flush=True)
        ota_parked_cmd = (
            "./guardian_gate.elf --pubkey " + pubkey_hex + " --version 10 --speed 0 >/tmp/coex/gate0.log 2>&1 & "
            "G0_PID=$!; waitfor /dev/pdxguardian 15; "
            "./gate_submit.elf t01_m.bin t01_fw.bin; "
            "./gate_submit.elf --status; "
            "kill $G0_PID 2>/dev/null; wait $G0_PID 2>/dev/null; "
            "printf 'COEX_ALL_%s\\n' 'DONE'\n"
        ).encode("ascii")
        sock.sendall(ota_parked_cmd)
        p4_out = read_until(sock, [b"COEX_ALL_DONE"], timeout=60.0)
        chunks.append(p4_out)
        p4_text = p4_out.decode("utf-8", errors="replace")

        c = socket.create_connection(("127.0.0.1", 18091), timeout=5.0)
        send_msg(c, {"op": "SHUTDOWN"})
        recv_msg(c)
        c.close()
    finally:
        sock.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd.shutdown()

    deny_count = p2_text.count('"decision":"DENY_NOT_STATIONARY"')
    parked_allow = (
        '"decision":"ALLOW"' in p4_text
        and '"active_version":11' in p4_text
        and '"active_slot":"SLOT_B"' in p4_text
        and '"chain_valid":true' in p4_text
    )

    clean_setup = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", setup_text).replace("\r\n", "\n")
    mount_block = ""
    pidin_block = ""
    if "===QNX_MOUNT===" in clean_setup and "===QNX_PIDIN===" in clean_setup:
        mount_block = clean_setup.split("===QNX_MOUNT===", 1)[1].split("===QNX_PIDIN===", 1)[0].strip()
        pidin_block = clean_setup.split("===QNX_PIDIN===", 1)[1].split("COEX_READY", 1)[0].strip()

    result = {
        "experiment": "dual_pillar_coexistence_qnx8",
        "guest": f"QNX 8.0.0 QEMU (-accel {args.accel}, -smp 2, -m 2G)",
        "qnx_mount_evidence": mount_block,
        "qnx_pidin_evidence": pidin_block,
        "phase1_inmotion_baseline_1": phase1,
        "phase2_inmotion_concurrent_ota_72kmh": {
            **phase2,
            "ota_attempts": 10,
            "ota_speed_kmh": 72,
            "deny_not_stationary_count": deny_count,
            "ota_dispatch_epoch_s": ota_dispatch_epoch,
            "ota_complete_epoch_s": ota_complete_epoch,
            "phase2_output_excerpt": p2_text.strip(),
        },
        "phase3_inmotion_baseline_2_post_ota": phase3_b2,
        "phase4_parked_ota_0kmh": {
            "ota_speed_kmh": 0,
            "parked_allow_v11": parked_allow,
            "phase4_output_excerpt": p4_text.strip(),
        },
    }
    (out_dir / "qnx_coexistence_results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "qnx_coexistence_serial.log").write_bytes(b"".join(chunks))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
