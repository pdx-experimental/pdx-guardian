#!/usr/bin/env python3
"""
Same-Hardware, Same-C-Source A/B Benchmark:
Compares identical STEP_BATCH execution (N=20, 50, 100, 200 vehicles/zone,
equivalent to 60, 150, 300, 600 3-zone fleet) between:
  1. OCI VM1 Ubuntu 24.04 native (qnx_veh_host_linux.elf)
  2. OCI VM1 QNX 8.0.0 QEMU+KVM guest (qnx_veh_host.elf)
"""

from __future__ import annotations

import base64
import json
import math
import socket
import struct
import subprocess
import time
from pathlib import Path

import os
VM1_IP = os.environ.get("PDX_OCI_VM1_IP", "198.51.100.1")
KEY_VM1 = os.environ.get("PDX_OCI_VM1_KEY", "~/.ssh/oci_vm1.key")
QNX_USER = os.environ.get("PDX_QNX_USER", "root")  # QNX QSTI default guest credentials
QNX_PASS = os.environ.get("PDX_QNX_PASS", "root")
FLEET_DIR = Path(__file__).resolve().parent
QNX_ELF = FLEET_DIR / "qnx_veh_host.elf"
OUT_DIR = FLEET_DIR / "out_qnx_vs_ubuntu"

REMOTE_BENCH_PY = r"""
import json, math, socket, struct, subprocess, sys, time

def send_msg(conn, obj):
    b = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack(">I", len(b)) + b)

def recv_msg(conn):
    hdr = b""
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c: raise ConnectionError("EOF")
        hdr += c
    (n,) = struct.unpack(">I", hdr)
    buf = bytearray()
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c: raise ConnectionError("EOF")
        buf.extend(c)
    return json.loads(bytes(buf).decode("utf-8"))

def pct(vals, p):
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((p / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 3)

def bench_host(port, counts=(200, 100, 50, 20), iters=200, warmup=30):
    c = None
    for _ in range(30):
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=10.0)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            send_msg(c, {"op": "STEP_BATCH", "sim_ms": 0, "restore_ms": 7500, "fault_enabled": False, "leader_ids": ["veh-000"], "inject_unsafe_vid": "", "vehicles": []})
            resp = recv_msg(c)
            os_info = {"os": resp.get("os"), "release": resp.get("release")}
            break
        except Exception:
            if c is not None:
                try: c.close()
                except Exception: pass
            time.sleep(0.5)
    else:
        raise RuntimeError(f"Failed to connect to port {port}")
    out = []
    try:
        # Global pre-warmup with 200-vehicle payload so caches, SLIRP, and KVM pages are fully warm
        pre_peers = [
            {
                "vehicle_id": f"veh-{j:03d}", "edge": "j1_s_in", "target_cz": "j1",
                "is_left_turn": (j % 5 == 0), "speed_mps": 8.0, "d_to_cz_m": 15.0 + (j % 10),
                "in_cz": (j % 7 == 0), "approaching": True,
            }
            for j in range(10)
        ]
        pre_vehs = [
            {
                "vehicle_id": f"veh-{i:03d}", "edge": "j1_w_in", "target_cz": "j1",
                "is_left_turn": (i % 4 == 0), "speed_mps": 9.5, "d_to_cz_m": 12.0 + (i % 15),
                "in_cz": False, "approaching": True, "visible_peers": pre_peers,
            }
            for i in range(200)
        ]
        for w in range(50):
            send_msg(c, {"op": "STEP_BATCH", "sim_ms": w * 100, "restore_ms": 7500, "fault_enabled": False, "leader_ids": ["veh-000"], "inject_unsafe_vid": "", "vehicles": pre_vehs})
            recv_msg(c)

        for nv in counts:
            peers = [
                {
                    "vehicle_id": f"veh-{j:03d}", "edge": "j1_s_in", "target_cz": "j1",
                    "is_left_turn": (j % 5 == 0), "speed_mps": 8.0, "d_to_cz_m": 15.0 + (j % 10),
                    "in_cz": (j % 7 == 0), "approaching": True,
                }
                for j in range(min(10, nv))
            ]
            vehs = [
                {
                    "vehicle_id": f"veh-{i:03d}", "edge": "j1_w_in", "target_cz": "j1",
                    "is_left_turn": (i % 4 == 0), "speed_mps": 9.5, "d_to_cz_m": 12.0 + (i % 15),
                    "in_cz": False, "approaching": True, "visible_peers": peers,
                }
                for i in range(nv)
            ]
            for w in range(warmup):
                send_msg(c, {"op": "STEP_BATCH", "sim_ms": w * 100, "restore_ms": 7500, "fault_enabled": False, "leader_ids": ["veh-000"], "inject_unsafe_vid": "", "vehicles": vehs})
                resp = recv_msg(c)
                os_info = {"os": resp.get("os"), "release": resp.get("release")}
            lat = []
            for k in range(iters):
                t0 = time.perf_counter_ns()
                send_msg(c, {"op": "STEP_BATCH", "sim_ms": (k + 10) * 100, "restore_ms": 7500, "fault_enabled": False, "leader_ids": ["veh-000"], "inject_unsafe_vid": "", "vehicles": vehs})
                recv_msg(c)
                lat.append((time.perf_counter_ns() - t0) / 1_000_000.0)
            out.append({
                "vehicles_per_zone": nv,
                "fleet_3zone_equiv": nv * 3,
                "iters": iters,
                "p50_ms": pct(lat, 50),
                "p95_ms": pct(lat, 95),
                "p99_ms": pct(lat, 99),
                "max_ms": round(max(lat), 3),
            })
        send_msg(c, {"op": "SHUTDOWN"})
        recv_msg(c)
    finally:
        c.close()
    return {"os_info": os_info, "results": out}

mode = sys.argv[1]
port = int(sys.argv[2])
print(json.dumps(bench_host(port), indent=2))
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    specs = [{"vehicle_id": f"veh-{i:03d}", "zone_id": "zone-a", "route": "r_a_to_b_n", "silent": False} for i in range(200)]
    specs_path = OUT_DIR / "bench_specs.json"
    specs_path.write_text(json.dumps(specs), encoding="utf-8")

    # Upload specs + qnx_veh_host.elf + bench script to VM1
    subprocess.run(["scp", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", str(specs_path), f"ubuntu@{VM1_IP}:/tmp/bench_specs.json"], check=True)
    subprocess.run(["scp", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", str(QNX_ELF), f"ubuntu@{VM1_IP}:/tmp/qnx_veh_host.elf"], check=True)
    b64_bench = base64.b64encode(REMOTE_BENCH_PY.encode("utf-8")).decode("ascii")

    # 1. Benchmark Ubuntu 24.04 native on OCI VM1
    ubuntu_cmd = (
        f"echo {b64_bench} | base64 -d > /tmp/remote_bench.py\n"
        "pkill -f '[q]nx_veh_host_linux.elf' || true\n"
        "nohup /tmp/qnx_veh_host_linux.elf --host-id ubuntu-zone-a --zone-id zone-a "
        "--rx-port 19201 --rpc-port 18201 --gw-ip 127.0.0.1 --gw-port 20201 "
        "--specs-json /tmp/bench_specs.json --mode cooperative </dev/null >/tmp/u_bench.log 2>&1 &\n"
        "sleep 1\n"
        "python3 /tmp/remote_bench.py ubuntu 18201\n"
    )
    u_out = subprocess.check_output(
        ["ssh", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM1_IP}", "bash -s"],
        input=ubuntu_cmd.encode("utf-8"), timeout=120,
    ).decode("utf-8")
    ubuntu_res = json.loads(u_out)

    # 2. Benchmark QNX 8.0.0 QEMU+KVM on OCI VM1
    # Start tiny HTTP server on VM1 so QNX guest can curl qnx_veh_host.elf & bench_specs.json
    qnx_setup = (
        "pkill -f '[q]emu-system-x86_64.*18202' || true\n"
        "pkill -f 'http.server 18280' || true\n"
        "nohup python3 -m http.server 18280 --directory /tmp </dev/null >/tmp/http_q.log 2>&1 &\n"
        "nohup qemu-system-x86_64 -enable-kvm -cpu max -smp 2 -m 512M -display none -monitor none -snapshot "
        "-drive file=disk-uncomp.qcow2,if=ide,format=qcow2 "
        "-netdev user,id=net0,hostfwd=tcp:127.0.0.1:18202-:8091 "
        "-device virtio-net-pci,netdev=net0 "
        "-serial tcp:127.0.0.1:14350,server,nowait </dev/null >/tmp/qemu_bench.log 2>&1 &\n"
        "sleep 2\n"
    )
    subprocess.run(
        ["ssh", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM1_IP}", "bash -s"],
        input=qnx_setup.encode("utf-8"), check=True, timeout=30,
    )

    remote_qnx_driver = r"""
import socket, time, subprocess
qnx_user = __QNX_USER_JSON__
qnx_pass = __QNX_PASS_JSON__
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
for _ in range(60):
    try:
        s.connect(("127.0.0.1", 14350)); break
    except Exception: time.sleep(0.5)
s.settimeout(0.5)
def read_until(markers, to):
    buf = b""
    dl = time.time() + to
    while time.time() < dl:
        try:
            c = s.recv(4096)
            if c:
                buf += c
                if any(m in buf for m in markers): return buf
        except socket.timeout: pass
    raise TimeoutError(f"wait {markers} tail={buf[-200:]!r}")

read_until([b"login:"], 140.0)
time.sleep(3.0)
s.sendall((qnx_user + "\n").encode("utf-8"))
read_until([b"Password:"], 20.0)
time.sleep(0.5)
s.sendall((qnx_pass + "\n").encode("utf-8"))
read_until([b"# ", b"$ "], 25.0)
time.sleep(35.0)
s.sendall(
    b"mkdir -p /tmp/bench && "
    b"curl -sS http://10.0.2.2:18280/qnx_veh_host.elf -o /tmp/bench/qnx_veh_host.elf && "
    b"curl -sS http://10.0.2.2:18280/bench_specs.json -o /tmp/bench/specs.json && "
    b"chmod +x /tmp/bench/qnx_veh_host.elf && "
    b"/tmp/bench/qnx_veh_host.elf --host-id qnx-zone-a --zone-id zone-a --rx-port 9101 --rpc-port 8091 --gw-ip 10.0.2.2 --gw-port 20201 --specs-json /tmp/bench/specs.json --mode cooperative > /tmp/qb.log 2>&1 &\n"
    b"sleep 1; echo QNX_BENCH_\"\"READY\n"
)
read_until([b"QNX_BENCH_READY\r\n", b"QNX_BENCH_READY\n"], 45.0)
print(subprocess.check_output(["python3", "/tmp/remote_bench.py", "qnx", "18202"], text=True))
s.close()
"""
    remote_qnx_driver = remote_qnx_driver.replace("__QNX_USER_JSON__", json.dumps(QNX_USER)).replace("__QNX_PASS_JSON__", json.dumps(QNX_PASS))
    try:
        q_out = subprocess.check_output(
            ["ssh", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM1_IP}", "python3 -"],
            input=remote_qnx_driver.encode("utf-8"), timeout=240,
        ).decode("utf-8")
        qnx_res = json.loads(q_out)
    finally:
        subprocess.run(
            ["ssh", "-i", KEY_VM1, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", f"ubuntu@{VM1_IP}",
             "pkill -f '[q]emu-system-x86_64.*18202' || true; pkill -f 'http.server 18280' || true"],
            timeout=15,
        )

    final = {
        "host_hardware": f"OCI VM1 ({VM1_IP}, 2 vCPU, 952 MiB RAM, /dev/kvm)",
        "source": "qnx_veh_host.c (identical C source, -O2)",
        "ubuntu_24_04_native": ubuntu_res,
        "qnx_8_0_0_kvm": qnx_res,
    }
    (OUT_DIR / "qnx_vs_ubuntu_results.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
