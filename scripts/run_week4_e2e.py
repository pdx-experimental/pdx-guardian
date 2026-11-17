#!/usr/bin/env python3
"""
Week 4 3-Arm Interleaved Jitter Benchmark Runner (QNX 8.0 QEMU -smp 2)
Runs 3 interleaved rounds of:
  1. idle (no background worker)
  2. same-vcpu (ecu_control CPU0 prio 50 FIFO vs update_worker CPU0 prio 10 RR)
  3. separated-vcpu (ecu_control CPU0 prio 50 FIFO vs update_worker CPU1 prio 10 RR)
Each run executes 1,000 warmup + 10,000 measured 10ms cycles, uploads raw signed
wakeup latencies via HTTP POST, and saves verified summary + raw CSVs under evidence/week4/.
"""

import argparse
import http.server
import json
import os
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path


def make_handler(workspace_dir: Path, samples_dir: Path):
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(workspace_dir), **kwargs)

        def log_message(self, format, *args):
            pass

        def do_POST(self):
            if not self.path.startswith("/upload/"):
                self.send_response(404)
                self.end_headers()
                return
            fname = Path(self.path[len("/upload/"):]).name
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            samples_dir.mkdir(parents=True, exist_ok=True)
            (samples_dir / fname).write_bytes(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    return QuietHandler


def start_http_server(workspace_dir: Path, samples_dir: Path, port: int = 18080) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    handler = make_handler(workspace_dir, samples_dir)
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
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


def recompute_csv_stats(csv_path: Path, period_us: float = 10000.0) -> dict:
    lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    if len(lines) < 2 or lines[0].strip() != "sample_idx,signed_wakeup_us,work_span_us":
        raise AssertionError(f"Malformed CSV {csv_path}")
    signed_vals = []
    work_spans = []
    for idx, line in enumerate(lines[1:]):
        parts = line.split(",")
        if len(parts) != 3 or int(parts[0]) != idx:
            raise AssertionError(f"Malformed CSV row {idx} in {csv_path}: {line}")
        signed_vals.append(float(parts[1]))
        work_spans.append(float(parts[2]))
    abs_sorted = sorted(abs(v) for v in signed_vals)
    n = len(abs_sorted)
    wakeup_overruns = sum(1 for v in signed_vals if v > period_us)
    ecu_deadline_misses = sum(1 for w in work_spans if w > period_us)
    return {
        "csv_samples": n,
        "csv_wakeup_overruns": wakeup_overruns,
        "csv_ecu_deadline_misses": ecu_deadline_misses,
        "csv_p50_us": round(abs_sorted[int((n - 1) * 0.50)], 3),
        "csv_p95_us": round(abs_sorted[int((n - 1) * 0.95)], 3),
        "csv_p99_us": round(abs_sorted[int((n - 1) * 0.99)], 3),
        "csv_p999_us": round(abs_sorted[int((n - 1) * 0.999)], 3),
        "csv_max_abs_us": round(abs_sorted[-1], 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="/workspace")
    parser.add_argument("--disk", default="/qemu/qemu/output/disk-qemu.qcow2")
    parser.add_argument("--qemu-bin", default="qemu-system-x86_64")
    parser.add_argument("--accel", default="tcg", choices=["tcg", "whpx", "kvm"])
    parser.add_argument("--cpu", default="max")
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    workspace_dir = Path(args.workspace).resolve()
    evidence_dir = Path(args.out_dir).resolve() if args.out_dir else (workspace_dir / "evidence" / "week4")
    samples_dir = evidence_dir / "samples"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    samples_dir.mkdir(parents=True, exist_ok=True)
    httpd = start_http_server(workspace_dir, samples_dir, 18080)

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
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", "tcp:127.0.0.1:4321,server,nowait",
    ]
    print(f"[Week 4 E2E] Starting QNX 8.0 QEMU (-accel {args.accel}, -cpu {args.cpu}, -smp 2)...", flush=True)
    proc = subprocess.Popen(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    sock = None
    for _ in range(30):
        try:
            sock = socket.create_connection(("127.0.0.1", 4321), timeout=2.0)
            break
        except OSError:
            time.sleep(0.5)

    if sock is None:
        proc.terminate()
        httpd.shutdown()
        raise RuntimeError("Failed to connect to QEMU serial TCP port 4321")

    transcript_chunks: list[bytes] = []
    try:
        out = read_until(sock, [b"login:", b"# "], timeout=240.0)
        transcript_chunks.append(out)
        if b"login:" in out:
            time.sleep(2.0)
            # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
            qnx_user = os.environ.get("PDX_QNX_USER", "root")
            qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
            sock.sendall(f"{qnx_user}\n".encode("ascii"))
            out = read_until(sock, [b"# ", b"Password:"], timeout=30.0)
            transcript_chunks.append(out)
            if b"Password:" in out:
                time.sleep(0.5)
                sock.sendall(f"{qnx_pass}\n".encode("ascii"))
                out = read_until(sock, [b"# ", b"$ "], timeout=30.0)
                transcript_chunks.append(out)

        cmd = (
            "curl -sf http://10.0.2.2:18080/scripts/qnx_week4_guest.sh "
            "| tr -d '\\r' > /tmp/qnx_week4_guest.sh && sh /tmp/qnx_week4_guest.sh\n"
        ).encode("ascii")
        sock.sendall(cmd)

        # 9 runs * 11,000 cycles * 10ms = ~990s + overhead -> allow 1600s
        out = read_until(sock, [b"WK4_JITTER_DONE_OK"], timeout=1600.0)
        transcript_chunks.append(out)
    finally:
        sock.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd.shutdown()

    raw_text = b"".join(transcript_chunks).decode("utf-8", errors="replace")
    (evidence_dir / "qnx_serial_transcript.log").write_text(raw_text, encoding="utf-8")

    matches = re.findall(
        r"JITTER_RESULT_BEGIN\s*(\{.*?\})\s*JITTER_RESULT_END",
        raw_text,
        flags=re.DOTALL,
    )
    if len(matches) != 9:
        raise AssertionError(f"Expected 9 JITTER_RESULT blocks (3 rounds x 3 scenarios), got {len(matches)}")

    runs = []
    by_scenario: dict[str, list[dict]] = {"idle": [], "same-vcpu": [], "separated-vcpu": []}
    for m in matches:
        data = json.loads(m)
        if not data.get("config_valid"):
            raise AssertionError(f"Run marked invalid (affinity/sched/io failure): {data}")
        if data["completed_samples"] != 10000:
            raise AssertionError(f"Incomplete samples: {data['completed_samples']} != 10000")
        tag = f"r{data['round']}_{data['scenario']}"
        csv_path = evidence_dir / "samples" / f"{tag}.csv"
        csv_stats = recompute_csv_stats(csv_path)
        if csv_stats["csv_samples"] != data["completed_samples"]:
            raise AssertionError(f"CSV sample count mismatch for {tag}")
        if csv_stats["csv_wakeup_overruns"] != data["wakeup_overruns"]:
            raise AssertionError(f"CSV wakeup_overruns mismatch for {tag}")
        if csv_stats["csv_ecu_deadline_misses"] != data["ecu_deadline_misses"]:
            raise AssertionError(f"CSV ecu_deadline_misses mismatch for {tag}")
        data["csv_file"] = f"samples/{tag}.csv"
        data["host_recomputed"] = csv_stats
        runs.append(data)
        by_scenario[data["scenario"]].append(data)

    for sc_name, sc_runs in by_scenario.items():
        if len(sc_runs) != 3:
            raise AssertionError(f"Scenario {sc_name} expected 3 rounds, got {len(sc_runs)}")

    summary_by_scenario = {}
    for sc_name, sc_runs in by_scenario.items():
        summary_by_scenario[sc_name] = {
            "rounds": len(sc_runs),
            "total_samples": sum(r["host_recomputed"]["csv_samples"] for r in sc_runs),
            "wakeup_overruns_total": sum(r["host_recomputed"]["csv_wakeup_overruns"] for r in sc_runs),
            "ecu_deadline_misses_total": sum(r["host_recomputed"]["csv_ecu_deadline_misses"] for r in sc_runs),
            "p50_us_median": sorted(r["host_recomputed"]["csv_p50_us"] for r in sc_runs)[1],
            "p99_us_median": sorted(r["host_recomputed"]["csv_p99_us"] for r in sc_runs)[1],
            "p999_us_median": sorted(r["host_recomputed"]["csv_p999_us"] for r in sc_runs)[1],
            "max_abs_us_worst": max(r["host_recomputed"]["csv_max_abs_us"] for r in sc_runs),
        }

    payload = {
        "week": "week4",
        "environment": f"QNX 8.0 x86_64 in QEMU (-accel {args.accel}, -cpu {args.cpu}, -smp 2)",
        "disclaimer": "Demonstration Benchmark on Virtualized Environment, Not an ASIL Certification Guarantee",
        "thresholds": {
            "wakeup_overruns": 0,
            "ecu_deadline_misses": 0,
            "p50_us_max": 50.0,
            "p99_us_max": 250.0,
            "max_us_max": 1500.0,
        },
        "summary_by_scenario": summary_by_scenario,
        "runs": runs,
    }
    out_file = evidence_dir / "qnx_week4_jitter.json"
    out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("\n[Week 4 E2E] 3-arm interleaved benchmark completed. Summary (median / worst across 3 rounds):")
    for sc_name, s in summary_by_scenario.items():
        print(
            f"  {sc_name}: total_samples={s['total_samples']}, overruns={s['wakeup_overruns_total']}, "
            f"ecu_misses={s['ecu_deadline_misses_total']}, p50_med={s['p50_us_median']}us, "
            f"p99_med={s['p99_us_median']}us, p99.9_med={s['p999_us_median']}us, worst_max={s['max_abs_us_worst']}us"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
