#!/usr/bin/env python3
"""
Week 1 Thin Vertical Thread E2E Runner (QEMU QNX 8.0)
Starts guardian_gate.elf (/dev/pdxguardian), submits valid v11 and tampered v12,
captures real QNX receipts into /workspace/evidence/week1/qnx_receipts.jsonl.
"""

import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

QEMU_CMD = [
    "qemu-system-x86_64",
    "-cpu", "max",
    "-smp", "2",
    "-m", "2G",
    "-display", "none",
    "-monitor", "none",
    "-snapshot",
    "-drive", "file=/qemu/qemu/output/disk-qemu.qcow2,if=ide,format=qcow2",
    "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
    "-device", "virtio-net-pci,netdev=net0",
    "-serial", "tcp:127.0.0.1:4321,server,nowait",
]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/workspace", **kwargs)

    def log_message(self, format, *args):
        pass


def start_http_server() -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", 18080), QuietHandler)
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
            if not chunk:
                break
            buf += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if any(m in buf for m in markers):
                return buf
        except socket.timeout:
            continue
    return buf


def main() -> int:
    meta_path = Path("/workspace/simulator/fixtures/week1/fixtures_meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    pubkey_hex = meta["ed25519_pubkey_hex"]

    evidence_dir = Path("/workspace/evidence/week1")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server()
    print("[Week 1 E2E] Starting QNX 8.0 QEMU...")
    proc = subprocess.Popen(QEMU_CMD, stdout=sys.stdout, stderr=sys.stderr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(30):
        try:
            sock.connect(("127.0.0.1", 4321))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        proc.terminate()
        httpd.shutdown()
        return 1

    try:
        read_until(sock, [b"login:"], timeout=120.0)
        time.sleep(2.0)
        # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
        qnx_user = os.environ.get("PDX_QNX_USER", "root")
        qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
        sock.sendall(f"{qnx_user}\n".encode("ascii"))
        resp = read_until(sock, [b"Password:"], timeout=10.0)
        if b"Password:" in resp:
            time.sleep(0.5)
            sock.sendall(f"{qnx_pass}\n".encode("ascii"))
            read_until(sock, [b"# ", b"$ "], timeout=15.0)

        cmd = (
            "mkdir -p /data/wk1 && cd /data/wk1 && "
            "curl -sS http://10.0.2.2:18080/qnx/guardian-gate/guardian_gate.elf -o guardian_gate.elf && "
            "curl -sS http://10.0.2.2:18080/qnx/guardian-gate/gate_submit.elf -o gate_submit.elf && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week1/manifest_v11.bin -o m11.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week1/fw_v11.bin -o fw11.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week1/manifest_v12.bin -o m12.bin && "
            "curl -sS http://10.0.2.2:18080/simulator/fixtures/week1/fw_v12_tampered.bin -o fw12.bin && "
            "chmod +x guardian_gate.elf gate_submit.elf; "
            f"./guardian_gate.elf --pubkey {pubkey_hex} --version 10 --speed 0 & "
            "waitfor /dev/pdxguardian 15 && "
            "ls -la /dev/pdxguardian && "
            "./gate_submit.elf m11.bin fw11.bin && "
            "./gate_submit.elf m12.bin fw12.bin && "
            "ls -la /data/pdx_guardian/slots/slot_b && "
            "echo JOURNAL_BEGIN && "
            "cat /data/pdx_guardian/journal/journal_chain.log && "
            "echo JOURNAL_END && "
            "printf 'WK1_E2E_%s_OK\\n' 'DONE'"
        )
        sock.sendall(cmd.encode("ascii") + b"\n")
        raw_out = read_until(sock, [b"WK1_E2E_DONE_OK"], timeout=45.0).decode("utf-8", errors="replace")

        receipts = []
        journal_lines = []
        in_journal = False
        for line in raw_out.splitlines():
            s = line.strip()
            if s == "JOURNAL_BEGIN":
                in_journal = True
                continue
            if s == "JOURNAL_END":
                in_journal = False
                continue
            if in_journal and s:
                journal_lines.append(s)
                continue
            if s.startswith('{"operation_id":') and s.endswith("}"):
                receipts.append(s)

        assert len(receipts) == 2, f"Expected 2 receipts, got {len(receipts)}"
        r0, r1 = json.loads(receipts[0]), json.loads(receipts[1])
        assert r0["decision"] == "ALLOW" and r0["slot_status"] == "STAGED_AND_ACTIVATED_SLOT_B", r0
        assert r1["decision"] == "DENY_HASH" and r1["slot_status"] == "UNCHANGED_SLOT_A", r1
        assert len(journal_lines) == 3, f"Expected 3 journal entries, got {len(journal_lines)}"

        (evidence_dir / "qnx_receipts.jsonl").write_text("\n".join(receipts) + "\n", encoding="utf-8")
        print(f"\n[Week 1 E2E] Captured {len(receipts)} verified receipts + {len(journal_lines)} journal entries")
        return 0
    finally:
        sock.close()
        proc.terminate()
        httpd.shutdown()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
