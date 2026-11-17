#!/usr/bin/env python3
"""
Week 2 E2E Runner (QEMU QNX 8.0)
Runs T01-T05 and T07A/T07B/T07C (all 3 crash points: tmp, after-rename, after-version)
against guardian_gate.elf (/dev/pdxguardian) inside QNX 8.0 QEMU, strictly asserts
all expected decisions, post-crash reconciliations, and independently verifies the
entire SHA-256 hash-chained journal.
"""

import hashlib
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

GENESIS_HASH = "0" * 64
JOURNAL_LINE_RE = re.compile(
    r"^seq=(\d+)\s+prev=([0-9a-f]{64})\s+op=(\S+)\s+state=(\S+)\s+ver=(\d+)\s+slot=(\S+)\s+hash=([0-9a-f]{64})$"
)


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


def verify_hash_chain(journal_lines: list[str]) -> None:
    prev_hash = GENESIS_HASH
    for idx, line in enumerate(journal_lines, start=1):
        m = JOURNAL_LINE_RE.match(line)
        assert m is not None, f"Malformed journal line {idx}: {line}"
        seq = int(m.group(1))
        prev = m.group(2)
        op_id = m.group(3)
        state = m.group(4)
        ver = int(m.group(5))
        slot = m.group(6)
        entry_hash = m.group(7)

        assert seq == idx, f"Journal seq mismatch: expected {idx}, got {seq}"
        assert prev == prev_hash, f"Journal prev_hash mismatch at seq={seq}"
        canonical = f"{seq}|{prev}|{op_id}|{state}|{ver}|{slot}".encode("utf-8")
        expected_hash = hashlib.sha256(canonical).hexdigest()
        assert entry_hash == expected_hash, f"Journal hash mismatch at seq={seq}: {entry_hash} != {expected_hash}"
        prev_hash = entry_hash


def main() -> int:
    meta_path = Path("/workspace/simulator/fixtures/week2/fixtures_meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    pubkey_hex = meta["public_key_hex"]

    evidence_dir = Path("/workspace/evidence/week2")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server()
    print("[Week 2 E2E] Starting QNX 8.0 QEMU...")
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
        boot_out = read_until(sock, [b"login:"], timeout=120.0)
        time.sleep(2.0)
        # QNX QSTI default guest image credentials; override via PDX_QNX_USER / PDX_QNX_PASS
        qnx_user = os.environ.get("PDX_QNX_USER", "root")
        qnx_pass = os.environ.get("PDX_QNX_PASS", "root")
        sock.sendall(f"{qnx_user}\n".encode("ascii"))
        resp = read_until(sock, [b"Password:"], timeout=10.0)
        login_out = resp
        if b"Password:" in resp:
            time.sleep(0.5)
            sock.sendall(f"{qnx_pass}\n".encode("ascii"))
            login_out += read_until(sock, [b"# ", b"$ "], timeout=15.0)

        cmd = (
            f"mkdir -p /data/wk2 && cd /data/wk2 && "
            f"curl -sS http://10.0.2.2:18080/scripts/qnx_week2_guest.sh | tr -d '\\r' > run.sh && "
            f"sh run.sh {pubkey_hex}"
        )
        sock.sendall(cmd.encode("ascii") + b"\n")
        raw_bytes = read_until(sock, [b"WK2_E2E_DONE_OK"], timeout=120.0)
        raw_out = raw_bytes.decode("utf-8", errors="replace")

        transcript_path = evidence_dir / "qnx_serial_transcript.log"
        transcript_path.write_bytes(boot_out + login_out + raw_bytes)

        receipts: list[dict] = []
        statuses: list[dict] = []
        journal_lines: list[str] = []
        fw_sha_by_case: dict[str, str] = {}
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
            if s.startswith("ACTIVE_FW_SHA256="):
                _, payload = s.split("=", 1)
                cid, digest = payload.split(":", 1)
                fw_sha_by_case[cid] = digest.strip().lower()
                continue
            if s.startswith('{"operation_id":') and s.endswith("}"):
                receipts.append(json.loads(s))
            elif s.startswith('{"status_query":') and s.endswith("}"):
                statuses.append(json.loads(s))

        case_by_id = {c["case_id"]: c for c in meta["cases"]}
        expected_v11_sha = case_by_id["T01"]["firmware_sha256"]
        expected_v12_sha = case_by_id["T07C"]["firmware_sha256"]

        # Strict assertions on T01-T05 receipts
        by_op = {r["operation_id"]: r for r in receipts}
        assert len(receipts) == 5, f"Expected 5 receipts, got {len(receipts)}"
        assert by_op["op-wk2-t01-valid-v11"]["decision"] == "ALLOW"
        assert by_op["op-wk2-t01-valid-v11"]["slot_status"] == "STAGED_AND_ACTIVATED_SLOT_B"
        assert by_op["op-wk2-t01-valid-v11"]["active_version"] == 11
        assert by_op["op-wk2-t02-tamper-v12"]["decision"] == "DENY_HASH"
        assert by_op["op-wk2-t03-badsig-v12"]["decision"] == "DENY_SIGNATURE"
        assert by_op["op-wk2-t04-rollback-v09"]["decision"] == "DENY_ROLLBACK"
        assert by_op["op-wk2-t05-speed-v12"]["decision"] == "DENY_NOT_STATIONARY"

        # Strict assertions on all 3 crash points (T07A, T07B, T07C) + preserved firmware SHA-256
        assert "T07A_EXIT=1" in raw_out, "Missing T07A non-zero exit"
        assert "T07B_EXIT=1" in raw_out, "Missing T07B non-zero exit"
        assert "T07C_EXIT=1" in raw_out, "Missing T07C non-zero exit"
        assert len(statuses) == 3, f"Expected 3 post-crash statuses, got {len(statuses)}"

        st_tmp, st_rename, st_ver = statuses
        assert st_tmp["chain_valid"] is True and st_tmp["reconcile_performed"] is True
        assert st_tmp["reconciled_op_id"] == "op-wk2-t07-crash-v12"
        assert st_tmp["reconciled_state"] == "RECONCILED_ABORTED"
        assert st_tmp["active_version"] == 11 and st_tmp["active_slot"] == "SLOT_B"
        assert st_tmp["last_sequence_id"] == 1
        assert fw_sha_by_case.get("T07A") == expected_v11_sha, (
            f"T07A active firmware SHA mismatch: {fw_sha_by_case.get('T07A')} != {expected_v11_sha}"
        )

        assert st_rename["chain_valid"] is True and st_rename["reconcile_performed"] is True
        assert st_rename["reconciled_op_id"] == "op-wk2-t07b-rename-v12"
        assert st_rename["reconciled_state"] == "RECONCILED_ABORTED"
        assert st_rename["active_version"] == 11 and st_rename["active_slot"] == "SLOT_B"
        assert st_rename["last_sequence_id"] == 1
        assert fw_sha_by_case.get("T07B") == expected_v11_sha, (
            f"T07B active firmware SHA mismatch: {fw_sha_by_case.get('T07B')} != {expected_v11_sha}"
        )

        assert st_ver["chain_valid"] is True and st_ver["reconcile_performed"] is True
        assert st_ver["reconciled_op_id"] == "op-wk2-t07c-ver-v12"
        assert st_ver["reconciled_state"] == "RECONCILED_ACTIVATED"
        assert st_ver["active_version"] == 12 and st_ver["active_slot"] == "SLOT_A"
        assert st_ver["last_sequence_id"] == 8
        assert fw_sha_by_case.get("T07C") == expected_v12_sha, (
            f"T07C active firmware SHA mismatch: {fw_sha_by_case.get('T07C')} != {expected_v12_sha}"
        )

        # Independent SHA-256 hash chain verification
        assert len(journal_lines) == 12, f"Expected 12 journal entries, got {len(journal_lines)}"
        verify_hash_chain(journal_lines)

        results = {
            "receipts": receipts,
            "crash_recoveries": [
                {
                    "case_id": "T07",
                    "crash_point": "tmp",
                    "operation_id": "op-wk2-t07-crash-v12",
                    "status": st_tmp,
                    "active_fw_sha256": fw_sha_by_case["T07A"],
                    "expected_fw_sha256": expected_v11_sha,
                },
                {
                    "case_id": "T07B",
                    "crash_point": "after-rename",
                    "operation_id": "op-wk2-t07b-rename-v12",
                    "status": st_rename,
                    "active_fw_sha256": fw_sha_by_case["T07B"],
                    "expected_fw_sha256": expected_v11_sha,
                },
                {
                    "case_id": "T07C",
                    "crash_point": "after-version",
                    "operation_id": "op-wk2-t07c-ver-v12",
                    "status": st_ver,
                    "active_fw_sha256": fw_sha_by_case["T07C"],
                    "expected_fw_sha256": expected_v12_sha,
                },
            ],
            "post_crash_status": st_ver,
            "journal_chain": journal_lines,
            "independent_hash_chain_verified": True,
            "serial_transcript_file": "evidence/week2/qnx_serial_transcript.log",
        }
        out_file = evidence_dir / "qnx_week2_results.json"
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(
            f"\n[Week 2 E2E] ALL ASSERTIONS PASSED: 5 receipts + 3 crash points "
            f"(tmp/after-rename->ABORTED, after-version->ACTIVATED) + {len(journal_lines)}-entry hash chain verified."
        )
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
