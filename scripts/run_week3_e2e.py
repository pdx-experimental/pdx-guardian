#!/usr/bin/env python3
"""
Week 3 10-Fault E2E Runner (QEMU QNX 8.0)
Runs T01-T10 (Policy, Hash, Sig, Rollback, Speed, HW Rev, 3x Crash Points,
Cross-Restart Replay, Persist-Error Uncertain Lock & Recovery, Tampered Journal
Fail-Closed Startup) against guardian_gate.elf (/dev/pdxguardian) inside QNX 8.0 QEMU.
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
    meta_path = Path("/workspace/simulator/fixtures/week3/fixtures_meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    pubkey_hex = meta["public_key_hex"]

    evidence_dir = Path("/workspace/evidence/week3")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server()
    print("[Week 3 E2E] Starting QNX 8.0 QEMU...")
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
            f"mkdir -p /data/wk3 && cd /data/wk3 && "
            f"curl -sS http://10.0.2.2:18080/scripts/qnx_week3_guest.sh | tr -d '\\r' > run.sh && "
            f"sh run.sh {pubkey_hex}"
        )
        sock.sendall(cmd.encode("ascii") + b"\n")
        raw_bytes = read_until(sock, [b"WK3_E2E_DONE_OK"], timeout=150.0)
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

        # 1. Receipts T01-T06, T08, T09, T09B (9 receipts)
        by_op = {r["operation_id"]: r for r in receipts}
        assert len(receipts) == 9, f"Expected 9 receipts, got {len(receipts)}: {[r['operation_id'] for r in receipts]}"
        assert by_op["op-wk3-t01-valid-v11"]["decision"] == "ALLOW"
        assert by_op["op-wk3-t01-valid-v11"]["slot_status"] == "STAGED_AND_ACTIVATED_SLOT_B"
        assert by_op["op-wk3-t02-tamper-v12"]["decision"] == "DENY_HASH"
        assert by_op["op-wk3-t03-badsig-v12"]["decision"] == "DENY_SIGNATURE"
        assert by_op["op-wk3-t04-rollback-v09"]["decision"] == "DENY_ROLLBACK"
        assert by_op["op-wk3-t05-speed-v12"]["decision"] == "DENY_NOT_STATIONARY"
        assert by_op["op-wk3-t06-hwrev-v12"]["decision"] == "DENY_HW_REV"
        assert by_op["op-wk3-t08-replay-v13"]["decision"] == "DENY_ROLLBACK"
        assert by_op["op-wk3-t09-ioerr-v13"]["decision"] == "UNKNOWN_OUTCOME"
        assert by_op["op-wk3-t09-ioerr-v13"]["slot_status"] == "UNCERTAIN_STAGE_WRITE_LOCKED"
        assert by_op["op-wk3-t09b-locked-v14"]["decision"] == "UNKNOWN_OUTCOME"
        assert by_op["op-wk3-t09b-locked-v14"]["slot_status"] == "UNCERTAIN_PERSISTENCE_LOCKED"

        # 2. Crash points & post-persist-error recovery (5 statuses: T07A, T07B, T07C, T09_locked, T09_recovered)
        assert "T07A_EXIT=1" in raw_out and "T07B_EXIT=1" in raw_out and "T07C_EXIT=1" in raw_out
        assert len(statuses) == 5, f"Expected 5 status queries, got {len(statuses)}"
        st_tmp, st_rename, st_ver, st_t09_locked, st_t09_rec = statuses

        assert st_tmp["reconciled_state"] == "RECONCILED_ABORTED" and st_tmp["active_slot"] == "SLOT_B"
        assert fw_sha_by_case.get("T07A") == expected_v11_sha
        assert st_rename["reconciled_state"] == "RECONCILED_ABORTED" and st_rename["active_slot"] == "SLOT_B"
        assert fw_sha_by_case.get("T07B") == expected_v11_sha
        assert st_ver["reconciled_state"] == "RECONCILED_ACTIVATED" and st_ver["active_slot"] == "SLOT_A"
        assert st_ver["active_version"] == 12 and st_ver["last_sequence_id"] == 8
        assert fw_sha_by_case.get("T07C") == expected_v12_sha

        assert st_t09_locked["uncertain_locked"] is True
        assert st_t09_rec["uncertain_locked"] is False
        assert st_t09_rec["reconcile_performed"] is True
        assert st_t09_rec["reconciled_op_id"] == "op-wk3-t09-ioerr-v13"
        assert st_t09_rec["reconciled_state"] == "RECONCILED_ABORTED"
        assert st_t09_rec["active_version"] == 12 and st_t09_rec["active_slot"] == "SLOT_A"
        assert fw_sha_by_case.get("T09_RECOVERED") == expected_v12_sha

        # 3. T10 tampered journal fail-closed startup
        assert "T10_TAMPER_EXIT=1" in raw_out, "T10 tampered journal did not fail closed!"
        assert "FATAL: pdx_journal_init failed closed" in raw_out

        # 4. Independent SHA-256 hash chain verification (16 entries before T10 tamper)
        assert len(journal_lines) == 16, f"Expected 16 journal entries, got {len(journal_lines)}"
        verify_hash_chain(journal_lines)

        results = {
            "receipts": receipts,
            "crash_recoveries": [
                {
                    "case_id": "T07",
                    "crash_point": "tmp",
                    "operation_id": "op-wk3-t07-crash-v12",
                    "status": st_tmp,
                    "active_fw_sha256": fw_sha_by_case["T07A"],
                },
                {
                    "case_id": "T07B",
                    "crash_point": "after-rename",
                    "operation_id": "op-wk3-t07b-rename-v12",
                    "status": st_rename,
                    "active_fw_sha256": fw_sha_by_case["T07B"],
                },
                {
                    "case_id": "T07C",
                    "crash_point": "after-version",
                    "operation_id": "op-wk3-t07c-ver-v12",
                    "status": st_ver,
                    "active_fw_sha256": fw_sha_by_case["T07C"],
                },
                {
                    "case_id": "T09_REC",
                    "crash_point": "persist-error",
                    "operation_id": "op-wk3-t09-ioerr-v13",
                    "status": st_t09_rec,
                    "active_fw_sha256": fw_sha_by_case["T09_RECOVERED"],
                },
            ],
            "t09_locked_status": st_t09_locked,
            "t10_tamper_fail_closed": True,
            "journal_chain": journal_lines,
            "independent_hash_chain_verified": True,
            "serial_transcript_file": "evidence/week3/qnx_serial_transcript.log",
        }
        out_file = evidence_dir / "qnx_week3_results.json"
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(
            f"\n[Week 3 E2E] ALL 10 FAULT SCENARIOS PASSED: "
            f"9 receipts + 4 crash/io-err recoveries + T10 fail-closed + {len(journal_lines)}-entry hash chain verified."
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
