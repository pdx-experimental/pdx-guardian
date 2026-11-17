#!/usr/bin/env python3
"""
Gate 0 QEMU Boot, ELF Execution & Filesystem Probe for QNX 8.0 QSTI
Serves /workspace over HTTP on port 18080 (accessible from QNX guest as 10.0.2.2:18080).
"""

import http.server
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time

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


def read_until(sock: socket.socket, markers: list[bytes], timeout: float = 60.0) -> bytes:
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


def send_cmd(sock: socket.socket, cmd: str, timeout: float = 20.0) -> bytes:
    sock.sendall(cmd.encode("ascii") + b"\n")
    return read_until(sock, [b"# ", b"$ "], timeout=timeout)


def main() -> int:
    httpd = start_http_server()
    print("[Gate 0 Probe] HTTP server listening on 0.0.0.0:18080")
    print("[Gate 0 Probe] Starting QEMU (TCG mode, -snapshot)...")
    proc = subprocess.Popen(QEMU_CMD, stdout=sys.stdout, stderr=sys.stderr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(30):
        try:
            sock.connect(("127.0.0.1", 4321))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        print("[Gate 0 Probe] Failed to connect to serial port 4321.", file=sys.stderr)
        proc.terminate()
        httpd.shutdown()
        return 1

    try:
        print("[Gate 0 Probe] Waiting for login prompt...")
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

        # Wait briefly for DHCP on vtnet0 if needed
        send_cmd(sock, "ifconfig vtnet0")

        # Download & execute QNX ELF binaries from 10.0.2.2:18080
        cmd = (
            "curl -sS http://10.0.2.2:18080/tests/hello_qnx.elf -o /data/hello_qnx.elf && "
            "chmod +x /data/hello_qnx.elf && /data/hello_qnx.elf && "
            "curl -sS http://10.0.2.2:18080/tests/fs_probe.elf -o /data/fs_probe.elf && "
            "chmod +x /data/fs_probe.elf && /data/fs_probe.elf && "
            "ls -la /data/pdx_probe && printf 'GATE0_%s_DONE\\n' 'FS'"
        )
        sock.sendall(cmd.encode("ascii") + b"\n")
        read_until(sock, [b"GATE0_FS_DONE"], timeout=30.0)
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
