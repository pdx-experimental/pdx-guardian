#!/usr/bin/env python3
"""
Paired 3-Arm Baseline on 3 Independent QNX 8.0.0 QEMU Guests (60v & 150v, paced):
Compares local_only vs healthy_coop vs fault_coop at medium traffic on QNX 8.0.0.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
import socket

from run_qnx_3guest import boot_qnx_guest
from run_qnx_ladder import QNX_ZONES, run_qnx_arm, start_http_server


def main() -> None:
    fleet_dir = Path(__file__).resolve().parent
    out_base = fleet_dir / "out_qnx_3guest_paired"
    out_base.mkdir(parents=True, exist_ok=True)
    http_port = 18182
    serial_base = 14341

    httpd = start_http_server(fleet_dir, http_port)
    procs: List[subprocess.Popen] = []
    zone_socks: Dict[str, socket.socket] = {}

    try:
        for idx, (hid, zid, h_rx, q_rx, h_rpc, q_rpc, _) in enumerate(QNX_ZONES):
            proc, sock = boot_qnx_guest(hid, h_rx, q_rx, h_rpc, q_rpc, serial_base + idx, http_port)
            procs.append(proc)
            zone_socks[hid] = sock

        paired: Dict[str, Any] = {}
        for nv in (60, 150):
            arm1 = run_qnx_arm(zone_socks, http_port, fleet_dir, nv, 101, "local_only", False, out_base / f"{nv}v_arm1_local", True)
            arm2 = run_qnx_arm(zone_socks, http_port, fleet_dir, nv, 101, "cooperative", False, out_base / f"{nv}v_arm2_healthy", True)
            arm3 = run_qnx_arm(zone_socks, http_port, fleet_dir, nv, 101, "cooperative", True, out_base / f"{nv}v_arm3_fault", True)
            paired[f"{nv}v"] = {
                "arm1_local_only": arm1,
                "arm2_healthy_coop": arm2,
                "arm3_fault_coop": arm3,
            }

        summary = {
            "target_os": "3 Independent QNX 8.0.0 x86pc QEMU Guests",
            "seed": 101,
            "pace_wall_clock": True,
            "paired_arms": paired,
        }
        (out_base / "qnx_3guest_paired_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))
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
