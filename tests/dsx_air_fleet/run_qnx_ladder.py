#!/usr/bin/env python3
"""
QNX 8.0.0 Native Multi-Intersection Capacity Ladder (60 -> 150 -> 300 -> 600) & 3-Arm Runner.
Boots QNX 8.0.0 (x86pc) in QEMU, runs 3 native QNX C processes (qnx_veh_host.elf for
zone-a, zone-b, zone-c) communicating over real UDP through dist_zone_gateway.py,
drives SUMO arterial_3j.net.xml via TraCI subscriptions, and verifies via ProDocuX.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import math
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

import traci
import traci.constants as tc

from dist_veh_host import cz_for_edge, recv_msg, send_msg
from intent_protocol import OCCLUSION_VIS_CLEAR_M, STEP_MS
from run_dsx_ladder import CZ_CENTERS, GW_DEFS, generate_multi_j_routes


QEMU_BIN = Path(os.environ.get("PDX_QEMU_BIN", shutil.which("qemu-system-x86_64") or "qemu-system-x86_64"))
QNX_QCOW2 = Path(os.environ.get("PDX_QNX_QCOW2", "disk-qemu.qcow2"))

QNX_ZONES = [
    ("qnx-zone-a", "zone-a", 19101, 9101, 18091, 8091, 20001),
    ("qnx-zone-b", "zone-b", 19102, 9102, 18092, 8092, 20002),
    ("qnx-zone-c", "zone-c", 19103, 9103, 18093, 8093, 20003),
]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def start_http_server(root: Path, port: int) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(QuietHandler, directory=str(root))
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def read_until(sock: socket.socket, markers: List[bytes], timeout: float = 30.0) -> bytes:
    sock.settimeout(0.5)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk:
                buf += chunk
                for m in markers:
                    if m in buf:
                        return buf
        except socket.timeout:
            continue
    raise TimeoutError(f"Timeout waiting for {markers}; tail={buf[-300:]!r}")


def _udp_rpc(ip: str, port: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(json.dumps(payload).encode("utf-8"), (ip, port))
        data, _ = s.recvfrom(65535)
        return json.loads(data.decode("utf-8"))
    finally:
        s.close()


def _percentile(vals: List[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((p / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 2)


def _recv_raw_frame(conn: socket.socket) -> bytes:
    import struct
    hdr = b""
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c:
            raise ConnectionError("EOF")
        hdr += c
    (length,) = struct.unpack(">I", hdr)
    buf = bytearray()
    while len(buf) < length:
        c = conn.recv(length - len(buf))
        if not c:
            raise ConnectionError("EOF")
        buf.extend(c)
    return bytes(buf)


def run_qnx_arm(
    sock: Any,
    http_port: int,
    fleet_dir: Path,
    n_veh: int,
    seed: int,
    mode: str,
    fault_enabled: bool,
    out_dir: Path,
    pace_wall_clock: bool,
    inject_unsafe_vid: str = "",
    use_binary: bool = False,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    net_file = fleet_dir / "sumo_net" / "arterial_3j.net.xml"
    rou_file = out_dir / f"routes_{n_veh}v_s{seed}.rou.xml"
    specs = generate_multi_j_routes(n_veh, seed, rou_file)
    spec_map = {s["vehicle_id"]: s for s in specs}

    specs_json = out_dir / "specs.json"
    specs_json.write_text(json.dumps(specs, indent=2), encoding="utf-8")
    rel_specs = specs_json.relative_to(fleet_dir).as_posix()

    hosts_cfg = {
        hid: {"ip": "127.0.0.1", "rx_port": h_rx, "zone_id": zid}
        for hid, zid, h_rx, _, _, _, _ in QNX_ZONES
    }
    hosts_json = out_dir / "hosts.json"
    hosts_json.write_text(json.dumps(hosts_cfg, indent=2), encoding="utf-8")

    gw_by_zone = {zid: ("127.0.0.1", up, cp) for zid, up, cp in GW_DEFS}
    gw_script = fleet_dir / "dist_zone_gateway.py"
    gw_procs: List[subprocess.Popen] = []
    rpc_conns: Dict[str, socket.socket] = {}

    try:
        for zid, up, cp in GW_DEFS:
            cmd = [
                sys.executable, str(gw_script),
                "--zone-id", zid, "--listen-ip", "127.0.0.1",
                "--udp-port", str(up), "--ctrl-port", str(cp),
                "--hosts-json", str(hosts_json),
                "--log-dir", str(out_dir),
            ]
            if fault_enabled:
                cmd.append("--fault-enabled")
            gw_procs.append(subprocess.Popen(cmd))

        # Fetch specs.json into QNX and start 3 native QNX qnx_veh_host.elf processes
        if isinstance(sock, dict):
            seen_socks = set()
            for hid, zid, _, q_rx, _, q_rpc, gw_up in QNX_ZONES:
                zs = sock[hid]
                zlines = []
                if id(zs) not in seen_socks:
                    seen_socks.add(id(zs))
                    zlines.append("slay -f qnx_veh_host.elf 2>/dev/null; sleep 1")
                    zlines.append(f"curl -sS http://10.0.2.2:{http_port}/{rel_specs} -o /data/pdx_qnx_fleet/specs.json")
                zlines.append(
                    f"/data/pdx_qnx_fleet/qnx_veh_host.elf --host-id {hid} --zone-id {zid} "
                    f"--rx-port {q_rx} --rpc-port {q_rpc} --gw-ip 10.0.2.2 --gw-port {gw_up} "
                    f"--specs-json /data/pdx_qnx_fleet/specs.json --mode {mode} > /tmp/{hid}.log 2>&1 &"
                )
                zlines.append('sleep 1; echo QNX_FLEET_""READY')
                zs.sendall(("\n".join(zlines) + "\n").encode("ascii"))
                read_until(zs, [b"QNX_FLEET_READY\r\n", b"QNX_FLEET_READY\n"], timeout=30.0)
        else:
            launch_lines = [
                "slay -f qnx_veh_host.elf 2>/dev/null; sleep 1",
                f"curl -sS http://10.0.2.2:{http_port}/{rel_specs} -o /data/pdx_qnx_fleet/specs.json",
            ]
            for hid, zid, _, q_rx, _, q_rpc, gw_up in QNX_ZONES:
                launch_lines.append(
                    f"/data/pdx_qnx_fleet/qnx_veh_host.elf --host-id {hid} --zone-id {zid} "
                    f"--rx-port {q_rx} --rpc-port {q_rpc} --gw-ip 10.0.2.2 --gw-port {gw_up} "
                    f"--specs-json /data/pdx_qnx_fleet/specs.json --mode {mode} > /tmp/{hid}.log 2>&1 &"
                )
            launch_lines.append('sleep 1; echo QNX_FLEET_""READY')
            sock.sendall(("\n".join(launch_lines) + "\n").encode("ascii"))
            read_until(sock, [b"QNX_FLEET_READY\r\n", b"QNX_FLEET_READY\n"], timeout=30.0)

        for hid, _, _, _, h_rpc, _, _ in QNX_ZONES:
            for _ in range(40):
                try:
                    c = socket.create_connection(("127.0.0.1", h_rpc), timeout=5.0)
                    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    rpc_conns[hid] = c
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(f"Failed to connect to QNX host {hid} on {h_rpc}")

        col_xml = out_dir / "collision.xml"
        trip_xml = out_dir / "tripinfo.xml"
        traci.start([
            "sumo", "-n", str(net_file), "-r", str(rou_file),
            "--step-length", "0.1",
            "--collision.action", "warn",
            "--collision.check-junctions", "true",
            "--collision-output", str(col_xml),
            "--tripinfo-output", str(trip_xml),
            "--no-step-log", "true",
            "--duration-log.disable", "true",
        ])

        step_times_ms: List[float] = []
        deadline_misses = 0
        cur_consec = 0
        max_consec = 0
        low_speed_steps = 0
        harsh_brakes = 0
        unsafe_cmds_detected = 0
        prev_speeds: Dict[str, float] = {}
        last_speed_mode: Dict[str, int] = {}
        subscribed: set[str] = set()
        cz_peaks = {"j1": 0, "j2": 0, "j3": 0}
        max_concurrent_active = 0
        restore_ms = 7500
        qnx_os_seen: Dict[str, Any] = {}
        rpc_rtt_by_zone: Dict[str, List[float]] = {hid: [] for hid, _, _, _, _, _, _ in QNX_ZONES}
        qnx_comp_by_zone: Dict[str, List[float]] = {hid: [] for hid, _, _, _, _, _, _ in QNX_ZONES}

        try:
            step_idx = 0
            next_wall_ns = time.monotonic_ns()
            while step_idx * STEP_MS <= 900000:
                t0_ns = time.monotonic_ns()
                traci.simulationStep()
                sim_ms = int(round(traci.simulation.getTime() * 1000.0))

                for dep_vid in traci.simulation.getDepartedIDList():
                    if dep_vid not in subscribed:
                        traci.vehicle.subscribe(dep_vid, [tc.VAR_POSITION, tc.VAR_ROAD_ID, tc.VAR_SPEED])
                        subscribed.add(dep_vid)
                sub_res = traci.vehicle.getAllSubscriptionResults()
                if step_idx > 20 and not sub_res and traci.simulation.getMinExpectedNumber() <= 0:
                    break
                if len(sub_res) > max_concurrent_active:
                    max_concurrent_active = len(sub_res)

                for zid, (_, _, cp) in gw_by_zone.items():
                    _udp_rpc("127.0.0.1", cp, {"cmd": "SYNC_SIM_MS", "sim_ms": sim_ms})

                raw: Dict[str, Dict[str, Any]] = {}
                cz_counts = {"j1": 0, "j2": 0, "j3": 0}
                edge_leader_d: Dict[str, float] = {}
                edge_leader_vid: Dict[str, str] = {}

                for vid, vals in sub_res.items():
                    x, y = vals[tc.VAR_POSITION]
                    edge = vals[tc.VAR_ROAD_ID]
                    spd = vals[tc.VAR_SPEED]
                    t_cz = cz_for_edge(edge)
                    in_cz = edge.startswith(":j")
                    approaching = (t_cz != "none")
                    d_cz = -1.0
                    if approaching and not in_cz:
                        cx, cy = CZ_CENTERS[t_cz]
                        d_cz = max(0.0, math.hypot(x - cx, y - cy) - 7.0)
                        cz_counts[t_cz] += 1
                        if edge not in edge_leader_d or d_cz < edge_leader_d[edge]:
                            edge_leader_d[edge] = d_cz
                            edge_leader_vid[edge] = vid
                    rk = spec_map[vid]["route"]
                    is_left = (rk == "r_a_to_b_n" and edge == "j1_to_j2") or (rk == "r_c_to_b_s" and edge == "j3_to_j2")
                    raw[vid] = {
                        "vehicle_id": vid, "edge": edge, "target_cz": t_cz, "is_left_turn": is_left,
                        "speed_mps": spd, "d_to_cz_m": d_cz, "in_cz": in_cz, "approaching": approaching,
                    }

                for cz_k in ("j1", "j2", "j3"):
                    if cz_counts[cz_k] > cz_peaks[cz_k]:
                        cz_peaks[cz_k] = cz_counts[cz_k]

                leader_ids = list(edge_leader_vid.values())
                by_cz_vis: Dict[str, List[Dict[str, Any]]] = {"j1": [], "j2": [], "j3": []}
                for pid, pst in raw.items():
                    t_cz = pst["target_cz"]
                    if t_cz in by_cz_vis and (
                        pst["in_cz"]
                        or (0.0 <= pst["d_to_cz_m"] <= OCCLUSION_VIS_CLEAR_M and pst["d_to_cz_m"] <= edge_leader_d.get(pst["edge"], 1e9) + 0.5)
                    ):
                        by_cz_vis[t_cz].append(pst)

                batches: Dict[str, List[Dict[str, Any]]] = {hid: [] for hid, _, _, _, _, _, _ in QNX_ZONES}
                for vid, st in raw.items():
                    hid = f"qnx-{spec_map[vid]['zone_id']}"
                    vis = [vp for vp in by_cz_vis.get(st["target_cz"], []) if vp["vehicle_id"] != vid]
                    batches[hid].append({**st, "visible_peers": vis})

                all_cmds: Dict[str, Dict[str, Any]] = {}
                if use_binary:
                    import struct
                    def _pad(s: str, n: int) -> bytes:
                        b = s.encode("ascii", errors="ignore")[: n - 1]
                        return b + b"\x00" * (n - len(b))
                    hdr_leaders = b"".join(_pad(lid, 32) for lid in leader_ids[:64])
                    n_ldr = min(len(leader_ids), 64)
                    t_send: Dict[str, int] = {}
                    for hid, vlist in batches.items():
                        if not vlist:
                            continue
                        parts = [
                            b"B",
                            struct.pack("<iiiii", sim_ms, restore_ms, 1 if fault_enabled else 0, n_ldr, len(vlist)),
                            _pad(inject_unsafe_vid, 32),
                            hdr_leaders,
                        ]
                        for st in vlist:
                            vis = st["visible_peers"]
                            parts.append(
                                _pad(st["vehicle_id"], 32) + _pad(st["edge"], 32) + _pad(st["target_cz"], 8)
                                + struct.pack("<iiiidd", 1 if st["is_left_turn"] else 0, 1 if st["in_cz"] else 0, 1 if st["approaching"] else 0, len(vis), float(st["speed_mps"]), float(st["d_to_cz_m"]))
                            )
                            for vp in vis:
                                parts.append(
                                    _pad(vp["vehicle_id"], 32) + _pad(vp["edge"], 32) + _pad(vp["target_cz"], 8)
                                    + struct.pack("<iidd", 1 if vp["is_left_turn"] else 0, 1 if vp["in_cz"] else 0, float(vp["speed_mps"]), float(vp["d_to_cz_m"]))
                                )
                        payload = b"".join(parts)
                        t_send[hid] = time.monotonic_ns()
                        rpc_conns[hid].sendall(struct.pack(">I", len(payload)) + payload)
                    for hid, vlist in batches.items():
                        if not vlist:
                            continue
                        raw_resp = _recv_raw_frame(rpc_conns[hid])
                        rpc_rtt_by_zone[hid].append((time.monotonic_ns() - t_send[hid]) / 1_000_000.0)
                        os_s = raw_resp[1:17].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                        rel_s = raw_resp[17:33].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                        rpid, rcmds, comp_us = struct.unpack("<iiq", raw_resp[33:49])
                        qnx_comp_by_zone[hid].append(float(comp_us))
                        if hid not in qnx_os_seen:
                            qnx_os_seen[hid] = {"os": os_s, "release": rel_s, "pid": rpid}
                        cmds_vals = struct.unpack(f"<{rcmds}d", raw_resp[49 : 49 + 8 * rcmds])
                        for st, cv in zip(vlist, cmds_vals):
                            all_cmds[st["vehicle_id"]] = {"cmd_v": cv}
                else:
                    for hid, vlist in batches.items():
                        if not vlist:
                            continue
                        send_msg(rpc_conns[hid], {
                            "op": "STEP_BATCH",
                            "sim_ms": sim_ms,
                            "restore_ms": restore_ms,
                            "fault_enabled": fault_enabled,
                            "leader_ids": leader_ids,
                            "inject_unsafe_vid": inject_unsafe_vid,
                            "vehicles": vlist,
                        })
                    for hid, vlist in batches.items():
                        if not vlist:
                            continue
                        resp = recv_msg(rpc_conns[hid])
                        if hid not in qnx_os_seen:
                            qnx_os_seen[hid] = {"os": resp.get("os"), "release": resp.get("release"), "pid": resp.get("pid")}
                        all_cmds.update(resp.get("cmds", {}))

                for vid, st in raw.items():
                    if last_speed_mode.get(vid) != 31:
                        traci.vehicle.setSpeedMode(vid, 31)
                        last_speed_mode[vid] = 31
                    cmd_v = float(all_cmds[vid]["cmd_v"])
                    if st["approaching"] and not st["in_cz"] and cmd_v > 15.0:
                        unsafe_cmds_detected += 1
                    traci.vehicle.setSpeed(vid, cmd_v)
                    act_v = st["speed_mps"]
                    if act_v < 2.0 and st["d_to_cz_m"] > 0.0:
                        low_speed_steps += 1
                    prev_v = prev_speeds.get(vid, act_v)
                    if (prev_v - act_v) / 0.1 >= 3.0:
                        harsh_brakes += 1
                    prev_speeds[vid] = act_v

                elapsed_ms = (time.monotonic_ns() - t0_ns) / 1_000_000.0
                step_times_ms.append(elapsed_ms)
                if elapsed_ms > STEP_MS:
                    deadline_misses += 1
                    cur_consec += 1
                    if cur_consec > max_consec:
                        max_consec = cur_consec
                else:
                    cur_consec = 0

                if pace_wall_clock:
                    next_wall_ns += STEP_MS * 1_000_000
                    sleep_ns = next_wall_ns - time.monotonic_ns()
                    if sleep_ns > 0:
                        time.sleep(sleep_ns / 1_000_000_000.0)
                step_idx += 1
        finally:
            traci.close()

        gw_stats = [_udp_rpc("127.0.0.1", cp, {"cmd": "GET_STATS"}) for _, (_, _, cp) in gw_by_zone.items()]
        host_summaries = {}
        for hid, _, _, _, _, _, _ in QNX_ZONES:
            send_msg(rpc_conns[hid], {"op": "GET_SUMMARY"})
            host_summaries[hid] = recv_msg(rpc_conns[hid])
            send_msg(rpc_conns[hid], {"op": "GET_LOG", "kind": "tx"})
            (out_dir / f"tx_{hid}.jsonl").write_bytes(_recv_raw_frame(rpc_conns[hid]))
            send_msg(rpc_conns[hid], {"op": "GET_LOG", "kind": "rx"})
            (out_dir / f"rx_{hid}.jsonl").write_bytes(_recv_raw_frame(rpc_conns[hid]))
    finally:
        for hid, c in rpc_conns.items():
            try:
                send_msg(c, {"op": "SHUTDOWN"})
                recv_msg(c)
            except Exception:
                pass
            c.close()
        for _, (_, _, cp) in gw_by_zone.items():
            try:
                _udp_rpc("127.0.0.1", cp, {"cmd": "SHUTDOWN"})
            except Exception:
                pass
        for p in gw_procs:
            try:
                p.wait(timeout=3.0)
            except Exception:
                p.terminate()

    collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
    trips = ET.parse(trip_xml).getroot().findall("tripinfo") if trip_xml.exists() else []
    total_wait = round(sum(float(t.attrib.get("waitingTime", "0")) for t in trips), 2)

    all_nodes: List[Dict[str, Any]] = []
    rx_q_max = 0
    for hs in host_summaries.values():
        rx_q_max = max(rx_q_max, int(hs["rx_queue_depth_max"]))
        all_nodes.extend(hs["nodes"].values())

    affected = [
        n for n in all_nodes
        if not n["silent"] and n["partition_affected"] and n["degraded_before_restore"] and n["still_approaching_at_restore"]
    ]
    denom_n = len(affected)
    intent_ready = [n["intent_ready_ms"] for n in affected if n["intent_ready_ms"] is not None]
    phys_to_coop = [
        max(0, (restore_ms + n["coop_recovered_ms"]) - (n["last_blocked_ms"] or restore_ms))
        for n in affected
        if n["coop_recovered_ms"] is not None
    ]
    recovery_cov_ok = (len(intent_ready) == denom_n and len(phys_to_coop) == denom_n) if fault_enabled else True

    tx_pids = set()
    for p in out_dir.glob("tx_*.jsonl"):
        for ln in p.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                tx_pids.add(json.loads(ln)["packet_id"])
    gw_drop_pids, gw_replay_pids = set(), set()
    for p in out_dir.glob("gateway_*.jsonl"):
        for ln in p.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                ev = json.loads(ln)
                if ev["event"] == "GW_PARTITION_DROP":
                    gw_drop_pids.add(ev["packet_id"])
                elif ev["event"] == "GW_DELAYED_REPLAY":
                    gw_replay_pids.add(ev["packet_id"])
    rx_stale_pids = set()
    for p in out_dir.glob("rx_*.jsonl"):
        for ln in p.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                rx_stale_pids.add(json.loads(ln)["packet_id"])

    tx_gw_rx_reconciled = (gw_drop_pids.issubset(tx_pids) and gw_replay_pids.issubset(rx_stale_pids)) if fault_enabled else True
    miss_rate = round((deadline_misses / max(1, len(step_times_ms))) * 100.0, 2)

    return {
        "n_vehicles": n_veh,
        "mode": mode,
        "fault_enabled": fault_enabled,
        "qnx_hosts": qnx_os_seen,
        "collisions": collisions,
        "completed_trips": len(trips),
        "unsafe_cmds_detected": unsafe_cmds_detected,
        "total_wait_s": total_wait,
        "low_speed_approach_steps": low_speed_steps,
        "harsh_brakes": harsh_brakes,
        "max_concurrent_active": max_concurrent_active,
        "cz_peaks": cz_peaks,
        "total_steps": len(step_times_ms),
        "step_elapsed_p50_ms": _percentile(step_times_ms, 50),
        "step_elapsed_p95_ms": _percentile(step_times_ms, 95),
        "step_elapsed_p99_ms": _percentile(step_times_ms, 99),
        "step_elapsed_max_ms": _percentile(step_times_ms, 100),
        "deadline_misses": deadline_misses,
        "max_consecutive_misses": max_consec,
        "deadline_miss_rate_pct": miss_rate,
        "rx_queue_depth_max": rx_q_max,
        "partition_drops": sum(int(g["partition_drops"]) for g in gw_stats),
        "delayed_burst_sent": sum(int(g["delayed_burst_sent"]) for g in gw_stats),
        "stale_dropped_total": sum(int(n["stale_dropped"]) for n in all_nodes),
        "rpc_rtt_ms_by_zone": {
            hid: {
                "p50": _percentile(vals, 50),
                "p95": _percentile(vals, 95),
                "p99": _percentile(vals, 99),
                "max": round(max(vals), 2) if vals else 0.0,
            }
            for hid, vals in rpc_rtt_by_zone.items() if vals
        },
        "qnx_compute_us_by_zone": {
            hid: {
                "p50": _percentile(vals, 50),
                "p95": _percentile(vals, 95),
                "p99": _percentile(vals, 99),
                "max": round(max(vals), 1) if vals else 0.0,
            }
            for hid, vals in qnx_comp_by_zone.items() if vals
        },
        "tx_gw_rx_reconciled": tx_gw_rx_reconciled,
        "recovery_denominator_count": denom_n,
        "intent_ready_covered_count": len(intent_ready),
        "coop_recovered_covered_count": len(phys_to_coop),
        "recovery_coverage_complete": recovery_cov_ok,
        "t_intent_ready_p95_ms": _percentile(intent_ready, 95) if len(intent_ready) == denom_n else 999999.0,
        "t_intent_ready_max_ms": _percentile(intent_ready, 100) if len(intent_ready) == denom_n else 999999.0,
        "t_phys_clear_to_coop_p95_ms": _percentile(phys_to_coop, 95) if len(phys_to_coop) == denom_n else 999999.0,
        "t_phys_clear_to_coop_max_ms": _percentile(phys_to_coop, 100) if len(phys_to_coop) == denom_n else 999999.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", nargs="+", type=int, default=[60, 150, 300, 600])
    ap.add_argument("--seed", type=int, default=101)
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "out_qnx_ladder"))
    ap.add_argument("--no-pace", action="store_true")
    ap.add_argument("--skip-600-arms", action="store_true")
    ap.add_argument("--http-port", type=int, default=18180)
    ap.add_argument("--serial-port", type=int, default=14322)
    args = ap.parse_args()

    fleet_dir = Path(__file__).resolve().parent
    out_base = Path(args.out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    httpd = start_http_server(fleet_dir, args.http_port)
    qemu_cmd = [
        str(QEMU_BIN),
        "-cpu", "max", "-smp", "4", "-m", "2G",
        "-display", "none", "-monitor", "none", "-snapshot",
        "-drive", f"file={QNX_QCOW2},if=ide,format=qcow2",
        "-netdev", (
            "user,id=net0,"
            "hostfwd=tcp::18091-:8091,hostfwd=tcp::18092-:8092,hostfwd=tcp::18093-:8093,"
            "hostfwd=udp::19101-:9101,hostfwd=udp::19102-:9102,hostfwd=udp::19103-:9103"
        ),
        "-device", "virtio-net-pci,netdev=net0",
        "-serial", f"tcp:127.0.0.1:{args.serial_port},server,nowait",
    ]
    proc = subprocess.Popen(qemu_cmd)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(30):
        try:
            sock.connect(("127.0.0.1", args.serial_port))
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        proc.terminate()
        httpd.shutdown()
        raise RuntimeError("Failed to connect to QNX QEMU serial")

    try:
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
            f"curl -sS http://10.0.2.2:{args.http_port}/qnx_veh_host.elf -o /data/pdx_qnx_fleet/qnx_veh_host.elf && "
            f"chmod +x /data/pdx_qnx_fleet/qnx_veh_host.elf && echo QNX_BIN_\"\"OK\n"
        ).encode("ascii"))
        read_until(sock, [b"QNX_BIN_OK\r\n", b"QNX_BIN_OK\n"], timeout=30.0)

        ladder_results: List[Dict[str, Any]] = []
        for n_veh in args.counts:
            res = run_qnx_arm(
                sock, args.http_port, fleet_dir, n_veh, args.seed,
                "cooperative", True, out_base / f"ladder_{n_veh}v", not args.no_pace,
            )
            ladder_results.append(res)

        arms_600: Dict[str, Any] = {}
        if not args.skip_600_arms and 600 in args.counts:
            a1 = run_qnx_arm(sock, args.http_port, fleet_dir, 600, args.seed, "local_only", False, out_base / "600v_arm1_local", not args.no_pace)
            a2 = run_qnx_arm(sock, args.http_port, fleet_dir, 600, args.seed, "cooperative", False, out_base / "600v_arm2_healthy", not args.no_pace)
            a3 = next(r for r in ladder_results if r["n_vehicles"] == 600)
            neg = run_qnx_arm(sock, args.http_port, fleet_dir, 60, args.seed, "cooperative", False, out_base / "neg_unsafe_cmd", False, inject_unsafe_vid="veh-000")
            arms_600 = {
                "arm1_local_only": a1,
                "arm2_healthy_coop": a2,
                "arm3_fault_coop": a3,
                "negative_unsafe_cmd_audit": {
                    "unsafe_cmds_detected": neg["unsafe_cmds_detected"],
                    "audit_correctly_failed": neg["unsafe_cmds_detected"] > 0,
                },
            }
    finally:
        sock.close()
        proc.terminate()
        httpd.shutdown()

    summary = {"target_os": "QNX 8.0.0 x86pc QEMU", "seed": args.seed, "pace_wall_clock": not args.no_pace, "ladder": ladder_results, "arms_600": arms_600}
    summary_bytes = json.dumps(summary, indent=2).encode("utf-8")
    summary_path = out_base / "qnx_ladder_results.json"
    summary_path.write_bytes(summary_bytes)

    checks = []
    for r in ladder_results:
        n = r["n_vehicles"]
        all_qnx = len(r["qnx_hosts"]) == 3 and all(v.get("os") == "QNX" for v in r["qnx_hosts"].values())
        checks.extend([
            {"name": f"ladder_{n}v_hosts_are_qnx_8_0", "passed": all_qnx},
            {"name": f"ladder_{n}v_zero_collisions", "passed": r["collisions"] == 0},
            {"name": f"ladder_{n}v_all_trips_completed", "passed": r["completed_trips"] == n},
            {"name": f"ladder_{n}v_zero_unsafe_cmds", "passed": r["unsafe_cmds_detected"] == 0},
            {"name": f"ladder_{n}v_tx_gw_rx_reconciled", "passed": r["tx_gw_rx_reconciled"] is True},
            {"name": f"ladder_{n}v_recovery_coverage_complete", "passed": r["recovery_coverage_complete"] is True},
        ])
    if arms_600:
        a1, a2, a3 = arms_600["arm1_local_only"], arms_600["arm2_healthy_coop"], arms_600["arm3_fault_coop"]
        checks.extend([
            {"name": "600v_all_3_arms_zero_collisions_and_600_trips", "passed": all(x["collisions"] == 0 and x["completed_trips"] == 600 for x in (a1, a2, a3))},
            {"name": "negative_unsafe_cmd_audit_fails_as_expected", "passed": arms_600["negative_unsafe_cmd_audit"]["audit_correctly_failed"] is True},
        ])

    matrix = {
        "schema": "prodocux.qnx_ladder.matrix.v1",
        "status": "pass" if all(c["passed"] for c in checks) else "fail",
        "passed": sum(1 for c in checks if c["passed"]),
        "total": len(checks),
        "checks": checks,
    }
    (out_base / "qnx_ladder_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    venv_py = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "python.exe"
    bundle_script = """
import hashlib, json, sys
from pathlib import Path
import prodocux_kernel
from prodocux_kernel.verification import verify_evidence_bundle
from prodocux_kernel.verification.evidence_models import (
    EvidenceBundleRequestV1, EvidenceCheck, EvidenceDocument, EvidenceItem,
    EvidenceRuleSet, ExtractionIdentity, PdfPageLocator, SourceReferenceV1,
)
summary_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
summary_bytes = summary_path.read_bytes()
data = json.loads(summary_bytes.decode("utf-8"))
doc_sha = hashlib.sha256(summary_bytes).hexdigest()
doc_id = "doc-qnx-air-ladder"
sr = SourceReferenceV1(
    schema_version="prodocux_source_reference_v1", source_sha256=doc_sha, media_type="application/json",
    locator=PdfPageLocator(kind="pdf_page", page=1), snippet="QNX 8.0.0 Native Fleet Capacity Ladder 60->150->300->600",
    extraction=ExtractionIdentity(method="host_supplied", extractor_id="pdx-guardian-qnx-ladder", extractor_version=prodocux_kernel.__version__),
    truncated=False,
)
ev_items, ev_checks = [], []
for r in data["ladder"]:
    n = r["n_vehicles"]
    qnx_ok = str(len(r["qnx_hosts"]) == 3 and all(v.get("os") == "QNX" for v in r["qnx_hosts"].values()))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-qnx", document_id=doc_id, field_name=f"ladder.{n}.all_qnx", value_type="string", value=qnx_ok, confidence=1.0, source_reference=sr))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-col", document_id=doc_id, field_name=f"ladder.{n}.collisions", value_type="number", value=r["collisions"], confidence=1.0, source_reference=sr))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-trip", document_id=doc_id, field_name=f"ladder.{n}.completed_trips", value_type="number", value=r["completed_trips"], confidence=1.0, source_reference=sr))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-rcov", document_id=doc_id, field_name=f"ladder.{n}.recovery_coverage_complete", value_type="string", value=str(r["recovery_coverage_complete"]), confidence=1.0, source_reference=sr))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-qnx", kind="equality", evidence_ids=[f"ev-{n}-qnx"], expected="True"))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-col", kind="numeric_range", evidence_ids=[f"ev-{n}-col"], minimum=0.0, minimum_inclusive=True, maximum=0.0, maximum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-trip", kind="numeric_range", evidence_ids=[f"ev-{n}-trip"], minimum=float(n), minimum_inclusive=True, maximum=float(n), maximum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-rcov", kind="equality", evidence_ids=[f"ev-{n}-rcov"], expected="True"))
req = EvidenceBundleRequestV1(
    schema_version="prodocux_evidence_bundle_request_v1", request_id=f"req-{doc_sha[:16]}",
    rule_set=EvidenceRuleSet(id="pdx-guardian-qnx-ladder", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-qnx-ladder-v1").hexdigest()),
    documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
    evidence=ev_items, checks=ev_checks,
)
b = verify_evidence_bundle(req)
bd = b if isinstance(b, dict) else b.model_dump(mode="json")
out_path.write_text(json.dumps(bd, indent=2), encoding="utf-8")
"""
    bundle_out = out_base / "prodocux_qnx_ladder_bundle_verification.json"
    subprocess.run([str(venv_py) if venv_py.exists() else sys.executable, "-c", bundle_script, str(summary_path), str(bundle_out)], check=True)
    bundle_dict = json.loads(bundle_out.read_text(encoding="utf-8"))
    print(json.dumps({"summary": summary, "matrix_checks": matrix, "prodocux_bundle_verification": bundle_dict}, indent=2))
    return 0 if (matrix["status"] == "pass" and bundle_dict.get("status") == "pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
