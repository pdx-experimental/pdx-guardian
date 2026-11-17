#!/usr/bin/env python3
"""
Distributed DSX Air Capacity Ladder (60 -> 150 -> 300 -> 600) & 3-Arm Multi-Intersection Runner.
Spawns 3 Zone Gateways + 6 Vehicle Host Workers over UDP + batched TCP RPC,
drives SUMO arterial_3j.net.xml via TraCI subscriptions, and verifies via ProDocuX.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple

import traci
import traci.constants as tc

from dist_veh_host import cz_for_edge, recv_msg, send_msg
from intent_protocol import OCCLUSION_VIS_CLEAR_M, STEP_MS, required_stopping_distance_m


CZ_CENTERS = {
    "j1": (0.0, 0.0),
    "j2": (200.0, 0.0),
    "j3": (400.0, 0.0),
}

HOST_DEFS = [
    ("veh-host-a1", "zone-a", 20101, 20201),
    ("veh-host-a2", "zone-a", 20102, 20202),
    ("veh-host-b1", "zone-b", 20103, 20203),
    ("veh-host-b2", "zone-b", 20104, 20204),
    ("veh-host-c1", "zone-c", 20105, 20205),
    ("veh-host-c2", "zone-c", 20106, 20206),
]

GW_DEFS = [
    ("zone-a", 20001, 20011),
    ("zone-b", 20002, 20012),
    ("zone-c", 20003, 20013),
]

ROUTES = {
    "r_ew_full": "w_to_j1 j1_to_j2 j2_to_j3 j3_to_e",
    "r_we_full": "e_to_j3 j3_to_j2 j2_to_j1 j1_to_w",
    "r_j1_ns":   "j1_n_in j1_s_out",
    "r_j1_sn":   "j1_s_in j1_n_out",
    "r_j2_ns":   "j2_n_in j2_s_out",
    "r_j2_sn":   "j2_s_in j2_n_out",
    "r_j3_ns":   "j3_n_in j3_s_out",
    "r_j3_sn":   "j3_s_in j3_n_out",
    "r_a_to_b_n": "w_to_j1 j1_to_j2 j2_n_out",
    "r_c_to_b_s": "e_to_j3 j3_to_j2 j2_s_out",
}
ROUTE_KEYS = list(ROUTES.keys())


def _percentile(vals: List[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((p / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 2)


def generate_multi_j_routes(n_veh: int, seed: int, out_rou: Path) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    specs: List[Dict[str, Any]] = []
    # Spread departures cleanly so all 3 intersections saturate concurrently without insertion teleporting
    span_s = max(14.0, n_veh / 16.0)
    lines = [
        "<routes>",
        '    <vType id="cav" accel="2.6" decel="4.5" length="4.5" minGap="2.5" maxSpeed="13.89" tau="0.8"/>',
    ]
    for rk, edges in ROUTES.items():
        lines.append(f'    <route id="{rk}" edges="{edges}"/>')

    entries = []
    for i in range(n_veh):
        vid = f"veh-{i:03d}"
        h_idx = i % len(HOST_DEFS)
        host_id, zone_id, _, _ = HOST_DEFS[h_idx]
        rk = ROUTE_KEYS[i % len(ROUTE_KEYS)]
        depart = round(0.4 + (i / max(1, n_veh - 1)) * span_s + rng.uniform(0.0, 0.25), 2)
        silent = (i % 15 == 3)
        spd0 = round(rng.uniform(10.5, 13.5), 2)
        entries.append((depart, vid, host_id, zone_id, rk, silent, spd0))

    entries.sort(key=lambda x: (x[0], x[1]))
    for depart, vid, host_id, zone_id, rk, silent, spd0 in entries:
        lines.append(
            f'    <vehicle id="{vid}" type="cav" route="{rk}" depart="{depart:.2f}" departPos="10.0" departSpeed="{spd0:.2f}"/>'
        )
        specs.append({
            "vehicle_id": vid,
            "host_id": host_id,
            "zone_id": zone_id,
            "route": rk,
            "depart": depart,
            "silent": silent,
        })
    lines.append("</routes>")
    out_rou.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return specs


def _udp_rpc(ip: str, port: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(json.dumps(payload).encode("utf-8"), (ip, port))
        data, _ = s.recvfrom(65535)
        return json.loads(data.decode("utf-8"))
    finally:
        s.close()


def run_distributed_arm(
    n_veh: int,
    seed: int,
    mode: str,
    fault_enabled: bool,
    out_dir: Path,
    pace_wall_clock: bool,
    inject_unsafe_vid: str = "",
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    net_file = Path(__file__).resolve().parent / "sumo_net" / "arterial_3j.net.xml"
    rou_file = out_dir / f"routes_{n_veh}v_s{seed}.rou.xml"
    specs = generate_multi_j_routes(n_veh, seed, rou_file)
    spec_map = {s["vehicle_id"]: s for s in specs}

    specs_json = out_dir / "specs.json"
    specs_json.write_text(json.dumps(specs, indent=2), encoding="utf-8")

    hosts_cfg = {
        hid: {"ip": "127.0.0.1", "rx_port": rxp, "rpc_port": rpcp, "zone_id": zid}
        for hid, zid, rxp, rpcp in HOST_DEFS
    }
    hosts_json = out_dir / "hosts.json"
    hosts_json.write_text(json.dumps(hosts_cfg, indent=2), encoding="utf-8")

    gw_by_zone = {zid: ("127.0.0.1", up, cp) for zid, up, cp in GW_DEFS}
    gw_script = Path(__file__).resolve().parent / "dist_zone_gateway.py"
    host_script = Path(__file__).resolve().parent / "dist_veh_host.py"

    gw_procs: List[subprocess.Popen] = []
    host_procs: List[subprocess.Popen] = []
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

        for hid, zid, rxp, rpcp in HOST_DEFS:
            gw_ip, gw_up, _ = gw_by_zone[zid]
            cmd = [
                sys.executable, str(host_script),
                "--host-id", hid, "--listen-ip", "127.0.0.1",
                "--rx-port", str(rxp), "--rpc-port", str(rpcp),
                "--gw-ip", gw_ip, "--gw-port", str(gw_up),
                "--specs-json", str(specs_json),
                "--mode", mode,
                "--log-dir", str(out_dir),
            ]
            host_procs.append(subprocess.Popen(cmd))

        # Connect persistent batched TCP RPC sockets to all 6 vehicle hosts
        for hid, _, _, rpcp in HOST_DEFS:
            for _ in range(40):
                try:
                    c = socket.create_connection(("127.0.0.1", rpcp), timeout=5.0)
                    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    rpc_conns[hid] = c
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(f"Failed to connect to {hid} on port {rpcp}")

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

        try:
            step_idx = 0
            next_wall_ns = time.monotonic_ns()
            while step_idx * STEP_MS <= 300000:
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
                        "vehicle_id": vid,
                        "edge": edge,
                        "target_cz": t_cz,
                        "is_left_turn": is_left,
                        "speed_mps": spd,
                        "d_to_cz_m": d_cz,
                        "in_cz": in_cz,
                        "approaching": approaching,
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

                batches: Dict[str, List[Dict[str, Any]]] = {hid: [] for hid, _, _, _ in HOST_DEFS}
                for vid, st in raw.items():
                    hid = spec_map[vid]["host_id"]
                    t_cz = st["target_cz"]
                    vis = [vp for vp in by_cz_vis.get(t_cz, []) if vp["vehicle_id"] != vid]
                    batches[hid].append({**st, "visible_peers": vis})

                # Send batched STEP_BATCH RPCs to all 6 hosts
                all_cmds: Dict[str, Dict[str, Any]] = {}
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
                    all_cmds.update(resp.get("cmds", {}))

                for vid, st in raw.items():
                    if last_speed_mode.get(vid) != 31:
                        traci.vehicle.setSpeedMode(vid, 31)
                        last_speed_mode[vid] = 31
                    cmd_v = float(all_cmds[vid]["cmd_v"])
                    # Independent command safety audit (non-labeled)
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
        for hid, _, _, _ in HOST_DEFS:
            send_msg(rpc_conns[hid], {"op": "GET_SUMMARY"})
            host_summaries[hid] = recv_msg(rpc_conns[hid])
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
        for p in host_procs + gw_procs:
            try:
                p.wait(timeout=3.0)
            except Exception:
                p.terminate()

    collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
    trips = ET.parse(trip_xml).getroot().findall("tripinfo") if trip_xml.exists() else []
    total_wait = round(sum(float(t.attrib.get("waitingTime", "0")) for t in trips), 2)

    all_nodes: List[Dict[str, Any]] = []
    rx_q_max = 0
    total_cpu_s = 0.0
    for hs in host_summaries.values():
        rx_q_max = max(rx_q_max, int(hs["rx_queue_depth_max"]))
        total_cpu_s += float(hs["cpu_time_s"])
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

    # Reconcile packet_ids across TX, gateway, and RX logs
    tx_pids = set()
    for p in out_dir.glob("tx_*.jsonl"):
        for ln in p.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                tx_pids.add(json.loads(ln)["packet_id"])
    gw_drop_pids = set()
    gw_replay_pids = set()
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

    tx_gw_rx_reconciled = (
        gw_drop_pids.issubset(tx_pids) and gw_replay_pids.issubset(rx_stale_pids)
    ) if fault_enabled else True

    miss_rate = round((deadline_misses / max(1, len(step_times_ms))) * 100.0, 2)
    return {
        "n_vehicles": n_veh,
        "mode": mode,
        "fault_enabled": fault_enabled,
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
        "total_host_cpu_s": round(total_cpu_s, 3),
        "partition_drops": sum(int(g["partition_drops"]) for g in gw_stats),
        "delayed_burst_sent": sum(int(g["delayed_burst_sent"]) for g in gw_stats),
        "stale_dropped_total": sum(int(n["stale_dropped"]) for n in all_nodes),
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
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "out_dsx_ladder"))
    ap.add_argument("--no-pace", action="store_true")
    ap.add_argument("--skip-600-arms", action="store_true")
    args = ap.parse_args()

    out_base = Path(args.out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    ladder_results: List[Dict[str, Any]] = []
    for n_veh in args.counts:
        res = run_distributed_arm(
            n_veh=n_veh,
            seed=args.seed,
            mode="cooperative",
            fault_enabled=True,
            out_dir=out_base / f"ladder_{n_veh}v",
            pace_wall_clock=not args.no_pace,
        )
        ladder_results.append(res)

    arms_600: Dict[str, Any] = {}
    if not args.skip_600_arms and 600 in args.counts:
        a1 = run_distributed_arm(600, args.seed, "local_only", False, out_base / "600v_arm1_local", not args.no_pace)
        a2 = run_distributed_arm(600, args.seed, "cooperative", False, out_base / "600v_arm2_healthy", not args.no_pace)
        a3 = next(r for r in ladder_results if r["n_vehicles"] == 600)
        neg = run_distributed_arm(60, args.seed, "cooperative", False, out_base / "neg_unsafe_cmd", False, inject_unsafe_vid="veh-000")
        arms_600 = {
            "arm1_local_only": a1,
            "arm2_healthy_coop": a2,
            "arm3_fault_coop": a3,
            "negative_unsafe_cmd_audit": {
                "unsafe_cmds_detected": neg["unsafe_cmds_detected"],
                "audit_correctly_failed": neg["unsafe_cmds_detected"] > 0,
            },
        }

    summary = {"seed": args.seed, "pace_wall_clock": not args.no_pace, "ladder": ladder_results, "arms_600": arms_600}
    summary_bytes = json.dumps(summary, indent=2).encode("utf-8")
    summary_path = out_base / "dsx_ladder_results.json"
    summary_path.write_bytes(summary_bytes)

    checks = []
    for r in ladder_results:
        n = r["n_vehicles"]
        checks.extend([
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
        "schema": "prodocux.dsx_air_ladder.matrix.v1",
        "status": "pass" if all(c["passed"] for c in checks) else "fail",
        "passed": sum(1 for c in checks if c["passed"]),
        "total": len(checks),
        "checks": checks,
    }
    (out_base / "dsx_ladder_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

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
doc_id = "doc-dsx-air-ladder"
sr = SourceReferenceV1(
    schema_version="prodocux_source_reference_v1", source_sha256=doc_sha, media_type="application/json",
    locator=PdfPageLocator(kind="pdf_page", page=1), snippet="Distributed DSX Air capacity ladder 60->150->300->600",
    extraction=ExtractionIdentity(method="host_supplied", extractor_id="pdx-guardian-dsx-ladder", extractor_version=prodocux_kernel.__version__),
    truncated=False,
)
ev_items, ev_checks = [], []
for r in data["ladder"]:
    n = r["n_vehicles"]
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-col", document_id=doc_id, field_name=f"ladder.{n}.collisions", value_type="number", value=r["collisions"], confidence=1.0, source_reference=sr))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-trip", document_id=doc_id, field_name=f"ladder.{n}.completed_trips", value_type="number", value=r["completed_trips"], confidence=1.0, source_reference=sr))
    ev_items.append(EvidenceItem(evidence_id=f"ev-{n}-rcov", document_id=doc_id, field_name=f"ladder.{n}.recovery_coverage_complete", value_type="string", value=str(r["recovery_coverage_complete"]), confidence=1.0, source_reference=sr))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-col", kind="numeric_range", evidence_ids=[f"ev-{n}-col"], minimum=0.0, minimum_inclusive=True, maximum=0.0, maximum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-trip", kind="numeric_range", evidence_ids=[f"ev-{n}-trip"], minimum=float(n), minimum_inclusive=True, maximum=float(n), maximum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-{n}-rcov", kind="equality", evidence_ids=[f"ev-{n}-rcov"], expected="True"))
req = EvidenceBundleRequestV1(
    schema_version="prodocux_evidence_bundle_request_v1", request_id=f"req-{doc_sha[:16]}",
    rule_set=EvidenceRuleSet(id="pdx-guardian-dsx-ladder", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-dsx-ladder-v1").hexdigest()),
    documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
    evidence=ev_items, checks=ev_checks,
)
b = verify_evidence_bundle(req)
bd = b if isinstance(b, dict) else b.model_dump(mode="json")
out_path.write_text(json.dumps(bd, indent=2), encoding="utf-8")
"""
    bundle_out = out_base / "prodocux_dsx_ladder_bundle_verification.json"
    subprocess.run([str(venv_py) if venv_py.exists() else sys.executable, "-c", bundle_script, str(summary_path), str(bundle_out)], check=True)
    bundle_dict = json.loads(bundle_out.read_text(encoding="utf-8"))
    print(json.dumps({"summary": summary, "matrix_checks": matrix, "prodocux_bundle_verification": bundle_dict}, indent=2))
    return 0 if (matrix["status"] == "pass" and bundle_dict.get("status") == "pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
