#!/usr/bin/env python3
"""
60-Vehicle Multi-Seed Urban Intersection Experiment (3 Zones x 20 Vehicles)
with 1:1 Wall-Clock Pacing, Step-Latency Telemetry, and ProDocuX Audit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import traci
import traci.constants as tc

from intent_protocol import (
    BROADCAST_PERIOD_MS,
    DrivingIntentV1,
    HARSH_DECEL_THRESHOLD_MPS2,
    OCCLUSION_VIS_CLEAR_M,
    PRIORITY_MOVEMENTS,
    STEP_MS,
    TTL_MS,
    has_higher_right_of_way,
    max_safe_approach_speed_mps,
    movements_conflict,
    required_stopping_distance_m,
    right_of_way_class,
    time_windows_overlap,
)

MOVEMENTS = [
    ("west_in", "east_out", "STRAIGHT"),
    ("east_in", "west_out", "STRAIGHT"),
    ("south_in", "north_out", "STRAIGHT"),
    ("north_in", "south_out", "STRAIGHT"),
    ("east_in", "south_out", "LEFT"),
    ("west_in", "north_out", "LEFT"),
    ("south_in", "east_out", "RIGHT"),
]
INCOMING_EDGES = {"west_in", "east_in", "south_in", "north_in"}


def _percentile(vals: List[float], pct: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((pct / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 2)


def generate_60v_routes(seed: int, out_rou: Path) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    specs: List[Dict[str, Any]] = []
    zones = [["zone-a", "zone-b", "zone-c"][i % 3] for i in range(60)]
    silent_indices = {3, 23, 43}  # 1 silent vehicle per zone (veh-04, veh-24, veh-44)

    lines = [
        '<routes>',
        '    <vType id="cav" accel="2.6" decel="4.5" emergencyDecel="6.0" sigma="0.0" length="4.5" minGap="2.0" maxSpeed="13.89" guiShape="passenger"/>',
    ]
    for idx, (in_e, out_e, _) in enumerate(MOVEMENTS):
        lines.append(f'    <route id="r_m{idx}" edges="{in_e} {out_e}"/>')

    # Generate 60 vehicles staggered over 0.0s .. 108.0s (~1.8s headway, within single-lane intersection capacity)
    raw_items = []
    for i in range(60):
        vid = f"veh-{i+1:02d}"
        zone = zones[i]
        m_idx = rng.randrange(len(MOVEMENTS))
        in_e, out_e, turn = MOVEMENTS[m_idx]
        depart = round(i * 1.80 + rng.uniform(0.0, 0.40), 2)
        depart_speed = round(rng.uniform(9.5, 12.0), 2)
        raw_items.append((depart, i, vid, zone, m_idx, in_e, out_e, turn, depart_speed, i in silent_indices))

    raw_items.sort(key=lambda x: (x[0], x[1]))
    for depart, _, vid, zone, m_idx, in_e, out_e, turn, dspeed, is_silent in raw_items:
        lines.append(
            f'    <vehicle id="{vid}" type="cav" route="r_m{m_idx}" depart="{depart}" departPos="10.0" departSpeed="{dspeed}"/>'
        )
        specs.append({
            "vehicle_id": vid,
            "zone_id": zone,
            "in_edge": in_e,
            "out_edge": out_e,
            "turn": turn,
            "silent": is_silent,
        })
    lines.append('</routes>')
    out_rou.write_text("\n".join(lines), encoding="utf-8")
    return specs


class InProcessVehicleNode:
    """Isolated per-vehicle state machine (mirrors vehicle_agent.py for 60-vehicle host scaling)."""

    def __init__(self, spec: Dict[str, Any], mode: str) -> None:
        self.vehicle_id = spec["vehicle_id"]
        self.zone_id = spec["zone_id"]
        self.in_edge = spec["in_edge"]
        self.out_edge = spec["out_edge"]
        self.turn = spec["turn"]
        self.silent = bool(spec["silent"])
        self.mode = mode
        self.seq = 0
        self.last_bcast_ms = -BROADCAST_PERIOD_MS
        self.cleared_tx = 0
        self.peer_intents: Dict[str, DrivingIntentV1] = {}
        self.last_seen_seq: Dict[str, int] = {}
        self.coop_state = "COOPERATIVE" if mode == "cooperative" else "LOCAL_ONLY"
        self.degraded_before_restore = False
        self.partition_affected = False
        self.still_approaching_at_restore = False
        self.intent_ready_ms: int | None = None
        self.coop_recovered_ms: int | None = None
        self.last_blocked_ms: int | None = None
        self.stale_dropped = 0
        self.stale_overwrites = 0
        self.expired_rx = 0

    def receive_intent(self, intent: DrivingIntentV1, sim_ms: int) -> None:
        if intent.vehicle_id == self.vehicle_id:
            return
        sender = intent.vehicle_id
        prev = self.last_seen_seq.get(sender, 0)
        if intent.seq <= prev:
            self.stale_dropped += 1
            return
        age = sim_ms - intent.issued_at_sim_ms
        if age > intent.ttl_ms:
            self.expired_rx += 1
        self.last_seen_seq[sender] = intent.seq
        self.peer_intents[sender] = intent

    def maybe_broadcast(self, sim_ms: int, speed: float, d_to_cz: float, approaching: bool) -> DrivingIntentV1 | None:
        if self.silent or self.mode == "local_only":
            return None
        if sim_ms - self.last_bcast_ms < BROADCAST_PERIOD_MS:
            return None
        if not approaching:
            if self.cleared_tx >= 5:
                return None
            self.cleared_tx += 1
        self.last_bcast_ms = sim_ms
        self.seq += 1
        eff_v = max(speed, 4.0)
        entry_ms = sim_ms + int((max(0.0, d_to_cz) / eff_v) * 1000.0)
        return DrivingIntentV1(
            schema="pdx.driving_intent.v2",
            vehicle_id=self.vehicle_id,
            zone_id=self.zone_id,
            seq=self.seq,
            tx_wall_ms=time.monotonic_ns() // 1_000_000,
            issued_at_sim_ms=sim_ms,
            ttl_ms=TTL_MS,
            incoming_edge=self.in_edge if approaching else "cleared",
            outgoing_edge=self.out_edge,
            turn_intent=self.turn,
            conflict_zone_id="j1_cz_center",
            conflict_entry_sim_ms=entry_ms,
            conflict_exit_sim_ms=entry_ms + 2200,
            right_of_way_class=right_of_way_class(self.in_edge, self.out_edge),
            speed_mps=round(speed, 3),
            intended_action="CLEARED" if not approaching else "PROCEED",
            packet_id=f"{self.vehicle_id}:{self.seq}",
        )

    def step_decide(
        self,
        sim_ms: int,
        speed: float,
        d_to_cz: float,
        approaching: bool,
        visible_peers: List[Dict[str, Any]],
        restore_ms: int,
        edge_leader_ids: set[str] | None = None,
    ) -> Tuple[float, str, str]:
        if not approaching or d_to_cz < 0.0:
            return 13.89, "PROCEED", "PAST_STOP_LINE_CLEAR"

        if self.mode == "cooperative" and self.partition_affected and self.intent_ready_ms is None and sim_ms >= restore_ms:
            fresh = [
                p for p in self.peer_intents.values()
                if p.intended_action != "CLEARED"
                and (sim_ms - p.issued_at_sim_ms) <= p.ttl_ms
                and p.issued_at_sim_ms >= restore_ms
            ]
            if fresh:
                self.intent_ready_ms = sim_ms - restore_ms

        d_req = required_stopping_distance_m(speed)
        ego_row = right_of_way_class(self.in_edge, self.out_edge)
        eff_v = max(speed, 4.0)
        ego_entry = sim_ms + int((d_to_cz / eff_v) * 1000.0)
        ego_exit = ego_entry + 2200

        local_block = False
        local_reason = ""
        for vp in visible_peers:
            if vp["in_cz"]:
                local_block = True
                local_reason = "BLOCKED_BY_SILENT_OR_OCCUPIED"
                break
            if movements_conflict(self.in_edge, self.out_edge, vp["in_edge"], vp["out_edge"]):
                vp_d = max(0.0, float(vp["d_to_cz_m"]))
                vp_v_raw = float(vp["speed_mps"])
                if vp_v_raw > 1.5 and vp_d <= required_stopping_distance_m(vp_v_raw) + 1.0:
                    local_block = True
                    local_reason = "BLOCKED_BY_COMMITTED_PEER"
                    break
                vp_v = max(vp_v_raw, 4.0)
                vp_entry = sim_ms + int((vp_d / vp_v) * 1000.0)
                if not has_higher_right_of_way(
                    self.vehicle_id, self.in_edge, self.out_edge, ego_entry,
                    vp["vehicle_id"], vp["in_edge"], vp["out_edge"], vp_entry,
                ):
                    local_block = True
                    local_reason = "LOCAL_VISIBLE_CONFLICT_YIELD"
                    break

        if local_block:
            if self.mode == "cooperative":
                self.coop_state = "DEGRADED_AUTONOMOUS"
                if sim_ms <= restore_ms:
                    self.degraded_before_restore = True
                if sim_ms >= restore_ms:
                    self.last_blocked_ms = sim_ms
            if d_to_cz < d_req:
                return 0.0, "MITIGATION_MAX_DECEL", local_reason
            cmd_v = max_safe_approach_speed_mps(d_to_cz)
            return cmd_v, ("STOP_YIELD" if cmd_v < 1.0 else "DECEL_YIELD"), local_reason

        if self.mode == "local_only":
            if d_to_cz > OCCLUSION_VIS_CLEAR_M:
                return min(13.89, max(4.5, max_safe_approach_speed_mps(d_to_cz - 4.0))), "APPROACH_CAUTION", "LOCAL_ONLY_BLIND_ZONE_CAP"
            if d_to_cz > 8.0:
                return 4.5, "APPROACH_CAUTION", "LOCAL_ONLY_VIS_CREEP"
            return 11.5, "PROCEED", "LOCAL_ONLY_VIS_CONFIRMED"

        expired_conflict = False
        intent_yield = False
        for pid, p_int in self.peer_intents.items():
            if edge_leader_ids is not None and pid not in edge_leader_ids:
                continue
            if p_int.intended_action == "CLEARED" or p_int.incoming_edge == "cleared":
                continue
            if not movements_conflict(self.in_edge, self.out_edge, p_int.incoming_edge, p_int.outgoing_edge):
                continue
            if (sim_ms - p_int.issued_at_sim_ms) > p_int.ttl_ms:
                expired_conflict = True
                continue
            if (p_int.conflict_entry_sim_ms - sim_ms) > 2500:
                continue
            if time_windows_overlap(ego_entry, ego_exit, p_int.conflict_entry_sim_ms, p_int.conflict_exit_sim_ms):
                if not has_higher_right_of_way(
                    self.vehicle_id, self.in_edge, self.out_edge, ego_entry,
                    pid, p_int.incoming_edge, p_int.outgoing_edge, p_int.conflict_entry_sim_ms,
                ):
                    intent_yield = True

        partition_blind = (len(self.peer_intents) == 0 and ego_row == "YIELD")
        if expired_conflict or partition_blind:
            self.coop_state = "DEGRADED_AUTONOMOUS"
            if sim_ms <= restore_ms:
                self.degraded_before_restore = True
            if sim_ms >= restore_ms:
                self.last_blocked_ms = sim_ms
            cmd_v = min(13.89, max_safe_approach_speed_mps(d_to_cz))
            return cmd_v, ("STOP_YIELD" if cmd_v < 1.0 else "DECEL_YIELD"), "EXPIRED_OR_MISSING_INTENT_DEGRADED"
        if intent_yield:
            if sim_ms >= restore_ms:
                self.last_blocked_ms = sim_ms
            cmd_v = min(13.89, max_safe_approach_speed_mps(d_to_cz))
            return cmd_v, ("STOP_YIELD" if cmd_v < 1.0 else "DECEL_YIELD"), "COOP_INTENT_YIELD"
        if ego_row == "YIELD" and d_to_cz > OCCLUSION_VIS_CLEAR_M:
            return min(13.89, max(6.5, max_safe_approach_speed_mps(d_to_cz))), "APPROACH_CAUTION", "WAIT_OCCLUSION_VIS_RECONFIRM"

        if self.partition_affected and self.coop_recovered_ms is None and sim_ms >= restore_ms:
            self.coop_recovered_ms = sim_ms - restore_ms
        self.coop_state = "COOPERATIVE"
        return 13.89, "PROCEED", "COOP_CLEAR_PROCEED"


def run_60v_arm(
    net_file: Path,
    rou_file: Path,
    specs: List[Dict[str, Any]],
    mode: str,
    fault_enabled: bool,
    out_dir: Path,
    pace_wall_clock: bool,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_map = {s["vehicle_id"]: s for s in specs}
    nodes = {s["vehicle_id"]: InProcessVehicleNode(s, mode) for s in specs}
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
    cur_consec_misses = 0
    max_consec_misses = 0
    low_speed_steps = 0
    harsh_brakes = 0
    prev_speeds: Dict[str, float] = {}
    last_speed_mode: Dict[str, int] = {}
    subscribed_vids: set[str] = set()
    partition_drops = 0
    restore_ms = 7500
    saved_replay: DrivingIntentV1 | None = None
    replayed = False

    try:
        step_idx = 0
        next_wall_ns = time.monotonic_ns()
        while step_idx * STEP_MS <= 240000:
            t0_ns = time.monotonic_ns()
            traci.simulationStep()
            sim_ms = int(round(traci.simulation.getTime() * 1000.0))
            for dep_vid in traci.simulation.getDepartedIDList():
                if dep_vid not in subscribed_vids:
                    traci.vehicle.subscribe(dep_vid, [tc.VAR_POSITION, tc.VAR_ROAD_ID, tc.VAR_SPEED])
                    subscribed_vids.add(dep_vid)
            sub_res = traci.vehicle.getAllSubscriptionResults()
            if step_idx > 20 and not sub_res and traci.simulation.getMinExpectedNumber() <= 0:
                break

            raw: Dict[str, Dict[str, Any]] = {}
            for vid, vals in sub_res.items():
                if fault_enabled and 5500 <= sim_ms < 7500:
                    nodes[vid].partition_affected = True
                x, y = vals[tc.VAR_POSITION]
                edge = vals[tc.VAR_ROAD_ID]
                spd = vals[tc.VAR_SPEED]
                sp = spec_map[vid]
                in_cz = edge.startswith(":j1")
                approaching = (edge in INCOMING_EDGES) or in_cz
                if sim_ms >= restore_ms and approaching:
                    nodes[vid].still_approaching_at_restore = True
                d_cz = max(0.0, math.hypot(x, y) - 7.0) if edge in INCOMING_EDGES else -1.0
                raw[vid] = {
                    "vehicle_id": vid, "in_edge": sp["in_edge"], "out_edge": sp["out_edge"],
                    "speed_mps": spd, "d_to_cz_m": d_cz, "in_cz": in_cz, "approaching": approaching,
                }

            # Broadcast & spatial-zone filtered forwarding (Zone A partition [5500, 7500])
            tx_pkts: List[DrivingIntentV1] = []
            for vid, st in raw.items():
                pkt = nodes[vid].maybe_broadcast(sim_ms, st["speed_mps"], st["d_to_cz_m"], st["approaching"])
                if pkt is not None:
                    tx_pkts.append(pkt)

            for pkt in tx_pkts:
                if fault_enabled and saved_replay is None and 4500 <= sim_ms < 5500 and pkt.zone_id == "zone-a":
                    saved_replay = pkt
                for dst_id in raw:
                    if dst_id == pkt.vehicle_id:
                        continue
                    if fault_enabled and 5500 <= sim_ms < 7500 and (pkt.zone_id == "zone-a" or spec_map[dst_id]["zone_id"] == "zone-a"):
                        partition_drops += 1
                        continue
                    nodes[dst_id].receive_intent(pkt, sim_ms)

            if fault_enabled and sim_ms >= 8200 and saved_replay is not None and not replayed:
                replayed = True
                for dst_id in raw:
                    if spec_map[dst_id]["zone_id"] == "zone-c":
                        nodes[dst_id].receive_intent(saved_replay, sim_ms)

            # Identify the head-of-line (closest to cz) vehicle on each incoming edge
            # so queued followers cannot block cross-traffic ahead of their own leader.
            edge_leader_d: Dict[str, float] = {}
            edge_leader_vid: Dict[str, str] = {}
            for pid, st in raw.items():
                if not st["in_cz"] and st["d_to_cz_m"] >= 0.0:
                    ie = st["in_edge"]
                    if ie not in edge_leader_d or st["d_to_cz_m"] < edge_leader_d[ie]:
                        edge_leader_d[ie] = st["d_to_cz_m"]
                        edge_leader_vid[ie] = pid
            leader_ids = set(edge_leader_vid.values())

            for vid, st in raw.items():
                desired_mode = 31 if st["in_cz"] else 23
                if last_speed_mode.get(vid) != desired_mode:
                    traci.vehicle.setSpeedMode(vid, desired_mode)
                    last_speed_mode[vid] = desired_mode
                vis = [
                    pst for pid, pst in raw.items()
                    if pid != vid and (
                        pst["in_cz"]
                        or (
                            0.0 <= pst["d_to_cz_m"] <= OCCLUSION_VIS_CLEAR_M
                            and pst["d_to_cz_m"] <= edge_leader_d.get(pst["in_edge"], 1e9) + 0.5
                        )
                    )
                ]
                cmd_v, _, _ = nodes[vid].step_decide(
                    sim_ms, st["speed_mps"], st["d_to_cz_m"], st["approaching"], vis, restore_ms, leader_ids
                )
                traci.vehicle.setSpeed(vid, cmd_v)
                act_v = st["speed_mps"]
                if act_v < 2.0 and st["d_to_cz_m"] > 0.0:
                    low_speed_steps += 1
                prev_v = prev_speeds.get(vid, act_v)
                if (prev_v - act_v) / 0.1 >= HARSH_DECEL_THRESHOLD_MPS2:
                    harsh_brakes += 1
                prev_speeds[vid] = act_v

            elapsed_ms = (time.monotonic_ns() - t0_ns) / 1_000_000.0
            step_times_ms.append(elapsed_ms)
            if elapsed_ms > STEP_MS:
                deadline_misses += 1
                cur_consec_misses += 1
                if cur_consec_misses > max_consec_misses:
                    max_consec_misses = cur_consec_misses
            else:
                cur_consec_misses = 0

            if pace_wall_clock:
                next_wall_ns += STEP_MS * 1_000_000
                sleep_ns = next_wall_ns - time.monotonic_ns()
                if sleep_ns > 0:
                    time.sleep(sleep_ns / 1_000_000_000.0)
            step_idx += 1
    finally:
        traci.close()

    import xml.etree.ElementTree as ET
    collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
    trips = ET.parse(trip_xml).getroot().findall("tripinfo") if trip_xml.exists() else []
    total_wait = round(sum(float(t.attrib.get("waitingTime", "0")) for t in trips), 2)

    affected_nodes = [
        n for n in nodes.values()
        if not n.silent and n.partition_affected and n.degraded_before_restore and n.still_approaching_at_restore
    ]
    denom_n = len(affected_nodes)
    intent_ready = [n.intent_ready_ms for n in affected_nodes if n.intent_ready_ms is not None]
    phys_to_coop = [
        max(0, (restore_ms + n.coop_recovered_ms) - (n.last_blocked_ms or restore_ms))
        for n in affected_nodes
        if n.coop_recovered_ms is not None
    ]
    recovery_cov_ok = (len(intent_ready) == denom_n and len(phys_to_coop) == denom_n) if fault_enabled else True
    miss_rate_pct = round((deadline_misses / max(1, len(step_times_ms))) * 100.0, 2)

    return {
        "collisions": collisions,
        "completed_trips": len(trips),
        "total_wait_s": total_wait,
        "low_speed_approach_steps": low_speed_steps,
        "harsh_brakes": harsh_brakes,
        "total_steps": len(step_times_ms),
        "step_elapsed_p50_ms": _percentile(step_times_ms, 50),
        "step_elapsed_p95_ms": _percentile(step_times_ms, 95),
        "step_elapsed_p99_ms": _percentile(step_times_ms, 99),
        "step_elapsed_max_ms": _percentile(step_times_ms, 100),
        "deadline_misses": deadline_misses,
        "max_consecutive_misses": max_consec_misses,
        "deadline_miss_rate_pct": miss_rate_pct,
        "partition_drops": partition_drops,
        "stale_dropped_total": sum(n.stale_dropped for n in nodes.values()),
        "recovery_denominator_count": denom_n,
        "intent_ready_covered_count": len(intent_ready),
        "coop_recovered_covered_count": len(phys_to_coop),
        "recovery_coverage_complete": recovery_cov_ok,
        "t_intent_ready_p50_ms": _percentile(intent_ready, 50) if len(intent_ready) == denom_n else 999999.0,
        "t_intent_ready_p95_ms": _percentile(intent_ready, 95) if len(intent_ready) == denom_n else 999999.0,
        "t_intent_ready_max_ms": _percentile(intent_ready, 100) if len(intent_ready) == denom_n else 999999.0,
        "t_phys_clear_to_coop_p95_ms": _percentile(phys_to_coop, 95) if len(phys_to_coop) == denom_n else 999999.0,
        "t_phys_clear_to_coop_max_ms": _percentile(phys_to_coop, 100) if len(phys_to_coop) == denom_n else 999999.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", nargs="+", type=int, default=[101, 202, 303])
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "out_60v"))
    ap.add_argument("--no-pace", action="store_true")
    args = ap.parse_args()

    net_file = Path(__file__).resolve().parent / "sumo_net" / "j1.net.xml"
    out_base = Path(args.out_dir)
    out_base.mkdir(parents=True, exist_ok=True)
    results = []
    for seed in args.seeds:
        rou_file = out_base / f"routes_60v_seed{seed}.rou.xml"
        specs = generate_60v_routes(seed, rou_file)
        a1 = run_60v_arm(net_file, rou_file, specs, "local_only", False, out_base / f"s{seed}_arm1", not args.no_pace)
        a2 = run_60v_arm(net_file, rou_file, specs, "cooperative", False, out_base / f"s{seed}_arm2", not args.no_pace)
        a3 = run_60v_arm(net_file, rou_file, specs, "cooperative", True, out_base / f"s{seed}_arm3", not args.no_pace)
        red_pct = round(((a1["low_speed_approach_steps"] - a2["low_speed_approach_steps"]) / max(1, a1["low_speed_approach_steps"])) * 100.0, 2)
        results.append({"seed": seed, "arm1": a1, "arm2": a2, "arm3": a3, "arm2_vs_arm1_delay_reduction_pct": red_pct})

    summary_bytes = json.dumps({"seeds": results}, indent=2).encode("utf-8")
    summary_path = out_base / "dsx_60v_multiseed_results.json"
    summary_path.write_bytes(summary_bytes)

    checks = []
    for r in results:
        s = r["seed"]
        a1, a2, a3 = r["arm1"], r["arm2"], r["arm3"]
        checks.extend([
            {"name": f"seed_{s}_zero_collisions_all_arms", "passed": a1["collisions"] == 0 and a2["collisions"] == 0 and a3["collisions"] == 0},
            {"name": f"seed_{s}_60_of_60_trips_completed_all_arms", "passed": a1["completed_trips"] == 60 and a2["completed_trips"] == 60 and a3["completed_trips"] == 60},
            {"name": f"seed_{s}_arm3_partition_and_replay_verified", "passed": a3["partition_drops"] > 0 and a3["stale_dropped_total"] > 0},
            {"name": f"seed_{s}_arm3_recovery_sla_and_coverage", "passed": a3["recovery_coverage_complete"] is True and a3["t_intent_ready_max_ms"] <= 600.0 and a3["t_phys_clear_to_coop_max_ms"] <= 1500.0},
            {"name": f"seed_{s}_realtime_pacing_ok", "passed": all(arm["step_elapsed_p99_ms"] <= 100.0 and arm["deadline_miss_rate_pct"] <= 1.0 for arm in (a1, a2, a3))},
        ])
    verif = {
        "schema": "prodocux.dsx_air_60v.matrix.v1",
        "pace_wall_clock": not args.no_pace,
        "status": "pass" if all(c["passed"] for c in checks) else "fail",
        "passed": sum(1 for c in checks if c["passed"]),
        "total": len(checks),
        "checks": checks,
    }
    (out_base / "prodocux_dsx_60v_verification.json").write_text(json.dumps(verif, indent=2), encoding="utf-8")

    import subprocess
    import sys
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
summary_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
summary_bytes = summary_path.read_bytes()
results = json.loads(summary_bytes.decode("utf-8"))["seeds"]
doc_sha = hashlib.sha256(summary_bytes).hexdigest()
doc_id = "doc-dsx-60v-multiseed"
src_ref = SourceReferenceV1(
    schema_version="prodocux_source_reference_v1",
    source_sha256=doc_sha,
    media_type="application/json",
    locator=PdfPageLocator(kind="pdf_page", page=1),
    snippet="60-vehicle 3-seed 3-arm SUMO+DSX Air verification summary",
    extraction=ExtractionIdentity(
        method="host_supplied",
        extractor_id="pdx-guardian-dsx-60v",
        extractor_version=prodocux_kernel.__version__,
    ),
    truncated=False,
)
ev_items, ev_checks = [], []
for r in results:
    s = r["seed"]
    for arm_name in ("arm1", "arm2", "arm3"):
        arm = r[arm_name]
        cid, tid = f"s{s}-{arm_name}-col", f"s{s}-{arm_name}-trip"
        p99id, mrid = f"s{s}-{arm_name}-p99", f"s{s}-{arm_name}-missrate"
        ev_items.append(EvidenceItem(evidence_id=f"ev-{cid}", document_id=doc_id, field_name=f"seed_{s}.{arm_name}.collisions", value_type="number", value=arm["collisions"], confidence=1.0, source_reference=src_ref))
        ev_items.append(EvidenceItem(evidence_id=f"ev-{tid}", document_id=doc_id, field_name=f"seed_{s}.{arm_name}.completed_trips", value_type="number", value=arm["completed_trips"], confidence=1.0, source_reference=src_ref))
        ev_items.append(EvidenceItem(evidence_id=f"ev-{p99id}", document_id=doc_id, field_name=f"seed_{s}.{arm_name}.step_elapsed_p99_ms", value_type="number", value=arm["step_elapsed_p99_ms"], confidence=1.0, source_reference=src_ref))
        ev_items.append(EvidenceItem(evidence_id=f"ev-{mrid}", document_id=doc_id, field_name=f"seed_{s}.{arm_name}.deadline_miss_rate_pct", value_type="number", value=arm["deadline_miss_rate_pct"], confidence=1.0, source_reference=src_ref))
        ev_checks.append(EvidenceCheck(check_id=f"chk-{cid}", kind="numeric_range", evidence_ids=[f"ev-{cid}"], minimum=0.0, minimum_inclusive=True, maximum=0.0, maximum_inclusive=True))
        ev_checks.append(EvidenceCheck(check_id=f"chk-{tid}", kind="numeric_range", evidence_ids=[f"ev-{tid}"], minimum=60.0, minimum_inclusive=True, maximum=60.0, maximum_inclusive=True))
        ev_checks.append(EvidenceCheck(check_id=f"chk-{p99id}", kind="numeric_range", evidence_ids=[f"ev-{p99id}"], minimum=0.0, minimum_inclusive=True, maximum=100.0, maximum_inclusive=True))
        ev_checks.append(EvidenceCheck(check_id=f"chk-{mrid}", kind="numeric_range", evidence_ids=[f"ev-{mrid}"], minimum=0.0, minimum_inclusive=True, maximum=1.0, maximum_inclusive=True))
    a3 = r["arm3"]
    ev_items.append(EvidenceItem(evidence_id=f"ev-s{s}-pdrop", document_id=doc_id, field_name=f"seed_{s}.arm3.partition_drops", value_type="number", value=a3["partition_drops"], confidence=1.0, source_reference=src_ref))
    ev_items.append(EvidenceItem(evidence_id=f"ev-s{s}-stale", document_id=doc_id, field_name=f"seed_{s}.arm3.stale_dropped_total", value_type="number", value=a3["stale_dropped_total"], confidence=1.0, source_reference=src_ref))
    ev_items.append(EvidenceItem(evidence_id=f"ev-s{s}-rcov", document_id=doc_id, field_name=f"seed_{s}.arm3.recovery_coverage_complete", value_type="string", value=str(a3["recovery_coverage_complete"]), confidence=1.0, source_reference=src_ref))
    ev_checks.append(EvidenceCheck(check_id=f"chk-s{s}-pdrop", kind="numeric_range", evidence_ids=[f"ev-s{s}-pdrop"], minimum=1.0, minimum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-s{s}-stale", kind="numeric_range", evidence_ids=[f"ev-s{s}-stale"], minimum=1.0, minimum_inclusive=True))
    ev_checks.append(EvidenceCheck(check_id=f"chk-s{s}-rcov", kind="equality", evidence_ids=[f"ev-s{s}-rcov"], expected="True"))
req = EvidenceBundleRequestV1(
    schema_version="prodocux_evidence_bundle_request_v1",
    request_id=f"req-{doc_sha[:16]}",
    rule_set=EvidenceRuleSet(id="pdx-guardian-dsx-60v", version="1.0.0", sha256=hashlib.sha256(b"pdx-guardian-dsx-60v-v1").hexdigest()),
    documents=[EvidenceDocument(document_id=doc_id, source_sha256=doc_sha, media_type="application/json")],
    evidence=ev_items,
    checks=ev_checks,
)
bundle_ver = verify_evidence_bundle(req)
bundle_dict = bundle_ver if isinstance(bundle_ver, dict) else bundle_ver.model_dump(mode="json")
out_path.write_text(json.dumps(bundle_dict, indent=2), encoding="utf-8")
"""
    bundle_out_path = out_base / "prodocux_dsx_60v_bundle_verification.json"
    py_exe = str(venv_py) if venv_py.exists() else sys.executable
    subprocess.run([py_exe, "-c", bundle_script, str(summary_path), str(bundle_out_path)], check=True)
    bundle_dict = json.loads(bundle_out_path.read_text(encoding="utf-8"))

    print(json.dumps({"seeds": results, "matrix_checks": verif, "prodocux_bundle_verification": bundle_dict}, indent=2))
    return 0 if (verif["status"] == "pass" and bundle_dict.get("status") == "pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
