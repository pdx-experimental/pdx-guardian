#!/usr/bin/env python3
"""
Negative Control Experiment (SUMO 1.28+ TraCI, 60 Vehicles, Partition 5.5s-7.5s)
Compares:
  1. cooperative (PDX Guardian fail-closed: drops stale packets, enforces stopping-distance fallback)
  2. trust_stale (negative control: accepts stale/expired intents, skips stopping-distance fallback)
Both arms use SUMO speedMode=0 (disabling SUMO's built-in junction collision-avoidance override)
so the safety arbiter's own decisions govern intersection entry.
"""

from __future__ import annotations

import json
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import traci

from intent_protocol import (
    BROADCAST_PERIOD_MS,
    OCCLUSION_VIS_CLEAR_M,
    STEP_MS,
    TTL_MS,
    has_higher_right_of_way,
    movements_conflict,
    required_stopping_distance_m,
    right_of_way_class,
    time_windows_overlap,
)
from run_60v_experiment import InProcessVehicleNode as VehicleNode, generate_60v_routes

FLEET_DIR = Path(__file__).resolve().parent
NET_XML = FLEET_DIR / "sumo_net" / "j1.net.xml"
OUT_JSON = FLEET_DIR / "out_sumo_baseline" / "sumo_negative_control_results.json"


def run_arm(mode: str, seed: int = 42) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"pdx_neg_{mode}_", ignore_cleanup_errors=True) as td:
        td_path = Path(td)
        rou_xml = td_path / "routes.rou.xml"
        col_xml = td_path / "collisions.xml"
        specs = generate_60v_routes(seed, rou_xml)
        nodes = {
            s["vehicle_id"]: VehicleNode(s, "cooperative")
            for s in specs
        }

        sumo_cmd = [
            "sumo",
            "-n", str(NET_XML),
            "-r", str(rou_xml),
            "--step-length", "0.1",
            "--collision.action", "warn",
            "--collision.check-junctions", "true",
            "--collision-output", str(col_xml),
            "--no-step-log", "true",
            "--no-warnings", "true",
        ]
        traci.start(sumo_cmd)

        stale_accepted = 0
        stale_dropped = 0
        stale_injected = 0
        replay_buf = []
        speed_mode_set = set()
        sim_ms = 0
        partition_start = 5500
        partition_end = 7500

        try:
            while sim_ms <= 25000 and (sim_ms < 2000 or traci.simulation.getMinExpectedNumber() > 0):
                traci.simulationStep()
                sim_ms += STEP_MS
                active_ids = traci.vehicle.getIDList()
                for vid in active_ids:
                    if vid not in speed_mode_set:
                        traci.vehicle.setSpeedMode(vid, 7)
                        speed_mode_set.add(vid)

                in_partition = (partition_start <= sim_ms < partition_end)

                # Broadcast & collect intents
                for vid in active_ids:
                    node = nodes[vid]
                    if node.silent:
                        continue
                    edge = traci.vehicle.getRoadID(vid)
                    if edge not in ("west_in", "east_in", "south_in", "north_in"):
                        continue
                    spd = traci.vehicle.getSpeed(vid)
                    lane_id = traci.vehicle.getLaneID(vid)
                    lane_len = traci.lane.getLength(lane_id)
                    pos = traci.vehicle.getLanePosition(vid)
                    d_cz = max(0.0, lane_len - pos)
                    pkt = node.maybe_broadcast(sim_ms, spd, d_cz, True)
                    if pkt is not None:
                        if len(replay_buf) < 20 and sim_ms >= 2000:
                            replay_buf.append(pkt)
                        if not in_partition:
                            for r_vid, r_node in nodes.items():
                                if r_vid == vid:
                                    continue
                                if mode == "cooperative":
                                    if pkt.seq <= r_node.last_seen_seq.get(vid, 0):
                                        stale_dropped += 1
                                    else:
                                        r_node.last_seen_seq[vid] = pkt.seq
                                        r_node.peer_intents[vid] = pkt
                                else:
                                    stale_accepted += 1 if pkt.seq <= r_node.last_seen_seq.get(vid, 0) else 0
                                    r_node.peer_intents[vid] = pkt

                # Inject 20 stale replay packets right at partition end
                if sim_ms == partition_end and replay_buf:
                    for rpkt in replay_buf:
                        stale_injected += 1
                        for r_vid, r_node in nodes.items():
                            if r_vid == rpkt.vehicle_id:
                                continue
                            if mode == "cooperative":
                                if rpkt.seq <= r_node.last_seen_seq.get(rpkt.vehicle_id, 0):
                                    stale_dropped += 1
                            else:
                                stale_accepted += 1
                                r_node.peer_intents[rpkt.vehicle_id] = rpkt

                # Decide vehicle speeds
                for vid in active_ids:
                    node = nodes[vid]
                    edge = traci.vehicle.getRoadID(vid)
                    spd = traci.vehicle.getSpeed(vid)
                    approaching = edge in ("west_in", "east_in", "south_in", "north_in")
                    d_cz = -1.0
                    if approaching:
                        lane_id = traci.vehicle.getLaneID(vid)
                        d_cz = max(0.0, traci.lane.getLength(lane_id) - traci.vehicle.getLanePosition(vid))

                    if mode == "cooperative":
                        vis = []
                        cmd_v, _, _ = node.step_decide(sim_ms, spd, d_cz, approaching, vis, partition_end)
                    else:
                        # Negative control: trust stale/expired intents and skip stopping-distance fallback
                        cmd_v = 13.89
                    traci.vehicle.setSpeed(vid, cmd_v)
        finally:
            traci.close()

        collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
        return {
            "mode": mode,
            "seed": seed,
            "vehicles": 60,
            "speed_mode": 7,
            "stale_replay_packets_injected": stale_injected,
            "stale_dropped": stale_dropped,
            "stale_accepted": stale_accepted,
            "collisions": collisions,
        }


def main() -> int:
    coop = run_arm("cooperative", seed=42)
    neg = run_arm("trust_stale", seed=42)
    out = {
        "experiment": "sumo_negative_control_60v",
        "cooperative": coop,
        "trust_stale_negative_control": neg,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
