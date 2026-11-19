#!/usr/bin/env python3
"""
Host-Side Python Reference Negative Control (SUMO 1.28+ TraCI, 60 Vehicles, 10 Seeds)
Note: Evaluates the host-side Python reference model (InProcessVehicleNode in intent_protocol.py),
not the C qnx_veh_host.c binary.
Compares 3 arms across seeds 42..51 under a 5.5s-7.5s partition + 20 stale replay packets:
  1. cooperative             (rejects stale packets, enforces stopping-distance fallback)
  2. accept_stale_only       (accepts stale packets, keeps stopping-distance fallback)
  3. trust_stale_no_fallback (accepts stale packets, skips stopping-distance fallback)
All arms use SUMO speedMode=7 (keeps longitudinal car-following while disabling SUMO's
built-in junction right-of-way and red-light overrides so arbiter decisions govern entry).
"""

from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import traci

from intent_protocol import (
    BROADCAST_PERIOD_MS,
    STEP_MS,
)
from run_60v_experiment import InProcessVehicleNode as VehicleNode, generate_60v_routes

FLEET_DIR = Path(__file__).resolve().parent
NET_XML = FLEET_DIR / "sumo_net" / "j1.net.xml"
OUT_JSON = FLEET_DIR / "out_sumo_baseline" / "sumo_negative_control_results.json"


def run_arm(mode: str, seed: int) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"pdx_neg_{mode}_", ignore_cleanup_errors=True) as td:
        td_path = Path(td)
        rou_xml = td_path / "routes.rou.xml"
        col_xml = td_path / "collisions.xml"
        specs = generate_60v_routes(seed, rou_xml)
        nodes = {s["vehicle_id"]: VehicleNode(s, "cooperative") for s in specs}

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
                                    if pkt.seq <= r_node.last_seen_seq.get(vid, 0):
                                        stale_accepted += 1
                                    r_node.peer_intents[vid] = pkt

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

                for vid in active_ids:
                    node = nodes[vid]
                    edge = traci.vehicle.getRoadID(vid)
                    spd = traci.vehicle.getSpeed(vid)
                    approaching = edge in ("west_in", "east_in", "south_in", "north_in")
                    d_cz = -1.0
                    if approaching:
                        lane_id = traci.vehicle.getLaneID(vid)
                        d_cz = max(0.0, traci.lane.getLength(lane_id) - traci.vehicle.getLanePosition(vid))

                    if mode in ("cooperative", "accept_stale_only"):
                        cmd_v, _, _ = node.step_decide(sim_ms, spd, d_cz, approaching, [], partition_end)
                    else:
                        cmd_v = 13.89
                    traci.vehicle.setSpeed(vid, cmd_v)
        finally:
            traci.close()

        collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
        return {
            "seed": seed,
            "stale_replay_packets_injected": stale_injected,
            "stale_dropped": stale_dropped,
            "stale_accepted_deliveries": stale_accepted,
            "collisions": collisions,
        }


def main() -> int:
    seeds = list(range(42, 52))
    arms = ["cooperative", "accept_stale_only", "trust_stale_no_fallback"]
    results = {arm: [run_arm(arm, s) for s in seeds] for arm in arms}
    summary = {
        arm: {
            "seeds_run": len(runs),
            "seeds_with_collisions": sum(1 for r in runs if r["collisions"] > 0),
            "total_collisions": sum(r["collisions"] for r in runs),
            "total_stale_dropped": sum(r["stale_dropped"] for r in runs),
            "total_stale_accepted_deliveries": sum(r["stale_accepted_deliveries"] for r in runs),
        }
        for arm, runs in results.items()
    }
    out = {
        "experiment": "sumo_negative_control_60v_10seeds",
        "model": "Host-side Python reference model (InProcessVehicleNode, intent_protocol.py)",
        "speed_mode": 7,
        "seeds": seeds,
        "summary": summary,
        "runs": results,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
