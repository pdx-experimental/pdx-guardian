#!/usr/bin/env python3
"""
Pure SUMO Native Baseline (60 -> 150 -> 300 -> 600, seed=101).
Runs SUMO arterial_3j.net.xml with native car-following & junction rules only
(no Guardian controller, no setSpeed overrides).
"""

from __future__ import annotations

import json
import math
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

import traci
import traci.constants as tc

from run_dsx_ladder import generate_multi_j_routes


def _pct(vals: List[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(math.ceil((p / 100.0) * len(s))) - 1))
    return round(float(s[idx]), 2)


def run_pure_sumo(fleet_dir: Path, n_veh: int, seed: int, out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    net_file = fleet_dir / "sumo_net" / "arterial_3j.net.xml"
    rou_file = out_dir / f"routes_{n_veh}v_s{seed}.rou.xml"
    generate_multi_j_routes(n_veh, seed, rou_file)

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

    step_ms: List[float] = []
    prev_speeds: Dict[str, float] = {}
    subscribed: set[str] = set()
    harsh_brakes = 0
    max_active = 0
    step_idx = 0
    try:
        while step_idx * 100 <= 900000:
            t0 = time.monotonic_ns()
            traci.simulationStep()
            for vid in traci.simulation.getDepartedIDList():
                if vid not in subscribed:
                    traci.vehicle.subscribe(vid, [tc.VAR_SPEED])
                    subscribed.add(vid)
            sub = traci.vehicle.getAllSubscriptionResults()
            if step_idx > 20 and not sub and traci.simulation.getMinExpectedNumber() <= 0:
                break
            if len(sub) > max_active:
                max_active = len(sub)
            for vid, d in sub.items():
                spd = float(d[tc.VAR_SPEED])
                pv = prev_speeds.get(vid, spd)
                if (pv - spd) / 0.1 >= 3.0:
                    harsh_brakes += 1
                prev_speeds[vid] = spd
            step_ms.append((time.monotonic_ns() - t0) / 1_000_000.0)
            step_idx += 1
    finally:
        traci.close()

    collisions = len(ET.parse(col_xml).getroot().findall("collision")) if col_xml.exists() else 0
    trips = ET.parse(trip_xml).getroot().findall("tripinfo") if trip_xml.exists() else []
    total_wait = round(sum(float(t.attrib.get("waitingTime", "0")) for t in trips), 2)
    return {
        "n_vehicles": n_veh,
        "mode": "pure_sumo_native",
        "collisions": collisions,
        "completed_trips": len(trips),
        "total_wait_s": total_wait,
        "harsh_brakes": harsh_brakes,
        "max_concurrent_active": max_active,
        "total_steps": len(step_ms),
        "step_elapsed_p50_ms": _pct(step_ms, 50),
        "step_elapsed_p95_ms": _pct(step_ms, 95),
        "step_elapsed_p99_ms": _pct(step_ms, 99),
        "step_elapsed_max_ms": round(max(step_ms), 2) if step_ms else 0.0,
    }


def main() -> None:
    fleet_dir = Path(__file__).resolve().parent
    out_base = fleet_dir / "out_sumo_baseline"
    out_base.mkdir(parents=True, exist_ok=True)
    runs = [run_pure_sumo(fleet_dir, n, 101, out_base / f"sumo_{n}v") for n in (60, 150, 300, 600)]
    res = {"environment": "Pure SUMO 1.28.0 Native (no Guardian)", "seed": 101, "runs": runs}
    (out_base / "sumo_baseline_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
