#!/usr/bin/env python3
"""
DrivingIntentV1 (schema pdx.driving_intent.v2) & Physical Safety Rules
for the DSX Air / SUMO Cooperative Urban Intersection Experiment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Set, Tuple

# Physical vehicle & safety constants (frozen for audit recomputation)
REACT_TIME_S = 0.20
MAX_BRAKE_MPS2 = 4.50
STOP_MARGIN_M = 2.00
OCCLUSION_VIS_CLEAR_M = 18.00
HARSH_DECEL_THRESHOLD_MPS2 = 3.50
TTL_MS = 500
BROADCAST_PERIOD_MS = 200
STEP_MS = 100
CONFLICT_BUFFER_MS = 400

# Unsignalized 4-way intersection j1 right-of-way priority:
# East-West straight is PRIORITY; North-South and all LEFT turns are YIELD.
PRIORITY_MOVEMENTS: Set[Tuple[str, str]] = {
    ("west_in", "east_out"),
    ("east_in", "west_out"),
}

# Pairs of (incoming_edge, outgoing_edge) movements whose paths intersect inside j1_cz_center.
# Right turns into non-overlapping lanes are excluded where geometrically disjoint,
# while crossing/merging movements are explicitly listed.
MOVEMENT_CONFLICTS: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {
    ("west_in", "east_out"): {
        ("south_in", "north_out"),
        ("north_in", "south_out"),
        ("east_in", "south_out"),
        ("south_in", "west_out"),
        ("north_in", "east_out"),
    },
    ("east_in", "west_out"): {
        ("south_in", "north_out"),
        ("north_in", "south_out"),
        ("west_in", "north_out"),
        ("south_in", "west_out"),
        ("north_in", "east_out"),
    },
    ("south_in", "north_out"): {
        ("west_in", "east_out"),
        ("east_in", "west_out"),
        ("east_in", "south_out"),
        ("north_in", "east_out"),
        ("west_in", "north_out"),
    },
    ("north_in", "south_out"): {
        ("west_in", "east_out"),
        ("east_in", "west_out"),
        ("west_in", "north_out"),
        ("south_in", "west_out"),
        ("east_in", "south_out"),
    },
    ("east_in", "south_out"): {
        ("west_in", "east_out"),
        ("south_in", "north_out"),
        ("north_in", "south_out"),
        ("west_in", "north_out"),
    },
    ("west_in", "north_out"): {
        ("east_in", "west_out"),
        ("south_in", "north_out"),
        ("north_in", "south_out"),
        ("east_in", "south_out"),
    },
    ("south_in", "east_out"): {
        ("west_in", "east_out"),
        ("north_in", "east_out"),
    },
}


def required_stopping_distance_m(speed_mps: float) -> float:
    """Physics-based stopping distance: v * t_react + v^2 / (2 * a_brake) + d_margin."""
    v = max(0.0, float(speed_mps))
    return v * REACT_TIME_S + (v * v) / (2.0 * MAX_BRAKE_MPS2) + STOP_MARGIN_M


def max_safe_approach_speed_mps(distance_to_stop_m: float) -> float:
    """Maximum speed v such that required_stopping_distance_m(v) <= distance_to_stop_m."""
    avail = max(0.0, float(distance_to_stop_m) - STOP_MARGIN_M)
    if avail <= 0.0:
        return 0.0
    # Solve v^2 / (2a) + v * t_r - avail = 0
    a = 1.0 / (2.0 * MAX_BRAKE_MPS2)
    b = REACT_TIME_S
    disc = b * b + 4.0 * a * avail
    return max(0.0, (-b + disc ** 0.5) / (2.0 * a))


def movements_conflict(
    in_a: str,
    out_a: str,
    in_b: str,
    out_b: str,
) -> bool:
    return (in_b, out_b) in MOVEMENT_CONFLICTS.get((in_a, out_a), set())


def time_windows_overlap(
    entry_a_ms: int,
    exit_a_ms: int,
    entry_b_ms: int,
    exit_b_ms: int,
    buffer_ms: int = CONFLICT_BUFFER_MS,
) -> bool:
    return (entry_a_ms - buffer_ms) <= exit_b_ms and (entry_b_ms - buffer_ms) <= exit_a_ms


def right_of_way_class(in_edge: str, out_edge: str) -> str:
    return "PRIORITY" if (in_edge, out_edge) in PRIORITY_MOVEMENTS else "YIELD"


def has_higher_right_of_way(
    veh_a: str,
    in_a: str,
    out_a: str,
    entry_a_ms: int,
    veh_b: str,
    in_b: str,
    out_b: str,
    entry_b_ms: int,
) -> bool:
    """Return True if veh_a has higher legal/cooperative priority than veh_b."""
    row_a = right_of_way_class(in_a, out_a)
    row_b = right_of_way_class(in_b, out_b)
    if row_a != row_b:
        return row_a == "PRIORITY"
    # Equal legal right-of-way: only use ETA if separated by > 600ms (anti-deadlock hysteresis);
    # otherwise break ties deterministically by lexicographical vehicle_id.
    if abs(entry_a_ms - entry_b_ms) > 600:
        return entry_a_ms < entry_b_ms
    return veh_a < veh_b


@dataclass
class DrivingIntentV1:
    schema: str
    vehicle_id: str
    zone_id: str
    seq: int
    tx_wall_ms: int
    issued_at_sim_ms: int
    ttl_ms: int
    incoming_edge: str
    outgoing_edge: str
    turn_intent: str
    conflict_zone_id: str
    conflict_entry_sim_ms: int
    conflict_exit_sim_ms: int
    right_of_way_class: str
    speed_mps: float
    intended_action: str
    plan_version: int = 1
    packet_id: str = ""
    digest_sha256: str = ""

    def compute_digest(self) -> str:
        payload = asdict(self)
        payload.pop("digest_sha256", None)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_bytes(self) -> bytes:
        if not self.digest_sha256:
            self.digest_sha256 = self.compute_digest()
        return json.dumps(asdict(self), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> Optional["DrivingIntentV1"]:
        try:
            data = json.loads(raw.decode("utf-8"))
            obj = cls(**data)
            if obj.digest_sha256 != obj.compute_digest():
                return None
            return obj
        except Exception:
            return None


DrivingIntentV2 = DrivingIntentV1
