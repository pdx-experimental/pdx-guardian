#!/usr/bin/env python3
"""
Distributed Vehicle Host Worker for DSX Air Multi-Intersection Fleet.
Hosts N/6 independent vehicle state machines on a single worker node:
- Exchanges DrivingIntentV2 packets over real UDP via zone_gateway
- Serves batched STEP_BATCH RPC over persistent length-prefixed TCP
- Logs TX/RX packet_id traces and per-vehicle recovery / RSS / CPU metrics
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Tuple

from intent_protocol import (
    BROADCAST_PERIOD_MS,
    OCCLUSION_VIS_CLEAR_M,
    TTL_MS,
    max_safe_approach_speed_mps,
    required_stopping_distance_m,
    time_windows_overlap,
)


ARTERIAL_EDGES = {
    "w_to_j1", "j1_to_j2", "j2_to_j3", "j3_to_e",
    "e_to_j3", "j3_to_j2", "j2_to_j1", "j1_to_w",
}


def cz_for_edge(edge: str) -> str:
    if edge in {"w_to_j1", "j2_to_j1", "j1_n_in", "j1_s_in"} or edge.startswith(":j1"):
        return "j1"
    if edge in {"j1_to_j2", "j3_to_j2", "j2_n_in", "j2_s_in"} or edge.startswith(":j2"):
        return "j2"
    if edge in {"j2_to_j3", "e_to_j3", "j3_n_in", "j3_s_in"} or edge.startswith(":j3"):
        return "j3"
    return "none"


def edge_axis(edge: str) -> str:
    if edge in {"w_to_j1", "j2_to_j1", "j1_to_j2", "j3_to_j2", "j2_to_j3", "e_to_j3"}:
        return "EW"
    return "NS"


def movements_conflict_cz(cz1: str, e1: str, l1: bool, cz2: str, e2: str, l2: bool) -> bool:
    if cz1 == "none" or cz1 != cz2:
        return False
    if e1 == e2:
        return False
    if edge_axis(e1) != edge_axis(e2):
        return True
    # Opposing edges on the same axis conflict if either vehicle is turning left
    return l1 or l2


def row_class_cz(edge: str, is_left_turn: bool = False) -> str:
    if is_left_turn:
        return "YIELD"
    return "PRIORITY_STRAIGHT" if edge_axis(edge) == "EW" else "YIELD"


def has_higher_row_cz(
    v1: str, e1: str, l1: bool, t1: int,
    v2: str, e2: str, l2: bool, t2: int,
) -> bool:
    r1 = row_class_cz(e1, l1)
    r2 = row_class_cz(e2, l2)
    if r1 != r2:
        return r1 == "PRIORITY_STRAIGHT"
    if abs(t1 - t2) >= 250:
        return t1 < t2
    return v1 < v2


class HostVehicleNode:
    def __init__(self, spec: Dict[str, Any], mode: str) -> None:
        self.vehicle_id = spec["vehicle_id"]
        self.zone_id = spec["zone_id"]
        self.silent = bool(spec.get("silent", False))
        self.mode = mode
        self.seq = 0
        self.last_bcast_ms = -1000
        self.peer_intents: Dict[str, Dict[str, Any]] = {}
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
        self.tx_count = 0

    def on_rx_intent(self, pkt: Dict[str, Any], sim_ms: int) -> str | None:
        sender = str(pkt.get("vehicle_id", ""))
        if not sender or sender == self.vehicle_id:
            return None
        seq = int(pkt.get("seq", 0))
        prev = self.last_seen_seq.get(sender, 0)
        if seq <= prev:
            self.stale_dropped += 1
            return "STALE_DROPPED"
        age = sim_ms - int(pkt.get("issued_at_sim_ms", sim_ms))
        if age > int(pkt.get("ttl_ms", TTL_MS)):
            self.expired_rx += 1
        self.last_seen_seq[sender] = seq
        self.peer_intents[sender] = pkt
        return "ACCEPTED"

    def maybe_build_intent(
        self, sim_ms: int, speed: float, d_to_cz: float, approaching: bool, edge: str, target_cz: str, is_left_turn: bool
    ) -> Dict[str, Any] | None:
        if self.silent or self.mode == "local_only" or not approaching or target_cz == "none":
            return None
        if sim_ms - self.last_bcast_ms < BROADCAST_PERIOD_MS:
            return None
        self.last_bcast_ms = sim_ms
        self.seq += 1
        eff_v = max(speed, 4.0)
        entry_ms = sim_ms + int((max(0.0, d_to_cz) / eff_v) * 1000.0)
        self.tx_count += 1
        return {
            "schema": "pdx.driving_intent.v2",
            "vehicle_id": self.vehicle_id,
            "zone_id": self.zone_id,
            "seq": self.seq,
            "tx_wall_ms": time.monotonic_ns() // 1_000_000,
            "issued_at_sim_ms": sim_ms,
            "ttl_ms": TTL_MS,
            "incoming_edge": edge,
            "is_left_turn": is_left_turn,
            "conflict_zone_id": f"{target_cz}_cz",
            "conflict_entry_sim_ms": entry_ms,
            "conflict_exit_sim_ms": entry_ms + 2200,
            "speed_mps": round(speed, 3),
            "intended_action": "PROCEED",
            "packet_id": f"{self.vehicle_id}:{self.seq}",
        }

    def step_decide(
        self,
        sim_ms: int,
        speed: float,
        d_to_cz: float,
        approaching: bool,
        edge: str,
        target_cz: str,
        is_left_turn: bool,
        visible_peers: List[Dict[str, Any]],
        restore_ms: int,
        edge_leader_ids: set[str],
        inject_unsafe: bool = False,
    ) -> Tuple[float, str, str]:
        if inject_unsafe:
            return 35.0, "PROCEED", "UNSAFE_CMD_INJECTED"
        if not approaching or d_to_cz < 0.0 or target_cz == "none":
            if self.partition_affected and self.degraded_before_restore and self.coop_recovered_ms is None and sim_ms >= restore_ms:
                self.coop_recovered_ms = sim_ms - restore_ms
            return 13.89, "PROCEED", "PAST_STOP_LINE_CLEAR"

        if self.mode == "cooperative" and self.partition_affected and self.intent_ready_ms is None and sim_ms >= restore_ms:
            fresh = [
                p for p in self.peer_intents.values()
                if (sim_ms - int(p.get("issued_at_sim_ms", 0))) <= int(p.get("ttl_ms", TTL_MS))
                and int(p.get("issued_at_sim_ms", 0)) >= restore_ms
            ]
            if fresh:
                self.intent_ready_ms = sim_ms - restore_ms

        d_req = required_stopping_distance_m(speed)
        ego_row = row_class_cz(edge, is_left_turn)
        eff_v = max(speed, 4.0)
        ego_entry = sim_ms + int((d_to_cz / eff_v) * 1000.0)
        ego_exit = ego_entry + 2200

        local_block = False
        local_reason = ""
        for vp in visible_peers:
            vp_cz = str(vp.get("target_cz", "none"))
            if vp_cz != target_cz:
                continue
            if vp.get("in_cz"):
                local_block = True
                local_reason = "BLOCKED_BY_SILENT_OR_OCCUPIED"
                break
            vp_edge = str(vp.get("edge", ""))
            vp_left = bool(vp.get("is_left_turn", False))
            if movements_conflict_cz(target_cz, edge, is_left_turn, vp_cz, vp_edge, vp_left):
                vp_d = max(0.0, float(vp["d_to_cz_m"]))
                vp_v_raw = float(vp["speed_mps"])
                if vp_v_raw > 1.5 and vp_d <= required_stopping_distance_m(vp_v_raw) + 1.0:
                    local_block = True
                    local_reason = "BLOCKED_BY_COMMITTED_PEER"
                    break
                vp_v = max(vp_v_raw, 4.0)
                vp_entry = sim_ms + int((vp_d / vp_v) * 1000.0)
                if not has_higher_row_cz(self.vehicle_id, edge, is_left_turn, ego_entry, str(vp["vehicle_id"]), vp_edge, vp_left, vp_entry):
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
            cmd_v = min(13.89, max_safe_approach_speed_mps(d_to_cz))
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
            if pid not in edge_leader_ids:
                continue
            p_cz = str(p_int.get("conflict_zone_id", "")).split("_")[0]
            p_edge = str(p_int.get("incoming_edge", ""))
            p_left = bool(p_int.get("is_left_turn", False))
            if not movements_conflict_cz(target_cz, edge, is_left_turn, p_cz, p_edge, p_left):
                continue
            if (sim_ms - int(p_int.get("issued_at_sim_ms", 0))) > int(p_int.get("ttl_ms", TTL_MS)):
                expired_conflict = True
                continue
            p_entry = int(p_int.get("conflict_entry_sim_ms", 0))
            p_exit = int(p_int.get("conflict_exit_sim_ms", 0))
            if (p_entry - sim_ms) > 5000:
                continue
            if time_windows_overlap(ego_entry, ego_exit, p_entry, p_exit):
                if not has_higher_row_cz(self.vehicle_id, edge, is_left_turn, ego_entry, pid, p_edge, p_left, p_entry):
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
        return 11.5, "PROCEED", "COOP_CLEAR_PROCEED"


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(conn: socket.socket) -> Dict[str, Any]:
    hdr = _recv_exact(conn, 4)
    (length,) = struct.unpack(">I", hdr)
    payload = _recv_exact(conn, length)
    return json.loads(payload.decode("utf-8"))


def send_msg(conn: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)


class DistVehHost:
    def __init__(
        self,
        host_id: str,
        listen_ip: str,
        rx_port: int,
        rpc_port: int,
        gw_ip: str,
        gw_port: int,
        specs: List[Dict[str, Any]],
        mode: str,
        log_dir: Path,
    ) -> None:
        self.host_id = host_id
        self.gw_addr = (gw_ip, gw_port)
        self.nodes = {s["vehicle_id"]: HostVehicleNode(s, mode) for s in specs}
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.tx_fp = (self.log_dir / f"tx_{host_id}.jsonl").open("w", encoding="utf-8")
        self.rx_fp = (self.log_dir / f"rx_{host_id}.jsonl").open("w", encoding="utf-8")

        self.rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rx_sock.bind((listen_ip, rx_port))
        self.rx_sock.settimeout(0.2)
        self.tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.rpc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rpc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rpc_sock.bind((listen_ip, rpc_port))
        self.rpc_sock.listen(4)

        self.rx_queue: deque[Dict[str, Any]] = deque()
        self.rx_queue_depth_max = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.cur_sim_ms = 0

    def _rx_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, _ = self.rx_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            with self.lock:
                self.rx_queue.append(pkt)
                if len(self.rx_queue) > self.rx_queue_depth_max:
                    self.rx_queue_depth_max = len(self.rx_queue)

    def _drain_rx(self, sim_ms: int) -> None:
        with self.lock:
            batch = list(self.rx_queue)
            self.rx_queue.clear()
        for pkt in batch:
            pkt_id = str(pkt.get("packet_id", ""))
            for node in self.nodes.values():
                status = node.on_rx_intent(pkt, sim_ms)
                if status == "STALE_DROPPED":
                    self.rx_fp.write(json.dumps({
                        "sim_ms": sim_ms, "vehicle_id": node.vehicle_id, "packet_id": pkt_id, "status": status
                    }) + "\n")

    def run(self) -> None:
        t_rx = threading.Thread(target=self._rx_loop, daemon=True)
        t_rx.start()
        try:
            while not self.stop_event.is_set():
                conn, _ = self.rpc_sock.accept()
                with conn:
                    while not self.stop_event.is_set():
                        try:
                            req = recv_msg(conn)
                        except ConnectionError:
                            break
                        op = req.get("op")
                        if op == "STEP_BATCH":
                            sim_ms = int(req["sim_ms"])
                            restore_ms = int(req.get("restore_ms", 7500))
                            fault_enabled = bool(req.get("fault_enabled", False))
                            leader_ids = set(req.get("leader_ids", []))
                            inject_vid = str(req.get("inject_unsafe_vid", ""))
                            self.cur_sim_ms = sim_ms
                            self._drain_rx(sim_ms)

                            cmds: Dict[str, Any] = {}
                            for vst in req["vehicles"]:
                                vid = vst["vehicle_id"]
                                node = self.nodes[vid]
                                if fault_enabled and 5500 <= sim_ms < 7500:
                                    node.partition_affected = True
                                if sim_ms >= restore_ms and vst["approaching"]:
                                    node.still_approaching_at_restore = True
                                pkt = node.maybe_build_intent(
                                    sim_ms, vst["speed_mps"], vst["d_to_cz_m"], vst["approaching"], vst["edge"], vst["target_cz"], bool(vst.get("is_left_turn", False))
                                )
                                if pkt is not None:
                                    self.tx_sock.sendto(json.dumps(pkt).encode("utf-8"), self.gw_addr)
                                    self.tx_fp.write(json.dumps({
                                        "sim_ms": sim_ms, "vehicle_id": vid, "packet_id": pkt["packet_id"]
                                    }) + "\n")
                                cmd_v, action, reason = node.step_decide(
                                    sim_ms,
                                    vst["speed_mps"],
                                    vst["d_to_cz_m"],
                                    vst["approaching"],
                                    vst["edge"],
                                    vst["target_cz"],
                                    bool(vst.get("is_left_turn", False)),
                                    vst["visible_peers"],
                                    restore_ms,
                                    leader_ids,
                                    inject_unsafe=(vid == inject_vid),
                                )
                                cmds[vid] = {"cmd_v": cmd_v, "action": action, "reason": reason}
                            send_msg(conn, {"ok": True, "cmds": cmds})
                        elif op == "GET_SUMMARY":
                            nodes_out = {}
                            for vid, n in self.nodes.items():
                                nodes_out[vid] = {
                                    "silent": n.silent,
                                    "partition_affected": n.partition_affected,
                                    "degraded_before_restore": n.degraded_before_restore,
                                    "still_approaching_at_restore": n.still_approaching_at_restore,
                                    "intent_ready_ms": n.intent_ready_ms,
                                    "coop_recovered_ms": n.coop_recovered_ms,
                                    "last_blocked_ms": n.last_blocked_ms,
                                    "stale_dropped": n.stale_dropped,
                                    "stale_overwrites": n.stale_overwrites,
                                    "expired_rx": n.expired_rx,
                                    "tx_count": n.tx_count,
                                }
                            send_msg(conn, {
                                "host_id": self.host_id,
                                "rx_queue_depth_max": self.rx_queue_depth_max,
                                "cpu_time_s": round(time.process_time(), 3),
                                "nodes": nodes_out,
                            })
                        elif op == "SHUTDOWN":
                            send_msg(conn, {"ok": True})
                            self.stop_event.set()
                            break
        finally:
            self.rx_sock.close()
            self.tx_sock.close()
            self.rpc_sock.close()
            self.tx_fp.flush()
            self.tx_fp.close()
            self.rx_fp.flush()
            self.rx_fp.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-id", required=True)
    ap.add_argument("--listen-ip", default="127.0.0.1")
    ap.add_argument("--rx-port", type=int, required=True)
    ap.add_argument("--rpc-port", type=int, required=True)
    ap.add_argument("--gw-ip", default="127.0.0.1")
    ap.add_argument("--gw-port", type=int, required=True)
    ap.add_argument("--specs-json", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--log-dir", required=True)
    args = ap.parse_args()

    all_specs = json.loads(Path(args.specs_json).read_text(encoding="utf-8"))
    my_specs = [s for s in all_specs if s["host_id"] == args.host_id]
    worker = DistVehHost(
        host_id=args.host_id,
        listen_ip=args.listen_ip,
        rx_port=args.rx_port,
        rpc_port=args.rpc_port,
        gw_ip=args.gw_ip,
        gw_port=args.gw_port,
        specs=my_specs,
        mode=args.mode,
        log_dir=Path(args.log_dir),
    )
    worker.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
