#!/usr/bin/env python3
"""
Distributed Zone Gateway for DSX Air Multi-Intersection Fleet.
Routes UDP DrivingIntentV2 packets using intersection + adjacent-zone subscriptions,
injects Zone-A partition & delayed stale packet bursts, and logs TX/drop/replay
events with shared packet_id to gateway_fault_log.jsonl.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple


ADJACENT_ZONES = {
    "zone-a": {"zone-a", "zone-b"},
    "zone-b": {"zone-a", "zone-b", "zone-c"},
    "zone-c": {"zone-b", "zone-c"},
}

CZ_HOME_ZONE = {
    "j1": "zone-a",
    "j2": "zone-b",
    "j3": "zone-c",
}


class DistZoneGateway:
    def __init__(
        self,
        zone_id: str,
        listen_ip: str,
        udp_port: int,
        ctrl_port: int,
        host_endpoints: Dict[str, Tuple[str, int, str]],  # host_id -> (ip, rx_port, zone_id)
        fault_enabled: bool,
        log_dir: Path,
    ) -> None:
        self.zone_id = zone_id
        self.listen_ip = listen_ip
        self.udp_port = udp_port
        self.ctrl_port = ctrl_port
        self.host_endpoints = host_endpoints
        self.fault_enabled = fault_enabled
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_fp = (self.log_dir / f"gateway_{zone_id}.jsonl").open("w", encoding="utf-8")

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((listen_ip, udp_port))
        self.udp_sock.settimeout(0.2)

        self.ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ctrl_sock.bind((listen_ip, ctrl_port))
        self.ctrl_sock.settimeout(0.2)

        self.lock = threading.Lock()
        self.sim_ms = 0
        self.stop_event = threading.Event()
        self.tx_forwarded = 0
        self.rx_received = 0
        self.partition_drops = 0
        self.delayed_burst_sent = 0
        self.saved_replay_raw: bytes | None = None
        self.saved_replay_pkt_id: str = ""
        self.burst_released = False

    def _log(self, ev: Dict[str, Any]) -> None:
        self.log_fp.write(json.dumps(ev) + "\n")

    def _subscribed_hosts(self, src_zone: str, target_cz: str) -> List[Tuple[str, str, int]]:
        cz_zone = CZ_HOME_ZONE.get(target_cz, src_zone)
        allowed_zones = ADJACENT_ZONES.get(cz_zone, {cz_zone})
        out: List[Tuple[str, str, int]] = []
        for hid, (hip, hport, hzone) in self.host_endpoints.items():
            if hzone in allowed_zones:
                out.append((hid, hip, hport))
        return out

    def _udp_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, _ = self.udp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = json.loads(data.decode("utf-8"))
            except Exception:
                continue

            pkt_id = str(pkt.get("packet_id", ""))
            src_zone = str(pkt.get("zone_id", self.zone_id))
            target_cz = str(pkt.get("conflict_zone_id", "j1")).split("_")[0]

            with self.lock:
                cur_sim_ms = self.sim_ms
                self.rx_received += 1
                if self.fault_enabled and self.saved_replay_raw is None and 4500 <= cur_sim_ms < 5500 and src_zone == "zone-a":
                    self.saved_replay_raw = data
                    self.saved_replay_pkt_id = pkt_id

                for hid, hip, hport in self._subscribed_hosts(src_zone, target_cz):
                    dst_zone = self.host_endpoints[hid][2]
                    if self.fault_enabled and 5500 <= cur_sim_ms < 7500 and (src_zone == "zone-a" or dst_zone == "zone-a"):
                        self.partition_drops += 1
                        self._log({
                            "event": "GW_PARTITION_DROP",
                            "sim_ms": cur_sim_ms,
                            "packet_id": pkt_id,
                            "src_zone": src_zone,
                            "dst_host": hid,
                            "dst_zone": dst_zone,
                        })
                        continue
                    self.udp_sock.sendto(data, (hip, hport))
                    self.tx_forwarded += 1

    def _ctrl_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, addr = self.ctrl_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                req = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            cmd = req.get("cmd")
            if cmd == "SYNC_SIM_MS":
                new_ms = int(req.get("sim_ms", 0))
                with self.lock:
                    self.sim_ms = new_ms
                    if self.fault_enabled and new_ms >= 8200 and self.saved_replay_raw is not None and not self.burst_released:
                        self.burst_released = True
                        for hid, (hip, hport, hzone) in self.host_endpoints.items():
                            if hzone in {"zone-b", "zone-c"}:
                                self.udp_sock.sendto(self.saved_replay_raw, (hip, hport))
                                self.delayed_burst_sent += 1
                                self._log({
                                    "event": "GW_DELAYED_REPLAY",
                                    "sim_ms": new_ms,
                                    "packet_id": self.saved_replay_pkt_id,
                                    "dst_host": hid,
                                    "dst_zone": hzone,
                                })
                self.ctrl_sock.sendto(b'{"ok":true}', addr)
            elif cmd == "GET_STATS":
                with self.lock:
                    stats = {
                        "zone_id": self.zone_id,
                        "rx_received": self.rx_received,
                        "tx_forwarded": self.tx_forwarded,
                        "partition_drops": self.partition_drops,
                        "delayed_burst_sent": self.delayed_burst_sent,
                    }
                self.ctrl_sock.sendto(json.dumps(stats).encode("utf-8"), addr)
            elif cmd == "SHUTDOWN":
                self.ctrl_sock.sendto(b'{"ok":true}', addr)
                self.stop_event.set()
                break

    def run(self) -> None:
        t_udp = threading.Thread(target=self._udp_loop, daemon=True)
        t_ctrl = threading.Thread(target=self._ctrl_loop, daemon=True)
        t_udp.start()
        t_ctrl.start()
        while not self.stop_event.is_set():
            time.sleep(0.1)
        self.udp_sock.close()
        self.ctrl_sock.close()
        self.log_fp.flush()
        self.log_fp.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zone-id", required=True)
    ap.add_argument("--listen-ip", default="127.0.0.1")
    ap.add_argument("--udp-port", type=int, required=True)
    ap.add_argument("--ctrl-port", type=int, required=True)
    ap.add_argument("--hosts-json", required=True)
    ap.add_argument("--fault-enabled", action="store_true")
    ap.add_argument("--log-dir", required=True)
    args = ap.parse_args()

    hosts_raw = json.loads(Path(args.hosts_json).read_text(encoding="utf-8"))
    host_endpoints = {
        k: (v["ip"], int(v["rx_port"]), v["zone_id"])
        for k, v in hosts_raw.items()
    }
    gw = DistZoneGateway(
        zone_id=args.zone_id,
        listen_ip=args.listen_ip,
        udp_port=args.udp_port,
        ctrl_port=args.ctrl_port,
        host_endpoints=host_endpoints,
        fault_enabled=args.fault_enabled,
        log_dir=Path(args.log_dir),
    )
    gw.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
