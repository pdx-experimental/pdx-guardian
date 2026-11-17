#!/usr/bin/env python3
"""Generate 3-intersection arterial SUMO network (j1=Zone A, j2=Zone B, j3=Zone C)."""

from __future__ import annotations

import subprocess
from pathlib import Path


NODES_XML = """<nodes>
    <node id="w_ext" x="-200.0" y="0.0" type="priority"/>
    <node id="j1"    x="0.0"    y="0.0" type="priority"/>
    <node id="j2"    x="200.0"  y="0.0" type="priority"/>
    <node id="j3"    x="400.0"  y="0.0" type="priority"/>
    <node id="e_ext" x="600.0"  y="0.0" type="priority"/>

    <node id="j1_n"  x="0.0"    y="200.0"  type="priority"/>
    <node id="j1_s"  x="0.0"    y="-200.0" type="priority"/>
    <node id="j2_n"  x="200.0"  y="200.0"  type="priority"/>
    <node id="j2_s"  x="200.0"  y="-200.0" type="priority"/>
    <node id="j3_n"  x="400.0"  y="200.0"  type="priority"/>
    <node id="j3_s"  x="400.0"  y="-200.0" type="priority"/>
</nodes>
"""

EDGES_XML = """<edges>
    <!-- East-West arterial (priority 2) -->
    <edge id="w_to_j1"  from="w_ext" to="j1"    numLanes="1" speed="13.89" priority="2"/>
    <edge id="j1_to_w"  from="j1"    to="w_ext" numLanes="1" speed="13.89" priority="2"/>
    <edge id="j1_to_j2" from="j1"    to="j2"    numLanes="1" speed="13.89" priority="2"/>
    <edge id="j2_to_j1" from="j2"    to="j1"    numLanes="1" speed="13.89" priority="2"/>
    <edge id="j2_to_j3" from="j2"    to="j3"    numLanes="1" speed="13.89" priority="2"/>
    <edge id="j3_to_j2" from="j3"    to="j2"    numLanes="1" speed="13.89" priority="2"/>
    <edge id="j3_to_e"  from="j3"    to="e_ext" numLanes="1" speed="13.89" priority="2"/>
    <edge id="e_to_j3"  from="e_ext" to="j3"    numLanes="1" speed="13.89" priority="2"/>

    <!-- j1 North-South cross street (priority 1) -->
    <edge id="j1_n_in"  from="j1_n" to="j1"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j1_n_out" from="j1"   to="j1_n" numLanes="1" speed="13.89" priority="1"/>
    <edge id="j1_s_in"  from="j1_s" to="j1"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j1_s_out" from="j1"   to="j1_s" numLanes="1" speed="13.89" priority="1"/>

    <!-- j2 North-South cross street (priority 1) -->
    <edge id="j2_n_in"  from="j2_n" to="j2"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j2_n_out" from="j2"   to="j2_n" numLanes="1" speed="13.89" priority="1"/>
    <edge id="j2_s_in"  from="j2_s" to="j2"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j2_s_out" from="j2"   to="j2_s" numLanes="1" speed="13.89" priority="1"/>

    <!-- j3 North-South cross street (priority 1) -->
    <edge id="j3_n_in"  from="j3_n" to="j3"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j3_n_out" from="j3"   to="j3_n" numLanes="1" speed="13.89" priority="1"/>
    <edge id="j3_s_in"  from="j3_s" to="j3"   numLanes="1" speed="13.89" priority="1"/>
    <edge id="j3_s_out" from="j3"   to="j3_s" numLanes="1" speed="13.89" priority="1"/>
</edges>
"""


def main() -> int:
    net_dir = Path(__file__).resolve().parent / "sumo_net"
    net_dir.mkdir(parents=True, exist_ok=True)
    nod = net_dir / "arterial_3j.nod.xml"
    edg = net_dir / "arterial_3j.edg.xml"
    out = net_dir / "arterial_3j.net.xml"
    nod.write_text(NODES_XML, encoding="utf-8")
    edg.write_text(EDGES_XML, encoding="utf-8")
    subprocess.run(
        [
            "netconvert",
            "--node-files", str(nod),
            "--edge-files", str(edg),
            "--output-file", str(out),
            "--no-turnarounds", "true",
        ],
        check=True,
    )
    print(f"Generated {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
