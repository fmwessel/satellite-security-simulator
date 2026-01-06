from __future__ import annotations

import argparse
import json
import uuid

from .attacker import Attacker, AttackerConfig
from .link import Link, LinkConfig
from .nodes import GroundStation, Satellite


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="configs/scenario.json")
    args = ap.parse_args()

    cfg = load_json(args.scenario)

    sim_cfg = cfg["sim"]
    tick_ms = int(sim_cfg["tick_ms"])
    duration_ms = int(sim_cfg["duration_ms"])

    uplink = Link(LinkConfig(**cfg["uplink"]), name="uplink")
    downlink = Link(LinkConfig(**cfg["downlink"]), name="downlink")

    attacker = Attacker(AttackerConfig(**cfg["attacker"]))

    session_id = uuid.uuid4().hex[:10]
    gs = GroundStation(session_id=session_id)
    sat = Satellite(session_id=session_id)

    now = 0

    
    uplink.send(gs.make_key_exchange(sat.public_key, now_ms=now), now_ms=now)

    
    traffic = cfg["traffic"]
    num_commands = int(traffic["num_commands"])
    interval = int(traffic["command_interval_ms"])
    next_command_at = 500  # wait a bit after start
    commands_sent = 0

    
    while now <= duration_ms:
        
        if commands_sent < num_commands and now >= next_command_at and gs.session_key is not None:
            cmd = {"kind": "command", "id": commands_sent + 1, "action": "PING"}
            uplink.send(gs.make_command(cmd, now_ms=now), now_ms=now)
            commands_sent += 1
            next_command_at += interval

        
        for pkt_bytes in uplink.recv_ready(now):
            for out_bytes in attacker.intercept(pkt_bytes, direction="UPLINK", now_ms=now):
                responses = sat.on_receive(out_bytes, now_ms=now)
                for resp_bytes in responses:
                    downlink.send(resp_bytes, now_ms=now)

        
        for pkt_bytes in downlink.recv_ready(now):
            for out_bytes in attacker.intercept(pkt_bytes, direction="DOWNLINK", now_ms=now):
                gs.on_receive(out_bytes, now_ms=now)

        now += tick_ms

    
    print("\n=== Simulation Summary ===")
    print(f"session_id: {session_id}")
    print(f"attacker_mode: {cfg['attacker']['mode']}")
    print("\n-- Link stats --")
    print(f"uplink: sent={uplink.sent} delivered={uplink.delivered} dropped={uplink.dropped}")
    print(f"downlink: sent={downlink.sent} delivered={downlink.delivered} dropped={downlink.dropped}")

    print("\n-- Node stats --")
    print(f"GS: sent={gs.stats.sent} recv={gs.stats.received} accepted={gs.stats.accepted} "
          f"auth_fail={gs.stats.auth_fail} replay={gs.stats.replay} bad_format={gs.stats.bad_format}")
    print(f"SAT: sent={sat.stats.sent} recv={sat.stats.received} accepted={sat.stats.accepted} "
          f"auth_fail={sat.stats.auth_fail} replay={sat.stats.replay} bad_format={sat.stats.bad_format}")

    print("\nTip: set attacker.mode to 'replay' or 'tamper' in configs/scenario.json and rerun.\n")


if __name__ == "__main__":
    main()

