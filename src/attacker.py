from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import protocol


@dataclass
class AttackerConfig:
    mode: str                 
    replay_after_ms: int = 1200
    tamper_rate: float = 1.0  

class Attacker:
    """
    Operates on packet BYTES. Has no keys. Can replay/tamper/mitm-relay.
    """

    def __init__(self, cfg: AttackerConfig):
        self.cfg = cfg
        self._recorded: Optional[Tuple[int, bytes, str]] = None  
        self._replayed = False

    def intercept(self, packet_bytes: bytes, direction: str, now_ms: int) -> List[bytes]:
        mode = self.cfg.mode.lower()

        if mode == "none":
            return [packet_bytes]

        if mode == "replay":
            
            if self._recorded is None:
                try:
                    pkt = protocol.decode(packet_bytes)
                    if pkt.msg_type == "DATA":
                        self._recorded = (now_ms, packet_bytes, direction)
                except Exception:
                    pass
                return [packet_bytes]

            rec_t, rec_bytes, rec_dir = self._recorded
            out = [packet_bytes]
            if (not self._replayed) and (now_ms - rec_t >= self.cfg.replay_after_ms):
                
                if direction == rec_dir:
                    out.append(rec_bytes)
                    self._replayed = True
            return out

        if mode == "tamper":
            return [self._maybe_tamper(packet_bytes)]

        if mode == "mitm":
            
            try:
                pkt = protocol.decode(packet_bytes)
                if pkt.direction == "UPLINK" and pkt.msg_type == "DATA":
                    if random.random() < self.cfg.tamper_rate:
                        return [self._tamper_one_byte(packet_bytes)]
            except Exception:
                
                if random.random() < 0.1:
                    return [self._tamper_one_byte(packet_bytes)]
            return [packet_bytes]

        # Unknown mode -> pass through
        return [packet_bytes]

    def _maybe_tamper(self, packet_bytes: bytes) -> bytes:
        if random.random() < self.cfg.tamper_rate:
            return self._tamper_one_byte(packet_bytes)
        return packet_bytes

    @staticmethod
    def _tamper_one_byte(packet_bytes: bytes) -> bytes:
        if not packet_bytes:
            return packet_bytes
        b = bytearray(packet_bytes)
        idx = random.randrange(0, len(b))
        b[idx] ^= 0x01  
        return bytes(b)

