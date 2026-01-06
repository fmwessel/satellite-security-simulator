from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class LinkConfig:
    latency_ms: int
    jitter_ms: int
    loss_rate: float


class Link:
    """
    Simulated link: adds latency+jitter, and drops packets with probability loss_rate.
    Stores bytes; does not parse or inspect content.
    """

    def __init__(self, cfg: LinkConfig, name: str):
        self.cfg = cfg
        self.name = name
        self._queue: List[Tuple[int, bytes]] = []  
        self.dropped = 0
        self.sent = 0
        self.delivered = 0

    def send(self, payload: bytes, now_ms: int) -> None:
        self.sent += 1
        if random.random() < self.cfg.loss_rate:
            self.dropped += 1
            return

        jitter = random.randint(-self.cfg.jitter_ms, self.cfg.jitter_ms) if self.cfg.jitter_ms > 0 else 0
        deliver_time = max(now_ms, now_ms + self.cfg.latency_ms + jitter)
        self._queue.append((deliver_time, payload))

    def recv_ready(self, now_ms: int) -> List[bytes]:
        ready: List[bytes] = []
        still: List[Tuple[int, bytes]] = []
        for t, payload in self._queue:
            if t <= now_ms:
                ready.append(payload)
            else:
                still.append((t, payload))
        self._queue = still
        self.delivered += len(ready)
        return ready

