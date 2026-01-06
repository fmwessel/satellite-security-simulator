from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto, protocol


@dataclass
class NodeStats:
    sent: int = 0
    received: int = 0
    accepted: int = 0
    auth_fail: int = 0
    replay: int = 0
    bad_format: int = 0


class GroundStation:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.session_key: Optional[bytes] = None
        self.seq_up = 0
        self.last_seq_down = -1
        self.stats = NodeStats()

    def make_key_exchange(self, sat_pub: RSAPublicKey, now_ms: int) -> bytes:
        wrapped, k = crypto.wrap_session_key(sat_pub)
        self.session_key = k
        pkt = protocol.make_key_exchange_packet(
            direction="UPLINK",
            session_id=self.session_id,
            seq=self._next_seq_up(),
            timestamp_ms=now_ms,
            proto_nonce=self._proto_nonce(),
            wrapped_key=wrapped,
        )
        self.stats.sent += 1
        return protocol.encode(pkt)

    def make_command(self, command: dict, now_ms: int) -> bytes:
        assert self.session_key is not None, "Session not established"
        plaintext = json.dumps(command, separators=(",", ":"), sort_keys=True).encode("utf-8")

        
        pkt_stub = protocol.Packet(
            version=1,
            msg_type="DATA",
            direction="UPLINK",
            session_id=self.session_id,
            seq=self._next_seq_up(),
            timestamp_ms=now_ms,
            proto_nonce=self._proto_nonce(),
        )
        aad = protocol.header_bytes(pkt_stub)
        ciphertext, tag, nonce = crypto.encrypt_aead(self.session_key, plaintext, aad)

        pkt = protocol.make_data_packet(
            direction="UPLINK",
            session_id=self.session_id,
            seq=pkt_stub.seq,
            timestamp_ms=now_ms,
            proto_nonce=pkt_stub.proto_nonce,
            crypto_nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        self.stats.sent += 1
        return protocol.encode(pkt)

    def on_receive(self, packet_bytes: bytes, now_ms: int) -> List[bytes]:
        self.stats.received += 1
        try:
            pkt = protocol.decode(packet_bytes)
        except Exception:
            self.stats.bad_format += 1
            return []

        
        if pkt.direction == "DOWNLINK":
            if pkt.seq <= self.last_seq_down:
                self.stats.replay += 1
                return []
        
        if pkt.msg_type == "DATA":
            if self.session_key is None:
                return []
            try:
                aad = protocol.header_bytes(pkt)
                crypto_nonce, ciphertext, tag = protocol.get_data_fields(pkt)
                plaintext = crypto.decrypt_aead(self.session_key, ciphertext, tag, crypto_nonce, aad)
            except Exception:
                self.stats.auth_fail += 1
                return []

            self.last_seq_down = max(self.last_seq_down, pkt.seq)
            self.stats.accepted += 1

            
            try:
                msg = json.loads(plaintext.decode("utf-8"))
                kind = msg.get("kind", "unknown")
             
            except Exception:
                pass

        return []

    def _next_seq_up(self) -> int:
        self.seq_up += 1
        return self.seq_up

    @staticmethod
    def _proto_nonce() -> str:
        return uuid.uuid4().hex[:12]


class Satellite:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.keys = crypto.generate_rsa_keypair()
        self.session_key: Optional[bytes] = None
        self.seq_down = 0
        self.last_seq_up = -1
        self.stats = NodeStats()

    @property
    def public_key(self) -> RSAPublicKey:
        return self.keys.public_key

    def on_receive(self, packet_bytes: bytes, now_ms: int) -> List[bytes]:
        self.stats.received += 1
        try:
            pkt = protocol.decode(packet_bytes)
        except Exception:
            self.stats.bad_format += 1
            return []

        
        if pkt.direction == "UPLINK":
            if pkt.seq <= self.last_seq_up:
                self.stats.replay += 1
                return []

        if pkt.msg_type == "KEY_EXCHANGE":
            try:
                wrapped = protocol.get_wrapped_key(pkt)
                self.session_key = crypto.unwrap_session_key(self.keys.private_key, wrapped)
                self.last_seq_up = max(self.last_seq_up, pkt.seq)
                self.stats.accepted += 1
            except Exception:
                self.stats.auth_fail += 1
            return []

        if pkt.msg_type == "DATA":
            if self.session_key is None:
                return []
            try:
                aad = protocol.header_bytes(pkt)
                crypto_nonce, ciphertext, tag = protocol.get_data_fields(pkt)
                plaintext = crypto.decrypt_aead(self.session_key, ciphertext, tag, crypto_nonce, aad)
            except Exception:
                self.stats.auth_fail += 1
                return []

            
            self.last_seq_up = max(self.last_seq_up, pkt.seq)
            self.stats.accepted += 1

            
            try:
                cmd = json.loads(plaintext.decode("utf-8"))
            except Exception:
                cmd = {"kind": "unknown"}

            telemetry = {
                "kind": "telemetry",
                "ack_for": cmd.get("kind", "command"),
                "t_ms": now_ms,
                "status": "OK",
            }
            return [self._make_downlink_data(telemetry, now_ms)]

        return []

    def _make_downlink_data(self, telemetry: dict, now_ms: int) -> bytes:
        assert self.session_key is not None
        plaintext = json.dumps(telemetry, separators=(",", ":"), sort_keys=True).encode("utf-8")

        pkt_stub = protocol.Packet(
            version=1,
            msg_type="DATA",
            direction="DOWNLINK",
            session_id=self.session_id,
            seq=self._next_seq_down(),
            timestamp_ms=now_ms,
            proto_nonce=uuid.uuid4().hex[:12],
        )
        aad = protocol.header_bytes(pkt_stub)
        ciphertext, tag, nonce = crypto.encrypt_aead(self.session_key, plaintext, aad)

        pkt = protocol.make_data_packet(
            direction="DOWNLINK",
            session_id=self.session_id,
            seq=pkt_stub.seq,
            timestamp_ms=now_ms,
            proto_nonce=pkt_stub.proto_nonce,
            crypto_nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        self.stats.sent += 1
        return protocol.encode(pkt)

    def _next_seq_down(self) -> int:
        self.seq_down += 1
        return self.seq_down

