from __future__ import annotations

import base64
import json
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class Packet:
    # Header (plaintext)
    version: int
    msg_type: str        
    direction: str       
    session_id: str
    seq: int
    timestamp_ms: int
    proto_nonce: str     
    
    wrapped_key_b64: Optional[str] = None  # KEY_EXCHANGE only

    
    crypto_nonce_b64: Optional[str] = None
    ciphertext_b64: Optional[str] = None
    tag_b64: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def encode(pkt: Packet) -> bytes:
    """
    Serialize packet to bytes. JSON is easiest for debugging.
    """
    return json.dumps(pkt.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode(b: bytes) -> Packet:
    d = json.loads(b.decode("utf-8"))
    return Packet(**d)


def header_bytes(pkt: Packet) -> bytes:
    """
    Canonical bytes for header fields only. This is used as AEAD AAD so that
    tampering with seq/msg_type/etc causes auth failure.
    """
    header = {
        "version": pkt.version,
        "msg_type": pkt.msg_type,
        "direction": pkt.direction,
        "session_id": pkt.session_id,
        "seq": pkt.seq,
        "timestamp_ms": pkt.timestamp_ms,
        "proto_nonce": pkt.proto_nonce,
    }
    return json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_key_exchange_packet(
    *,
    direction: str,
    session_id: str,
    seq: int,
    timestamp_ms: int,
    proto_nonce: str,
    wrapped_key: bytes,
) -> Packet:
    return Packet(
        version=1,
        msg_type="KEY_EXCHANGE",
        direction=direction,
        session_id=session_id,
        seq=seq,
        timestamp_ms=timestamp_ms,
        proto_nonce=proto_nonce,
        wrapped_key_b64=_b64e(wrapped_key),
    )


def make_data_packet(
    *,
    direction: str,
    session_id: str,
    seq: int,
    timestamp_ms: int,
    proto_nonce: str,
    crypto_nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> Packet:
    return Packet(
        version=1,
        msg_type="DATA",
        direction=direction,
        session_id=session_id,
        seq=seq,
        timestamp_ms=timestamp_ms,
        proto_nonce=proto_nonce,
        crypto_nonce_b64=_b64e(crypto_nonce),
        ciphertext_b64=_b64e(ciphertext),
        tag_b64=_b64e(tag),
    )


def get_wrapped_key(pkt: Packet) -> bytes:
    assert pkt.wrapped_key_b64 is not None
    return _b64d(pkt.wrapped_key_b64)


def get_data_fields(pkt: Packet) -> tuple[bytes, bytes, bytes]:
    assert pkt.crypto_nonce_b64 and pkt.ciphertext_b64 and pkt.tag_b64
    return _b64d(pkt.crypto_nonce_b64), _b64d(pkt.ciphertext_b64), _b64d(pkt.tag_b64)

