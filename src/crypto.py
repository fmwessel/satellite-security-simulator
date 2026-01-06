from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class RSAKeypair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


def generate_rsa_keypair() -> RSAKeypair:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return RSAKeypair(private_key=priv, public_key=priv.public_key())


def wrap_session_key(pub: rsa.RSAPublicKey) -> Tuple[bytes, bytes]:
    """
    Returns (wrapped_key, session_key).
    session_key is 32 bytes (AES-256).
    """
    session_key = os.urandom(32)
    wrapped = pub.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped, session_key


def unwrap_session_key(priv: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    return priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes, bytes]:
    """
    AES-GCM: returns (ciphertext, tag, nonce)
    cryptography's AESGCM.encrypt returns ciphertext||tag, so we split.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return ciphertext, tag, nonce


def decrypt_aead(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    ct_and_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_and_tag, aad)

