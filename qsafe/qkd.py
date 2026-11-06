"""Simulated BB84 quantum key distribution + hybrid key transport.

This is a classical simulation of the BB84 protocol's statistics, NOT real
quantum hardware. It reproduces the property that matters: an eavesdropper
who measures photons disturbs them, which raises the error rate (QBER) and
reveals her presence.

The hybrid channel combines the QKD key with an ML-KEM shared secret, so
key transfer between issuing offices stays secure unless BOTH fail.
"""
from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto

QBER_THRESHOLD = 0.11  # standard BB84 security bound


@dataclass
class BB84Result:
    photons_sent: int
    sifted_bits: int
    qber: float
    eavesdropper_detected: bool
    key: bytes | None  # 32-byte key after privacy amplification, or None if aborted


def run_bb84(n_photons: int = 4096, eavesdrop_fraction: float = 0.0,
             channel_error: float = 0.0, sample_fraction: float = 0.25,
             rng: random.Random | None = None) -> BB84Result:
    rng = rng or random.SystemRandom()
    alice_bits = [rng.getrandbits(1) for _ in range(n_photons)]
    alice_bases = [rng.getrandbits(1) for _ in range(n_photons)]  # 0 = +, 1 = x
    bob_bases = [rng.getrandbits(1) for _ in range(n_photons)]
    bob_bits = []
    for bit, a_basis, b_basis in zip(alice_bits, alice_bases, bob_bases):
        photon_bit, photon_basis = bit, a_basis
        if rng.random() < eavesdrop_fraction:  # Eve: intercept, measure, resend
            e_basis = rng.getrandbits(1)
            if e_basis != photon_basis:
                photon_bit = rng.getrandbits(1)
            photon_basis = e_basis
        measured = photon_bit if b_basis == photon_basis else rng.getrandbits(1)
        if rng.random() < channel_error:
            measured ^= 1
        bob_bits.append(measured)

    # Sifting: keep positions where Alice and Bob used the same basis (public comparison of bases).
    keep = [i for i in range(n_photons) if alice_bases[i] == bob_bases[i]]
    a_sift = [alice_bits[i] for i in keep]
    b_sift = [bob_bits[i] for i in keep]

    # Publicly compare a random sample to estimate the error rate, then discard it.
    sample = set(rng.sample(range(len(keep)), int(len(keep) * sample_fraction)))
    errors = sum(a_sift[i] != b_sift[i] for i in sample)
    qber = errors / max(1, len(sample))
    if qber > QBER_THRESHOLD:
        return BB84Result(n_photons, len(keep), qber, True, None)

    a_key = [b for i, b in enumerate(a_sift) if i not in sample]
    b_key = [b for i, b in enumerate(b_sift) if i not in sample]
    # (A real system runs error correction such as Cascade here.)
    if a_key != b_key:
        return BB84Result(n_photons, len(keep), qber, False, None)
    # Privacy amplification: compress to 256 bits.
    key = hashlib.sha3_256(bytes(a_key)).digest()
    return BB84Result(n_photons, len(keep), qber, False, key)


# ------------------------------------------------------- hybrid channel ---
def hybrid_key(qkd_key: bytes, kem_secret: bytes) -> bytes:
    """Combine both secrets; an attacker must recover BOTH to learn the result."""
    return HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None,
                info=b"qsafe-certs hybrid QKD+ML-KEM v1").derive(qkd_key + kem_secret)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def establish_hybrid_channel(eavesdrop_fraction: float = 0.0, bb84: BB84Result | None = None):
    """Office A <-> Office B. Returns (key_A, key_B, bb84_result).

    Pass an existing BB84 result to reuse it; otherwise a new exchange is run.
    """
    bb84 = bb84 or run_bb84(eavesdrop_fraction=eavesdrop_fraction)
    if bb84.key is None:
        return None, None, bb84
    kem_b, pk_b = crypto.kem_keypair()                  # Office B publishes ML-KEM key
    ct, secret_a = crypto.kem_encapsulate(pk_b)        # Office A encapsulates
    secret_b = crypto.kem_decapsulate(kem_b, ct)       # Office B decapsulates
    return hybrid_key(bb84.key, secret_a), hybrid_key(bb84.key, secret_b), bb84
