"""Signature and key-exchange primitives.

Post-quantum algorithms come from Open Quantum Safe (liboqs); the classical
baseline (ECDSA P-256) comes from the `cryptography` package. Every signer
exposes the same small interface so the rest of the system is crypto-agile:
it never hard-codes an algorithm.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Friendly name -> candidate liboqs identifiers (names differ across versions).
_PQC_SIG_NAMES = {
    "ML-DSA-65": ["ML-DSA-65"],
    "SLH-DSA-SHA2-128s": [
        "SLH_DSA_PURE_SHA2_128S",
        "SLH-DSA-SHA2-128s",
        "SPHINCS+-SHA2-128s-simple",
    ],
}
CLASSICAL_SIGS = {"ECDSA-P256"}


_RESOLVED: dict[str, str] = {}


def _resolve_oqs_sig(name: str) -> str:
    """Pick the first liboqs implementation that passes a real sign/verify self-test.

    Some implementations misbehave on some platforms (e.g. a Windows build where
    one SLH-DSA variant signs but never verifies), so we test before trusting.
    """
    if name in _RESOLVED:
        return _RESOLVED[name]
    enabled = set(oqs.get_enabled_sig_mechanisms())
    for candidate in _PQC_SIG_NAMES[name]:
        if candidate not in enabled:
            continue
        try:
            s = oqs.Signature(candidate)
            pk = s.generate_keypair()
            sig = s.sign(b"self-test")
            with oqs.Signature(candidate) as v:
                if v.verify(b"self-test", sig, pk):
                    _RESOLVED[name] = candidate
                    return candidate
        except Exception:
            pass
    raise ValueError(f"No working liboqs implementation for {name}")


def resolved_implementations() -> dict[str, str]:
    """Which liboqs implementation each friendly name is using (for diagnostics)."""
    return dict(_RESOLVED)


def supported_signature_algorithms() -> list[str]:
    return sorted(CLASSICAL_SIGS | set(_PQC_SIG_NAMES))


def key_id(public_key: bytes) -> str:
    return hashlib.sha3_256(public_key).hexdigest()[:16]


@dataclass
class KeyPair:
    algorithm: str
    public_key: bytes
    _secret: object  # algorithm-specific private material

    @property
    def key_id(self) -> str:
        return key_id(self.public_key)


def generate_keypair(algorithm: str) -> KeyPair:
    if algorithm == "ECDSA-P256":
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        return KeyPair(algorithm, pk, sk)
    signer = oqs.Signature(_resolve_oqs_sig(algorithm))
    pk = signer.generate_keypair()
    return KeyPair(algorithm, pk, signer)


def sign(keypair: KeyPair, message: bytes) -> bytes:
    if keypair.algorithm == "ECDSA-P256":
        return keypair._secret.sign(message, ec.ECDSA(hashes.SHA256()))
    return keypair._secret.sign(message)


def verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    if algorithm == "ECDSA-P256":
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        try:
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    try:
        with oqs.Signature(_resolve_oqs_sig(algorithm)) as v:
            return v.verify(message, signature, public_key)
    except Exception:
        return False


# ---------------------------------------------------------------- ML-KEM ---
KEM_ALGORITHM = "ML-KEM-768"


def kem_keypair():
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    return kem, kem.generate_keypair()


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        return kem.encap_secret(public_key)


def kem_decapsulate(kem, ciphertext: bytes) -> bytes:
    return kem.decap_secret(ciphertext)
