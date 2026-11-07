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

# Friendly name -> alternative liboqs NAMES FOR THE SAME ALGORITHM, never a different one.
# SLH-DSA (FIPS 205) and SPHINCS+ (its pre-standard version) are NOT interchangeable:
# pure SLH-DSA prefixes every message with a context, so neither verifies the other's
# signatures. They are therefore separate algorithms with separate names, and the code
# never substitutes one for the other.
_PQC_SIG_NAMES = {
    "ML-DSA-65": ["ML-DSA-65"],
    "SLH-DSA-SHA2-128s": ["SLH_DSA_PURE_SHA2_128S", "SLH-DSA-SHA2-128s"],      # FIPS 205
    "SPHINCS+-SHA2-128s-simple": ["SPHINCS+-SHA2-128s-simple"],               # pre-standard
    "ML-DSA-87": ["ML-DSA-87"],                                              # last-resort renewal
}
# Hash-based algorithm used for renewals, in order of preference.
HASH_BASED_PREFERENCE = ["SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple"]
CLASSICAL_SIGS = {"ECDSA-P256"}


_RESOLVED: dict[str, str] = {}
_UNAVAILABLE: dict[str, str] = {}


class AlgorithmUnavailable(RuntimeError):
    """No working implementation of exactly this algorithm exists in this liboqs build."""


def _resolve_oqs_sig(name: str) -> str:
    """Pick the first liboqs implementation OF THIS SAME ALGORITHM that passes a sign/verify self-test.

    Some implementations misbehave on some platforms (e.g. a Windows build where SLH-DSA
    signs but never verifies). If none works, raise AlgorithmUnavailable: never fall back
    to a different algorithm under the same name.
    """
    if name in _RESOLVED:
        return _RESOLVED[name]
    if name in _UNAVAILABLE:
        raise AlgorithmUnavailable(_UNAVAILABLE[name])
    if name not in _PQC_SIG_NAMES:
        raise ValueError(f"Unknown algorithm {name}")
    enabled = set(oqs.get_enabled_sig_mechanisms())
    tried = []
    for candidate in _PQC_SIG_NAMES[name]:
        if candidate not in enabled:
            tried.append(f"{candidate} (not in this build)")
            continue
        try:
            s = oqs.Signature(candidate)
            pk = s.generate_keypair()
            sig = s.sign(b"self-test")
            with oqs.Signature(candidate) as v:
                if v.verify(b"self-test", sig, pk):
                    _RESOLVED[name] = candidate
                    return candidate
            tried.append(f"{candidate} (signs but fails to verify)")
        except Exception as e:  # noqa: BLE001
            tried.append(f"{candidate} (error: {e})")
    _UNAVAILABLE[name] = (f"No working implementation of {name} in this liboqs build; tried: "
                          f"{'; '.join(tried)}. No other algorithm is substituted.")
    raise AlgorithmUnavailable(_UNAVAILABLE[name])


def is_available(name: str) -> bool:
    if name in CLASSICAL_SIGS:
        return True
    try:
        _resolve_oqs_sig(name)
        return True
    except AlgorithmUnavailable:
        return False


def available_signature_algorithms() -> list[str]:
    """Algorithms with a working implementation on this machine."""
    return [a for a in supported_signature_algorithms() if is_available(a)]


RENEWAL_FALLBACK = "ML-DSA-87"


def renewal_algorithm() -> tuple[str, str | None]:
    """The algorithm to renew evidence with, and a warning if it is a fallback.

    Prefers a hash-based signature (SLH-DSA, else SPHINCS+), which rests on different
    assumptions from lattice-based ML-DSA. If neither works in this build (e.g. liboqs
    0.16.0 on Windows/MSVC, where SLH-DSA fails to verify and SPHINCS+ was removed),
    falls back to ML-DSA-87 under its own name and says so: renewals still work, but
    without the diversity of a second family of assumptions.
    """
    try:
        return hash_based_algorithm(), None
    except AlgorithmUnavailable:
        if not is_available(RENEWAL_FALLBACK):
            raise AlgorithmUnavailable("No algorithm available for renewals in this liboqs build.")
        return RENEWAL_FALLBACK, ("No working hash-based signature in this liboqs build; renewing with "
                                  f"{RENEWAL_FALLBACK} instead, which loses diversity from lattice assumptions.")


def hash_based_algorithm() -> str:
    """The hash-based algorithm to renew with: SLH-DSA if it works here, else SPHINCS+ (under its own name)."""
    for name in HASH_BASED_PREFERENCE:
        if is_available(name):
            return name
    raise AlgorithmUnavailable("No working hash-based signature (SLH-DSA or SPHINCS+) in this liboqs build.")


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
