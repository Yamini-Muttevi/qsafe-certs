"""Crypto-agile academic certificate.

A certificate is its content plus a LIST of signatures, each labelled with
the algorithm, the signing key and the date. Nothing assumes a single
algorithm, so new signatures can be added as algorithms age.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date

from . import crypto


def canonical(obj) -> bytes:
    """Deterministic JSON encoding, so the same data always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------ directory ---
@dataclass
class DirectoryEntry:
    owner: str
    role: str  # "issuer" or "tsa"
    algorithm: str
    public_key: bytes


class KeyDirectory:
    """Public register of trusted issuer and timestamping keys.

    In a national deployment this would be published by the regulator
    (e.g. UGC / NAD) so that anyone can look up a university's keys.
    """

    def __init__(self) -> None:
        self._entries: dict[str, DirectoryEntry] = {}

    def register(self, owner: str, role: str, kp: crypto.KeyPair) -> None:
        self._entries[kp.key_id] = DirectoryEntry(owner, role, kp.algorithm, kp.public_key)

    def lookup(self, key_id: str) -> DirectoryEntry | None:
        return self._entries.get(key_id)


# ---------------------------------------------------------- certificate ---
@dataclass
class SignatureEntry:
    algorithm: str
    key_id: str
    signed_on: str  # ISO date
    signature: bytes

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signed_on": self.signed_on,
            "signature": self.signature.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "SignatureEntry":
        return SignatureEntry(d["algorithm"], d["key_id"], d["signed_on"], bytes.fromhex(d["signature"]))


@dataclass
class Certificate:
    certificate_id: str
    issuer: str
    issued_on: str  # ISO date
    content: dict
    signatures: list[SignatureEntry] = field(default_factory=list)

    def body(self) -> bytes:
        """The bytes every signature covers (content, never the signatures)."""
        return canonical({
            "certificate_id": self.certificate_id,
            "issuer": self.issuer,
            "issued_on": self.issued_on,
            "content": self.content,
        })

    def to_dict(self) -> dict:
        return {
            "certificate_id": self.certificate_id,
            "issuer": self.issuer,
            "issued_on": self.issued_on,
            "content": self.content,
            "signatures": [s.to_dict() for s in self.signatures],
        }

    def to_bytes(self) -> bytes:
        """Full signed certificate; this is what the evidence chain protects."""
        return canonical(self.to_dict())

    def fingerprint(self) -> str:
        return hashlib.sha3_256(self.to_bytes()).hexdigest()

    @staticmethod
    def from_dict(d: dict) -> "Certificate":
        return Certificate(
            d["certificate_id"], d["issuer"], d["issued_on"], d["content"],
            [SignatureEntry.from_dict(s) for s in d["signatures"]],
        )


class Issuer:
    """A university holding one key per algorithm it signs with."""

    def __init__(self, name: str, algorithms: list[str], directory: KeyDirectory) -> None:
        self.name = name
        self.keys = {alg: crypto.generate_keypair(alg) for alg in algorithms}
        for kp in self.keys.values():
            directory.register(name, "issuer", kp)

    def issue(self, certificate_id: str, content: dict, on: date) -> Certificate:
        cert = Certificate(certificate_id, self.name, on.isoformat(), content)
        body = cert.body()
        for alg, kp in self.keys.items():
            cert.signatures.append(SignatureEntry(alg, kp.key_id, on.isoformat(), crypto.sign(kp, body)))
        return cert
