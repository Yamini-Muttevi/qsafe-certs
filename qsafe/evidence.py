"""Long-term evidence chain (inspired by RFC 4998 Evidence Record Syntax).

1. Fingerprints of many certificates are put into a Merkle tree. Several
   independent Timestamp Authorities (TSAs) each sign the same root and date
   -> an *archive timestamp* carrying several signatures.
2. Before the TSAs' algorithm weakens, every record is *renewed*: a new tree
   is built over hash(certificate) + hash(previous evidence), and TSAs using
   a stronger algorithm (and optionally a stronger hash) sign it.
3. A verifier walks the chain. Each link needs valid signatures from at least
   `policy.tsa_threshold` DIFFERENT authorities, using algorithms that were
   still secure when the next link protected it. If every link passes, the
   first timestamp proves the certificate existed on that date.

Requiring k-of-n authorities means one stolen TSA key, or one dishonest TSA,
cannot backdate a forged certificate. Renewal only ever touches hashes, so
the party renewing the archive cannot change any certificate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date

from . import crypto
from .certificate import Certificate, KeyDirectory, canonical
from .policy import TrustPolicy

HASHES = {"SHA3-256": hashlib.sha3_256, "SHA3-512": hashlib.sha3_512}


def H(alg: str, data: bytes) -> bytes:
    return HASHES[alg](data).digest()


# ---------------------------------------------------------------- Merkle ---
def _leaf(alg: str, data: bytes) -> bytes:
    return H(alg, b"\x00" + data)


def _node(alg: str, left: bytes, right: bytes) -> bytes:
    return H(alg, b"\x01" + left + right)


def merkle_root_and_proofs(alg: str, leaves: list[bytes]) -> tuple[bytes, list[list[tuple[str, bytes]]]]:
    """Returns the root and, for each leaf, its proof as [(side, sibling), ...]."""
    level = [_leaf(alg, x) for x in leaves]
    proofs: list[list[tuple[str, bytes]]] = [[] for _ in leaves]
    positions = list(range(len(leaves)))
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        for i, pos in enumerate(positions):
            sib = pos ^ 1
            proofs[i].append(("L" if sib < pos else "R", level[sib]))
            positions[i] = pos // 2
        level = [_node(alg, level[j], level[j + 1]) for j in range(0, len(level), 2)]
    return level[0], proofs


def merkle_verify(alg: str, data: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    h = _leaf(alg, data)
    for side, sib in proof:
        h = _node(alg, sib, h) if side == "L" else _node(alg, h, sib)
    return h == root


# ------------------------------------------------------------- timestamps ---
@dataclass
class TSASignature:
    tsa: str
    algorithm: str
    key_id: str
    signature: bytes


@dataclass
class ArchiveTimestamp:
    hash_alg: str
    root: bytes
    time: str  # ISO date
    signatures: list[TSASignature] = field(default_factory=list)

    def message(self) -> bytes:
        """What every authority signs. Identical for all of them, so they vouch for the same thing."""
        return canonical({"hash_alg": self.hash_alg, "root": self.root.hex(), "time": self.time})

    @property
    def authorities(self) -> list[str]:
        return [s.tsa for s in self.signatures]

    @property
    def algorithms(self) -> list[str]:
        return sorted({s.algorithm for s in self.signatures})


class TimestampAuthority:
    def __init__(self, name: str, algorithm: str, directory: KeyDirectory) -> None:
        self.name = name
        self.kp = crypto.generate_keypair(algorithm)
        directory.register(name, "tsa", self.kp)

    def sign(self, ts: ArchiveTimestamp) -> TSASignature:
        return TSASignature(self.name, self.kp.algorithm, self.kp.key_id, crypto.sign(self.kp, ts.message()))

    def stamp(self, hash_alg: str, root: bytes, on: date) -> ArchiveTimestamp:
        return joint_stamp([self], hash_alg, root, on)


def joint_stamp(tsas: list[TimestampAuthority], hash_alg: str, root: bytes, on: date) -> ArchiveTimestamp:
    """Every authority signs the same root and date."""
    ts = ArchiveTimestamp(hash_alg, root, on.isoformat())
    ts.signatures = [t.sign(ts) for t in tsas]
    return ts


def _as_list(tsas) -> list[TimestampAuthority]:
    return [tsas] if isinstance(tsas, TimestampAuthority) else list(tsas)


@dataclass
class EvidenceLink:
    timestamp: ArchiveTimestamp
    proof: list[tuple[str, bytes]]

    def to_dict(self) -> dict:
        t = self.timestamp
        return {
            "hash_alg": t.hash_alg, "root": t.root.hex(), "time": t.time,
            "signatures": [{"tsa": s.tsa, "algorithm": s.algorithm, "key_id": s.key_id,
                            "signature": s.signature.hex()} for s in t.signatures],
            "proof": [[side, h.hex()] for side, h in self.proof],
        }


@dataclass
class EvidenceRecord:
    links: list[EvidenceLink] = field(default_factory=list)

    def serialize_prefix(self, n: int) -> bytes:
        return canonical([link.to_dict() for link in self.links[:n]])


def leaf_input(hash_alg: str, cert_bytes: bytes, record: EvidenceRecord, index: int) -> bytes:
    """What link `index` commits to: the certificate, plus all earlier links."""
    if index == 0:
        return H(hash_alg, cert_bytes)
    return H(hash_alg, cert_bytes) + H(hash_alg, record.serialize_prefix(index))


# ---------------------------------------------------------------- archive ---
class Archive:
    """Holds certificates and keeps their evidence records alive.

    The archive is only storage: the evidence's strength comes from the
    authorities' signatures, so a dishonest archive cannot fake a record.
    """

    def __init__(self) -> None:
        self.certs: dict[str, bytes] = {}
        self.records: dict[str, EvidenceRecord] = {}

    def _stamp_all(self, ids: list[str], tsas, hash_alg: str, on: date) -> None:
        inputs = [leaf_input(hash_alg, self.certs[i], self.records[i], len(self.records[i].links)) for i in ids]
        root, proofs = merkle_root_and_proofs(hash_alg, inputs)
        ts = joint_stamp(_as_list(tsas), hash_alg, root, on)
        for cid, proof in zip(ids, proofs):
            self.records[cid].links.append(EvidenceLink(ts, proof))

    def add_batch(self, certs: list[Certificate], tsas, on: date, hash_alg: str = "SHA3-256") -> None:
        """`tsas` is one TimestampAuthority or a list of them."""
        for c in certs:
            self.certs[c.certificate_id] = c.to_bytes()
            self.records[c.certificate_id] = EvidenceRecord()
        self._stamp_all([c.certificate_id for c in certs], tsas, hash_alg, on)

    def renew(self, tsas, on: date, hash_alg: str = "SHA3-256",
              directory: KeyDirectory | None = None, policy: TrustPolicy | None = None) -> int:
        """Re-protect records with new authorities / hash. One joint timestamp for the whole archive.

        With `directory` and `policy`, the archive first VALIDATES each record's existing chain as of
        the renewal date, under the same rules a verifier uses, and renews only the records that pass.
        This matches the condition under which Geihs, Demirel and Buchmann (2015) prove ERS secure:
        the archive validates preceding timestamps at renewal. Refused records are listed in
        `self.last_refused` (certificate id -> reason) and are not extended.
        Without them, every record is renewed unchecked (kept for experiments and old callers).
        """
        self.last_refused: dict[str, str] = {}
        ids = list(self.certs)
        if directory is not None and policy is not None:
            valid = []
            for cid in ids:
                cert = Certificate.from_dict(json.loads(self.certs[cid]))
                proven, notes = verify_evidence(cert, self.records[cid], directory, policy, on)
                if proven is None:
                    self.last_refused[cid] = notes[-1] if notes else "invalid evidence"
                else:
                    valid.append(cid)
            ids = valid
        if ids:
            self._stamp_all(ids, tsas, hash_alg, on)
        return len(ids)


# ----------------------------------------------------------- verification ---
def verify_evidence(cert: Certificate, record: EvidenceRecord, directory: KeyDirectory,
                    policy: TrustPolicy, today: date) -> tuple[date | None, list[str]]:
    """Returns (date the certificate is proven to have existed, notes). None = no valid proof."""
    notes: list[str] = []
    cert_bytes = cert.to_bytes()
    if not record.links:
        return None, ["no evidence record"]
    k = policy.tsa_threshold
    for i, link in enumerate(record.links):
        ts = link.timestamp
        if i and ts.time <= record.links[i - 1].timestamp.time:
            return None, notes + [f"link {i}: timestamps out of order"]
        data = leaf_input(ts.hash_alg, cert_bytes, record, i)
        if not merkle_verify(ts.hash_alg, data, link.proof, ts.root):
            return None, notes + [f"link {i}: certificate not in timestamped tree"]
        # The link must still have been secure when the NEXT link protected it,
        # or (for the last link) must be secure today.
        checked_on = date.fromisoformat(record.links[i + 1].timestamp.time) if i + 1 < len(record.links) else today
        if not policy.trusted_at(ts.hash_alg, checked_on):
            return None, notes + [f"link {i}: {ts.hash_alg} was broken before it was renewed"]

        valid: set[str] = set()
        broken: set[str] = set()
        for s in ts.signatures:
            entry = directory.lookup(s.key_id)
            if entry is None or entry.role != "tsa" or entry.owner != s.tsa or entry.algorithm != s.algorithm:
                continue
            if not crypto.verify(entry.algorithm, entry.public_key, ts.message(), s.signature):
                continue
            if not policy.trusted_at(entry.algorithm, checked_on):
                broken.add(entry.algorithm)
                continue
            valid.add(entry.owner)  # count each authority once, however many keys it holds
        if len(valid) < k:
            why = f"; {', '.join(sorted(broken))} was broken before it was renewed" if broken else ""
            return None, notes + [f"link {i}: only {len(valid)} of the {k} required timestamp authorities valid{why}"]
        notes.append(f"link {i}: {ts.time} by {len(valid)} authorities ({', '.join(ts.algorithms)}, "
                     f"{ts.hash_alg}) ok")
    return date.fromisoformat(record.links[0].timestamp.time), notes
