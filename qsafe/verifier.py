"""End-to-end certificate verification.

A certificate is GENUINE if at least one of its signatures:
  * is mathematically valid under a key registered to the named issuer, and
  * is either still secure today, OR the evidence chain proves the
    certificate existed before that algorithm was broken.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from . import crypto
from .certificate import Certificate, KeyDirectory
from .evidence import EvidenceRecord, verify_evidence
from .policy import TrustPolicy


@dataclass
class Result:
    genuine: bool
    reasons: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        head = "GENUINE" if self.genuine else "REJECTED"
        return head + "".join(f"\n    - {r}" for r in self.reasons)


def verify_certificate(cert: Certificate, record: EvidenceRecord | None, directory: KeyDirectory,
                       policy: TrustPolicy, today: date) -> Result:
    reasons: list[str] = []
    proven_on, ev_notes = (None, ["no evidence record"]) if record is None else \
        verify_evidence(cert, record, directory, policy, today)
    reasons.append(f"evidence: existence proven on {proven_on}" if proven_on else f"evidence: {ev_notes[-1]}")

    body = cert.body()
    # Prefer signatures that are still secure today; fall back to evidence for broken ones.
    for s in sorted(cert.signatures, key=lambda s: not policy.trusted_at(s.algorithm, today)):
        entry = directory.lookup(s.key_id)
        if entry is None or entry.role != "issuer" or entry.owner != cert.issuer or entry.algorithm != s.algorithm:
            reasons.append(f"{s.algorithm}: key not registered to {cert.issuer}")
            continue
        if not crypto.verify(s.algorithm, entry.public_key, body, s.signature):
            reasons.append(f"{s.algorithm}: signature does not match content (tampered?)")
            continue
        if policy.trusted_at(s.algorithm, today):
            reasons.append(f"{s.algorithm}: valid and still secure today")
            return Result(True, reasons)
        broken = policy.broken_at[s.algorithm]
        if proven_on and proven_on < broken:
            reasons.append(f"{s.algorithm}: broken on {broken}, but evidence proves signature existed on {proven_on}")
            return Result(True, reasons)
        reasons.append(f"{s.algorithm}: broken on {broken} and no earlier evidence; could be a forgery")
    return Result(False, reasons)
