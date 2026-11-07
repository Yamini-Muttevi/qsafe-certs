"""One shared 'world' for the web app: a university, a national archive with
timestamp authorities, a public key directory, and a trust policy.

Keeping this outside the UI means it can be tested without Streamlit.
Everything lives in memory; restarting the app starts a fresh world.
"""
from __future__ import annotations

from datetime import date

from . import crypto
from .certificate import Certificate, Issuer, KeyDirectory, SignatureEntry
from .evidence import Archive, EvidenceRecord, TimestampAuthority, verify_evidence
from .policy import TrustPolicy
from .verifier import Result, verify_certificate

UNIVERSITY = "Deccan Institute of Technology"
TSA_NAMES = ["National Timestamp Service", "Academic Consortium TSA", "Independent Auditor TSA"]
# The hash-based renewal algorithm is whichever genuinely works here: SLH-DSA (FIPS 205) if
# available, otherwise SPHINCS+ under its own name (see crypto.hash_based_algorithm).
HASH_BASED, RENEWAL_WARNING = crypto.renewal_algorithm()
TSA_ALGORITHMS = ["ML-DSA-65", HASH_BASED]
HASH_ALGORITHMS = ["SHA3-256", "SHA3-512"]


class Registry:
    def __init__(self) -> None:
        self.directory = KeyDirectory()
        self.policy = TrustPolicy()
        self.issuer = Issuer(UNIVERSITY, ["ECDSA-P256", "ML-DSA-65"], self.directory)
        # Three independent authorities, each holding one key per algorithm.
        self.tsas = {alg: {name: TimestampAuthority(name, alg, self.directory) for name in TSA_NAMES}
                     for alg in TSA_ALGORITHMS}
        self.policy.tsa_threshold = 2  # any 2 of the 3 authorities must agree
        self.archive = Archive()
        self.issued: dict[str, Certificate] = {}
        self.renewals: list[tuple[date, str, str, list[str], int]] = []  # (date, algorithm, hash, authorities, records)
        self._counter = 0

    # --------------------------------------------------------------- issue ---
    def issue(self, name: str, degree: str, cgpa: str, year: int, on: date) -> Certificate:
        self._counter += 1
        cert = self.issuer.issue(f"DIT-{year}-{self._counter:04d}",
                                 {"name": name, "degree": degree, "cgpa": cgpa, "year": year}, on)
        self.archive.add_batch([cert], list(self.tsas["ML-DSA-65"].values()), on)
        self.issued[cert.certificate_id] = cert
        return cert

    # -------------------------------------------------------------- renew ---
    def latest_evidence_date(self) -> date | None:
        dates = [date.fromisoformat(r.links[-1].timestamp.time) for r in self.archive.records.values() if r.links]
        return max(dates) if dates else None

    def renew(self, tsa_algorithm: str, hash_alg: str, on: date, authorities: list[str] | None = None) -> int:
        if authorities is None:
            authorities = TSA_NAMES
        if not authorities:
            raise ValueError("Choose at least one timestamp authority.")
        latest = self.latest_evidence_date()
        if latest and on <= latest:
            raise ValueError(f"Renewal must be dated after the latest timestamp ({latest}).")
        tsas = [self.tsas[tsa_algorithm][a] for a in authorities]
        # Validate every record's existing evidence before extending it (see Archive.renew).
        n = self.archive.renew(tsas, on, hash_alg=hash_alg, directory=self.directory, policy=self.policy)
        self.renewals.append((on, tsa_algorithm, hash_alg, list(authorities), n))
        return n

    @property
    def last_refused(self) -> dict[str, str]:
        """Records the last renewal refused because their evidence was already invalid."""
        return getattr(self.archive, "last_refused", {})

    def set_threshold(self, k: int) -> None:
        self.policy.tsa_threshold = max(1, min(k, len(TSA_NAMES)))

    # ------------------------------------------------------------- policy ---
    def set_broken(self, algorithm: str, when: date | None) -> None:
        if when is None:
            self.policy.broken_at.pop(algorithm, None)
        else:
            self.policy.mark_broken(algorithm, when)

    # -------------------------------------------------------------- forge ---
    def forge(self, name: str, cgpa: str, claimed_date: date) -> Certificate:
        """An attacker who has derived the university's ECDSA key (e.g. via Shor's
        algorithm) signs a fake degree and backdates it. It has no evidence record."""
        k = self.issuer.keys["ECDSA-P256"]
        cert = Certificate(f"DIT-{claimed_date.year}-9{self._counter:03d}", UNIVERSITY, claimed_date.isoformat(),
                           {"name": name, "degree": "B.Tech CSE", "cgpa": cgpa, "year": claimed_date.year})
        cert.signatures.append(SignatureEntry(k.algorithm, k.key_id, claimed_date.isoformat(),
                                              crypto.sign(k, cert.body())))
        return cert

    def forge_with_authorities(self, name: str, cgpa: str, claimed_date: date,
                               compromised: list[str]) -> tuple[Certificate, EvidenceRecord]:
        """As forge(), but the attacker also controls some timestamp authorities' ML-DSA keys
        (stolen, or the authorities are dishonest) and gets a backdated timestamp from them."""
        cert = self.forge(name, cgpa, claimed_date)
        fake = Archive()
        fake.add_batch([cert], [self.tsas["ML-DSA-65"][a] for a in compromised], claimed_date)
        return cert, fake.records[cert.certificate_id]

    # ------------------------------------------------------------- verify ---
    def record_for(self, cert: Certificate) -> EvidenceRecord | None:
        """The archive only vouches for a record if it holds exactly these bytes."""
        stored = self.archive.certs.get(cert.certificate_id)
        if stored is None:
            return None
        return self.archive.records[cert.certificate_id]

    def verify(self, cert: Certificate, as_of: date,
               record: EvidenceRecord | None = None) -> tuple[Result, list[str]]:
        """Uses `record` if given (evidence presented with the certificate), else the archive's."""
        record = record or self.record_for(cert)
        result = verify_certificate(cert, record, self.directory, self.policy, as_of)
        notes = verify_evidence(cert, record, self.directory, self.policy, as_of)[1] if record else []
        return result, notes
