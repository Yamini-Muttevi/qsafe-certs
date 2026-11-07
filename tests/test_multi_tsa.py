"""Several independent timestamp authorities: a stolen key or a dishonest TSA
must not be enough to backdate a forged certificate."""
from datetime import date

import pytest

from qsafe import crypto
from qsafe.certificate import Certificate, Issuer, KeyDirectory, SignatureEntry
from qsafe.evidence import Archive, EvidenceLink, EvidenceRecord, TimestampAuthority
from qsafe.policy import TrustPolicy
from qsafe.verifier import verify_certificate

HB = crypto.hash_based_algorithm()  # SLH-DSA if it works here, else SPHINCS+

D2026, D2040, D2045 = date(2026, 6, 1), date(2040, 1, 1), date(2045, 6, 1)
NAMES = ["National TSA", "Academic Consortium TSA", "Independent Auditor TSA"]


@pytest.fixture
def world():
    d, p = KeyDirectory(), TrustPolicy(tsa_threshold=2)
    uni = Issuer("Uni", ["ECDSA-P256", "ML-DSA-65"], d)
    tsas = [TimestampAuthority(n, "ML-DSA-65", d) for n in NAMES]
    return d, p, uni, tsas


def forge(uni) -> Certificate:
    """Attacker has broken ECDSA and signs a fake degree backdated to 2026."""
    c = Certificate("F1", "Uni", "2026-06-01", {"name": "Fraud"})
    k = uni.keys["ECDSA-P256"]
    c.signatures.append(SignatureEntry(k.algorithm, k.key_id, "2026-06-01", crypto.sign(k, c.body())))
    return c


def evidence_by(tsas, cert, on) -> EvidenceRecord:
    a = Archive()
    a.add_batch([cert], tsas, on)
    return a.records[cert.certificate_id]


def test_single_trusted_authority_can_backdate_a_forgery(world):
    """Documents the weakness that motivates k-of-n: with threshold 1, one compromised TSA is enough."""
    d, p, uni, tsas = world
    p.tsa_threshold = 1
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    forged = forge(uni)
    assert verify_certificate(forged, evidence_by(tsas[0], forged, D2026), d, p, D2045).genuine


def test_one_compromised_authority_cannot_backdate_with_threshold_two(world):
    d, p, uni, tsas = world
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    forged = forge(uni)
    r = verify_certificate(forged, evidence_by(tsas[0], forged, D2026), d, p, D2045)
    assert not r.genuine
    assert any("only 1 of the 2 required" in x for x in r.reasons)


def test_one_authority_with_two_keys_counts_once(world):
    d, p, uni, tsas = world
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    second_key = TimestampAuthority(NAMES[0], "ML-DSA-65", d)  # same organisation, extra key
    forged = forge(uni)
    assert not verify_certificate(forged, evidence_by([tsas[0], second_key], forged, D2026), d, p, D2045).genuine


def test_impersonating_another_authority_fails(world):
    """A compromised TSA labels its own signature with another authority's name."""
    d, p, uni, tsas = world
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    forged = forge(uni)
    rec = evidence_by(tsas[0], forged, D2026)
    ts = rec.links[0].timestamp
    fake = ts.signatures[0].__class__(NAMES[1], ts.signatures[0].algorithm, ts.signatures[0].key_id,
                                      ts.signatures[0].signature)
    ts.signatures.append(fake)
    assert not verify_certificate(forged, rec, d, p, D2045).genuine


def test_genuine_certificate_accepted_with_two_or_three_authorities(world):
    d, p, uni, tsas = world
    cert = uni.issue("C1", {"name": "Student"}, D2026)
    assert verify_certificate(cert, evidence_by(tsas, cert, D2026), d, p, D2026).genuine
    assert verify_certificate(cert, evidence_by(tsas[:2], cert, D2026), d, p, D2026).genuine


def test_two_of_three_survives_after_algorithm_break_with_renewal(world):
    d, p, uni, tsas = world
    cert = uni.issue("C1", {"name": "Student"}, D2026)
    a = Archive()
    a.add_batch([cert], tsas, D2026)
    a.renew([TimestampAuthority(n, HB, d) for n in NAMES], D2040, "SHA3-512")
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    p.mark_broken("ML-DSA-65", date(2050, 1, 1))
    assert verify_certificate(cert, a.records["C1"], d, p, date(2051, 1, 1)).genuine


def test_renewal_by_too_few_authorities_is_rejected(world):
    d, p, uni, tsas = world
    cert = uni.issue("C1", {"name": "Student"}, D2026)
    a = Archive()
    a.add_batch([cert], tsas, D2026)
    a.renew([TimestampAuthority(NAMES[0], HB, d)], D2040, "SHA3-512")  # only one renewed
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    p.mark_broken("ML-DSA-65", date(2050, 1, 1))
    assert not verify_certificate(cert, a.records["C1"], d, p, date(2051, 1, 1)).genuine


def test_threshold_limit_two_colluding_authorities_succeed(world):
    """Honest limit of the design: if k authorities collude, they can still backdate."""
    d, p, uni, tsas = world
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    forged = forge(uni)
    assert verify_certificate(forged, evidence_by(tsas[:2], forged, D2026), d, p, D2045).genuine
