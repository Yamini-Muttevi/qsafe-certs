"""Renewal validates existing evidence first (the condition in Geihs, Demirel & Buchmann 2015)."""
from datetime import date

import pytest

from qsafe import crypto
from qsafe.certificate import Issuer, KeyDirectory
from qsafe.evidence import Archive, TimestampAuthority
from qsafe.policy import TrustPolicy
from qsafe.registry import Registry
from qsafe.verifier import verify_certificate

HB = crypto.hash_based_algorithm()  # SLH-DSA if it works here, else SPHINCS+

NAMES = ["A", "B", "C"]


@pytest.fixture
def world():
    d, p = KeyDirectory(), TrustPolicy(tsa_threshold=2)
    uni = Issuer("Uni", ["ECDSA-P256", "ML-DSA-65"], d)
    old = [TimestampAuthority(n, "ML-DSA-65", d) for n in NAMES]
    new = [TimestampAuthority(n, HB, d) for n in NAMES]
    certs = [uni.issue(f"C{i}", {"name": f"Student {i}"}, date(2026, 6, 1)) for i in range(3)]
    a = Archive()
    a.add_batch(certs, old, date(2026, 6, 1))
    return d, p, certs, a, new


def test_valid_records_are_renewed(world):
    d, p, certs, a, new = world
    assert a.renew(new, date(2040, 1, 15), "SHA3-512", directory=d, policy=p) == 3
    assert a.last_refused == {}
    assert all(len(r.links) == 2 for r in a.records.values())


def test_renewal_after_break_is_refused_and_not_extended(world):
    d, p, certs, a, new = world
    p.mark_broken("ML-DSA-65", date(2035, 1, 1))  # broke before the 2040 renewal
    assert a.renew(new, date(2040, 1, 15), "SHA3-512", directory=d, policy=p) == 0
    assert set(a.last_refused) == {"C0", "C1", "C2"}
    assert "broken before it was renewed" in a.last_refused["C0"]
    assert all(len(r.links) == 1 for r in a.records.values())  # nothing was extended


def test_damaged_record_is_refused_others_renewed(world):
    d, p, certs, a, new = world
    sig = a.records["C1"].links[0].timestamp.signatures  # shared timestamp object: copy before damaging C1
    import copy
    a.records["C1"].links[0] = copy.deepcopy(a.records["C1"].links[0])
    for s in a.records["C1"].links[0].timestamp.signatures:
        s.signature = bytes(len(s.signature))  # wipe C1's timestamp signatures
    assert a.renew(new, date(2040, 1, 15), "SHA3-512", directory=d, policy=p) == 2
    assert list(a.last_refused) == ["C1"]
    assert len(a.records["C0"].links) == 2 and len(a.records["C1"].links) == 1
    assert len(sig) == 3  # the other records' shared timestamp is untouched


def test_renewed_records_still_survive_later_breaks(world):
    d, p, certs, a, new = world
    a.renew(new, date(2040, 1, 15), "SHA3-512", directory=d, policy=p)
    p.mark_broken("ECDSA-P256", date(2045, 1, 1))
    p.mark_broken("ML-DSA-65", date(2050, 1, 1))
    assert verify_certificate(certs[0], a.records["C0"], d, p, date(2051, 1, 1)).genuine


def test_registry_reports_refused_records():
    reg = Registry()
    reg.issue("A", "B.Tech CSE", "8.00", 2026, date(2026, 6, 1))
    reg.set_broken("ML-DSA-65", date(2035, 1, 1))
    assert reg.renew(HB, "SHA3-512", date(2040, 1, 15)) == 0
    assert len(reg.last_refused) == 1
