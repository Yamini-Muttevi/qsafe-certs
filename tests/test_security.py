import copy
import random
from datetime import date

import pytest

from qsafe import crypto
from qsafe.certificate import Certificate, Issuer, KeyDirectory, SignatureEntry
from qsafe.evidence import Archive, TimestampAuthority, merkle_root_and_proofs, merkle_verify
from qsafe.policy import TrustPolicy
from qsafe.qkd import QBER_THRESHOLD, run_bb84
from qsafe.verifier import verify_certificate

D2026, D2040 = date(2026, 6, 1), date(2040, 1, 1)


@pytest.fixture
def world():
    directory, policy = KeyDirectory(), TrustPolicy()
    uni = Issuer("Test University", ["ECDSA-P256", "ML-DSA-65"], directory)
    tsa_a = TimestampAuthority("TSA-A", "ML-DSA-65", directory)
    tsa_b = TimestampAuthority("TSA-B", "SLH-DSA-SHA2-128s", directory)
    certs = [uni.issue(f"C{i}", {"name": f"Student {i}", "cgpa": "8.0"}, D2026) for i in range(5)]
    archive = Archive()
    archive.add_batch(certs, tsa_a, D2026)
    return directory, policy, uni, tsa_a, tsa_b, certs, archive


def verify(world, cert, today, record="auto"):
    directory, policy, *_, archive = world
    rec = archive.records.get(cert.certificate_id) if record == "auto" else record
    return verify_certificate(cert, rec, directory, policy, today).genuine


@pytest.mark.parametrize("alg", crypto.supported_signature_algorithms())
def test_sign_verify_each_algorithm(alg):
    kp = crypto.generate_keypair(alg)
    sig = crypto.sign(kp, b"hello")
    assert crypto.verify(alg, kp.public_key, b"hello", sig)
    assert not crypto.verify(alg, kp.public_key, b"hellO", sig)


@pytest.mark.parametrize("n", [1, 2, 3, 7, 16])
def test_merkle_proofs(n):
    leaves = [bytes([i]) * 8 for i in range(n)]
    root, proofs = merkle_root_and_proofs("SHA3-256", leaves)
    for leaf, proof in zip(leaves, proofs):
        assert merkle_verify("SHA3-256", leaf, proof, root)
        assert not merkle_verify("SHA3-256", leaf + b"x", proof, root)


def test_genuine_certificate_verifies(world):
    assert verify(world, world[5][0], date(2026, 7, 1))


def test_any_tampering_rejected(world):
    cert = copy.deepcopy(world[5][0])
    cert.content["cgpa"] = "9.9"
    assert not verify(world, cert, date(2026, 7, 1))


def test_unregistered_issuer_rejected(world):
    directory, policy, *_ = world
    impostor = Issuer("Fake University", ["ML-DSA-65"], KeyDirectory())  # not in the real directory
    cert = impostor.issue("X1", {"name": "Someone"}, D2026)
    assert not verify(world, cert, date(2026, 7, 1), record=None)


def test_survives_classical_break_and_blocks_backdated_forgery(world):
    directory, policy, uni, tsa_a, tsa_b, certs, archive = world
    policy.mark_broken("ECDSA-P256", date(2045, 1, 1))
    today = date(2045, 6, 1)
    assert verify(world, certs[0], today)

    forged = Certificate("F1", uni.name, "2026-06-01", {"name": "Fraud"})
    k = uni.keys["ECDSA-P256"]
    forged.signatures.append(SignatureEntry(k.algorithm, k.key_id, "2026-06-01", crypto.sign(k, forged.body())))
    assert not verify(world, forged, today, record=None)

    late = Archive()
    late.add_batch([forged], tsa_b, today)
    assert not verify(world, forged, today, record=late.records["F1"])


def test_renewal_keeps_trust_after_all_signature_algorithms_break(world):
    directory, policy, uni, tsa_a, tsa_b, certs, archive = world
    lazy = Archive()
    lazy.add_batch(certs, tsa_a, D2026)
    archive.renew(tsa_b, D2040, hash_alg="SHA3-512")
    policy.mark_broken("ECDSA-P256", date(2045, 1, 1))
    policy.mark_broken("ML-DSA-65", date(2050, 1, 1))
    today = date(2051, 1, 1)
    assert verify(world, certs[0], today)
    assert not verify(world, certs[0], today, record=lazy.records["C0"])


def test_renewal_too_late_is_rejected(world):
    directory, policy, uni, tsa_a, tsa_b, certs, archive = world
    policy.mark_broken("ECDSA-P256", date(2045, 1, 1))
    policy.mark_broken("ML-DSA-65", date(2050, 1, 1))
    archive.renew(tsa_b, date(2050, 6, 1))  # after ML-DSA already broke
    assert not verify(world, certs[0], date(2051, 1, 1))


def test_renewal_does_not_change_certificates(world):
    *_, tsa_b, certs, archive = world
    before = dict(archive.certs)
    archive.renew(tsa_b, D2040)
    assert archive.certs == before


def test_bb84_detects_eavesdropper():
    rng = random.Random(7)
    assert run_bb84(rng=rng).qber == 0
    spied = run_bb84(eavesdrop_fraction=1.0, rng=rng)
    assert spied.qber > QBER_THRESHOLD and spied.key is None
