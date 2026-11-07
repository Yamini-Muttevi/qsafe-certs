"""An algorithm name must always mean the same algorithm, on every machine.

SLH-DSA (FIPS 205) and SPHINCS+ are different algorithms: neither verifies the other's
signatures. A Windows build where SLH-DSA failed its self-test used to fall back to SPHINCS+
under the SLH-DSA name, so evidence renewed there would not verify on Linux.
"""
import pytest

from qsafe import crypto


@pytest.fixture(autouse=True)
def fresh_cache():
    saved = dict(crypto._RESOLVED), dict(crypto._UNAVAILABLE)
    crypto._RESOLVED.clear()
    crypto._UNAVAILABLE.clear()
    yield
    crypto._RESOLVED.clear(); crypto._RESOLVED.update(saved[0])
    crypto._UNAVAILABLE.clear(); crypto._UNAVAILABLE.update(saved[1])


def test_each_name_maps_to_one_algorithm_only():
    seen = {}
    for name, candidates in crypto._PQC_SIG_NAMES.items():
        for c in candidates:
            assert c not in seen, f"{c} listed under both {seen.get(c)} and {name}"
            seen[c] = name
    assert not any("SPHINCS" in c for c in crypto._PQC_SIG_NAMES["SLH-DSA-SHA2-128s"])


PAIRS = [(crypto.SLH_DSA, crypto.SPHINCS), (crypto.SLH_DSA, "SLH-DSA-SHAKE-128s"),
         ("SLH-DSA-SHAKE-128s", crypto.SPHINCS)]


@pytest.mark.parametrize("first,second", PAIRS)
def test_hash_based_algorithms_do_not_verify_each_other(first, second):
    if not (crypto.is_available(first) and crypto.is_available(second)):
        pytest.skip(f"needs working {first} and {second}")
    for signer, verifier in [(first, second), (second, first)]:
        kp = crypto.generate_keypair(signer)
        sig = crypto.sign(kp, b"message")
        assert crypto.verify(signer, kp.public_key, b"message", sig)
        assert not crypto.verify(verifier, kp.public_key, b"message", sig)


def _break(monkeypatch, is_broken):
    """Make every liboqs implementation whose name matches `is_broken` sign but fail to verify."""
    real = crypto.oqs.Signature

    class Broken:
        def __init__(self, name, *a, **k):
            self._s = real(name, *a, **k)
            self._broken = is_broken(name)
        def __getattr__(self, attr):
            return getattr(self._s, attr)
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self._s.free()
        def verify(self, *args):
            return False if self._broken else self._s.verify(*args)

    monkeypatch.setattr(crypto.oqs, "Signature", Broken)


def test_windows_msvc_bug_renews_with_slh_dsa_shake(monkeypatch):
    """liboqs issue #2516: with MSVC, SLH-DSA SHA-2 variants fail to verify; SHAKE variants work."""
    if not crypto.is_available("SLH-DSA-SHAKE-128s"):
        pytest.skip("needs SLH-DSA-SHAKE-128s")
    crypto._RESOLVED.clear(); crypto._UNAVAILABLE.clear()
    _break(monkeypatch, lambda n: "SLH" in n.upper() and "SHA2" in n.upper())
    assert not crypto.is_available("SLH-DSA-SHA2-128s")
    assert crypto.renewal_algorithm() == ("SLH-DSA-SHAKE-128s", None)


def test_broken_implementation_is_not_replaced_by_another_algorithm(monkeypatch):
    """Every SLH-DSA implementation fails its self-test (SHA-2 and SHAKE)."""
    _break(monkeypatch, lambda n: "SLH" in n.upper())
    with pytest.raises(crypto.AlgorithmUnavailable, match="No other algorithm is substituted"):
        crypto.generate_keypair("SLH-DSA-SHA2-128s")
    assert not crypto.is_available("SLH-DSA-SHA2-128s")
    # The renewal algorithm falls back honestly, under its own name: SPHINCS+ where it exists
    # (liboqs 0.15), otherwise ML-DSA-87 with a warning (liboqs 0.16 removed SPHINCS+).
    alg, warning = crypto.renewal_algorithm()
    if crypto.is_available("SPHINCS+-SHA2-128s-simple"):
        assert alg == "SPHINCS+-SHA2-128s-simple" and warning is None
    else:
        assert alg == "ML-DSA-87" and warning


def test_unknown_algorithm_is_rejected():
    with pytest.raises(ValueError):
        crypto.generate_keypair("NOT-AN-ALGORITHM")


def test_renewal_falls_back_to_ml_dsa_87_when_no_hash_based_algorithm(monkeypatch):
    """Simulate liboqs 0.16.0 on Windows: SLH-DSA fails to verify and SPHINCS+ is absent."""
    real_enabled = crypto.oqs.get_enabled_sig_mechanisms
    monkeypatch.setattr(crypto.oqs, "get_enabled_sig_mechanisms",
                        lambda: [m for m in real_enabled() if "SLH" not in m.upper() and "SPHINCS" not in m])
    with pytest.raises(crypto.AlgorithmUnavailable):
        crypto.hash_based_algorithm()
    alg, warning = crypto.renewal_algorithm()
    assert alg == "ML-DSA-87"
    assert warning and "loses diversity" in warning
