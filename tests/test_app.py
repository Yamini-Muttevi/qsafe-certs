import json
from datetime import date

import pytest
from streamlit.testing.v1 import AppTest

from qsafe import crypto
from qsafe.certificate import Certificate
from qsafe.registry import Registry

HB = crypto.hash_based_algorithm()  # SLH-DSA if it works here, else SPHINCS+


# ------------------------------------------------------------- registry ---
def test_registry_full_lifecycle():
    reg = Registry()
    cert = reg.issue("A. Kumar", "B.Tech CSE", "8.70", 2026, date(2026, 6, 1))
    assert reg.verify(cert, date(2026, 7, 1))[0].genuine

    reg.renew(HB, "SHA3-512", date(2040, 1, 15))
    reg.set_broken("ECDSA-P256", date(2045, 3, 1))
    reg.set_broken("ML-DSA-65", date(2052, 1, 1))
    assert reg.verify(cert, date(2052, 6, 1))[0].genuine

    forged = reg.forge("M. Fraud", "9.80", date(2026, 6, 1))
    assert not reg.verify(forged, date(2045, 6, 1))[0].genuine


def test_registry_rejects_tampered_upload_reusing_genuine_id():
    reg = Registry()
    cert = reg.issue("A. Kumar", "B.Tech CSE", "8.70", 2026, date(2026, 6, 1))
    d = cert.to_dict()
    d["content"]["cgpa"] = "9.90"
    assert not reg.verify(Certificate.from_dict(d), date(2026, 7, 1))[0].genuine


def test_registry_renewal_must_move_forward():
    reg = Registry()
    reg.issue("A", "B.Tech CSE", "8.00", 2026, date(2026, 6, 1))
    with pytest.raises(ValueError):
        reg.renew("ML-DSA-65", "SHA3-256", date(2026, 1, 1))


# ------------------------------------------------------------------ app ---
@pytest.fixture
def app():
    at = AppTest.from_file("../app.py", default_timeout=60)
    at.run()
    at.button[-1].click().run()  # "Start over": fresh world for each test
    return at


def test_app_loads_with_four_tabs(app):
    assert not app.exception
    assert [t.label for t in app.tabs] == ["Issue", "Verify", "Simulate the future", "Key transfer"]


def test_app_issue_then_verify(app):
    app.text_input[0].set_value("S. Reddy")
    app.button[0].click().run()  # Issue certificate (form submit)
    assert not app.exception
    assert any("Issued certificate" in s.value for s in app.success)
    app.radio[0].set_value("Choose an issued certificate").run()
    assert any("Genuine" in m.value for m in app.markdown)


def test_app_forgery_is_rejected(app):
    app.text_input[0].set_value("A. Kumar")
    app.button[0].click().run()
    app.checkbox(key="brk-ECDSA-P256").check().run()
    forge = next(b for b in app.button if b.label == "Forge certificate")
    forge.click().run()
    assert not app.exception
    assert any("Rejected" in m.value for m in app.markdown)


def test_app_key_exchange_detects_eavesdropper(app):
    app.slider[0].set_value(100).run()
    run = next(b for b in app.button if b.label == "Run key exchange")
    run.click().run()
    assert any("Eavesdropper detected" in e.value for e in app.error)


def _verdicts(at):
    return [m.value for m in at.markdown if 'class="verdict"' in m.value]


def test_app_verify_updates_immediately_after_breaks_and_renewal(app):
    """Regression: Verify is drawn before Simulate the future, so changes there
    must be applied before the page is drawn, not one interaction later."""
    app.text_input[0].set_value("A. Kumar")
    app.button[0].click().run()                                   # issue, dated 2026
    app.radio[0].set_value("Choose an issued certificate").run()
    app.date_input(key="verify-asof").set_value(date(2053, 1, 1)).run()
    assert "Genuine" in _verdicts(app)[0]                          # nothing broken yet

    app.checkbox(key="brk-ECDSA-P256").check().run()
    app.checkbox(key="brk-ML-DSA-65").check().run()
    assert "Rejected" in _verdicts(app)[0]                         # both broken, no renewal

    renew = next(b for b in app.button if b.label == "Renew archive")
    renew.click().run()
    assert any("Renewed 1 record with" in s.value for s in app.success)
    assert "Genuine" in _verdicts(app)[0]                          # renewed in 2040: genuine again


def _forge_with(app, compromised):
    app.text_input[0].set_value("A. Kumar")
    app.button[0].click().run()
    app.checkbox(key="brk-ECDSA-P256").check().run()
    app.multiselect(key="forge-tsas").set_value(compromised).run()
    next(b for b in app.button if b.label == "Forge certificate").click().run()
    assert not app.exception
    return _verdicts(app)[-1]


def test_app_one_compromised_authority_cannot_backdate(app):
    assert "Rejected" in _forge_with(app, ["National Timestamp Service"])


def test_app_threshold_one_lets_one_compromised_authority_backdate(app):
    app.radio(key="tsa-threshold").set_value(1).run()
    assert "Genuine" in _forge_with(app, ["National Timestamp Service"])


def test_app_two_colluding_authorities_can_backdate(app):
    assert "Genuine" in _forge_with(app, ["National Timestamp Service", "Academic Consortium TSA"])


def test_registry_renewal_by_one_authority_fails_threshold_after_break():
    reg = Registry()
    cert = reg.issue("A", "B.Tech CSE", "8.00", 2026, date(2026, 6, 1))
    reg.renew(HB, "SHA3-512", date(2040, 1, 15), ["National Timestamp Service"])
    reg.set_broken("ECDSA-P256", date(2045, 3, 1))
    reg.set_broken("ML-DSA-65", date(2052, 1, 1))
    assert not reg.verify(cert, date(2053, 1, 1))[0].genuine
    with pytest.raises(ValueError):
        reg.renew(HB, "SHA3-512", date(2041, 1, 1), [])
