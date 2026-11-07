"""Walk through 26 years of a degree certificate's life, with simulated algorithm breaks.

Run:  python demo.py
"""
import copy
from datetime import date

from qsafe.certificate import Certificate, Issuer, KeyDirectory, SignatureEntry
from qsafe import crypto
from qsafe.evidence import Archive, TimestampAuthority
from qsafe.policy import TrustPolicy
from qsafe.qkd import decrypt, encrypt, establish_hybrid_channel, run_bb84
from qsafe.verifier import verify_certificate


def section(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def check(label, result):
    print(f"\n[{label}]\n  {result}")


directory = KeyDirectory()
policy = TrustPolicy(tsa_threshold=2)  # any 2 of the 3 timestamp authorities must agree
TSA_NAMES = ["National Timestamp Service", "Academic Consortium TSA", "Independent Auditor TSA"]

# ------------------------------------------------------------------ 2026 ---
section("2026: university issues degrees with hybrid ECDSA + ML-DSA signatures")
uni = Issuer("Deccan Institute of Technology", ["ECDSA-P256", "ML-DSA-65"], directory)
tsa_2026 = [TimestampAuthority(n, "ML-DSA-65", directory) for n in TSA_NAMES]

issued = date(2026, 6, 1)
certs = [
    uni.issue(f"DIT-2026-{i:04d}", {"name": n, "degree": "B.Tech CSE", "cgpa": g, "year": 2026}, issued)
    for i, (n, g) in enumerate([("A. Kumar", "8.7"), ("S. Reddy", "9.1"), ("F. Khan", "7.9")], 1)
]
genuine = certs[0]
print(f"Issued {len(certs)} certificates. Certificate {genuine.certificate_id} carries "
      f"{len(genuine.signatures)} signatures: {[s.algorithm for s in genuine.signatures]}")

archive = Archive()
archive.add_batch(certs, tsa_2026, date(2026, 6, 2))
print("Archive: one joint ML-DSA timestamp, signed by 3 independent authorities, covers all fingerprints.")

# Counterfactual archive that is NEVER renewed, to show why renewal matters.
lazy_archive = Archive()
lazy_archive.add_batch(certs, tsa_2026, date(2026, 6, 2))

check("2026 verify genuine certificate",
      verify_certificate(genuine, archive.records[genuine.certificate_id], directory, policy, date(2026, 7, 1)))

tampered = copy.deepcopy(genuine)
tampered.content["cgpa"] = "9.9"
check("2026 verify tampered certificate (CGPA 8.7 -> 9.9)",
      verify_certificate(tampered, archive.records[genuine.certificate_id], directory, policy, date(2026, 7, 1)))

# ------------------------------------------------------------------ 2040 ---
HB = crypto.hash_based_algorithm()  # SLH-DSA if it works here, else SPHINCS+ under its own name
section(f"2040: archive renewed with a hash-based signature ({HB}) and SHA3-512")
tsa_2040 = [TimestampAuthority(n, HB, directory) for n in TSA_NAMES]
n = archive.renew(tsa_2040, date(2040, 1, 15), hash_alg="SHA3-512", directory=directory, policy=policy)
print(f"Renewed {n} records with ONE joint timestamp from 3 authorities. Certificate contents were never touched.")

# ------------------------------------------------------------------ 2045 ---
section("2045: a quantum computer breaks ECDSA")
policy.mark_broken("ECDSA-P256", date(2045, 3, 1))
today = date(2045, 6, 1)

check("2045 verify genuine certificate",
      verify_certificate(genuine, archive.records[genuine.certificate_id], directory, policy, today))

# The attacker derives the university's ECDSA private key (simulated by handing it over)
# and forges a degree dated 2026 that carries a mathematically valid ECDSA signature.
stolen_ecdsa = uni.keys["ECDSA-P256"]
forged = Certificate("DIT-2026-0999", uni.name, "2026-06-01",
                     {"name": "M. Fraud", "degree": "B.Tech CSE", "cgpa": "9.8", "year": 2026})
forged.signatures.append(SignatureEntry("ECDSA-P256", stolen_ecdsa.key_id, "2026-06-01",
                                        crypto.sign(stolen_ecdsa, forged.body())))
check("2045 verify FORGED certificate (valid ECDSA signature, backdated to 2026)",
      verify_certificate(forged, None, directory, policy, today))

# The forger even gets it timestamped today, hoping that helps.
forger_archive = Archive()
forger_archive.add_batch([forged], tsa_2040, date(2045, 6, 1), hash_alg="SHA3-512")
check("2045 verify FORGED certificate with a fresh 2045 timestamp",
      verify_certificate(forged, forger_archive.records[forged.certificate_id], directory, policy, today))

# The forger ALSO controls one timestamp authority (stolen key or dishonest insider)
# and gets it to sign a timestamp backdated to 2026.
backdated = Archive()
backdated.add_batch([forged], tsa_2026[0], date(2026, 6, 2))
check("2045 verify FORGED certificate, backdated by ONE compromised authority",
      verify_certificate(forged, backdated.records[forged.certificate_id], directory, policy, today))

policy.tsa_threshold = 1
check("Same forgery if a single authority were trusted (threshold 1): the weakness 2-of-3 fixes",
      verify_certificate(forged, backdated.records[forged.certificate_id], directory, policy, today))
policy.tsa_threshold = 2

# ------------------------------------------------------------------ 2052 ---
section("2052 (hypothetical): ML-DSA is ALSO broken")
policy.mark_broken("ML-DSA-65", date(2052, 1, 1))
today = date(2052, 6, 1)

check("2052 verify genuine certificate, renewed archive",
      verify_certificate(genuine, archive.records[genuine.certificate_id], directory, policy, today))
check("2052 verify genuine certificate, archive that was NEVER renewed",
      verify_certificate(genuine, lazy_archive.records[genuine.certificate_id], directory, policy, today))

# ------------------------------------------------------------------- QKD ---
section("Key transfer between issuing offices: simulated BB84 + ML-KEM")
clean = run_bb84()
print(f"No eavesdropper:   {clean.sifted_bits} sifted bits, QBER {clean.qber:.1%}, "
      f"detected={clean.eavesdropper_detected}")
spied = run_bb84(eavesdrop_fraction=1.0)
print(f"Eavesdropper Eve:  {spied.sifted_bits} sifted bits, QBER {spied.qber:.1%}, "
      f"detected={spied.eavesdropper_detected}  -> key discarded")

key_a, key_b, _ = establish_hybrid_channel()
backup = b"encrypted backup of the university signing keys"
blob = encrypt(key_a, backup)
print(f"Hybrid channel: keys match={key_a == key_b}; backup sent ({len(blob)} bytes) "
      f"and recovered={decrypt(key_b, blob) == backup}")

from qsafe.crypto import resolved_implementations
print(f"\nliboqs implementations in use on this machine: {resolved_implementations()}")
