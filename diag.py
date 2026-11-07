"""Check which post-quantum signature implementations work on this machine.

Run:  python diag.py
"""
import traceback

import oqs

print("liboqs version:", oqs.oqs_version())
for name in ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S", "SLH-DSA-SHA2-128s", "SLH_DSA_PURE_SHAKE_128S",
             "SPHINCS+-SHA2-128s-simple"]:
    if name not in oqs.get_enabled_sig_mechanisms():
        print(f"{name}: not available in this build")
        continue
    try:
        s = oqs.Signature(name)
        pk = s.generate_keypair()
        sig = s.sign(b"test")
        with oqs.Signature(name) as v:
            print(f"{name}: verifies = {v.verify(b'test', sig, pk)}")
    except Exception:
        print(f"{name}: ERROR")
        traceback.print_exc()

# Which algorithms the project will actually use on this machine.
from qsafe import crypto  # noqa: E402

print("\nProject algorithms available here:", ", ".join(crypto.available_signature_algorithms()))
alg, warning = crypto.renewal_algorithm()
print("Renewal algorithm used here:", alg)
if warning:
    print("WARNING:", warning)
if crypto.is_available(crypto.SLH_DSA) and crypto.is_available(crypto.SPHINCS):
    a, b = crypto.SLH_DSA, crypto.SPHINCS
    kp = crypto.generate_keypair(a)
    sig = crypto.sign(kp, b"interop")
    print(f"{a} signature accepted by {b} verifier: {crypto.verify(b, kp.public_key, b'interop', sig)} "
          "(must be False: they are different algorithms)")
