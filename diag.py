"""Check which post-quantum signature implementations work on this machine.

Run:  python diag.py
"""
import traceback

import oqs

print("liboqs version:", oqs.oqs_version())
for name in ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S", "SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple"]:
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
