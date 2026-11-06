# qsafe-certs benchmark results

| Item | Value |
| --- | --- |
| Date | 2026-11-04 10:44 |
| OS | Windows-11-10.0.26300-SP0 |
| CPU | 13th Gen Intel(R) Core(TM) i9-13900H |
| Logical cores | 20 |
| RAM | 31.6 GB |
| Python | 3.12.4 |
| liboqs | 0.15.0 |
| liboqs-python | 0.16.0.2 |

Each time is the median of 5 runs.

| Algorithm | Public key (B) | Signature (B) | Sign (ms) | Verify (ms) | Verify, reused object (ms) |
| --- | --- | --- | --- | --- | --- |
| RSA-3072 | 422 | 384 | 2.001 | 0.051 | 0.051 |
| ECDSA-P256 | 33 | 71 | 0.029 | 0.123 | 0.123 |
| ML-DSA-65 | 1,952 | 3,309 | 0.560 | 0.155 | 0.145 |
| SLH-DSA-SHA2-128s | 32 | 7,856 | 1180.697 | 1.050 | 1.128 |

Renewing 1,000,000 certificates: one timestamp signature; Merkle tree built in 8.9 s (pure Python, single run); proof per certificate = 20 hashes (1,280 bytes).
