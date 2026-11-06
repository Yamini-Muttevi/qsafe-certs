# qsafe-certs benchmark results

| Item | Value |
| --- | --- |
| Date | 2026-11-06 17:48 |
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
| RSA-3072 | 422 | 384 | 1.329 | 0.035 | 0.035 |
| ECDSA-P256 | 33 | 71 | 0.020 | 0.079 | 0.079 |
| ML-DSA-65 | 1,952 | 3,309 | 0.381 | 0.097 | 0.092 |
| SLH-DSA-SHA2-128s | 32 | 7,856 | 572.437 | 0.568 | 0.564 |

Renewing 1,000,000 certificates: one timestamp signature; Merkle tree built in 5.2 s (pure Python, single run); proof per certificate = 20 hashes (1,280 bytes).
