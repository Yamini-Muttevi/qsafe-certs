# k-of-n timestamp authority study

Machine: Linux-6.18.44-fc-v242-x86_64-with-glibc2.39, Python 3.12.3.

## A. Cost (measured)

Self-contained evidence for one certificate and one link, in an archive of 1,000,000 certificates (20 proof hashes). Signing is done once per batch, not per certificate. Times are medians (ML-DSA: 5 signing runs, 50 verification runs; SLH-DSA: 1 and 10).

| Algorithm | Hash | n | Signatures (B) | Evidence per link (B) | Joint signing (ms) | Verification (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | SHA3-256 | 1 | 3,309 | 4,013 | 0.1 | 0.09 |
| ML-DSA-65 | SHA3-256 | 2 | 6,618 | 7,330 | 0.2 | 0.13 |
| ML-DSA-65 | SHA3-256 | 3 | 9,927 | 10,647 | 0.4 | 0.18 |
| ML-DSA-65 | SHA3-256 | 5 | 16,545 | 17,281 | 0.6 | 0.27 |
| SLH-DSA-SHA2-128s | SHA3-512 | 1 | 7,856 | 9,232 | 633.6 | 0.72 |
| SLH-DSA-SHA2-128s | SHA3-512 | 2 | 15,712 | 17,096 | 1,254.1 | 1.30 |
| SLH-DSA-SHA2-128s | SHA3-512 | 3 | 23,568 | 24,960 | 1,879.5 | 1.94 |
| SLH-DSA-SHA2-128s | SHA3-512 | 5 | 39,280 | 40,688 | 3,071.3 | 3.35 |

## B and C. Security and availability (tested against the real code)

| Configuration | Compromised authorities needed to backdate a forgery | Authorities needed at a renewal for genuine certificates to survive |
| --- | --- | --- |
| 1-of-1 | 1 | 1 |
| 1-of-3 | 1 | 1 |
| 2-of-3 | 2 | 2 |
| 3-of-3 | 3 | 3 |
| 2-of-5 | 2 | 2 |
| 3-of-5 | 3 | 3 |
| 4-of-5 | 4 | 4 |

## D. Probabilities

Assumes each authority is compromised, or offline, independently and with the same probability. Real authorities may share failures (same software, same jurisdiction), which would make these figures optimistic.

| Configuration | P(forgery), q=0.01 | P(forgery), q=0.05 | P(forgery), q=0.1 | P(renewal fails), p=0.99 | P(renewal fails), p=0.95 | P(renewal fails), p=0.9 |
| --- | --- | --- | --- | --- | --- | --- |
| 1-of-1 | 0.01 | 0.05 | 0.1 | 0.01 | 0.05 | 0.1 |
| 1-of-3 | 0.0297 | 0.1426 | 0.271 | 1.0e-06 | 0.0001 | 0.001 |
| 2-of-3 | 0.0003 | 0.0073 | 0.028 | 0.0003 | 0.0072 | 0.028 |
| 3-of-3 | 1.0e-06 | 0.0001 | 0.001 | 0.0297 | 0.1426 | 0.271 |
| 2-of-5 | 0.001 | 0.0226 | 0.0815 | 5.0e-08 | 3.0e-05 | 0.0005 |
| 3-of-5 | 9.9e-06 | 0.0012 | 0.0086 | 9.9e-06 | 0.0012 | 0.0086 |
| 4-of-5 | 5.0e-08 | 3.0e-05 | 0.0005 | 0.001 | 0.0226 | 0.0815 |

Charts: `evidence_size.png`, `security_vs_availability.png`.
