| # | Scenario | Expected | Actual | Result | Screenshot |
| --- | --- | --- | --- | --- | --- |
| 1 | Certificate issued (2026-06-01), signed with ECDSA + ML-DSA | - | - | Done (no verdict) | `01_issue.png` |
| 2 | Genuine certificate verified today | Genuine | Genuine | Pass | `02_verify_genuine_today.png` |
| 3 | Uploaded certificate with CGPA edited 8.70 -> 9.90 | Rejected | Rejected | Pass | `03_tampered_rejected.png` |
| 4 | Original file restored | Genuine | Genuine | Pass | `04_restored_genuine.png` |
| 5 | ECDSA broken from 2045-03-01, ML-DSA from 2052-01-01 | - | - | Done (no verdict) | `05_algorithms_broken.png` |
| 6 | Checked as of 2053, archive not renewed | Rejected | Rejected | Pass | `06_verify_2053_before_renewal.png` |
| 7 | Archive renewed 2040-01-15: SLH-DSA, SHA3-512, 3 authorities | - | - | Done (no verdict) | `07_archive_renewed.png` |
| 8 | Checked as of 2053 after renewal | Genuine | Genuine | Pass | `08_verify_2053_after_renewal.png` |
| 9 | Forged degree, stolen ECDSA key, no evidence | Rejected | Rejected | Pass | `09_forgery_no_evidence.png` |
| 10 | Forgery backdated by 1 compromised authority, 2 of 3 required | Rejected | Rejected | Pass | `10_forgery_one_authority_2of3.png` |
| 11 | Same forgery with only 1 of 3 required (old weakness) | Genuine | Genuine | Pass | `11_forgery_one_authority_1of3.png` |
| 12 | Forgery backdated by 2 colluding authorities (design limit) | Genuine | Genuine | Pass | `12_forgery_two_colluding.png` |
| 13 | BB84 with no eavesdropper | - | - | Done (no verdict) | `13_bb84_no_eavesdropper.png` |
| 14 | BB84 with eavesdropper intercepting 100% | - | - | Done (no verdict) | `14_bb84_eavesdropper.png` |
