"""How many timestamp authorities, and how many must agree? A measured trade-off study.

For k-of-n configurations (n authorities sign each timestamp, k must be valid):

  A. Cost (measured)      evidence size per certificate, joint signing time, verification time
  B. Security (tested)    smallest number of compromised authorities that gets a backdated
                          forgery accepted, found by actually attacking the real code
  C. Availability (tested) smallest number of authorities that must be online at a renewal for a
                          genuine certificate to survive a later algorithm break
  D. Probabilities        B and C turned into probabilities, assuming authorities fail or are
                          compromised independently with the same probability

Run from the project folder:  python experiments/threshold_study.py
Results go to experiments/results/.
"""
import math
import os
import platform
import statistics
import sys
import time
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from qsafe import crypto  # noqa: E402
from qsafe.certificate import Certificate, Issuer, KeyDirectory, SignatureEntry  # noqa: E402
from qsafe.evidence import Archive, joint_stamp, TimestampAuthority, verify_evidence  # noqa: E402
from qsafe.policy import TrustPolicy  # noqa: E402
from qsafe.verifier import verify_certificate  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)

ALGS = ["ML-DSA-65", crypto.hash_based_algorithm()]
NS = [1, 2, 3, 5]
CONFIGS = [(1, 1), (1, 3), (2, 3), (3, 3), (2, 5), (3, 5), (4, 5)]
ARCHIVE_SIZE = 1_000_000          # certificates covered by one timestamp
PROOF_HASHES = math.ceil(math.log2(ARCHIVE_SIZE))
HASH_BYTES = {"SHA3-256": 32, "SHA3-512": 64}
KEY_ID_BYTES = 8                  # key_id is 16 hex characters
META_BYTES = 24                   # date, hash-algorithm label, authority label (approximate)
Q_COMPROMISE = [0.01, 0.05, 0.10]  # chance a given authority is compromised
P_AVAILABLE = [0.99, 0.95, 0.90]   # chance a given authority is online for a renewal
D2026, D2040, D2045 = date(2026, 6, 1), date(2040, 1, 15), date(2045, 6, 1)


def median_ms(fn, runs):
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times)


def link_bytes(sig_lengths, hash_alg):
    """Self-contained evidence for one certificate and one link, in an archive of ARCHIVE_SIZE."""
    h = HASH_BYTES[hash_alg]
    return sum(sig_lengths) + len(sig_lengths) * KEY_ID_BYTES + PROOF_HASHES * h + h + META_BYTES


# ------------------------------------------------------------------ A. cost ---
def part_a():
    print("A. Cost")
    rows = []
    directory = KeyDirectory()
    uni = Issuer("Uni", ["ML-DSA-65"], directory)
    cert = uni.issue("C1", {"name": "Student"}, D2026)
    for alg in ALGS:
        hash_alg = "SHA3-256" if alg == "ML-DSA-65" else "SHA3-512"
        sign_runs, verify_runs = (5, 50) if alg == "ML-DSA-65" else (1, 10)
        for n in NS:
            tsas = [TimestampAuthority(f"TSA-{alg}-{i}", alg, directory) for i in range(n)]
            root = os.urandom(HASH_BYTES[hash_alg])
            sign_ms = median_ms(lambda: joint_stamp(tsas, hash_alg, root, D2026), sign_runs)
            archive = Archive()
            archive.add_batch([cert], tsas, D2026, hash_alg)
            record = archive.records["C1"]
            policy = TrustPolicy(tsa_threshold=n)
            ok, _ = verify_evidence(cert, record, directory, policy, D2026)
            assert ok, "evidence should verify"
            verify_ms = median_ms(lambda: verify_evidence(cert, record, directory, policy, D2026), verify_runs)
            sigs = [len(s.signature) for s in record.links[0].timestamp.signatures]
            size = link_bytes(sigs, hash_alg)
            rows.append({"alg": alg, "hash": hash_alg, "n": n, "sign_ms": sign_ms, "verify_ms": verify_ms,
                         "sig_bytes": sum(sigs), "link_bytes": size})
            print(f"  {alg:<19} n={n}: sign {sign_ms:9.1f} ms, verify {verify_ms:6.2f} ms, link {size:,} B")
    return rows


# ------------------------------------------------------------ B. security ---
def forge(uni):
    c = Certificate("F1", "Uni", "2026-06-01", {"name": "Fraud"})
    k = uni.keys["ECDSA-P256"]
    c.signatures.append(SignatureEntry(k.algorithm, k.key_id, "2026-06-01", crypto.sign(k, c.body())))
    return c


def part_b():
    """Attack every configuration with 0..n compromised authorities, using the real verifier."""
    print("B. Security (attacking the real code)")
    results = {}
    for k, n in CONFIGS:
        directory = KeyDirectory()
        policy = TrustPolicy(tsa_threshold=k)
        policy.mark_broken("ECDSA-P256", date(2045, 3, 1))
        uni = Issuer("Uni", ["ECDSA-P256", "ML-DSA-65"], directory)
        tsas = [TimestampAuthority(f"TSA-{i}", "ML-DSA-65", directory) for i in range(n)]
        accepted = []
        for c in range(n + 1):
            forged = forge(uni)
            record = None
            if c:
                fake = Archive()
                fake.add_batch([forged], tsas[:c], D2026)  # c compromised authorities backdate it
                record = fake.records["F1"]
            accepted.append(verify_certificate(forged, record, directory, policy, D2045).genuine)
        needed = next((c for c, a in enumerate(accepted) if a), None)
        results[(k, n)] = needed
        print(f"  {k}-of-{n}: forgery first accepted with {needed} compromised authorities "
              f"(accepted pattern {['Y' if a else 'n' for a in accepted]})")
    return results


# -------------------------------------------------------- C. availability ---
def part_c():
    """Renew with only a of n authorities online, then break the old algorithm."""
    print("C. Availability (renewing with authorities offline)")
    results = {}
    for k, n in CONFIGS:
        survives = []
        for a in range(n + 1):
            directory = KeyDirectory()
            policy = TrustPolicy(tsa_threshold=k)
            uni = Issuer("Uni", ["ECDSA-P256", "ML-DSA-65"], directory)
            old = [TimestampAuthority(f"TSA-{i}", "ML-DSA-65", directory) for i in range(n)]
            new = [TimestampAuthority(f"TSA-{i}", ALGS[1], directory) for i in range(a)]
            cert = uni.issue("C1", {"name": "Student"}, D2026)
            archive = Archive()
            archive.add_batch([cert], old, D2026)
            if a:
                archive.renew(new, D2040, "SHA3-512")
            policy.mark_broken("ECDSA-P256", date(2045, 3, 1))
            policy.mark_broken("ML-DSA-65", date(2052, 1, 1))
            survives.append(verify_certificate(cert, archive.records["C1"], directory, policy,
                                               date(2053, 1, 1)).genuine)
        needed = next((a for a, s in enumerate(survives) if s), None)
        results[(k, n)] = needed
        print(f"  {k}-of-{n}: genuine certificate survives when {needed} authorities take part in the renewal "
              f"(pattern {['Y' if s else 'n' for s in survives]})")
    return results


# -------------------------------------------------------- D. probabilities ---
def at_least(m, n, p):
    """P(at least m of n independent events, each with probability p)."""
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(m, n + 1))


def part_d(sec, avail):
    rows = []
    for k, n in CONFIGS:
        row = {"k": k, "n": n, "attacker_needs": sec[(k, n)], "renewal_needs": avail[(k, n)]}
        for q in Q_COMPROMISE:
            row[f"forge_{q}"] = at_least(sec[(k, n)], n, q)
        for p in P_AVAILABLE:
            row[f"renew_fail_{p}"] = 1 - at_least(avail[(k, n)], n, p)
        rows.append(row)
    return rows


# ---------------------------------------------------------------- outputs ---
def fmt_p(x):
    if x == 0:
        return "0"
    if x < 1e-4:
        return f"{x:.1e}"
    return f"{x:.4f}".rstrip("0").rstrip(".")


def charts(cost, probs):
    fig, ax = plt.subplots(figsize=(6.4, 4))
    for alg, marker in zip(ALGS, ["o", "s"]):
        pts = [r for r in cost if r["alg"] == alg]
        ax.plot([r["n"] for r in pts], [r["link_bytes"] / 1024 for r in pts], marker=marker, label=alg)
    ax.set_xlabel("Authorities signing each timestamp (n)")
    ax.set_ylabel("Evidence per certificate per link (KiB)")
    ax.set_xticks(NS)
    ax.set_title("Evidence size grows linearly with the number of authorities")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "evidence_size.png"), dpi=160)

    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    q, p = 0.05, 0.95
    for r in probs:
        x, y = r[f"renew_fail_{p}"], r[f"forge_{q}"]
        ax.scatter(max(x, 1e-9), max(y, 1e-9), s=60)
        ax.annotate(f"{r['k']}-of-{r['n']}", (max(x, 1e-9), max(y, 1e-9)), textcoords="offset points",
                    xytext=(6, 4), fontsize=9)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(f"P(renewal fails) if each authority is online with p = {p}")
    ax.set_ylabel(f"P(forgery accepted) if each is compromised with q = {q}")
    ax.set_title("Security vs availability (lower-left is better)")
    ax.grid(alpha=0.3, which="both")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "security_vs_availability.png"), dpi=160)


def report(cost, sec, avail, probs):
    lines = [
        "# k-of-n timestamp authority study", "",
        f"Machine: {platform.platform()}, Python {platform.python_version()}.", "",
        "## A. Cost (measured)", "",
        f"Self-contained evidence for one certificate and one link, in an archive of {ARCHIVE_SIZE:,} certificates "
        f"({PROOF_HASHES} proof hashes). Signing is done once per batch, not per certificate. "
        "Times are medians (ML-DSA: 5 signing runs, 50 verification runs; SLH-DSA: 1 and 10).", "",
        "| Algorithm | Hash | n | Signatures (B) | Evidence per link (B) | Joint signing (ms) | Verification (ms) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in cost:
        lines.append(f"| {r['alg']} | {r['hash']} | {r['n']} | {r['sig_bytes']:,} | {r['link_bytes']:,} | "
                     f"{r['sign_ms']:,.1f} | {r['verify_ms']:.2f} |")
    lines += ["", "## B and C. Security and availability (tested against the real code)", "",
              "| Configuration | Compromised authorities needed to backdate a forgery | "
              "Authorities needed at a renewal for genuine certificates to survive |",
              "| --- | --- | --- |"]
    for k, n in CONFIGS:
        lines.append(f"| {k}-of-{n} | {sec[(k, n)]} | {avail[(k, n)]} |")
    lines += ["", "## D. Probabilities", "",
              "Assumes each authority is compromised, or offline, independently and with the same probability. "
              "Real authorities may share failures (same software, same jurisdiction), which would make these "
              "figures optimistic.", "",
              "| Configuration | " + " | ".join(f"P(forgery), q={q}" for q in Q_COMPROMISE) + " | "
              + " | ".join(f"P(renewal fails), p={p}" for p in P_AVAILABLE) + " |",
              "| --- |" + " --- |" * (len(Q_COMPROMISE) + len(P_AVAILABLE))]
    for r in probs:
        lines.append(f"| {r['k']}-of-{r['n']} | "
                     + " | ".join(fmt_p(r[f"forge_{q}"]) for q in Q_COMPROMISE) + " | "
                     + " | ".join(fmt_p(r[f"renew_fail_{p}"]) for p in P_AVAILABLE) + " |")
    lines += ["", "Charts: `evidence_size.png`, `security_vs_availability.png`.", ""]
    path = os.path.join(OUT, "threshold_study.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nSaved {path} and charts to {OUT}")


def main():
    cost = part_a()
    sec = part_b()
    avail = part_c()
    probs = part_d(sec, avail)
    charts(cost, probs)
    report(cost, sec, avail, probs)


if __name__ == "__main__":
    main()
