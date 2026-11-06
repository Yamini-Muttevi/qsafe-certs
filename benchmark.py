"""Measure signature cost (RQ4) and archive renewal cost (RQ3).

Runs every measurement several times and reports the median, records the
machine's details, and saves the results to a Markdown file.

Run:  python benchmark.py                 (5 runs, 1,000,000-certificate renewal)
      python benchmark.py --runs 3 --renew-size 100000
"""
import argparse
import os
import platform
import statistics
import sys
import time
from datetime import datetime

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from qsafe import crypto
from qsafe.certificate import canonical
from qsafe.evidence import H, merkle_root_and_proofs

MSG = canonical({"name": "A. Kumar", "degree": "B.Tech CSE", "cgpa": "8.7", "year": 2026})


# ------------------------------------------------------------ system info ---
def cpu_name() -> str:
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        if sys.platform == "darwin":
            return os.popen("sysctl -n machdep.cpu.brand_string").read().strip()
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def ram_gb() -> str:
    try:
        if sys.platform == "win32":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(m)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return f"{m.ullTotalPhys / 2**30:.1f} GB"
        if sys.platform == "darwin":
            return f"{int(os.popen('sysctl -n hw.memsize').read()) / 2**30:.1f} GB"
        with open("/proc/meminfo") as f:
            return f"{int(f.readline().split()[1]) / 2**20:.1f} GB"
    except Exception:
        return "unknown"


def system_info() -> dict:
    return {
        "Date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "OS": platform.platform(),
        "CPU": cpu_name(),
        "Logical cores": str(os.cpu_count()),
        "RAM": ram_gb(),
        "Python": platform.python_version(),
        "liboqs": oqs.oqs_version(),
        "liboqs-python": getattr(oqs, "oqs_python_version", lambda: "unknown")(),
    }


# ------------------------------------------------------------ measurement ---
def per_call_ms(fn, n: int) -> float:
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t) / n * 1000


def measure_once(alg: str, iters: int) -> dict:
    """Sign, verify through the project's wrapper, and verify with a reused library object.

    The last column separates the cost of the algorithm itself from the overhead of
    creating a new verifier object per call, which the wrapper does.
    """
    if alg == "RSA-3072":
        sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pk = sk.public_key()
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        sig = sk.sign(MSG, pss, hashes.SHA256())
        verify = lambda: pk.verify(sig, MSG, pss, hashes.SHA256())  # noqa: E731
        return {
            "pk": len(pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "sig": len(sig),
            "sign": per_call_ms(lambda: sk.sign(MSG, pss, hashes.SHA256()), iters),
            "verify": per_call_ms(verify, iters * 4),
            "verify_reused": per_call_ms(verify, iters * 4),
        }
    kp = crypto.generate_keypair(alg)
    sig = crypto.sign(kp, MSG)
    assert crypto.verify(alg, kp.public_key, MSG, sig)
    out = {
        "pk": len(kp.public_key),
        "sig": len(sig),
        "sign": per_call_ms(lambda: crypto.sign(kp, MSG), iters),
        "verify": per_call_ms(lambda: crypto.verify(alg, kp.public_key, MSG, sig), max(iters, 20)),
    }
    if alg == "ECDSA-P256":
        out["verify_reused"] = out["verify"]
    else:
        with oqs.Signature(crypto._resolve_oqs_sig(alg)) as v:
            out["verify_reused"] = per_call_ms(lambda: v.verify(MSG, sig, kp.public_key), max(iters, 20))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=5, help="repetitions per measurement (median is reported)")
    ap.add_argument("--renew-size", type=int, default=1_000_000, help="certificates in the renewal test")
    ap.add_argument("--out", help="results file (default: results_<os>_<date>.md)")
    args = ap.parse_args()

    info = system_info()
    lines = ["# qsafe-certs benchmark results", "", "| Item | Value |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in info.items()]
    lines += ["", f"Each time is the median of {args.runs} runs.", ""]
    for k, v in info.items():
        print(f"{k:<14}{v}")
    print()

    algorithms = [("RSA-3072", 50), ("ECDSA-P256", 200), ("ML-DSA-65", 200), ("SLH-DSA-SHA2-128s", 3)]
    header = ("| Algorithm | Public key (B) | Signature (B) | Sign (ms) | Verify (ms) | Verify, reused object (ms) |\n"
              "| --- | --- | --- | --- | --- | --- |")
    lines.append(header)
    print(f"{'Algorithm':<20}{'Public key (B)':>15}{'Signature (B)':>15}{'Sign (ms)':>11}"
          f"{'Verify (ms)':>13}{'Verify, reused (ms)':>21}")
    for alg, iters in algorithms:
        runs = []
        for i in range(args.runs):
            print(f"  measuring {alg}: run {i + 1}/{args.runs}...", end="\r", flush=True)
            runs.append(measure_once(alg, iters))
        med = {k: statistics.median(r[k] for r in runs) for k in ("sign", "verify", "verify_reused")}
        pk, sig = runs[0]["pk"], runs[0]["sig"]
        print(f"{alg:<20}{pk:>15}{sig:>15}{med['sign']:>11.3f}{med['verify']:>13.3f}{med['verify_reused']:>21.3f}")
        lines.append(f"| {alg} | {pk:,} | {sig:,} | {med['sign']:.3f} | {med['verify']:.3f} | "
                     f"{med['verify_reused']:.3f} |")

    n = args.renew_size
    print(f"\n  building renewal tree for {n:,} certificates (pure Python, may take a while)...", flush=True)
    fps = [H("SHA3-256", i.to_bytes(8, "big")) for i in range(n)]
    t = time.perf_counter()
    _, proofs = merkle_root_and_proofs("SHA3-512", fps)
    secs = time.perf_counter() - t
    proof_bytes = sum(len(h) for _, h in proofs[0])
    renew = (f"Renewing {n:,} certificates: one timestamp signature; Merkle tree built in {secs:.1f} s "
             f"(pure Python, single run); proof per certificate = {len(proofs[0])} hashes ({proof_bytes:,} bytes).")
    print(renew)
    lines += ["", renew, ""]

    out = args.out or f"results_{platform.system().lower()}_{datetime.now():%Y%m%d_%H%M}.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
