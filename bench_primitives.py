#!/usr/bin/env python3
"""
Python micro-benchmark of the cryptographic primitives used by the protocol suite.

The timings reported in Table 2 of the paper were obtained with the MIRACL C/C++ SDK;
this script is a portable cross-check that any reader can run without MIRACL.
Absolute numbers differ from MIRACL (Python/OpenSSL bindings), but the relative
ordering of primitives is the same.

    pip install cryptography
    python3 bench_primitives.py
"""
import hashlib
import os
import platform
import statistics
import time

from cryptography.hazmat.primitives.asymmetric import ec

RUNS = 2000


def bench(fn, runs=RUNS):
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)
    return statistics.median(samples)


def main():
    print(f"Platform: {platform.platform()} | {platform.processor() or platform.machine()}")
    msg = os.urandom(64)
    t_h = bench(lambda: hashlib.sha256(msg).digest())

    # ECC scalar multiplication on secp160r1 is not in OpenSSL's default provider;
    # secp256r1 is used as a conservative stand-in (upper bound for 160-bit curves).
    a = ec.generate_private_key(ec.SECP256R1())
    b_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    t_m = bench(lambda: a.exchange(ec.ECDH(), b_pub), runs=500)

    print(f"T_H  (SHA-256)                     : {t_h:.4f} ms")
    print(f"T_M  (ECC scalar mult., P-256 ECDH): {t_m:.4f} ms")

    # Cost expressions of Section 4.3 evaluated with these Python timings
    gcs = 12 * t_h + 2 * t_m
    drone = 7 * t_h + 3 * t_m
    print(f"ECC scheme  GCS  ~ {gcs:.3f} ms, drone ~ {drone:.3f} ms (point additions ignored)")


if __name__ == "__main__":
    main()
