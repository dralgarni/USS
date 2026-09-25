# USS-Protocol-Suite — supplementary material

Code and extended results for **"A Protocol Suite for Unmanned Security System"** (A. D. Algarni, *ICT Express*, revised manuscript).

| Folder | Contents |
|---|---|
| `avispa/uss_ecc.hlpsl` | HLPSL specification of the ECC-based RQ authentication protocol (roles `dri`, `gcs`, `drj`, `session`, `environment`; secrecy and authentication goals) |
| `avispa/output/` | OFMC and CL-AtSe output files (add after running, see below) |
| `testbed/cost_model.py` | Reproduces every number in Section 4 (computation, communication, energy, comparison, scalability) from the MIRACL timings of Table 2, and regenerates Figs. 3 and 4 |
| `testbed/bench_primitives.py` | Portable Python micro-benchmark of SHA-256 and ECC scalar multiplication (cross-check, no MIRACL needed) |
| `pqc/bench_pqc.c` | Benchmark of the NIST PQC baseline in Table 6: ML-KEM-512 (FIPS 203) + ML-DSA-44 (FIPS 204) via liboqs |

## 1. AVISPA

```bash
avispa avispa/uss_ecc.hlpsl --ofmc    > avispa/output/ofmc.txt
avispa avispa/uss_ecc.hlpsl --cl-atse > avispa/output/clatse.txt
```

Modelling abstractions: scalar multiplication `a.P` → uninterpreted function `Mul`; the XOR mask of `M4` → symmetric encryption under `SVd1`; timestamps → fresh nonces; `M5`, `M7`, `M9` → hashes keyed with the registration secrets. Two parallel sessions run under the Dolev–Yao intruder, who knows all public values and holds a registered credential of its own (`pidi`, `svi`).

## 2. Cost model and figures

```bash
pip install matplotlib numpy
cd testbed && python3 cost_model.py --figures   # writes results.json, Fig-Cost.pdf (Fig. 3) and Fig-Scal.pdf (Fig. S1, copy in results/)
```

Primitive timings (MIRACL SDK, Table 2):

| Symbol | Operation | Laptop i7-6500U (ms) | Galaxy A05 (ms) |
|---|---|---|---|
| T_H | SHA-256 hash | 0.056 | 0.98 |
| T_M | ECC point multiplication | 0.445 | 0.405 |
| T_A | ECC point addition | 0.0018 | 0.635 |
| T_HM | HECC divisor multiplication | 0.48 | 0.97 |

Main results: ECC scheme 3.3 ms / 2080 bits / 35.9 mJ; HECC scheme 9.81 ms / 720 bits / 106.7 mJ (E = 10.88 W × t).

**Scalability of aggregate verification (GCS, laptop timings).** Individual cost = N(3T_HM + T_H); aggregate cost = (2N+1)T_HM + N·T_H + (N−1)T_A.

| N ADs | Individual (ms) | Aggregate (ms) | Time saved | Signature bits (ind. → agg.) |
|---|---|---|---|---|
| 5 | 7.48 | 5.57 | 25.6 % | 800 → 160 |
| 10 | 14.96 | 10.66 | 28.8 % | 1600 → 160 |
| 20 | 29.92 | 20.83 | 30.4 % | 3200 → 160 |
| 50 | 74.80 | 51.37 | 31.3 % | 8000 → 160 |
| 100 | 149.60 | 102.26 | 31.6 % | 16000 → 160 |
| 200 | 299.20 | 204.04 | 31.8 % | 32000 → 160 |

## 3. NIST PQC baseline

```bash
# liboqs >= 0.12.0 installed
gcc -O2 pqc/bench_pqc.c -loqs -o bench_pqc && ./bench_pqc
```

The baseline mirrors the paper's four-message, three-party flow. Each message carries either an ML-KEM-512 encapsulation key (800 B) or a ciphertext (768 B), plus an ML-DSA-44 signature (2420 B) and a 32-bit timestamp. The session needs 2 KeyGen, 2 Encaps, 2 Decaps, 4 Sign and 4 Verify. Communication is 102,656 bits.

Reference run (portable C build of liboqs 0.12.0, Intel Xeon @ 2.1 GHz): KeyGen 0.037 ms, Encaps 0.040 ms, Decaps 0.050 ms, Sign 0.348 ms, Verify 0.086 ms, **total 2.0 ms**. With AVX2 enabled the total is ≈ 0.47 ms.
