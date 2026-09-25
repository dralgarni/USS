#!/usr/bin/env python3
"""
Testbed cost model for "A Protocol Suite for Unmanned Security System" (ICT Express, revised).

Reproduces every number reported in Section 4 (computation, communication, energy,
comparison, scalability) from the primitive timings measured with the MIRACL SDK
(Table 2 of the paper), and regenerates Fig. 3 of the paper and Fig. S1 (scalability, repository only).

Usage:
    python3 cost_model.py            # prints all results, writes results.json
    python3 cost_model.py --figures  # also writes Fig-Cost.pdf (Fig. 3) and Fig-Scal.pdf (Fig. S1)
"""
import json
import sys

# ---------------------------------------------------------------------------
# Table 2: primitive execution times (ms), MIRACL SDK
#   laptop = Intel Core i7-6500U @ 2.50 GHz (GCS)
#   mobile = Samsung Galaxy A05, Helio G85 (drone-class device)
# ---------------------------------------------------------------------------
T = {
    "laptop": {"H": 0.056, "M": 0.445, "A": 0.0018, "HM": 0.48},
    "mobile": {"H": 0.98, "M": 0.405, "A": 0.635, "HM": 0.97},
}
E_W = 10.88  # W, CPU power used for energy estimation (E = E_W x time)

# Sizes (bits), MIRACL parameters
B_ID, B_HASH, B_ECP, B_HCP, B_T = 160, 256, 160, 80, 32


def cost(counts, platform="laptop"):
    t = T[platform]
    return sum(n * t[k] for k, n in counts.items())


# ---------------------------------------------------------------------------
# Computation
# ---------------------------------------------------------------------------
ECC_GCS = {"H": 12, "M": 2, "A": 1}
ECC_DRONE = {"H": 7, "M": 3, "A": 2}
HECC = {"M": 8, "HM": 13, "A": 5}

res = {}
res["ecc_gcs_ms"] = cost(ECC_GCS)
res["ecc_drone_ms"] = cost(ECC_DRONE)
res["ecc_total_ms"] = res["ecc_gcs_ms"] + res["ecc_drone_ms"]
res["ecc_drone_mobile_ms"] = cost(ECC_DRONE, "mobile")
res["hecc_total_ms"] = cost(HECC)

# ---------------------------------------------------------------------------
# Communication (bits)
# ---------------------------------------------------------------------------
msgs = {
    "M_A (DR_i->GCS)": B_ECP + B_HASH + B_T,
    "M_B (GCS->DR_j)": B_HASH + B_HASH + B_T,
    "M_C (DR_j->GCS)": B_HASH + B_HASH + B_T,
    "M_D (GCS->DR_i)": B_HASH + B_HASH + B_T,
}
res["ecc_messages_bits"] = msgs
res["ecc_comm_bits"] = sum(msgs.values())
res["hecc_comm_bits"] = 3 * B_ECP + 3 * B_HCP

# ---------------------------------------------------------------------------
# Energy (mJ) = W x ms
# ---------------------------------------------------------------------------
res["ecc_energy_mJ"] = E_W * round(res["ecc_total_ms"], 1)
res["hecc_energy_mJ"] = E_W * round(res["hecc_total_ms"], 2)

# ---------------------------------------------------------------------------
# Comparison (Table 6). Prior-work values as reported in the paper.
# PQC baseline: ML-KEM-512 (FIPS 203) + ML-DSA-44 (FIPS 204) mirroring the
# 4-message flow; computation measured with ../pqc/bench_pqc.c (liboqs 0.12.0,
# portable C build). Re-run bench_pqc on the GCS laptop and update PQC_MS.
# ---------------------------------------------------------------------------
PQC_MS = 2.0
PQC_BITS = 8 * (2 * (800 + 2420) + 2 * (768 + 2420)) + 4 * B_T
prior = {
    "Won et al. [8]": (87.75, 3232),
    "Wazid et al. [9]": (27.02, 1696),
    "Cho et al. [10]": (84.27, 5240),
    "Wang et al. [11]": (17.51, 4056),
    "Chen et al. [12]": (9.06, 5536),
    "Jan et al. [14]": (29.87, 3604),
    "ML-KEM-512+ML-DSA-44": (PQC_MS, PQC_BITS),
}
ours = (round(res["ecc_total_ms"], 1), res["ecc_comm_bits"])  # 3.3 ms as reported
res["comparison"] = {}
for k, (c, b) in prior.items():
    res["comparison"][k] = {
        "comp_ms": c,
        "comm_bits": b,
        "comp_reduction_pct": round(100 * (1 - ours[0] / c), 1),
        "comm_reduction_pct": round(100 * (1 - ours[1] / b), 1),
    }


# ---------------------------------------------------------------------------
# Scalability of AD aggregate verification at the GCS (Section 4.8)
#   individual: per signature 1 HM (pk_i = Cert.lambda) + 1 H + 2 HM (verify)
#   aggregate : N HM (pk_i) + N H + N HM (H_i.pk_i) + (N-1) A + 1 HM (sigma.D)
# ---------------------------------------------------------------------------
def verify_individual(n, p="laptop"):
    t = T[p]
    return n * (3 * t["HM"] + t["H"])


def verify_aggregate(n, p="laptop"):
    t = T[p]
    return (2 * n + 1) * t["HM"] + n * t["H"] + (n - 1) * t["A"]


SIG_BITS = B_ECP  # one Jacobian element, compressed
Ns = [1, 5, 10, 20, 50, 100, 200]
res["scalability"] = [
    {
        "N": n,
        "individual_ms": round(verify_individual(n), 3),
        "aggregate_ms": round(verify_aggregate(n), 3),
        "time_saving_pct": round(100 * (1 - verify_aggregate(n) / verify_individual(n)), 1),
        "sig_bits_individual": n * SIG_BITS,
        "sig_bits_aggregate": SIG_BITS,
    }
    for n in Ns
]
# ECC scheme: sessions per second a single GCS core can serve
res["gcs_sessions_per_s"] = 1000.0 / res["ecc_gcs_ms"]


def main():
    print(json.dumps(res, indent=2))
    with open("results.json", "w") as f:
        json.dump(res, f, indent=2)
    if "--figures" in sys.argv:
        make_figures()


def make_figures():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    BLUE, ORANGE, AQUA, GRAY = "#2a78d6", "#eb6834", "#1baf7a", "#9a9a94"
    INK = "#2b2b2b"
    plt.rcParams.update({
        "font.family": "serif", "font.size": 7, "axes.titlesize": 7.5,
        "axes.labelsize": 7, "xtick.labelsize": 6.3, "ytick.labelsize": 6.3,
        "axes.edgecolor": "#8a8a8a", "axes.linewidth": 0.6,
        "xtick.color": INK, "ytick.color": INK, "text.color": INK,
        "axes.labelcolor": INK, "pdf.fonttype": 42,
    })

    def clean(ax):
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", color="#e6e6e3", lw=0.5)
        ax.set_axisbelow(True)

    # ---------------- Fig. 3: cost analysis (1x3) ----------------
    fig, axs = plt.subplots(1, 3, figsize=(3.5, 1.75), gridspec_kw={"width_ratios": [5, 4.4, 2.6]})
    # (a) computation
    ax = axs[0]
    labels = ["GCS", "Drone", "ECC", "HECC"]
    vals = [res["ecc_gcs_ms"], res["ecc_drone_ms"], res["ecc_total_ms"], res["hecc_total_ms"]]
    b = ax.bar(labels, vals, color=[BLUE, BLUE, BLUE, AQUA], width=0.66, edgecolor="white", linewidth=1)
    for r, v in zip(b, vals):
        ax.text(r.get_x() + r.get_width() / 2, v + 0.15, f"{v:.2f}", ha="center", va="bottom", fontsize=4.9)
    ax.set_ylabel("Time (ms)")
    ax.set_ylim(0, 11.5)
    ax.set_title("(a) Computation", fontsize=6.6)
    ax.tick_params(axis="x", labelsize=5.2, length=0)
    clean(ax)
    # (b) communication per message
    ax = axs[1]
    ml = ["$M_A$", "$M_B$", "$M_C$", "$M_D$", "HECC"]
    mv = list(msgs.values()) + [res["hecc_comm_bits"]]
    b = ax.bar(ml, mv, color=[BLUE] * 4 + [AQUA], width=0.66, edgecolor="white", linewidth=1)
    for r, v in zip(b, mv):
        ax.text(r.get_x() + r.get_width() / 2, v + 12, f"{v}", ha="center", va="bottom", fontsize=5.3)
    ax.set_ylabel("Size (bits)")
    ax.set_ylim(0, 820)
    ax.set_title("(b) Communication", fontsize=6.6)
    ax.tick_params(axis="x", labelsize=5.2, length=0)
    clean(ax)
    # (c) energy
    ax = axs[2]
    ev = [res["ecc_energy_mJ"], res["hecc_energy_mJ"]]
    b = ax.bar(["ECC", "HECC"], ev, color=[BLUE, AQUA], width=0.62, edgecolor="white", linewidth=1)
    for r, v in zip(b, ev):
        ax.text(r.get_x() + r.get_width() / 2, v + 2, f"{v:.1f}", ha="center", va="bottom", fontsize=5.3)
    ax.set_ylabel("Energy (mJ)")
    ax.set_ylim(0, 125)
    ax.set_title("(c) Energy", fontsize=6.6)
    ax.tick_params(axis="x", labelsize=5.2, length=0)
    clean(ax)
    fig.tight_layout(pad=0.3, w_pad=0.5)
    fig.savefig("Fig-Cost.pdf")
    plt.close(fig)

    # ---------------- Fig. 4: scalability (1x2) ----------------
    import numpy as np

    n = np.arange(1, 201)
    ind = np.array([verify_individual(k) for k in n])
    agg = np.array([verify_aggregate(k) for k in n])
    fig, axs = plt.subplots(1, 2, figsize=(3.5, 1.65))
    ax = axs[0]
    ax.plot(n, ind, color=ORANGE, lw=1.6, label="Individual")
    ax.plot(n, agg, color=BLUE, lw=1.6, label="Aggregate")
    ax.set_xlabel("Number of ADs, $N$")
    ax.set_ylabel("GCS verification (ms)")
    ax.set_title("(a) Verification time")
    ax.legend(frameon=False, fontsize=6, loc="upper left")
    clean(ax)
    ax = axs[1]
    ax.plot(n, n * SIG_BITS / 1000, color=ORANGE, lw=1.6, label="Individual")
    ax.plot(n, np.full_like(n, SIG_BITS, dtype=float) / 1000, color=BLUE, lw=1.6, label="Aggregate")
    ax.set_xlabel("Number of ADs, $N$")
    ax.set_ylabel("Signature payload (kbit)")
    ax.set_title("(b) Signature overhead")
    ax.legend(frameon=False, fontsize=6, loc="upper left")
    clean(ax)
    fig.tight_layout(pad=0.4, w_pad=0.8)
    fig.savefig("Fig-Scal.pdf")
    plt.close(fig)


if __name__ == "__main__":
    main()
