"""Independent re-implementation for the characteristic audit.

Reads one JSON instance from stdin:
    {"word": w, "bit": b, "rounds": r, "samples": n, "seeds": [s, ...]}
and writes JSON to stdout:
    {"trail": {"delta_w": [...], "states": [[8 words] x (r+1)]},
     "costs": {"sequential": [...], "grouped": [...], "signed": [...]},
     "runs": [{"seed": s, "samples": n, "followers": [count per state index]}],
     "generator": "numpy PCG64", "numpy": version}

Everything here is written separately from the Rust code: SHA-256 rounds
from FIPS 180-4 vectorised with numpy, a different random generator
(PCG64 instead of SplitMix64), and the trail and its three cost estimates
derived again from their definitions:

- XOR trail: modular additions act as XOR on differences; Ch and Maj output
  difference 0 wherever it isn't determined by the input differences.
- sequential: Lipmaa-Moriai cost hw((alpha | beta) & 0x7fffffff) for every
  addition, left to right.
- grouped: operands without a difference are summed first; the combined
  difference is charged once against them.
- signed: if the operand differences sit on disjoint bits, each non-MSB
  difference bit of the sum's output costs one bit; otherwise grouped.
"""

import json
import sys

import numpy as np

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
FULL = 0xFFFFFFFF
LOW31 = 0x7FFFFFFF


# --- differences on Python ints -------------------------------------------

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & FULL


def big0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def popcount(x):
    return bin(x).count("1")


def lm(alpha, beta):
    return popcount((alpha | beta) & LOW31)


def cost_sequential(diffs):
    acc, cost = diffs[0], 0
    for d in diffs[1:]:
        cost += lm(acc, d)
        acc ^= d
    return acc, cost


def cost_grouped(diffs):
    nonzero = [d for d in diffs if d]
    if not nonzero:
        return 0, 0
    acc, cost = nonzero[0], 0
    for d in nonzero[1:]:
        cost += lm(acc, d)
        acc ^= d
    if len(nonzero) < len(diffs):
        cost += lm(acc, 0)
    return acc, cost


def cost_signed(diffs):
    union = 0
    for d in diffs:
        if union & d:
            return cost_grouped(diffs)
        union |= d
    return union, popcount(union & LOW31)


def ch_out(de, df, dg):
    fixed = ~de & ~(df ^ dg) & FULL
    return fixed & df, popcount(~fixed & FULL)


def maj_out(da, db, dc):
    fixed = ~(da ^ db) & ~(db ^ dc) & FULL
    return fixed & da, popcount(~fixed & FULL)


def trail(word, bit, rounds):
    dw = [0] * 64
    dw[word] = 1 << bit
    sched = {"sequential": [0] * 64, "grouped": [0] * 64, "signed": [0] * 64}
    for t in range(16, 64):
        terms = [small1(dw[t - 2]), dw[t - 7], small0(dw[t - 15]), dw[t - 16]]
        dw[t] = cost_grouped(terms)[0]
        sched["sequential"][t] = cost_sequential(terms)[1]
        sched["grouped"][t] = cost_grouped(terms)[1]
        sched["signed"][t] = cost_signed(terms)[1]
    states = [[0] * 8]
    costs = {"sequential": [], "grouped": [], "signed": []}
    for t in range(rounds):
        a, b, c, d, e, f, g, h = states[-1]
        chd, chc = ch_out(e, f, g)
        mjd, mjc = maj_out(a, b, c)
        s1, s0 = big1(e), big0(a)
        for name, fn in (("sequential", cost_sequential), ("grouped", cost_grouped)):
            t1, c1 = fn([h, s1, chd, 0, dw[t]])
            t2, c2 = fn([s0, mjd])
            costs[name].append(sched[name][t] + chc + mjc + c1 + c2 + fn([t1, t2])[1] + fn([d, t1])[1])
        na, ca = cost_signed([h, s1, chd, 0, dw[t], s0, mjd])
        ne, ce = cost_signed([d, h, s1, chd, 0, dw[t]])
        costs["signed"].append(sched["signed"][t] + chc + mjc + ca + ce)
        states.append([na, a, b, c, ne, e, f, g])
    return dw[:rounds], states, costs


# --- vectorised SHA-256 rounds ---------------------------------------------

U = np.uint32


def vrotr(x, n):
    return (x >> U(n)) | (x << U(32 - n))


def followers(word, bit, rounds, samples, seed, want_w, want_states, chunk=1 << 20):
    rng = np.random.Generator(np.random.PCG64(seed))
    counts = np.zeros(rounds + 1, dtype=np.int64)
    done = 0
    while done < samples:
        n = min(chunk, samples - done)
        cv = [rng.integers(0, 1 << 32, n, dtype=np.uint32) for _ in range(8)]
        m = [rng.integers(0, 1 << 32, n, dtype=np.uint32) for _ in range(16)]
        m2 = list(m)
        m2[word] = m2[word] ^ U(1 << bit)
        ok = np.ones(n, dtype=bool)
        counts[0] += n
        with np.errstate(over="ignore"):
            w1, w2 = list(m), list(m2)
            s1, s2 = list(cv), list(cv)
            for t in range(rounds):
                if t >= 16:
                    for w in (w1, w2):
                        x2, x15 = w[t - 2], w[t - 15]
                        sig1 = vrotr(x2, 17) ^ vrotr(x2, 19) ^ (x2 >> U(10))
                        sig0 = vrotr(x15, 7) ^ vrotr(x15, 18) ^ (x15 >> U(3))
                        w.append(sig1 + w[t - 7] + sig0 + w[t - 16])
                for s, w in ((s1, w1), (s2, w2)):
                    a, b, c, d, e, f, g, h = s
                    t1 = h + (vrotr(e, 6) ^ vrotr(e, 11) ^ vrotr(e, 25)) + ((e & f) ^ (~e & g)) + U(K[t]) + w[t]
                    t2 = (vrotr(a, 2) ^ vrotr(a, 13) ^ vrotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
                    s[:] = [t1 + t2, a, b, c, d + t1, e, f, g]
                ok &= (w1[t] ^ w2[t]) == U(want_w[t])
                for k in range(8):
                    ok &= (s1[k] ^ s2[k]) == U(want_states[t + 1][k])
                counts[t + 1] += int(ok.sum())
        done += n
    return counts.tolist()


def main():
    inst = json.load(sys.stdin)
    word, bit, rounds = inst["word"], inst["bit"], inst["rounds"]
    dw, states, costs = trail(word, bit, rounds)
    runs = [
        {"seed": s, "samples": inst["samples"], "followers": followers(word, bit, rounds, inst["samples"], s, dw, states)}
        for s in inst["seeds"]
    ]
    json.dump({
        "trail": {"delta_w": dw, "states": states},
        "costs": costs,
        "runs": runs,
        "generator": "numpy PCG64",
        "numpy": np.__version__,
    }, sys.stdout)


if __name__ == "__main__":
    main()
