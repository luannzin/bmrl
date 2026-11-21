"""Z3 bit-vector model of reduced-round SHA-256d nonce search.

Reads one JSON instance from stdin:
    {"midstate": [8 x u32], "tail": [3 x u32], "rounds": r,
     "zero_bits": k, "timeout_ms": t, "seed": s}
Writes one JSON result to stdout:
    {"status": "sat" | "unsat" | "unknown", "nonce": int | null,
     "solve_seconds": float, "z3_version": str}

Model. The header midstate (compression of header bytes 0..64, computed by
the caller with the same round count) is concrete; the 32-bit nonce is
symbolic. The second header block and the outer hash of the 32-byte digest
are each compressed with `rounds` rounds plus feed-forward, exactly as
bitcoin-header::HeaderMidstate::with_rounds. The constraint asks for `k`
leading zero bits of the hash read as Bitcoin's little-endian 256-bit number,
i.e. bswap(H7) >> (32 - k) == 0 (k <= 32).

Invoked by `bmr research smt`; every reported nonce is re-verified in Rust
by two independent SHA-256 implementations.
"""

import json
import sys
import time

import z3

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
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def bv(x):
    return z3.BitVecVal(x, 32)


def rotr(x, n):
    return z3.RotateRight(x, n)


def bsig0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def bsig1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def ssig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ z3.LShR(x, 3)


def ssig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ z3.LShR(x, 10)


def bswap(x):
    return z3.Concat(z3.Extract(7, 0, x), z3.Extract(15, 8, x), z3.Extract(23, 16, x), z3.Extract(31, 24, x))


def compress(state, block, rounds):
    w = list(block)
    for t in range(16, rounds):
        w.append(ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16])
    a, b, c, d, e, f, g, h = state
    for t in range(rounds):
        t1 = h + bsig1(e) + ((e & f) ^ (~e & g)) + K[t] + w[t]
        t2 = bsig0(a) + ((a & b) ^ (a & c) ^ (b & c))
        h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
    return [z3.simplify(s + v) for s, v in zip(state, [a, b, c, d, e, f, g, h])]


def solve(inst):
    rounds, k = inst["rounds"], inst["zero_bits"]
    assert 0 <= rounds <= 64 and 1 <= k <= 32
    nonce = z3.BitVec("nonce", 32)
    block = [bv(inst["tail"][0]), bv(inst["tail"][1]), bv(inst["tail"][2]), bswap(nonce), bv(0x80000000)]
    block += [bv(0)] * 10 + [bv(640)]
    inner = compress([bv(x) for x in inst["midstate"]], block, rounds)
    outer = compress([bv(x) for x in IV], inner + [bv(0x80000000)] + [bv(0)] * 6 + [bv(256)], rounds)
    top = bswap(outer[7])
    solver = z3.SolverFor("QF_BV")
    solver.set("timeout", int(inst["timeout_ms"]))
    solver.set("random_seed", int(inst["seed"]) % 2**31)
    solver.add(z3.Extract(31, 32 - k, top) == 0)
    start = time.perf_counter()
    result = solver.check()
    elapsed = time.perf_counter() - start
    status = "sat" if result == z3.sat else "unsat" if result == z3.unsat else "unknown"
    found = solver.model()[nonce].as_long() if status == "sat" else None
    return {"status": status, "nonce": found, "solve_seconds": elapsed, "z3_version": z3.get_version_string()}


if __name__ == "__main__":
    json.dump(solve(json.load(sys.stdin)), sys.stdout)
