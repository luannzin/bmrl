"""Solver-based searches on the Bitcoin header's second block (z3).

Reads one JSON request from stdin and writes one JSON result to stdout.

mode "characteristics"
    {"mode": "characteristics", "start": "nonce" | "time-nonce",
     "max_rounds_after_entry": R, "timeout_ms": t, "budget_ms": b, "seed": s}
    (t bounds one solver call, b the whole search for this start)

    Optimal XOR characteristics of the second header block under the signed
    carry-free model, found by the solver instead of chosen by hand. The
    message difference is free in the words a miner can change without
    changing the midstate: W3 (nonce) for "nonce", W1 (time) and W3 for
    "time-nonce". W0 (the merkle root's last four bytes) is excluded: the
    root's other 28 bytes sit in block 1, so a W0 difference under a fixed
    midstate needs a 224-bit merkle-root collision. R counts rounds from
    round 3 (where the nonce enters) for both starts, so both cover rounds up
    to 3 + R - 1; the time-nonce start begins at round 1. W2 (bits) and the
    padding words W4..W15 never differ, and rounds stay below 16, so no
    schedule word W16+ is involved.

    Model, per round. Sigma0/Sigma1 are XOR-linear. Ch costs one bit where
    its output difference is not fixed by the input differences (e differs,
    or f and g differ unequally) and is free to choose there; Maj likewise
    unless a, b, c differ identically. Modular sums are tracked as signed
    digits: each operand difference bit contributes +-2^i with its sign set by
    the operand's value bit. At each bit at most two digits may meet:
      * one digit: the sum shows the XOR difference at that bit if its value
        bit equals the source's (probability 1/2, free at the MSB);
      * two digits: they cancel if their signs are opposite (1/2, free at the
        MSB) and the sum has no difference there.
    T1 = h + S1 + Ch + W is reduced first (its cancellations are charged
    once), then a' = T1 + S0 + Maj and e' = d + T1 are charged for every bit
    where a digit arrives. This is the laboratory's signed estimator
    (2^-11 for the MSB template, measured 2^-11.010) extended with free
    Ch/Maj choices and two-digit cancellations, which local collisions need.
    The model is an estimate: the caller measures every characteristic it
    returns on real pairs.

    Result: one entry per number of rounds R after the entry round with the
    minimum weight found, the solver status, and the characteristic (per
    round: dW, dA, dE as integers).

mode "identities"
    {"mode": "identities", "timeout_ms": t}

    Exact proofs over all templates (symbolic midstate and tail words):
      four_round: H7(n1) - bswap(n1) == H7(n2) - bswap(n2) at 4 rounds;
      five_round: H7(n) == K + bswap(n) + S1(X) + Ch(X, IV4, IV5) at 5 rounds,
        X = C0 + mid0 + A5(n), with A5 one inner round of n (derivation in the
        nonce-atlas report).
    Each is proved by asking for a counterexample: unsat = proved.
"""

import json
import sys
import time

import z3

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
]
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


# ------------------------------------------------------------ characteristics

def rot(bits, n):
    """Bits of rotr(x, n): bit i of the result is bit (i + n) mod 32 of x."""
    return [bits[(i + n) % 32] for i in range(32)]


def xor3(x, y, z):
    return [z3.Xor(z3.Xor(a, b), c) for a, b, c in zip(x, y, z)]


def word(name):
    return [z3.Bool(f"{name}_{i}") for i in range(32)]


ZERO = [z3.BoolVal(False)] * 32


def exactly(lits, k):
    return z3.PbEq([(x, 1) for x in lits], k)


def at_most(lits, k):
    return z3.PbLe([(x, 1) for x in lits], k)


def characteristic_model(start, rounds_after):
    """Constraints, per-round cost literals and variables of the model."""
    # Both starts end at the same round: R rounds counted from round 3, where the
    # nonce enters. The time-nonce start begins at round 1, where W1 enters, so
    # every free word enters inside the searched window.
    entry, free_w = {"nonce": (3, {3}), "time-nonce": (1, {1, 3})}[start]
    last = 3 + rounds_after
    assert last <= 16, "rounds must stay below 16 (no schedule expansion)"
    cons, costs = [], []
    dw = {t: word(f"w{t}") for t in free_w}
    cons.append(z3.Or([b for t in sorted(dw) for b in dw[t]]))
    # A[k], E[k]: differences after k rounds; zero up to the entry round.
    A = {k: ZERO for k in range(-3, entry + 1)}
    E = {k: ZERO for k in range(-3, entry + 1)}
    for t in range(entry, last):
        a, b, c, d = A[t], A[t - 1], A[t - 2], A[t - 3]
        e, f, g, h = E[t], E[t - 1], E[t - 2], E[t - 3]
        w = dw.get(t, ZERO)
        s1 = xor3(rot(e, 6), rot(e, 11), rot(e, 25))
        s0 = xor3(rot(a, 2), rot(a, 13), rot(a, 22))
        ch, mj, na, ne = word(f"ch{t}"), word(f"mj{t}"), word(f"a{t + 1}"), word(f"e{t + 1}")
        round_costs = []
        for i in range(32):
            det = z3.And(z3.Not(e[i]), f[i] == g[i])
            cons.append(z3.Implies(det, ch[i] == f[i]))
            round_costs.append(z3.Not(det))
            det = z3.And(a[i] == b[i], b[i] == c[i])
            cons.append(z3.Implies(det, mj[i] == a[i]))
            round_costs.append(z3.Not(det))
            paid = i < 31
            # T1 = h + S1 + Ch + W: one digit passes on, two cancel.
            t1 = [h[i], s1[i], ch[i], w[i]]
            cons.append(at_most(t1, 2))
            u = exactly(t1, 1)
            if paid:
                round_costs.append(exactly(t1, 2))
            ops = [u, s0[i], mj[i]]
            cons.append(at_most(ops, 2))
            cons.append(na[i] == exactly(ops, 1))
            cons.append(ne[i] == z3.Xor(d[i], u))
            if paid:
                round_costs.append(z3.Or(ops))
                round_costs.append(z3.Or(d[i], u))
        costs.append(round_costs)
        A[t + 1], E[t + 1] = na, ne
    return cons, costs, dw, A, E, entry


def bits_value(model, bits):
    return sum(1 << i for i, b in enumerate(bits) if z3.is_true(model.eval(b, model_completion=True)))


def characteristics(req):
    start, max_r, timeout = req["start"], int(req["max_rounds_after_entry"]), int(req["timeout_ms"])
    deadline = time.perf_counter() + int(req.get("budget_ms", 6 * timeout)) / 1000
    out, lower = [], 0
    for r in range(1, max_r + 1):
        cons, costs, dw, A, E, entry = characteristic_model(start, r)
        flat = [c for rc in costs for c in rc]
        solver = z3.Solver()
        solver.set("random_seed", int(req.get("seed", 0)) % 2**31)
        solver.add(cons)
        t0 = time.perf_counter()
        # Weight is monotone in r: the first r - 1 rounds of an optimum are a characteristic.
        w, status, model = lower, "unknown", None
        while True:
            remaining = int((deadline - time.perf_counter()) * 1000)
            if remaining <= 0:
                status = "timeout"
                break
            solver.set("timeout", min(timeout, remaining))
            solver.push()
            solver.add(z3.PbLe([(c, 1) for c in flat], w))
            res = solver.check()
            if res == z3.sat:
                model, status = solver.model(), "optimal"
                solver.pop()
                break
            solver.pop()
            if res == z3.unknown:
                status = "timeout"
                break
            w += 1
        last = 3 + r
        entry_out = {"rounds_after_entry": r, "entry_round": entry, "last_round": last - 1,
                     "status": status, "seconds": time.perf_counter() - t0}
        if model is not None:
            per_round = []
            for t in range(entry, last):
                per_round.append({
                    "round": t,
                    "dw": bits_value(model, dw[t]) if t in dw else 0,
                    "da": bits_value(model, A[t + 1]),
                    "de": bits_value(model, E[t + 1]),
                    "cost": sum(1 for c in costs[t - entry] if z3.is_true(model.eval(c, model_completion=True))),
                })
            entry_out.update({"weight": w, "rounds": per_round})
            lower = w
        else:
            entry_out.update({"weight_at_least": w})
        out.append(entry_out)
        if status != "optimal":
            break
    return {"start": start, "results": out, "z3_version": z3.get_version_string()}


# ------------------------------------------------------------------ identities

def bv(x):
    return z3.BitVecVal(x, 32)


def rotr(x, n):
    return z3.RotateRight(x, n)


def bsig0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def bsig1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def ch(e, f, g):
    return (e & f) ^ (~e & g)


def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def bswap(x):
    return z3.Concat(z3.Extract(7, 0, x), z3.Extract(15, 8, x), z3.Extract(23, 16, x), z3.Extract(31, 24, x))


def rounds_from(state, w, first, last):
    """Rounds first..last-1 on state (a..h)."""
    a, b, c, d, e, f, g, h = state
    for t in range(first, last):
        t1 = h + bsig1(e) + ch(e, f, g) + bv(K[t]) + w[t]
        t2 = bsig0(a) + maj(a, b, c)
        h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
    return [a, b, c, d, e, f, g, h]


def header_h7(mid, tail, nonce, rounds):
    """H7 of SHA256d(header) with every compression cut to `rounds` (as HeaderMidstate::with_rounds)."""
    w = [tail[0], tail[1], tail[2], bswap(nonce), bv(0x80000000)] + [bv(0)] * 10 + [bv(640)]
    s = rounds_from(mid, w, 0, rounds)
    inner = [m + x for m, x in zip(mid, s)]
    w2 = inner + [bv(0x80000000)] + [bv(0)] * 6 + [bv(256)]
    s2 = rounds_from([bv(x) for x in IV], w2, 0, rounds)
    return bv(IV[7]) + s2[7]


def prove(claim, timeout):
    s = z3.SolverFor("QF_BV")
    s.set("timeout", timeout)
    s.add(z3.Not(claim))
    t0 = time.perf_counter()
    r = s.check()
    return {"status": "proved" if r == z3.unsat else "counterexample" if r == z3.sat else "unknown",
            "seconds": time.perf_counter() - t0}


def identities(req):
    timeout = int(req["timeout_ms"])
    mid = [z3.BitVec(f"mid{i}", 32) for i in range(8)]
    tail = [z3.BitVec(f"tail{i}", 32) for i in range(3)]
    n1, n2 = z3.BitVec("n1", 32), z3.BitVec("n2", 32)
    four = header_h7(mid, tail, n1, 4) - bswap(n1) == header_h7(mid, tail, n2, 4) - bswap(n2)

    # Five rounds, unrolled by hand (see the nonce-atlas report).
    w = [tail[0], tail[1], tail[2], bv(0), bv(0x80000000)]
    a3, a2, a1, a0, e3, e2, e1, e0 = rounds_from(mid, w + [bv(0)] * 11, 0, 3)
    nh = bswap(n1)
    p = e0 + bsig1(e3) + ch(e3, e2, e1) + bv(K[3]) + bsig0(a3) + maj(a3, a2, a1)  # A4 = p + nh
    q = a0 + e0 + bsig1(e3) + ch(e3, e2, e1) + bv(K[3])                         # E4 = q + nh
    a4, e4 = p + nh, q + nh
    a5 = e1 + bsig1(e4) + ch(e4, e3, e2) + bv(K[4]) + bv(0x80000000) + bsig0(a4) + maj(a4, a3, a2)
    c0 = bv(IV[3]) + bv(IV[7]) + bsig1(bv(IV[4])) + ch(bv(IV[4]), bv(IV[5]), bv(IV[6])) + bv(K[0])
    x = c0 + mid[0] + a5
    k_star = bv(IV[7]) + bv(IV[2]) + bv(IV[6]) + bv(K[1]) + mid[1] + p
    five = header_h7(mid, tail, n1, 5) == k_star + nh + bsig1(x) + ch(x, bv(IV[4]), bv(IV[5]))
    return {"four_round": prove(four, timeout), "five_round": prove(five, timeout), "z3_version": z3.get_version_string()}


if __name__ == "__main__":
    request = json.load(sys.stdin)
    handlers = {"characteristics": characteristics, "identities": identities}
    json.dump(handlers[request["mode"]](request), sys.stdout)
