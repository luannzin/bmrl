"""Profiled SMT/SAT solve of one reduced-round SHA-256d nonce-search instance.

Input (stdin, JSON):
    {"midstate": [8], "tail": [3], "rounds": r, "zero_bits": k,
     "timeout_ms": t, "seed": s, "encoding": "qfbv" | "bitblast-sat",
     "cnf_stats": bool}
Output (stdout, JSON):
    {"status", "nonce", "encoding", "build_seconds", "solve_seconds",
     "dag_nodes", "cnf": {"clauses", "variables", "seconds"} | null,
     "stats": {...z3 statistics...}, "z3_version"}

Encodings
    qfbv          Z3's QF_BV solver on the word-level model (bvadd, rotations).
    bitblast-sat  The same constraint pre-processed by the tactic chain
                  simplify -> bit-blast -> sat, i.e. a pure CNF/SAT search.

`cnf_stats` bit-blasts the goal separately (simplify, bit-blast,
tseitin-cnf) and counts clauses and propositional variables, so model size can
be compared with solve time when investigating timeouts. Its cost is not part
of solve_seconds.

The model is identical to smt_reduced_round.py (shared construction below is
imported from it to keep one source of truth).
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import z3  # noqa: E402

from smt_reduced_round import IV, bswap, bv, compress  # noqa: E402


def build(inst):
    rounds, k = inst["rounds"], inst["zero_bits"]
    assert 0 <= rounds <= 64 and 1 <= k <= 32
    nonce = z3.BitVec("nonce", 32)
    block = [bv(inst["tail"][0]), bv(inst["tail"][1]), bv(inst["tail"][2]), bswap(nonce), bv(0x80000000)]
    block += [bv(0)] * 10 + [bv(640)]
    inner = compress([bv(x) for x in inst["midstate"]], block, rounds)
    outer = compress([bv(x) for x in IV], inner + [bv(0x80000000)] + [bv(0)] * 6 + [bv(256)], rounds)
    return nonce, z3.Extract(31, 32 - k, bswap(outer[7])) == 0


def dag_nodes(expr):
    seen, stack = set(), [expr]
    while stack:
        e = stack.pop()
        i = e.get_id()
        if i in seen:
            continue
        seen.add(i)
        stack.extend(e.children())
    return len(seen)


def cnf_stats(constraint):
    start = time.perf_counter()
    goal = z3.Goal()
    goal.add(constraint)
    result = z3.Then("simplify", "bit-blast", "tseitin-cnf")(goal)
    clauses, atoms = 0, set()
    for sub in result:
        for clause in sub:
            clauses += 1
            lits = clause.children() if z3.is_or(clause) else [clause]
            for lit in lits:
                atom = lit.arg(0) if z3.is_not(lit) else lit
                atoms.add(atom.get_id())
    return {"clauses": clauses, "variables": len(atoms), "seconds": time.perf_counter() - start}


def numeric_stats(stats):
    out = {}
    for key in stats.keys():
        value = stats.get_key_value(key)
        if isinstance(value, (int, float)):
            out[key] = value
    return out


def solve(inst):
    t0 = time.perf_counter()
    nonce, constraint = build(inst)
    nodes = dag_nodes(constraint)
    build_seconds = time.perf_counter() - t0
    encoding = inst.get("encoding", "qfbv")
    if encoding == "qfbv":
        solver = z3.SolverFor("QF_BV")
    elif encoding == "bitblast-sat":
        solver = z3.Then("simplify", "bit-blast", "sat").solver()
    else:
        raise ValueError(f"unknown encoding {encoding}")
    solver.set("timeout", int(inst["timeout_ms"]))
    solver.set("random_seed", int(inst["seed"]) % 2**31)
    solver.add(constraint)
    start = time.perf_counter()
    result = solver.check()
    solve_seconds = time.perf_counter() - start
    status = "sat" if result == z3.sat else "unsat" if result == z3.unsat else "unknown"
    found = None
    if status == "sat":
        value = solver.model().eval(nonce, model_completion=True)
        found = value.as_long()
    return {
        "status": status,
        "nonce": found,
        "encoding": encoding,
        "build_seconds": build_seconds,
        "solve_seconds": solve_seconds,
        "dag_nodes": nodes,
        "cnf": cnf_stats(constraint) if inst.get("cnf_stats") else None,
        "stats": numeric_stats(solver.statistics()),
        "reason_unknown": solver.reason_unknown() if status == "unknown" else None,
        "z3_version": z3.get_version_string(),
    }


if __name__ == "__main__":
    json.dump(solve(json.load(sys.stdin)), sys.stdout)
