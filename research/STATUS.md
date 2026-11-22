# Research status, 2026-11-21

Final run on commit `480c36f`; `bmr research audit` passes. Details and
record ids: [README.md](README.md). The characteristic and the mining
question in full: [differential-cryptanalysis/REPORT.md](differential-cryptanalysis/REPORT.md).

## 1. Experimentally demonstrated

- **The pipeline is correct.** SHA-256 and SHA-256d pass the NIST vectors.
  Three implementations agree on every round count. The header engine
  reproduces real mainnet blocks. Bitcoin Core accepted 204 regtest blocks
  from CPU and GPU, and one block from each backend on the end-to-end
  benchmark.
- **The real mining path is measured.** On a live template: 116.7 MH/s CPU,
  508.1 MH/s GPU, 622.1 MH/s combined. That is within run-to-run variation of
  raw SHA256d throughput, so the template work is too small to see. All
  1,504 hits were independently verified.
- **One reduced-round characteristic is fully explained.** A single-bit MSB
  difference passes the round after it enters with probability exactly
  2^-11. That is 11 independent bit conditions from signed differences,
  measured at 2^-11.010 (CI 2^-11.024 to 2^-10.996) over 83.9M pairs, five
  seeds and an independent implementation, with 0 counterexamples. The four
  measured trails are this same property at different rounds.
- **The 4-round header hash is affine in the nonce:** H7 = K + bswap(nonce).
  Solvers and neighbour search exploit it, at 4 rounds only.
- **Every result reproduces.** Each deterministic experiment repeated its
  digest bit for bit across runs. Out-of-process reproductions match.

## 2. Disproven or invalidated

- **Mining shortcuts from the characteristic: none.** At 64 rounds,
  neighbours of share hits are target hits at 1.004x the chance rate (CI
  0.983 to 1.026). Inputs meeting the trail conditions hit at 1.010x
  (0.990 to 1.031). The two strategies cost 0.9997x and about 81x the
  exhaustive work.
- **Statistical bias in full-round SHA-256 / SHA256d / header hashing:
  none.** This holds across 32 seeds and a calibrated control.
- **Invalidated by our own reruns, kept with errata:**
  - the schedule-folding timing in schedule-0001 (wrong constant);
  - the sequential and grouped trail estimators (15.9 and 6.9 bits off);
  - the SMT scaling interpretation (heavy-tailed solve times; "the encoding
    is the bottleneck" withdrawn);
  - two hardware register counts.
- A registry id bug was found and fixed before it overwrote anything.

## 3. Still uncertain

- **Solver scaling with target size.** The current data can't measure it.
  It needs fixed generous timeouts and more instances.
- **The 5-round anti-correlation** (A = 0.69). It is measured but not yet
  derived.
- **One header-specific trail (W3[10]) runs 0.09 bits above its estimate**,
  probably early-round non-uniformity with fixed padding.
- **FPGA throughput and every energy figure are estimates.** No RTL was
  synthesized and no power was measured.
- **Three hypotheses rest on one seed** (H-STAT-01, H-STAT-02, H-SCHED-01).

## 4. Does any result change the expected work of Bitcoin mining?

**No.** Every engineering optimisation lowers the cost per hash and leaves
the number of hashes per block at exactly the exhaustive value
(`expected_work_per_block_factor` 1.0). Every structure found vanishes long
before 64 rounds. The only measured work reduction is at 4 rounds per
compression (0.045x), where the function is affine in the nonce; Bitcoin
uses 64. Measured directly on full SHA256d with the real target comparison,
no trail-based strategy changes the probability of SHA256d(header) ≤ target.

## 5. The three most promising next directions

1. **GPU kernel v2 (engineering, measurable now).** Port the CPU kernel's
   host precompute, early reject and folded schedule to WGSL, and put
   several nonces in each thread. Today it does 491.8 MH/s; my rough ALU
   ceiling estimate for the RX 7600 is about 1.4 GH/s. Every change is gated
   by the existing GPU/CPU parity checks and the end-to-end benchmark.
2. **Close the open reduced-round questions properly.** Derive the 5-round
   anti-correlation as was done for 4 rounds. Rerun the SMT scaling study
   with fixed timeouts, 10+ instances and a native SAT solver. Add second
   seeds for the single-seed hypotheses. This is where the lab's methodology
   is strongest, and each item ends in an exact, reproducible statement.
3. **Real hardware numbers.** Emit RTL for one round stage from the
   hardware model, check it against the Rust simulator, and synthesize it.
   Measure power with a wall-plug meter. That replaces the two largest
   groups of assumptions (area/clock, energy) with measurements.
