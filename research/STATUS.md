# Research status, 2026-11-22

Final run on commit `49a3e3c`; `bmr research audit` passes; every older
experiment kind reproduced its previous result digest bit for bit. Details:
[README.md](README.md) (structural run), [breakthrough/REPORT.md](breakthrough/REPORT.md)
(structural-shortcut search), [BOARD.md](BOARD.md) (every hypothesis, generated).

## 1. Experimentally demonstrated

- **The pipeline is correct.** NIST vectors, three SHA-256 implementations
  on every round count, real mainnet headers, 204 regtest blocks accepted in
  the final run (102 per backend), one live-template block per backend.
- **Throughput (cost per hash only):** CPU 116.6 MH/s, GPU 496.6 MH/s,
  CPU + GPU 574.6 MH/s concurrent [bench-compare-0003]. GPU kernel v2
  (2026-11-22): 1.749 GH/s against v1's 502.7 MH/s on the same run, 3.48x,
  same digests and hits [bench-gpu-0005]; 102 regtest blocks accepted
  [bench-regtest-0007].
- **Every nonce of 16 templates behaves like a random function at 64
  rounds** [nonce-atlas-0002]: image size, top-word zeros, leading zeros,
  cube and sub-cube sums all at the null; the four mainnet winning nonces
  found. No input-selection strategy (2^25 linear half-spaces, 3k class
  strategies, 1,555 neighbour strategies, all 2^32 differences among hits)
  lowers the held-out work per hit; a fixed-bit strategy saves < 0.4% (95%).
- **Solver-optimal nonce characteristics** cost 0, 11, 38 and >= 50 bits
  through rounds 3, 4, 5, 6 of the second block; measured 2^-11.007 and
  2^-35.7 [trail-sat-0001]. Time freedom does not help. No nonce pair per
  template follows past round 5.
- **Exact reduced-round identities, proved for all templates:** 4-round
  H7 = K + bswap(nonce); 5-round H7 = K + bswap(n) + Σ1(X) + Ch(X, IV4, IV5).
- **New 5-round structure:** H7 bits 1 and 0 sum to zero over the nonce's
  low byte too often (0.5272, z = 445; 0.5038, z = 63). Nothing at 6 or 8
  rounds.

## 2. Disproven or invalidated

- **Mining shortcuts: none.** Every candidate algorithm (class selection,
  linear selection, neighbours, trail filters, early abort, SAT/SMT, Grover)
  either measures at the exhaustive work at 64 rounds, is cost per hash
  only, or is a speculative model.
- **Invalidated by our own checks, before publication:** a normal
  approximation on tiny expected counts (false significance); a solver
  window that let a late W3 difference count for free; W0 trails, which no
  miner can reach under one midstate (errata on trail-search-0001/0002); an
  incomplete provenance fingerprint.
- Earlier corrections (schedule-0001, estimators, SMT scaling, register
  counts, registry ids) stand as recorded.

## 3. Still uncertain

- **Characteristics past round 5:** the solver bound is >= 50 bits (nonce)
  and >= 39 (nonce + time) after the time budget; the optima are unknown.
- **Why H7 bits 0 and 1 lose degree at 5 rounds:** located and reduced to
  c ^ X0 ^ X6 ^ X11 ^ X25 for bit 0; the condition on the fixed bits is not
  derived.
- **Solver scaling with target size**, the W3[10] trail offset, FPGA
  throughput and every energy figure (unchanged from 2026-11-21).
- **Every hypothesis rests on one run seed** (kinds use several seeds or
  templates inside); the board queues reruns on a new seed.

## 4. Does any result change the expected work of Bitcoin mining?

**No.** At 64 rounds nothing departs from the random-function null, over the
full nonce space of every tested template, and no held-out strategy beats
exhaustive search. Work reductions exist only at 4 rounds per compression;
measurable structure stops at 5. Grover cuts queries in a model but needs
about 4.5 × 10^15 machines to meet the block interval at 80 bits.

## 5. Next

1. **GPU kernel v2: done** (3.48x, see section 1). It changed the source
   fingerprint, so the full suite must be rerun from the current commit.
2. **`bmr research evolve` queue:** smt at 5-7 rounds (frontier), trail-sat
   with 4x the solver budget, new-seed replications, and first experiments
   for the untested families (probabilistic neutral bits, differential-linear).
3. **Derive the 5-round degree condition** and check it with z3 over all
   templates.
