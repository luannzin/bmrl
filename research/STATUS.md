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
- **Discovery wave (2026-11-22)**, all from committed code:
  - *Work sharing* [work-sharing-0001]: an exact DAG count of every
    feasible way to batch headers. Only version rolling (overt AsicBoost)
    shares per-nonce work: 11.6% at 4 headers, 15.5% at most; every other
    pattern under 1%. GPU kernel v3 (8 version-rolled headers per nonce)
    measures 1.914 GH/s against v2's 1.752, +9.2% [bench-gpu-0006].
  - *Mainnet header atlas* [header-atlas-0001]: 977,066 headers from P2P
    peers validated by our own consensus code (0 failures). hash / target
    is uniform over every block (KS p = 0.869; per era 0.064 to 0.992).
    Miner fingerprints only: nonce bit 7 biased (|z| up to 149), BIP320
    version bits in 95.9% of 2026 blocks. Network 9.87e20 H/s.
  - *Evolved rules* [evolved-rules-0001]: 60,000 GP rules per round count.
    At 4 rounds the search rediscovered `bswap(bswap(n) + probe7)`, held-out
    A = 64.0 (positive control). 5, 6, 8, 64 rounds: best held-out A 0.994,
    1.021, 1.005, 1.008, none significant.
  - *Grover circuit* [grover-circuit-0001]: the 64-round header SHA256d as a
    reversible circuit (14,977 qubits, 82,496 Toffoli per half, 1.65e5 per
    iteration against the model's 1.47e5), correct on every input; simulated
    Grover reaches 0.9999 as theory says. With Pauli noise at 1e-3 per gate
    even 4 rounds is a random guess; 8 rounds drops to 0.099 at 1e-5.
- **Wave 2 (2026-11-22):**
  - *Dead-code frontier* [work-sharing-0002]: deciding the target needs
    9.3% of the r-round double hash's per-nonce work at 4 rounds, 33.7% at
    5, 55.9% at 8, 72.7% at 11 and 96.1% at 64. The target reads inner
    digest words W0..W(r-4), so the reduced-round shortcut is dead code
    that is gone by 11 rounds; at 64 only the early reject remains.
  - *Luck on the real chain* [header-atlas-0002]: no nonce, version-rolling
    or time bit, nor the previous block's luck, shifts hash / target
    (smallest p 0.016, threshold 1.7e-5 over 60 tests).
  - *Evolved rules at scale* [evolved-rules-0002]: 450,000 rules per round
    count, 56 held-out templates of 2^22 nonces: nothing at 5, 6, 8 or 64
    rounds; at 64 the best rule's held-out A is 0.998 (0.991..1.005).
- **Template luck (2026-11-22)** [template-luck-0001]: every nonce of 2,048
  templates on the GPU (2^43 header hashes, 74 min). Hit counts at 20 bits
  are Poisson (D/df 0.956, p 0.15); even and odd nonces do not correlate
  (r -0.010); the top 10% chosen on even nonces give A = 1.0008
  (0.9978..1.0039) on odd ones, 1.007 (0.960..1.057) at 28 bits. Template
  rate spread <= 0.13% SD (95%). Positive control: at 4 rounds the same
  selection gives A = 9.85. 5, 6, 8 rounds clean.

## 2. Disproven or invalidated

- **Mining shortcuts: none.** Every candidate algorithm (class selection,
  linear selection, neighbours, trail filters, early abort, SAT/SMT, Grover,
  template choice)
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

1. **GPU kernels v2 and v3: done** (3.48x, then +9.2%, see section 1). The
   source fingerprint changed several times since the last full run, so
   the full suite must be rerun from the current commit before
   `bmr research audit` passes again.
2. **`bmr research evolve` queue:** smt at 5-7 rounds (frontier), trail-sat
   with 4x the solver budget, new-seed replications, and first experiments
   for the untested families (probabilistic neutral bits, differential-linear).
3. **Derive the 5-round degree condition** and check it with z3 over all
   templates.
