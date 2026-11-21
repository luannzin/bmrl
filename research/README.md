# Research findings

Every number below comes from a verified, reproduced record in
`experiments/results/` (ids in brackets). The seed is 1112363596 unless a
record says otherwise. "Deviation" always means "distinguishable from the
random baseline at the record's stated power". None of the results below
reduces the expected work to find a Bitcoin block, and no full 64-round
deviation was found.

## Summary

| Hypothesis | Primitive | Status | What the data says |
| --- | --- | --- | --- |
| H-AVAL-01 | sha256-compression | supported, reduced-round only | Avalanche deviations through 22 rounds; none at 24, 32 or 64 |
| H-DIFF-01 | sha256-compression | supported, reduced-round only | Repeated output differences up to 2 rounds after a 1-bit difference enters |
| H-STAT-01 | bitcoin-header-sha256d | not supported (one seed) | No deviation at 8, 12, 16, 20 or 64 rounds (4.2M hashes each) |
| H-SMT-01 | bitcoin-header-sha256d | supported, reduced-round only | Z3 wins only at 4 rounds, where H7 is affine in the nonce (explained below) |

| H-CHAR-01 | sha256-compression | supported, reduced-round only | XOR trails followed up to 2 rounds after entry; grouped estimator within 6 bits where measurable |
| H-ALG-01 | sha256-compression | supported, reduced-round only | Zero-sum cubes up to 5 rounds after entry; carry-free agreement above chance up to 4 rounds |
| H-SCHED-01 | sha256-message-schedule | not supported (one seed) | Schedule invertible and unbiased; only W16, W17 are nonce-free; folding saves 2.7% of a double compression |
| H-SMT-02 | bitcoin-header-sha256d | supported, reduced-round only | Only 4 rounds beat brute force; heavy-tailed solve times make the scaling fits unreliable |
| H-STAT-02 | sha256, sha256d, header | not supported (one master seed) | 32 seeds, all p-value distributions uniform; non-SHA control calibrated |
| H-HW-01 | datapath | modelled | 6 pipeline variants exact in simulation; folding saves 11.6% adders |

## Corrections

Three records carry errata (`bmr research show <id>`, field `errata`). Each is
superseded by a v2 rerun:

- **schedule-0001**: the constant-folded outer schedule had a wrong constant,
  σ0(256) = 0x04000022 instead of 0x00400022. It differed from the generic
  schedule on all 1024 inputs, so its timing is invalid, and v1 verification
  didn't check that. v2 builds the constants from calls on literals, and
  verification fails unless the folded schedule matches the generic one.
- **characteristic-0001**: the sequential estimator charged a lone difference
  once per addition in a five-term sum. It was up to 15 bits too pessimistic.
- **smt-scaling-0001**: the time budget ran out inside the first encoding, so
  the encoding comparison never happened.
- **hardware-0001 and hardware-0002**: register counts kept schedule words
  W61..W63 alive in early-reject designs, though the outer block stops after
  round 60. The two records got it wrong in different variants. hardware-0003
  is correct, and a test now requires early reject to need fewer registers.
- **smt-scaling-0002**: the measurements stand, but heavy-tailed solve times
  make its frontiers and growth fits unreliable (see the SAT/SMT section). Not
  superseded yet.

## Reduced-round avalanche [reduced-round-0001]

Strict avalanche criterion on the compression function, 16,384 random
(chaining value, block) pairs per round count, all 512 x 256 bit pairs.

| Rounds | Bonferroni-significant pairs | Max bias |
| --- | --- | --- |
| 16 | 30,821 | 0.5 (deterministic pairs) |
| 20 | 3,434 | 0.5 |
| 21 | 853 | 0.438 |
| 22 | 40 | 0.084 |
| 24 | 0 | 0.0185 |
| 32 | 0 | 0.0189 |
| 64 | 0 | 0.0186 |

From 24 rounds on, the largest |z| (about 4.8 over 131,072 cells) is what
noise alone produces. Detectable single-cell bias at this sample size is
about 0.023, so smaller biases are not excluded.

## Single-bit XOR differentials [differential-0001]

131,072 pairs per configuration. For differences in W15 (enters at round 15)
and W0 (round 0), repeated 256-bit output differences appear only up to 2
rounds after the difference enters. The weight distribution of output
differences departs from Binomial(256, 1/2) up to 6 rounds after entry
(21 rounds for W15). Nothing is detectable at 64 rounds.

## Statistical tests of header SHA-256d [statistical-0001]

64 random headers x 65,536 consecutive nonces per round count. Bit
frequencies, leading-zero distribution and consecutive-nonce agreement show
no deviation, even at 8 rounds. Full-round 8-bit target hit rate: 0.003883,
expected 0.003906, 95% CI 0.003824 to 0.003943.

The double hash hides reduced-round structure that the compression-level
tests above expose: the outer compression re-randomises its input.

## Z3 on reduced-round header SHA-256d [smt-0001]

Target: 8 leading zero bits, 2 random headers per round count, 30 s timeout.

- 4 rounds: Z3 finds a valid nonce in about 1.6 ms. Brute force from nonce 0
  finds none in its 2^20-nonce cap.
- 8 and 12 rounds: Z3 solves, but much slower than brute force.
- 16 rounds: timeout.

The 4-round result has a closed form (pinned by the unit test
`four_round_h7_is_affine_in_the_nonce`):

- Inner rounds 0 to 2 do not see the nonce, so after 4 rounds
  a = c + W3 and e = c' + W3, with W3 = bswap(nonce).
- The outer compression's H7 = IV7 + e0 is then exactly K + bswap(nonce)
  (mod 2^32).
- The hash number's most significant byte is H7's low byte, so it depends only
  on the nonce's most significant byte. Scanning from 0 never changes that
  byte. The solver inverts the affine map.

This is structure of the 4-round function only; at 5 rounds the relation
already fails (same test).

## SAT/SMT scaling [smt-scaling-0002]

Rounds 4 to 16, target sizes 2 to 16 bits, 3 random headers per point,
adaptive timeouts up to 30 s, 900 s budget. Word-level QF_BV (`qfbv`) and
bit-blasted SAT (`bitblast-sat`) alternate at every point. 129 solver runs,
every answer verified.

- **Only 4 rounds beat brute force**, for the affine reason above.
- **Solve times are heavy-tailed, and that decides everything else here.**
  At 6 and 8 rounds an instance either solves in 0.1 to 0.5 s with about 100
  to 200 conflicts, or runs past its 2 to 4 s timeout with 15,000 to 40,000.
  The target size barely changes which one happens.
- **So this run can't compare the encodings or measure growth.** The
  adaptive timeout (8x the previous solve time, at least 2 s) stopped
  bitblast-sat at 8 rounds and 4 bits with a 3.2 s limit. At that same point
  qfbv failed 2 of 3 instances and only went on because one solved. The
  fitted growth rates (2^0.34 to 2^0.60 per target bit, against about 2^0.92
  for brute force) mostly count the lucky fast solves. The record carries an
  erratum saying so.
- **Bit-blasted model size**, from Z3's CNF: 33 clauses at 4 rounds, 12,347 at
  6, 62,340 at 8 and 172,574 at 10.

Measuring scaling properly needs a fixed, generous timeout, at least ten
instances per point, and the fraction solved next to the median time,
with both encodings on the same instances.

## Differential characteristics through 64 rounds [characteristic-0002]

For each single-bit message difference, the carry-free XOR trail is built
for all 64 rounds, and 1,048,576 random pairs are traced against it.

| Difference | Followed (>= 2 pairs) through | Last biased state bit | Estimate at 64 rounds |
| --- | --- | --- | --- |
| W15 bit 31 | round 17 | round 22 | 2^-10537 |
| W15 bit 0 | round 17 | round 22 | 2^-10475 |
| W8 bit 31 | round 10 | round 15 | 2^-11682 |
| W0 bit 31 | round 2 | round 7 | 2^-12860 |

At round 17, 503 of 1,048,576 pairs follow the W15 bit 31 trail (2^-11.0).
Two estimators are compared with every measurable round:

- **Sequential**: every modular addition charged with Lipmaa–Moriai. Up to
  15 bits too pessimistic.
- **Grouped**: zero-difference operands of a multi-operand sum are added
  first, and the difference is charged once. Within 6 bits everywhere it can
  be measured, mean error +0.35 to +3.0 bits, still on the pessimistic side.

The estimates at 64 rounds are extrapolations, not evidence. They are listed
to show the scale: no single-bit XOR trail comes anywhere near 2^-256.

## Algebraic degree and carries [algebraic-0001]

- **Cube sums.** Cubes of 4 to 16 bits in W0 or W15 sum to zero on more
  output bits than chance allows, up to 5 rounds after the word enters. The
  proven degree bounds (exact ripple-carry propagation) were never
  contradicted: 0 violations over every configuration. 79 zero-sum cubes are
  stored as witnesses.
- **Carries.** The real compression agrees with its carry-free (XOR) model on
  52.4% of output bits after 1 round, 51.0% after 3 and 50.4% after 4. From
  6 rounds on it is indistinguishable from 50%.

## Message schedule [schedule-0002]

- Linearized over GF(2), every window of 16 consecutive words has rank 512,
  so the expansion is invertible. Forcing j expanded words to vanish leaves
  exactly 512 - 32j free message bits.
- Through W16..W63, the lightest expansion of a 1-bit message difference
  weighs 466 bits and of a 2-bit difference 489. The longest run of zero
  expanded words is 8.
- The real schedule agrees with the linearized one beyond chance only up to
  W19, and shows no biased bits or correlated neighbouring words.
- For Bitcoin headers, only W16 and W17 of the second block are independent
  of the nonce, and the CPU kernel already precomputes both. In the outer
  block no word is independent of the inner digest. Folding its zero padding
  terms leaves 125 additions and 86 σ evaluations per nonce instead of
  144 and 96.
- Measured on the generic path: folded 99.45 ns vs 118.25 ns, 18.81 ns or
  2.7% of one double compression (704.1 ns). Whether the optimised kernels
  already get this from the compiler hasn't been measured.

## Multi-seed tests [multiseed-0001]

32 independent seeds, 131,072 hashes per seed and cell, for SHA-256 and
SHA-256d of headers over the nonce and SHA-256d of random inputs, at 16, 20,
24 and 64 rounds. Under the null hypothesis each test's p-values are uniform
across seeds. A KS test decides.

- No cell departs from uniform. The non-SHA control doesn't either, so the
  battery is calibrated at this size.
- Full-round 8-bit target hit ratios (observed / expected): 0.990
  (CI 0.972 to 1.008) for single SHA-256, 1.004 (0.988 to 1.021) for header
  SHA-256d, 1.007 (0.992 to 1.021) for SHA-256d of random inputs.

## Hardware datapaths [hardware-0003]

Six fully pipelined variants are simulated cycle by cycle. Every output
matches the software reference, and the independent SHA-256 on an unseen
header. Each pipeline takes one nonce per cycle.

| Variant | Stages | 32-bit adders | Register bits |
| --- | --- | --- | --- |
| midstate | 128 | 1,201 | 93,696 |
| + precompute 3 rounds + early reject + constant folding | 122 | 1,062 | 81,824 |

Constant folding on a design without midstate removes block 1 and the first
three second-block rounds by itself. The result is exactly the midstate +
precompute datapath, which the test suite checks.

The FPGA mapping is a model with stated assumptions (32 LUTs per 32-bit
operator, assumed clocks and toggle energies). Up to 6.8 GH/s on a Virtex
UltraScale+ VU9P, against 115.8 MH/s measured on this lab's CPU and
498.8 MH/s on its GPU. These are estimates until RTL is synthesized.
