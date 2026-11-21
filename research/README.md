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

The structural-exploration rows (H-CHAR-01, H-ALG-01, H-SCHED-01, H-SMT-02,
H-STAT-02, H-HW-01) are listed in `bmr research hypotheses`; see the sections
below.

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
