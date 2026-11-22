# The round-17 characteristic and the mining question

This report covers the single-bit XOR characteristics that the lab could
measure, why they have the probability they have, and whether any of them
helps find a Bitcoin block. Short answer to the last part: no. Everything
below is about reduced-round SHA-256. Nothing is extrapolated to 64 rounds.

Records: `characteristic-audit-0001`, `trail-search-0001`,
`characteristic-0003` (see `experiments/results/`). Reproduce:

```powershell
.\target\release\bmr research characteristic-audit
.\target\release\bmr research trail-search
.\target\release\bmr research characteristic
.\target\release\bmr research reproduce characteristic-audit-0001
```

## Notation

One SHA-256 round on state (a, b, c, d, e, f, g, h) with message word W_t:

    T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t
    T2 = Σ0(a) + Maj(a, b, c)
    (a, b, c, d, e, f, g, h) <- (T1 + T2, a, b, c, d + T1, e, f, g)

Additions are mod 2^32. A pair of messages (M, M ^ Δ) *follows* a trail when,
at every round, both the schedule difference and the full 256-bit state
difference equal the trail's.

## The characteristic

Input difference: bit 31 (the MSB) of W15, nothing else.

- **Rounds 0 to 14:** no difference.
- **Round 15:** T1 gets the difference 2^31. An MSB difference produces no
  carry, so a and e both get exactly 2^31, with probability 1.
- **Schedule:** W16 = σ1(W14) + W9 + σ0(W1) + W0 doesn't contain W15, so
  ΔW16 = 0.
- **Round 16** (state index 16 to 17): the inputs differ only in a and e, by
  2^31. Rotation is linear, so Σ1(e) differs by Σ1(2^31) = 2^25 + 2^20 + 2^6
  (0x02100040) and Σ0(a) by Σ0(2^31) = 2^29 + 2^18 + 2^9 (0x20040200).

The trail requires the round's output difference to be

    Δa' = 0x22140240,  Δb' = 0x80000000,  Δe' = 0x02100040,  Δf' = 0x80000000,

with zero difference in c', d', g', h'.

### The 11 exact conditions

Write x_i for bit i of x in the first message of the pair.

| # | Condition | Why |
| --- | --- | --- |
| 1 | f_31 = g_31 | Ch(e^2^31, f, g) differs from Ch(e, f, g) at bit 31 by f_31 ^ g_31 |
| 2 | b_31 = c_31 | Maj(a^2^31, b, c) differs at bit 31 by b_31 ^ c_31 |
| 3-5 | e'_i = Σ1(e)_i for i = 6, 20, 25 | see below |
| 6-8 | a'_i = Σ1(e)_i for i = 6, 20, 25 | see below |
| 9-11 | a'_i = Σ0(a)_i for i = 9, 18, 29 | see below |

With conditions 1 and 2, Ch and Maj contribute no difference. The *signed*
(modular) difference of T1 is then

    δT1 = Σ_{i ∈ {6,20,25}} s_i 2^i,   s_i = +1 if Σ1(e)_i = 0, otherwise -1,

because flipping bit i of Σ1(e) adds or subtracts 2^i. Likewise δT2 has
signs from Σ0(a) at bits 9, 18, 29.

- e' = d + T1, so δe' = δT1. Adding s_i 2^i flips exactly bit i, with no
  carry, if and only if e'_i already equals the value it moves away from:
  e'_i = Σ1(e)_i. These are conditions 3 to 5.
- a' = T1 + T2, so δa' = δT1 + δT2. The six bits are disjoint, which gives
  conditions 6 to 11 by the same argument.

So the pair follows the trail through round 17 **if and only if** all 11
conditions hold. Each one is an equality between an output bit and an
input-derived bit, with no two sharing an output bit. For a uniformly
distributed state they are independent fair coins, so the probability is
exactly 2^-11.

What does *not* need to hold: the XOR differences of T1 and T2 themselves.
Many carry patterns inside T1 give the same signed difference. That is where
the earlier estimators lost bits:

| Estimator | Round-17 cost | Why |
| --- | --- | --- |
| sequential (v1) | 26 bits | Lipmaa–Moriai on each of T1's four additions (3 bits each), plus T2, a', e', Ch, Maj |
| grouped (v2) | 17 bits | T1's difference charged once, but ΔT1 and ΔT2 still required as XOR differences: 6 unnecessary conditions |
| signed (v3) | 11 bits | only a' and e' must show their XOR difference |
| measured | 2^-11.03 | 503 of 1,048,576 pairs in characteristic-0002 |

### Measurement

characteristic-audit-0001: 5 independent seeds × 2^24 random (chaining
value, message) pairs, plus 2 × 2^22 pairs in the independent Python/numpy
implementation with a different random generator (PCG64).

| Quantity | Value |
| --- | --- |
| Pairs following through round 17 | 40,668 of 83,886,080 |
| Probability | 2^-11.010, 95% CI 2^-11.024 to 2^-10.996 |
| Per seed | 8109, 7997, 8308, 8103, 8151 (homogeneity p = 0.18) |
| Python/numpy | 4,101 of 8,388,608 = 2^-10.998 (agreement p = 0.61) |
| Pairs satisfying all 11 conditions | 40,668, the same pairs |
| Conditions hold but no follow / follow but conditions fail | 0 / 0 |
| Each condition alone | 0.5000 to 0.5001 |
| Most dependent pair of conditions | \|z\| = 2.76 (threshold 3.74 for 55 pairs at α = 0.01) |
| Conditions implied by the others | 0 of 11 |
| All 2,048 satisfied-condition patterns vs independence | chi-square p = 0.31 |

So the probability is 2^-11 to within the measurement, the 11 conditions are
exactly the event, and they are independent. No smaller equivalent set
exists in bit terms: any set of conditions that defines this event must
carry −log2 P = 11 bits. They can be regrouped (for example
e'_i = a'_i = Σ1(e)_i), but not reduced.

Across every round where pairs were observed, for all four trails, the
signed estimator is within 0.03 to 0.09 bits of the measured rate.
The grouped estimator is off by up to 6.9 bits and the sequential one by up
to 15.9 (characteristic-0003).

### Relationship between the four trails

The construction above never used the round index. Any MSB difference that
enters through W_t, while every other difference is zero, produces the same 11
conditions one round later:

| Trail | Measured through | Conditions | Measured (95% CI) | Template |
| --- | --- | --- | --- | --- |
| W15 bit 31 | round 17 | 11 | 2^-11.010 (−11.024 to −10.996) | reference |
| W8 bit 31 | round 10 | 11 | 2^-10.998 (−11.012 to −10.984) | identical |
| W0 bit 31 | round 2 | 11 | 2^-11.001 (−11.015 to −10.987) | identical |
| W15 bit 0 | round 17 | 2 + 11 | 2^-13.000 (−13.028 to −12.972) | rotated by one bit |

Each trail shows 0 counterexamples in either direction, and Python agrees
with each (p = 0.61, 0.07, 0.62, 0.69).

A bit-0 difference isn't free when it enters: a'_0 = W15_0 and e'_0 = W15_0
must hold at round 15, which is 2 more conditions. After that, Σ1(2^0) =
2^26 + 2^21 + 2^7 and Σ0(2^0) = 2^30 + 2^19 + 2^10. That is the bit-31
template with every position moved up by one.

So these are not four discoveries. They are one local property of the
round function, seen at four places.

### Why the trail stops

At round 18 the trail has 7 active bits in a, 3 in e, the MSB in b and f, and
ΔW17 = σ1(2^31) = 2^21 + 2^14 + 2^12 enters too. Every one of those bits
feeds Σ0, Σ1, Ch and Maj, so the number of conditions grows faster than one
round can absorb. No pair among 2^20 (characteristic-0002) or 5 × 2^24
(characteristic-audit-0001) followed past round 17.

## From a characteristic to a search

### The mining problem

Find a header, in practice a nonce plus the extranonce in the coinbase,
such that SHA256d(header), read as a little-endian 256-bit number, is at most
the target T. For a target with k leading zero bits, P_T = 2^-k per header.
Exhaustive search needs W_exh = 2^k SHA256d evaluations per hit on average.

A differential characteristic is a statement about *pairs* (x, x ^ Δ). The
target is a statement about *one* input. A characteristic can only lower the
work if it makes the target event more likely for some inputs a miner can
choose. There are three ways that could happen, and the lab measured each one
on the real header layout. Only W0 (merkle tail), W1 (time) and W3 (nonce)
of the second block vary; the padding words are fixed.

### Strategy 1: neighbours of share hits

Find a share, x with k_s < k leading zero bits (cost 2^k_s). Then evaluate
its neighbours x ^ Δ for Δ in a set D, hoping they reach k bits. Let

    q_Δ = P[ H(x ^ Δ) <= T | H(x) <= T_share ].

Count every evaluation and every hit, from the scan and from the neighbours.
Per share the scan costs 2^k_s evaluations and yields 2^(k_s - k) target hits
on its own, and the neighbours cost |D| and yield Σ q_Δ. So

    W_1 = (2^k_s + |D|) / (2^(k_s - k) + Σ_Δ q_Δ).

If q_Δ = 2^-k for every Δ, the neighbours are no better than fresh nonces,
and W_1 = 2^k exactly. The strategy wins only if the mean amplification
A = q̄ / 2^-k exceeds 1. For that, a difference would have to survive all 125
nonce-dependent rounds of the two compressions after the midstate and leave
the hash's top k
bits unchanged.

### Strategy 2: filter by the trail's conditions

Before hashing a nonce, compute the first 5 rounds of the second block
(5/128 of a SHA256d) and keep it only if the 11 round conditions hold
(P_C = 2^-11). Let A_C = P[H <= T | C] / 2^-k. Then

    W_2 = (5/128 + P_C) / (P_C · A_C · 2^-k) = W_exh · (1 + 5/(128 P_C)) / A_C.

With P_C = 2^-11, the filter breaks even only when A_C > 81. A filter that
is independent of the output makes the search 81 times slower.

### Strategy 3: pairs of hits

A characteristic could at best produce a second valid header for the same
template. A block needs one. Two valid headers for the same block are worth
the same as one, so this route has no mining value. The only version with
value is strategy 1, where the easier event (a share) predicts the harder
one (a block).

### Trail search over what a miner controls

trail-search-0001 built the signed-difference trail for 592 differences in
the words a miner can change: every single bit of W0, W1 and W3, and every
pair of bits in W3 (the nonce). It kept each trail as long as its estimate
stayed within 24 bits.

- The best trails (W3 bits 5, 10, 24 and 31) last until round 5, at
  2^-11. The nonce enters at round 3, so that is the same 2 rounds as above.
  The next tier (W3 bits 1, 12, 21; bit 0) costs 12 or 13 bits for the same
  rounds.
- No controllable difference survives past round 5 within 24 bits.
- Measured on header-shaped pairs (fixed padding, random midstate),
  4,194,304 pairs each:
  - W3[5]: 2^-11.006, estimate inside the CI.
  - W3[24]: 2^-11.027, inside.
  - W3[10]: 2^-10.907 (CI 2^-10.968 to 2^-10.847), so the estimate is
    0.09 bits off. With the padding fixed, the state at round 4 is not yet
    uniform. It is a small effect, and it doesn't matter for anything below.

The second header block then has 59 more rounds and the outer compression 64,
with no trail anywhere near them.

### Measured conditional probabilities

trail-search-0001. For each round count: 64 random headers, nonces scanned in
a scrambled order, until 2^20 share hits (k_s = 8) over about 2.7 × 10^8
nonces. Every share's 32 neighbours were evaluated, one per nonce bit; the
top trail differences are all nonce bits, so they're among them. Target:
k = 12 leading zero bits. Rounds below 64 mean all three compressions cut to
that many rounds. Significance uses Bonferroni over 272 tests, |z| > 4.13.

| Rounds | Neighbour amplification A (95% CI) | Δ with significant A | W_1 / W_exh |
| --- | --- | --- | --- |
| 4 | 192.0 (191.7 to 192.3) | 32 of 32 | 0.045 |
| 5 | 0.691 (0.674 to 0.710), z = −28 | 25 of 32 | 1.035 |
| 6 | 1.007 (0.985 to 1.029) | 0 | 0.9994 |
| 8 | 1.018 (0.996 to 1.040) | 0 | 0.9979 |
| 12 | 1.011 (0.990 to 1.033) | 0 | 0.9990 |
| 16 | 0.987 (0.966 to 1.009) | 0 | 1.0010 |
| 24 | 1.007 (0.986 to 1.029) | 0 | 0.9993 |
| **64** | **1.004 (0.983 to 1.026)** | **0** | **0.9997** |

Condition filter (strategy 2), the 11 conditions of the nonce-MSB trail at
round 4, at 64 rounds. The amplification is measured at three levels,
because at the 12-bit level only 35 hits fall among filtered nonces:

| Level | Hits among filtered nonces | A_C (95% CI) |
| --- | --- | --- |
| 4 bits | 8,772 | 1.010 (0.990 to 1.031) |
| 8 bits | 524 | 0.966 (0.886 to 1.052) |
| 12 bits | 35 | 1.032 (0.742 to 1.435) |

A_C ≈ 1 at every round count from 5 to 64. With P_C ≈ 2^-11 the filter
needs A_C > 81 to break even, so as a search algorithm it is about 81 times
*slower* than exhaustive search.

What the reduced-round rows mean:

- **4 rounds** is the affine structure found earlier (`smt-0001`): H7 =
  K + bswap(nonce), so the hash number's top byte depends only on the
  nonce's top byte. Flipping a nonce bit in that byte always destroys a share
  (A = 0 for W3 bits 0 to 7). Flipping a higher bit keeps the share and
  re-randomises only the next 4 bits (A ≈ 256). The neighbour strategy needs
  0.045 of the exhaustive work, at 4 rounds only.
- **5 rounds** shows real structure in the other direction: neighbours of
  shares are 31% *less* likely to be target hits. That makes the neighbour
  strategy 3.5% more expensive than exhaustive search. The best single
  difference there (W3[5], A = 1.33) would save about 0.07%.
- **From 6 rounds on**, nothing is distinguishable from independence.

## Conclusion

1. **The characteristic is real and fully explained.** Single-bit MSB
   differences pass one round of SHA-256 compression with probability
   exactly 2^-11. That is 11 independent bit conditions from signed
   differences, measured at 2^-11.010 (CI 2^-11.024 to 2^-10.996) over
   83.9 million pairs, five seeds and two independent implementations. The
   four measured trails are this one local property at different rounds. It
   is a statement about 2 rounds after a difference enters, and says nothing
   about 64-round SHA-256.
2. **It does not give a search algorithm for Bitcoin.** The trail stops 2
   rounds after the nonce enters, and 123 of the 125 nonce-dependent rounds
   remain (second block rounds 3 to 63, then the 64 outer rounds). Strategy 1 (neighbours of shares) and strategy 2 (filtering by
   the conditions) were each measured on full SHA256d with the real target
   comparison and the real header layout. Neither changes the target-hit
   probability: A = 1.004 (CI 0.983 to 1.026) and A_C = 1.010 (CI 0.990 to
   1.031). Expected work: W_1 = 0.9997 × W_exh, and W_2 ≈ 81 × W_exh.
3. **No reduction in Bitcoin mining work has been demonstrated.** The only
   work reduction anywhere in these measurements is at 4 rounds per
   compression (0.045 × W_exh), where the function is affine in the nonce.
   Real Bitcoin uses 64. The validated characteristic is a cryptanalytic
   finding about reduced-round SHA-256, not a mining shortcut.
