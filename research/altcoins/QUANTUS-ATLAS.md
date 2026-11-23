# Quantus QPoW output-bias atlas — result

Run 2026-11-23 from `crates/quantus-pow`. First built experiment of the
altcoin program. Honest headline: **null at full rounds.** No break; a
validated reference and a decisive negative on the cheap lens.

## What was built (and validated)

A bit-exact Rust reference of the live Quantus QPoW, pinned from
`Quantus-Network/chain` and `Quantus-Network/qp-poseidon`:
- Goldilocks field (`field.rs`), Poseidon2 width-12 permutation with the
  literal round constants (`poseidon2.rs`), and the `hash_squeeze_twice`
  sponge + the `block_hash || nonce` PoW hash (`lib.rs`).
- **Validated against qp-poseidon's own known-answer vectors**: the
  permutation on the zero state and on `[1..12]`, `apply_mat4`,
  `external_linear_layer`, `exp7`, and 9 `hash_bytes` digests (empty, zeros,
  `[1..8]`, `0xFF*32`, `"hello world"`, `0..32`, `0..64`) all match exactly
  (13 tests pass). So the attack runs on the real function, not an approximation.

## The attack

Output-bias atlas (`attack.rs`), the lab's `header-atlas` method pointed at
Quantus: over a sequential nonce sweep (as real mining does), does any
choosable nonce bit predict the smallness of the 512-bit output? A PoW only
needs to beat ~2^37 (genesis difficulty ~10^11), far below Poseidon2's full
security, so a cheap below-target predictor would be a mining break. Three
lenses: top-8-bit uniformity (chi-square), per-nonce-bit median split
(two-proportion z, Bonferroni over 32 bits), and a held-out tail
amplification A (learn the best single-bit selector for a rare tail hit on the
first half, measure it out-of-sample on the second half). Parallel across
cores; a reduced-round frontier is the positive control.

## Result

Reduced-round frontier (1,048,576 nonces each) and full schedule (30,000,000):

| rounds (ext_init, int, ext_term) | uniform chi2 p | min bit p (Bonferroni 1.56e-3) | tail A (K=10) 95% CI | verdict |
| --- | --- | --- | --- | --- |
| 0, 0, 0 (pure linear control) | 0.000 | — | degenerate | **BIAS (caught)** |
| 1, 0, 0 | 0.823 | 1.2e-1 | [0.82, 1.06] | null |
| 2, 0, 0 | 0.626 | 1.3e-1 | [0.96, 1.21] | null |
| 4, 0, 0 | 0.124 | 2.3e-2 | [0.94, 1.19] | null |
| 4, 4, 0 | 0.853 | 6.5e-3 | [0.90, 1.16] | null |
| 4, 11, 4 | 0.177 | 1.2e-2 | [0.90, 1.15] | null |
| **4, 22, 4 (live Quantus), 30M** | **0.711** | **5.5e-2** | **0.999 [0.976, 1.022]** | **null** |

- **Full rounds: null.** Over 30M sequential nonces the output is uniform, no
  nonce bit predicts smallness (min p 5.5e-2, well above the Bonferroni gate),
  and the best out-of-sample tail selector gives A = 0.999, 95% CI
  [0.976, 1.022] — a statistical mining edge above ~2.2% is excluded.
- **Harness has power:** the 0-round pure-linear control is flagged (chi2
  p = 0). Statistical structure collapses already after one external round,
  the same fast-mixing behaviour the Bitcoin run saw past its round cliff.

## Verdict and next

The cheap statistical lens finds no edge on Quantus — exactly as it did on
SHA256d. "Young and unaudited" did not mean weak rounds: Quantus runs the full
8+22 Poseidon2, believed secure. This confirms the structural law and saves
chasing a dead lens.

The only remaining C3 surface is **algebraic** (degree-annihilation / CICO /
Groebner over GF(p) at PoW-security, not full security) — the heavy
`algebraic-engine` prime-field build. Expected payoff on full-round Poseidon2
is low (published attacks like eprint 2026/1254 reach only reduced rounds),
and Quantus's pot is small regardless. So this is a decision point, not an
automatic next build: the validated reference stands as the first weapon
component, reusable for any future Goldilocks-Poseidon2 target.

## Mining economics verdict (honest, 2026-11-23)

A working CPU miner was built on the validated reference (`miner.rs`,
`bin/mine.rs`): the exact node rule (`target = U512::MAX / difficulty`, strict
big-endian compare), a nonce search, and a benchmark. It solves real blocks
(a difficulty-2^24 block found in 9.8M hashes / 7.9s, independently
re-verified) and measures **1.217 MH/s on the Xeon E5-2680 v4 (28 threads)**.

Live Quantus economics (herominers API / Kryptex / CMC, 2026-11-23): network
difficulty ~3.253e14, reward 0.30 QTC/block, ~12-14.5 s blocks, price ~$30.6,
24h volume ~$0.1-0.7M. Daily yield = `hashrate * 86400 / difficulty * 0.30`.
User tariff R$1.029/kWh ≈ $0.175/kWh.

| Setup | hashrate | gross $/day | power $/day | net $/day |
| --- | --- | --- | --- | --- |
| CPU (measured) | 1.22 MH/s | $0.003 | ~0.63-0.93 | **~ -0.7** |
| RX 7600 GPU (est., tuned) | ~200-250 MH/s | $0.49-0.61 | ~0.69-0.93 | **~ -0.3 to -0.1** |
| break-even | ~310-420 MH/s | = power | = power | 0 |

- **Quantus does not pay on this hardware at this tariff.** CPU is a dead loss.
  Even a best-case RX 7600 kernel (no public AMD miner exists; ~200 MH/s
  expected, scaling from NVIDIA ~1.3 GH/s on a 4090) lands below break-even,
  which sits at ~310-420 MH/s. And at ~$0.1-0.7M daily volume the order book
  could not absorb selling anyway.
- **Conclusion: the GPU kernel is not worth building for Quantus** — it cannot
  turn negative economics positive. The miner's value is as a validated
  capability and as the measurement that settles this, not as income.

This closes the Quantus line on both axes: no break (statistical null; full
rounds), and no profit (negative even optimally). Consistent with the
program's structural law — the exploitable/young coins are also the small,
unprofitable ones.
