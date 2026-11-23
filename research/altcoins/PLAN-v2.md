# Altcoin PoW: the money plan (v2)

Written 2026-11-23, after one day of desk research on the v1 candidates;
reweighted the same day to break-first after the user set the objective to
"win the most, soonest, max effort, time and effort no object." Supersedes
the candidate ranking and pipeline in [PLAN.md](PLAN.md); v1's economics,
kill rule and ethics rules still hold. Nothing here is a result yet. Every
number is quoted from a source or derived from one, and phase 0 re-checks all
of them. Sources at the end.

## Objective

Maximize expected winnings, soonest. Not day-0 cash flow; the biggest win
reachable. One target only, chosen for the largest `pot x P(break)`, and the
lab's full machinery thrown at the break. A small honest income is a
by-product of the attack harness, not the goal, and its sign does not change
the decision.

## Phase 0 finding (2026-11-23): the headline break is refuted on the live protocol

Pearl source read in detail. The low-rank-through-transcript attack described
below is **dead against the live INT protocol**, by the exact code:

- The transcript is a running int32 prefix sum (`tCrC`, cleared once per
  output tile), XOR-reduced over every element of the tile every R columns,
  folded with `rotl_xor<13>`, then a final keyed blake3 compared to target
  (`pow_utils.hpp`, `collective_mainloop.hpp`, `pearl_gemm_kernel.h`). This
  materializes the full bM x bN int32 tile at each of K/R checkpoints, so the
  work is O(M x N x K) even when A, B and the rank-R noise make the end
  product low rank. XOR of int32 prefix sums is non-linear in the operands;
  the code offers no per-chunk shortcut. With A=B=0 the product is the rank-R
  `E_A E_B^T` (each noise entry O(1) via the index formula), but the per-chunk
  materialization still forces O(M x N x K). The authors' defense holds.
- The ZK certificate pins it: a Starky STARK plus two Plonky2 recursion
  layers (120-bit), constraint (c) "matmul + reduction of noised slices equal
  JACKPOT_MSG", noise preprocessed and digest-checked, matrices Merkle-bound
  to `JOB_KEY = Blake3(BlockHeader || MiningConfiguration)`
  (`pearl_circuit.rs`, `pearl_program.rs`, `pearl_air.rs`). A cheap or partial
  transcript yields a different HASH_JACKPOT and fails the cert.
- The lottery target is scaled by work (`target x tile_size x
  dot_product_length`, `check_jackpot_against_nbits`), so shrinking the matmul
  shrinks the win chance in proportion — no free tickets from small work.
- The devs already penalize low rank: `RankPenaltyForkHeight 96251`,
  `PENALTY_BASE_RANK = 128` (valid rank now 128..1024). This exact class was
  patched.

Net: **no mining break on the int protocol from the lab's tooling.** The clean
`k ~ K/R` bet loses to the source. What survives, all smaller:

1. **FP-protocol watch.** PIP-3 (Draft, not live): no transcript, tickets on
   the final product C' only, "Jackpot Policy: TBD", and its own text warns a
   verification tolerance invites grinding. If an FP fork activates with a
   weak or undefined policy, low-rank C' grinding becomes a live break. The
   one future break window. Monitor pips and fork heights.
2. **Mining-config optimization.** (m, n, k, r, MoE) are miner-chosen within
   `sanity_checks.rs` bounds (rank 128..1024 pow2, 16r <= k <= 4r^2,
   k <= 2^16, 32 <= h*w <= 256). Search the box for the config whose credited
   work (`tile_size x k`) most exceeds its true wall-clock cost on this card.
   A legit efficiency edge, bounded; the RankPenalty fork shows the devs watch
   this.
3. **AMD WMMA kernel efficiency.** An engineering edge per credited-work-unit.
   But single-card revenue is set by GLOBAL network difficulty, so a better
   kernel does not multiply one card's ~$2/day — it pays only at scale or as a
   dev-fee miner, both out of current scope.
4. **Soundness audit** of the unread chip constraints
   (`zk-pow/src/circuit/chip/*`): a bug is a bounty (Track C), never mined,
   and Pearl pays only acknowledgement.

Honest magnitude: on ONE RX 7600, no scale, no business and no live crypto
break, there is no path to large money on Pearl. Large money requires one of:
the FP fork landing weak (uncertain, not live), a bounty-class soundness bug
(low pay here), or re-opening scale / a dev-fee miner business.

## The target: Pearl (PRL)

v1 ranked Quantus first. The research flips that to Pearl, and the max-effort
objective sharpens it: Pearl is the only candidate where a break pays in the
millions.

- **Only real pot.** Pearl does about 24 EH/s and pays about $1.63M/day
  (study: 800 blocks x 2,674 PRL x $0.76; PRL now about $2.04, so larger).
  Annual emission is on the order of hundreds of millions of dollars — the
  ceiling where v1's "$10M/yr needs k ~ 1,700 on a >= $100M/yr coin" becomes
  reachable. Quantus is a $23-27M-cap coin, about $237k/day volume on one or
  two thin markets; even at 100% share and a working break it cannot pay
  $300k or be sold into. Tari C29 is 25% of a four-algorithm split on a
  smaller coin. Both fail v1's pot filter and are dropped as mining targets.
- **Exotic, young, conjectural PoW.** Pearl's work is NoisyGEMM: an int8
  matrix multiply (INT7 operands, INT32 accumulate, per PIP-3) where the
  **miner chooses both input matrices A and B**. Security is an *explicit
  open conjecture* (cuPOW, Komargodski-Weinstein 2025): the 1+o(1) honest
  overhead holds only if computing the transcript has "no noticeable speedup
  possible", reduced to the hardness of "a batch of low-rank random linear
  equations", which the authors leave open. A money-making PoW whose security
  is a one-year-old unproven conjecture is the strongest break surface the
  lab has ever had.
- **The lab's one card fits the work.** RX 7600 (gfx1102, RDNA3) has WMMA
  int8 at about 43.5 TOPS — the exact operation NoisyGEMM needs — and the
  public miners target NVIDIA tensor cores. The cuPOW study reports its
  authors mined "the first Pearl shares ever mined on non-NVIDIA hardware"
  (41 shares, AMD MI300X). The GPU that would run a break is already here and
  nearly uncontested on AMD.

Phase 0 also sweeps for any other coin with a comparably young, published,
conjectural PoW and a real pot; Pearl leads unless that sweep finds better.

## The headline attack: low-rank structure vs the transcript

This is the whole bet, stated plainly so it can be killed or confirmed fast.

The miner picks A (M x K) and B (N x K). Deterministic noise E, F is derived
by keyed blake3 from the header bytes, the mining config and the Merkle roots
of A, B (`commitment_hash.py`: `key = blake3(incomplete_header_bytes +
mining_config)`), so the noise cannot be chosen but its *structure* is fixed
and known: E, F are **rank R** (R is 64 or 128), built as a dense M x R (or
N x R) int8 factor on [-32, 32) times a sparse R x K factor with one +1 and
one -1 per row (`noise_generation_kernel.h`: `NOISE_ABS_MAX = 128`,
`NOISE_RANGE = 64`, `PERM_IDXS_PER_COL = 2`).

Honest work is one int8 GEMM, O(M x N x K). The product
`(A+E)(B+F)^T = AB^T + AF^T + EB^T + EF^T`. The authors already closed the
`A=B=0` output-hash hole (then the product is `EF^T`, low rank, cheap) by
hashing the **transcript** — the per-K-chunk partial sums — instead of the
output, and argue the zero case is "as hard as any other product." Their
defense rests entirely on the claim that hashing per-chunk partial sums
forces the full K dimension to be touched even when the end product is low
rank.

**The lever:** `EF^T` is a product of two rank-R matrices and is truly
computable in O(M x N x R), a factor K/R cheaper than honest. If R = 64 and
mainnet K is in the thousands, that is a 50-100x gap — exactly the `k >= 50`
the money math needs — *if* it can be realized through the transcript rather
than only in the final product. Whether it can depends on three exact facts,
none yet pinned from source:

1. **The per-chunk reduction.** If `xor_reduction` of a partial-product tile
   is a function the low-rank factorization passes through cheaply, the
   per-chunk transcript entry costs O((M+N) x R) not O(M x N) per chunk. If
   it demands the fully materialized int32 M x N partial product every chunk,
   the low-rank win collapses to O(M x N x K) and the defense holds. The code
   XORs int32 tile values (`xor3_lop3`, `lop3 0x96`) then folds with
   `rotl_xor<13>` — XOR of integer products is non-linear in the inputs, which
   is likely what kills the naive version, but the chunking granularity
   decides it.
2. **Chunk size vs R** (`ReduceEveryK`, `bK`, the MMA atom K). A chunk larger
   than R leaves room; a chunk equal to R does not.
3. **What the ZK certificate actually proves.** If the circuit enforces that
   the transcript equals the honest per-chunk partial sums, a cheap transcript
   must still satisfy the matmul relation. If it proves only ranges + final
   hash + Merkle consistency, a cheaply-produced transcript that hashes below
   target is a *mined* break; if it is simply unsound, it is a consensus bug
   for a bounty (Track C), never mined.

Phase 0 pins all three. If (1) and (2) leave a gap and (3) does not block it,
this is a direct `k ~ K/R` break and the plan goes straight to a kernel. If
the transcript genuinely forces full-K work, the low-rank angle dies and the
attack moves to the subtler surfaces below.

## Attack surfaces, in priority order

1. **Low-rank / structured A, B through the transcript** (above). First,
   cheapest to probe, highest payoff. The lab's work-sharing DAG compiler
   (`work_sharing.rs`) is built to count exactly this: shared sub-sums across
   a computation. Point it at the transcript DAG for structured A, B.
2. **Partial-sum collisions in the XOR accumulator.** The transcript folds
   per-chunk hashes with `rotl_xor<13>`. Structured A, B that make many
   per-chunk reductions cancel or repeat could cut work even without full low
   rank. GP evolved-rules (`evolved_rules.rs`) searches this space with a
   positive control, as it did for Bitcoin's 4-round shortcut.
3. **Nonce/noise work-sharing.** Varying the nonce reseeds the noise, so
   transcripts across nonces should share nothing (the intended defense). The
   DAG measures whether any choosable field leaves reuse — the direct analogue
   of the Bitcoin header-atlas null, now on a coin where a non-null pays.
4. **Certificate weakness / grinding.** PIP-3's FP protocol "checks tickets on
   C' only" and its own rationale warns "any tolerance in verification becomes
   vulnerable to grinding attacks." If the FP cert (version 3) is live and
   checks only the final product within a tolerance, grinding A, B for a
   cheap below-target C' is a break. Needs the cert code to confirm.
5. **Reduced-parameter frontier.** For every surface above, the v1 method:
   find the small NoisyGEMM dimension where a shortcut works (positive
   control), then plot how k decays toward mainnet dims. A curve that reaches
   mainnet goes deep; a collapsing one is killed.

## The supporting miner (harness, not the goal)

A correct NoisyGEMM path on this card is needed anyway — to verify any GPU
hit on CPU, to submit real blocks as third-party proof in phase 3, and
because the WMMA kernel it builds is the same kernel a structured-A,B break
runs on. So it gets built, but as the attack's test rig, not as an income
business. Its net $/day (rough: +$1-2/day at full WMMA efficiency and ~$2
PRL, dependent on the real ZK-cert cost) is recorded and ignored for the
go/no-go decision. The old "G0 floor gate" is dropped: negative honest
economics does not kill the target, because the break is the point.

## What the lab reuses and what is missing

Reused as-is: `experiment-engine` + `bmr research audit` provenance;
`statistical-engine` kill rules (held-out A with CIs, Poisson dispersion,
Bonferroni), the exact machinery that killed every Bitcoin lens; the
work-sharing DAG (`work_sharing.rs`) for surfaces 1-3; GP evolved-rules
(`evolved_rules.rs`) for surface 2; the header-atlas method
(`header_atlas.rs`) to fingerprint Pearl stealth miners; the wgpu + CPU-verify
harness and `bmr benchmark gpu` parity checks.

Missing, build in dependency order (time no object, so build all that
survive phase 0):

1. **A NoisyGEMM CPU reference with a reduced-dimension knob** — the thing
   every attack is tested against, and the positive-control rig. Pure Rust,
   no GPU. Build first; it needs only the spec, not the hardware.
2. **The transcript + noise model in the reference** — exact rank-R noise
   construction, per-chunk XOR/rotl-13 accumulator, blake3 keyed compress,
   target compare — so a shortcut can be proven to produce a valid transcript
   on CPU before any kernel exists.
3. **The work-sharing DAG extended to the NoisyGEMM transcript**, so surfaces
   1-3 run as cheap operation-count experiments (algorithmic k) with no GPU.
4. **An RDNA3 WMMA int8 kernel** via Vulkan `VK_KHR_cooperative_matrix` or
   HIP/rocWMMA (WGSL has no int8 cooperative-matrix and no u64). Shared by the
   harness miner and any realized break. First confirm `vulkaninfo` exposes
   int8 cooperative-matrix on this gfx1102 driver.
5. **The ZK certificate path** (Plonky-class), needed to submit valid blocks
   in phase 3 and to settle surface 4. Biggest unknown; may need its own spike.
6. **(Track C only)** Goldilocks prime-field support in `algebraic-engine`
   (today GF(2) only) and a Poseidon2 CICO solver, built only if the Quantus
   bounty angle is pursued.

## Pipeline

### Phase 0 — pin the attack target (days, desk + light reads, no mining)

Settle the three facts the headline attack hinges on — the per-chunk
reduction, the chunk size vs R, and what the certificate proves — plus the
mainnet dims (M, N, K, R), the cert cost, and the emission/difficulty
constants, all from the Pearl source and PIPs. Header-atlas the live chain for
stealth-miner fingerprints. Deliver a one-page atlas that either (a) shows a
concrete `k ~ K/R` gap and sends the plan straight to the reference +
shortcut, or (b) shows the transcript forces full-K work and routes effort to
surfaces 2-5. Also run the "other young conjectural coin" sweep.

### Phase 1 — reference + cheap kill/confirm (parallel, no GPU yet)

Build missing items 1-3. Run every surface as an operation-count experiment
at reduced dims with positive controls and the statistical-engine kill rules.
Each surface either shows an algorithmic k that holds toward mainnet dims
(goes to phase 2) or is killed. This is where most of the bet is won or lost,
cheaply, before any kernel.

### Phase 2 — deep break + kernel (only for surviving surfaces)

Push the surviving surface toward mainnet dims, build missing item 4 (the
WMMA kernel) to realize the algorithmic k as wall-clock k, and build item 5
(the cert path) if the break needs to submit. Measure algorithmic k and
engineering k separately; never let one hide in the other.

### Phase 3 — quiet proof (short)

Mine on a public pool with the one card. Accepted shares and blocks are
third-party verification. Measure k at the wall against the best public miner
on the same card. Continue only if k >= 50 (break) — the harness miner's own
economics do not gate this.

### Phase 4 — scale (unchanged from v1, not in scope yet)

Reinvest, own solo node, 10% share cap, sell daily, watch exit triggers. The
user has put scale (renting, fleets) out of scope for now; stays written-down
until a break is real.

## Odds, honestly

- **Break (the bet):** low probability, very high payoff, and the
  highest-odds break surface the lab has faced — a live money coin whose
  security is an admitted open conjecture, attacked by tooling built for
  exactly this (sub-sum sharing, reduced-parameter frontier, GP with positive
  controls). The low-rank lever is a clean `k ~ K/R` if the transcript does
  not block it, and that single fact is cheap to settle in phase 0. Most
  surfaces will still die, as every Bitcoin lens did; the difference is that
  one survivor here is worth millions, and dying is cheap.
- **Harness miner:** a small positive or negative $/day, recorded, ignored
  for the decision.
- **Bounty (Track C):** opportunistic; the live paid Poseidon bounty pivoted
  to Poseidon1/KoalaBear, not Quantus's Poseidon2, so a Quantus result is a
  research by-product, and a Pearl consensus bug earns only acknowledgement.

Board ids: `H-ALT-xx`, same record format as the rest.

## Sources

- cuPOW construction and conjecture: Komargodski & Weinstein, "Proofs of
  Useful Work from Arbitrary Matrix Multiplication", arXiv:2504.09971
  (ESA 2026). https://arxiv.org/abs/2504.09971
- Pearl empirical study (throughput, revenue, no-inference, 24 EH/s):
  arXiv:2606.04819. https://arxiv.org/abs/2606.04819
- Pearl Jackpot/flexibility analysis: arXiv:2610.25347.
  https://arxiv.org/abs/2610.25347
- Pearl source (seed binding, rank-R noise ranges, transcript accumulator,
  PIPs): github.com/pearl-research-labs/pearl and .../pips (seed.rs,
  commitment_hash.py, noise_generation_kernel.h, pow_utils.hpp,
  inner_hash_kernel.cu, PIPS/pip-0003.md).
- Pearl price/volume (Nov 23 2026, ~$2.04, ~$22.9M/day): Bybit, Crypto.com,
  Cryptorank Pearl (pearlresearch.ai) PRL pages.
- Quantus QPoW (double Poseidon2 / Goldilocks, 64-byte U512 nonce):
  docs-7or.pages.dev/deep-dives/qpow, hackmd.io/@rob-tn/qpow-mining,
  github.com/0xmoei/quantus.
- Quantus price/cap/volume (thin): coinmarketcap.com/currencies/quantus,
  coinpaprika.com/coin/qtc-quantus.
- Tari four-algorithm / C29: pool.kryptex.com xtm-c29 pages.
- RDNA3 WMMA int8 (gfx1102, ~43.5 TOPS): gpuopen.com WMMA on RDNA3,
  rocm.docs.amd.com GPU specs; Vulkan coopmat: Phoronix AMDVLK 2024.Q2.3
  (confirm with vulkaninfo on the card).
- Poseidon bounties (~$1M through Dec 2026, 2026 pivot to Poseidon1/KoalaBear):
  poseidon-initiative slides, crypto.ethereum.org/bounties/zk-hash.
