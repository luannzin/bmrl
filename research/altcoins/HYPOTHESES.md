# Altcoin PoW: the hypothesis space (break program)

Written 2026-11-23. The objective, set by the user: find a way to compute
valid PoW for some mineable coin with far less work than the best public
miner, keep it quiet and mine it for ourselves until validated, then report
or bounty later. Resources: one AMD RX 7600 (RDNA3), effectively unlimited AI
time, and patience; no capital for fleets. Bounties are not a target in
themselves, only an exit after a self-mined edge is validated.

This file is the wide search. [PLAN-v2.md](PLAN-v2.md) is the Pearl-specific
analysis (its break is closed on the live protocol; see its "Phase 0
finding"). [BUSINESS-MINER.md](BUSINESS-MINER.md) is the separate, legitimate
income line. Candidate coins are filled from the atlas (pending) at the end.

## Selection criterion: expected value, not cheapness

Rank every hypothesis by `P(realizable break) x realizable payoff`, and pursue
the high-EV ones even when the probability is low and the work is long. The
payoff bar is real returns — the money math's "a GPU every ~12 days" (k ~ 53,
about $625/month/card, compounding to ~40 cards in ~2 months), not dollars a
day. Two consequences:

- A big pot with a hard, low-probability break beats a small pot with an easy
  one: a 5% shot at a $300k/yr coin outranks a 90% shot at $700/yr. So the big
  pots earlier dismissed as "mature/ASIC" (Kaspa, Ergo, Alephium, Pearl) are
  back in scope. A *mathematical* shortcut beats ASICs too, because it is
  algorithmic, not hardware; ASIC dominance rules out only a stock-efficiency
  edge, never a break.
- Cheap probes are still run, but as triage that decides where the deep effort
  goes, not as the goal. A cheap null on a big-pot coin is information worth
  having; a cheap win on a micro-cap is not the target.

The small-pot efficiency and micro-cap kernel paths (Spectre, Kaspa-fork
tuning) and the dev-fee miner business are demoted to fallback or
parallel-cash only. The effort goes where the pot x structure product is
largest. The candidate ranking below is being rebuilt on this basis (big-pot
structured-PoW hunt + Autolykos2/kHeavyHash deep-dive + a Pearl ZK-certificate
forgery audit in progress).

## Five reframes that widen the search

The lab spent its whole Bitcoin run proving a negative. These reframes are
why altcoins are different, and where the extra surface is.

### Reframe 1 — PoW security is far below cryptographic security

Acceptance is `hash(header, nonce) < target`. The target is about 2^50 to
2^60 of expected work (coin-dependent), not the hash's 2^128 collision or
preimage resistance. So the bar is low:

- Any method that produces outputs **biased below target** is a break, even
  if it is useless for collisions or preimages.
- Any method that decides "is this below target" with **less than full work**
  (early-reject, partial evaluation, a cheap necessary condition) is a break.
- A hash can be cryptographically sound and still mineable-with-an-edge if its
  *low-work output distribution* has structure.

This is exactly the lab's `header-atlas` method (output luck vs
miner-choosable bits), which found null on SHA256d but is coin-agnostic and
cheap to re-point. Reduced-round, low-degree, and arithmetization-friendly
hashes are the likeliest to carry such bias, because they are tuned for
proving-cheapness and small round counts, not for avalanche over the whole
output.

### Reframe 2 — our asymmetry is hypothesis throughput, not depth on one coin

One GPU and unlimited AI time does not out-muscle a fleet. It out-*searches*
them. The win is a **coin-agnostic automated PoW-analysis pipeline**: ingest a
coin's PoW spec, run the whole battery (below), auto-kill or auto-escalate,
and sweep it across every mineable coin. Most die; the pipeline finds the one
that does not. The lab is already 80% of this (experiment-engine, statistical
kill rules, work-sharing DAG, GP, SAT, header-atlas). The deliverable is the
pipeline; the edge is how many coins it can chew through cheaply.

### Reframe 3 — a modest efficiency edge already pays, and compounds

A break is the jackpot. But the user is broke and needs cash soon. Stock
mining here loses (best coin, Tari C29, needs 1.10x to break even at R$1.03/kWh).
So a **1.2x to 2x honest edge** — a faster kernel, overt version rolling, a
better memory schedule — flips the best coin from a loss to a profit on *this*
card. That is a real, high-probability win now, and it compounds: v1's money
math shows a per-card profit reinvested buys a card every ~12 days at k=53.
The discipline: pick a coin that is (a) near break-even at stock and (b) has a
realizable efficiency edge, so this card goes net-positive, then reinvest.
This is distinct from the Pearl harness, which could not pay because its
difficulty is set globally; here the edge must move *our* per-card economics.

### Reframe 4 — new-launch sniping is an edge of timing, not cryptanalysis

At a fair launch, difficulty starts near zero and the reference miner is
slow. A ready, optimized kernel at genesis mines many blocks before difficulty
catches up. Precedents: early Zcash, Kaspa's CPU-only start. Repeatable, and
occasionally very lucrative for one card. Needs a launch-watch and kernels
ready on day 0 — which is also the ideal moment to *deploy* a break, if one is
found, because early is when the reference miner is weakest and `k` is largest.

### Reframe 5 — "credited work" vs "real work" in flexible / useful-work PoW

When a PoW scales the target by a *nominal* work count (Pearl:
`target x tile_size x dot_product_length`) and lets the miner pick parameters,
a gap exists wherever nominal credit exceeds the real minimal cost of a valid
proof for some allowed config. This is config-optimization inside the rules,
not a break, and it generalizes to any parameter-flexible or useful-work PoW.
The devs patch it when found (Pearl shipped a rank penalty), which is itself a
signal the gap was real.

## The break-class taxonomy (what to run per coin)

Each class names the structural weakness, the attack, the lab tool, and the
kill signal. A coin is scored by which classes its PoW exposes.

### C1 — Memory-hard with a small or reusable seed (the ProgPoW pattern)

- Weakness: a DAG or lookup table that is small enough to skip, regenerated
  predictably, or addressed by low-entropy functions of the nonce.
- Attack: bypass the memory (ProgPoW 0.9.2's 64-bit seed), precompute a small
  DAG, or cache lookups reused across nonces.
- Tool: work-sharing DAG (nonce-independent lookups), header-atlas (lookup
  address bias).
- Targets to classify: Autolykos2 (Ergo, k=32 table lookups), FishHash
  (Iron Fish), XelisHash v2/v3, kHeavyHash (Kaspa), any Ethash-family fork.
- Kill: lookups are high-entropy in the nonce and the table is large and
  per-epoch random.

### C2 — Graph-search / collision PoW (the solver IS the algorithm)

- Weakness: the PoW is a search problem (find a cycle, find colliding pairs);
  a better solver beats the hash entirely. Equihash gave 10x+ historically.
- Attack: new trimming/solver algorithms, time-memory tradeoffs.
- Tool: new code (lab has none yet); GP to search solver heuristics; the
  reduced-parameter frontier.
- Targets: Cuckoo variants (prefer NEW/young ones; Grin and Tari C29 are
  mature), Equihash (n,k) variants with immature solvers, BeamHash.
- Kill: the coin's solver competition is already mature (bounties, years of
  tuning).

### C3 — Algebraic / arithmetization-friendly hash with PoW-level security only

- Weakness (strongest class): a PoW hash (Poseidon/Poseidon2, Rescue, Griffin,
  Anemoi, Monolith, Tip5, ...) whose round count or field is tuned for
  ZK-proving cheapness. A PoW only needs to beat ~2^50-2^60, so a CICO,
  Gröbner, resultant, or degree-annihilation attack that beats the *target*
  (not full 128-bit security) is a direct mining break. Live research shows
  reduced-round Poseidon/Poseidon2 falling (eprint 2026/1254 degree
  annihilation; 2024 HADES algebraic cryptanalysis).
- Attack: CICO against the PoW predicate; biased low-output sampling; a cheap
  necessary condition for "below target"; degree/round frontier.
- Tool: NEEDS BUILDING — prime-field support in `algebraic-engine` (today
  GF(2) only), a Gröbner/resultant path, z3/SAT over the field. This is the
  biggest build but the highest-ceiling class.
- Targets: Quantus (Poseidon2/Goldilocks — but no pot; good as the science
  rig and a later bounty), any coin the atlas finds using an algebraic hash
  with a real pot.
- Kill: full recommended rounds, large field, and the PoW predicate needing
  near-full security; Gröbner finds nothing even at reduced params (the
  2026/409 negative result).

### C4 — Floating-point / non-deterministic GPU math (grinding)

- Weakness: FP accumulation order, rounding, and subnormals are
  non-deterministic across hardware; any verification tolerance invites
  grinding (Pearl's own PIP-3 warns of exactly this for its FP protocol).
- Attack: perturb a near-miss output within tolerance to mint many tickets
  from one real computation; or exploit a verifier that cannot reproduce the
  miner's exact FP.
- Tool: header-atlas-style bias tests on FP outputs; the config gap (Reframe 5).
- Targets: any PoW using FP in the hashed path; Pearl's FP fork *if* it
  activates (watch).
- Kill: the PoW is bit-exact integer, or the verifier whitelists hardware and
  reproduces FP exactly with zero tolerance.

### C5 — Hand-rolled chains with weak mixing

- Weakness: a custom PoW (chained standard hashes, bespoke permutations) with
  a miner-choosable path or incomplete diffusion.
- Attack: find the miner-choosable bits that bias the output; midstate reuse;
  differential/linear structure.
- Tool: header-atlas, differential-engine, SAT, GP — the exact Bitcoin
  battery, now on code that was not reviewed by thousands of cryptographers.
- Targets: small coins with a unique, unaudited PoW (the atlas flags these).
- Kill: the mixing is a standard, well-analyzed primitive at full strength.

### C6 — Nonce-independent work sharing (overt AsicBoost, legitimate)

- Weakness: a large part of the hash is independent of the nonce or of a
  cheaply-rolled field, so work is shared across candidates.
- Attack: version rolling, midstate reuse, batching — all legitimate, valid
  PoW with less work (what the lab's v3 kernel already did for Bitcoin: +15.5%
  ceiling).
- Tool: work-sharing DAG (built for exactly this).
- Targets: any coin with a wide nonce-independent prefix and a naive miner.
- Kill: the whole input feeds the nonce early (good mixing), already done by
  the public miner.

### C7 — Number-theoretic / group structure in modexp or lattice PoW

- Weakness: a PoW built on modular exponentiation (`m^e mod n`), a
  hidden-order group, or lattice/RSA structure. Consecutive nonces relate by
  one group operation, and the group's order or the modulus factorization may
  be short, smooth, or leak. No live candidate uses this today: Quantus's
  RSA-group description (`m^(h+s) mod n`, XOR-distance) was a stale hackmd
  design note, and its live mainnet code is plain Poseidon2-below-target with
  no modexp (spec pinned from source, see Tier 1). Keep the class for a future
  PoW built on RSA, class groups, VDFs, or lattices.
- Attack: exploit the orbit (precompute a short cycle if `ord_n(m)` is small);
  jump the exponent (baby-step/giant-step or Pohlig-Hellman if the order is
  smooth, or if n's factorization is known/weak); or, separately, win on the
  per-step 512-bit modular-multiply kernel, which is the real throughput
  bottleneck, not the hash.
- Tool: NEEDS BUILDING — a GPU bignum path (512-bit Montgomery multiply;
  WGSL has no u64, so Vulkan/HIP), plus number-theory analysis of n and
  `ord_n(m)`.
- Target: Chia (XCH) — class-group-of-unknown-order VDF (Wesolowski), the one
  live C7 coin found. Any future PoW on RSA, class groups, VDFs, or lattices.
- Kill: n is a proper RSA modulus with unknown factorization and m has full
  order (no exponent shortcut), and the modmul is already optimally
  implemented by the public miner.

## Strategy: run the pipeline, not one deep dive

1. Build the coin-agnostic pipeline shell: a `Pow` trait (reference impl +
   reduced-parameter knob) and the C1/C5/C6 probes (header-atlas, work-sharing
   DAG, differential/SAT/GP) wired to the statistical kill rules. These reuse
   the lab almost entirely and need no new cryptography.
2. Run the cheap classes (C1, C4-bias, C5, C6) across the atlas shortlist
   first — they need only each coin's hash and mainnet data, and they kill
   fast. Parallel, days per coin.
3. In parallel, run Reframe 3 (efficiency edge) on the best near-break-even
   coin to get *this card* net-positive now — the cash floor while the break
   search runs.
4. Build the expensive C3 prime-field algebraic path only for a surviving
   algebraic target with a real pot (or Quantus as the rig). Highest ceiling,
   so worth it once a target justifies it.
5. Keep the C2 graph-solver path cold until a young graph coin with an
   immature solver appears.
6. Maintain a launch-watch (Reframe 4) and the Pearl FP-fork watch.

Each coin becomes a board entry `H-ALT-xx`, same record and kill-rule format
as the Bitcoin run. A class dies on the statistical kill rule (held-out
amplification CI includes 1, or the credible upper bound on `k` is below the
profitability threshold). Dying is cheap; one survivor pays for all of them.

## Candidate ranking by expected value (2026-11-23, post deep-dive)

Two deep-dives (a big-pot structured-PoW hunt; a Pearl node+circuit audit)
give a hard structural law: **exploitable structure and a big pot do not
coincide.** A coin big enough to matter has drawn enough scrutiny and ASICs to
close its soft spots; the genuinely math-exploitable PoWs are all young and
small. So EV is maximized not by today's biggest pot but by (young +
exploitable + credible upside), where a quiet break compounds as the coin
grows. All market numbers are late-2026 snapshots and move fast.

Confirmed negatives — do not spend break effort here:
- **Pearl (PRL): CLOSED on mainnet.** Node + circuit audit: the ZK cert binds
  matmul reads to committed+hashed matrix entries, fully constrains the noise
  to `job_key`, and the complete K-sum/jackpot schedule leaves no skippable
  chunk; the rank penalty, the MoE dense-only rule and difficulty saturation
  are all enforced in the Go consensus layer (`CheckCertificateRules`) even
  though the ZK verifier omits them. The pre-fork rank discount is moot
  (mainnet is past `RankPenaltyForkHeight` 96251). Unbound A,B does not cheapen
  the prover (the trace still fills every per-chunk cumsum, O(M*N*K)). Watch
  only the FP fork (PIP-3, not live).
- **Kaspa (kHeavyHash): math-inert.** The 64x64 integer matmul sits between two
  Keccak-f1600 permutations, nonce entering only the first; a fixed per-block
  linear map, output XORed and re-hashed. Linearity gives no way to skip
  Keccak. The "KHeavyHash is broken" posts are entropy/hardware arguments, not
  a sub-brute-force attack. Optical-hardware edge only.
- **Ergo (Autolykos2): math-inert, now ~$17-26M.** The 32-index sum is a
  PRF-forced accumulation, not a free k-sum, so Wagner's k-tree does not apply.
  Memory/compute-hard, no shortcut; v2 removed the non-outsourceable property.

### Group 1 — young + exploitable + upside (the EV play: build the weapon, break, accumulate)

**Quantus (QTC).** Spec pinned from source (`Quantus-Network/chain`, `qpow-math/src/lib.rs`, the
qpow pallet, runtime, and `Quantus-Network/qp-poseidon`). The RSA-group /
XOR-distance description was a stale design note; the SHA3->Poseidon2
migration is already complete. The LIVE rule is plain hash-below-target:
`Poseidon2_sponge(block_hash[32] || nonce[64]) < U512::MAX / difficulty`, one
sponge with two squeezes (512-bit output), strict compare. Poseidon2 over
Goldilocks (p = 2^64-2^32+1), width 12, rate 8, S-box x^7, 8 external + 22
internal rounds (constants seed 0x3141592653589793). Ethereum-style retarget,
genesis difficulty 99,999,999,999 (~2^36.5 work/block), floor 2^17. Nonce
64 bytes, +1 increment; zero nonce rejected. Exposes two classes:
- **C3 (algebraic) — the main hope, cheap to test.** The whole PoW is an
  algebraic hash below target, and a PoW only needs to beat ~2^37, far below
  Poseidon2's full security. The question: does any nonce-choosable structure
  bias the 512-bit output's top bits toward zero more often than random? This
  is exactly the lab's nonce-/header-atlas method, which was null on SHA256d
  (ARX) but has never been run on a low-degree GF(p) permutation. Poseidon2's
  x^7 algebraic structure is where the lab's algebraic / SAT / degree tools
  could bite when they could not on SHA256. Full 8+22 rounds are believed
  secure (reduced-round attacks like eprint 2026/1254 do not reach them), so
  odds are modest, but the test is cheap and squarely in the lab's wheelhouse.
- **C-impl (engineering) — bounded cash.** The official miner is wgpu/WGSL
  (`mining.wgsl`, `mining_u64.wgsl`) plus a native CUDA crate; there is NO
  AMD/ROCm/HIP-tuned path, only the generic wgpu Vulkan/DX12 backend (untested
  on AMD per the README). A hand-tuned RDNA3 Goldilocks-Poseidon2 kernel
  (x^7 S-boxes, 64-bit Goldilocks reduction; the midstate cache already cuts
  5 permutations/nonce to 3) could beat the generic path.

NOT C7: there is no modexp or bignum on the live path, so the 512-bit
modular-multiply and group-orbit stories do not apply. Pot is small (MC
~$14-27M, ~2,232 QTC/day, thin volume), so a self-mined win is capped and
selling moves the price. Quantus's value is the C3 algebraic science — cheap,
high ceiling if any bias exists, and the prime-field tooling transfers to the
next young algebraic coin — plus a bounded AMD-kernel cash edge. Caveat: the
`main` branch ties to the Planck testnet; the live mainnet version and current
on-chain difficulty were not confirmed.

**Aleo (ALEO).** Proof of Succinct Work: search a seed so an R1CS/Varuna
witness (Poseidon over BLS12-377) hashes below a threshold — the most
arithmetization-friendly puzzle of any live coin (C3). ~$23M, could re-rate; a
zkSecurity audit found no soundness bug, so a genuine cryptanalysis target, not
a cheap gap.

**Chia (XCH).** The VDF is repeated squaring in a class group of unknown order
(Wesolowski) — genuine number theory (C7). ~$17-20M. Attack = faster
class-group squaring, or class-number / form structure. The one real live C7
target (Quantus turned out not to be one).

**Neptune Cash.** Uses Tip5, an arithmetization-friendly hash (Triton
VM/STARK) (C3). PoW details and pot unconfirmed — needs a dedicated spec pin
before scoring.

### Group 2 — big pot, genuinely algorithmic, but hardened (the moonshot)

**Zcash (ZEC).** Equihash 200,9 is a generalized-birthday / Wagner k-tree
problem (C2) — the single most-studied structured PoW, and by far the biggest
pot (MC ~$20-24B, ~$700-900M/yr to miners). A better solver IS a direct mining
edge, and the solver frontier is still moving (eprint 2025/2141 memory
tradeoff; Alcock-Ren on tradeoff-resistance). BUT ASIC-dominated since 2018, so
beating it enough to beat ASICs needs a fundamental algorithmic leap the whole
field and the ASIC makers missed — very low probability, astronomical payoff.
A pure `p x payoff` moonshot. **Horizen (ZEN, ~$93-137M)** is the same math at
a smaller pot: the cheaper place to validate a solver idea before touching ZEC.

### Group 3 — fallback cash (demoted, not the focus)

- **Spectre (SPR):** SpectreX = SHA3 -> AstroBWTv3 -> HeavyHash, shipped
  CPU-only, **no public GPU miner**. Writing the first competent RDNA3 kernel
  is a clean C-impl / Reframe-3 win, potentially orders of magnitude over the
  reference. Micro-cap, so the ceiling is low, but it is low-risk engineering
  that can put this card net-positive.
- **Kaspa-fork custom family (Karlsen, Pyrin, Nexellia):** young HeavyHash
  tweaks (GhostDAG), public AMD miners exist but tuning lags the base Kaspa
  stack — plausible per-watt AMD gains (C-impl/C5). Small caps.
- **GPU fair-launch watch (Reframe 4):** Quinvium (Ethash+EVM, live
  2026-11-14), Doomsday (consumer-GPU L1), Cypherium Colossus-X (useful-work).
  Have a tuned kernel ready at genesis for the low-difficulty window. (The
  RandomX CPU fair launches — Brisvia, Block Zero, PoolPayCoin — give this
  card no PoW edge, only the low-difficulty window; skip unless CPU-mining the
  Xeon is worth it.)

### Watch / study, not mine now

- **Pearl (PRL):** fully closed on mainnet (see Confirmed negatives above;
  node + circuit audited). Watch only the FP fork (PIP-3, C4), not live.
- **PHICOIN (PHI):** Phihash adds FP32 branches (a clean C4 grinding
  primitive), but MC ~$59k — study the FP32 attack here, mine it nowhere.

### Dead for a lone-researcher edge

Iron Fish (FishHash), Alephium (Blake3, ASIC), Grin (Cuckoo, mature solver),
Beam (Equihash, tiny pot), Quai (KawPoW), Nexa, Radiant, Nimiq, Dynex, Dero —
mature miners or ASIC era, no edge, marginal or negative economics. Kaspa and
Ergo: see Confirmed negatives (math-inert, not dead for lack of a pot).

### Immediate order of work

1. Decide the primary bet: Group 1 (young-exploitable-accumulate) vs the
   Group 2 Zcash moonshot vs both.
2. Build the weapon (serves both groups): prime-field arithmetic in
   `algebraic-engine` (today GF(2) only; add Goldilocks and BLS12-377 scalar),
   Poseidon2 / Poseidon / Tip5 CICO + Groebner / degree-annihilation at
   PoW-security, a generalized-birthday / k-tree solver (Equihash), and
   class-group arithmetic (Chia VDF). Built once, validated on the small young
   coins.
3. First concrete experiment, cheapest kill/confirm: the Poseidon2-Goldilocks
   reference + nonce-atlas output-bias battery on Quantus (no GPU, reuses the
   atlas machinery and the statistical kill rules).
4. Pin the Neptune Cash spec; re-score Aleo and Chia once the weapon exists.
5. Keep the launch-watch and the Pearl FP-fork watch warm; Group 3 cash only
   if a floor is needed.
