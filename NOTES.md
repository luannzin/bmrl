# Progress log

Append-only. Newest entry at the bottom. Every entry says what was done,
where things stand, and what comes next. Results live in
`experiments/` (one JSON file per record, SQLite registry); this file is the
narrative that ties them together.

## 2026-11-21: MVP and Structural Exploration

Done:
- Workspace, SHA-256 from FIPS 180-4, independent second SHA-256, Bitcoin
  header engine, CPU (scalar, AVX2) and GPU (wgpu/WGSL) backends, Bitcoin
  Core 32.1 regtest mining, `bmr` CLI, SQLite experiment registry.
- All 10 MVP acceptance items verified on this machine (Xeon E5-2680 v4,
  RX 7600): CPU 115.8 MH/s, GPU 498.8 MH/s, 102 regtest blocks accepted from
  each backend.
- Ten experiment kinds (4 MVP + 6 structural), hypothesis registry with
  evidence, errata.
- Private repo `luannzin/bmrl`, checkpoints pushed to `main`.

Corrections found by rerunning (errata recorded, records kept):
- schedule-0001: wrong constant σ0(256) in the folded schedule; v2 fixed.
- characteristic-0001: sequential estimator 15 bits pessimistic; v2 adds the
  grouped estimator (within 6 bits).
- smt-scaling-0001: budget ran out in the first encoding; v2 alternates.
- smt-scaling-0002: heavy-tailed solve times make its scaling fits unreliable.
- hardware-0001/0002: unused schedule words counted as registers; fixed in
  hardware-0003.

## 2026-11-21: Scientific closure (in progress)

Goal: close the run, audit the round-17 characteristic, audit the hardware
model, benchmark the real mining path, write the report. Priority is
verification, not new experiments.

Plan:
1. Provenance audit: every current result must come from the final committed
   code (`bmr research audit`), history kept.
2. Characteristic audit: why 503 of 1,048,576 pairs follow the round-17 trail.
3. Hardware audit: every modelled pipeline simulated; measured vs simulated
   vs estimated kept apart.
4. Mining path benchmark: real template, coinbase, merkle root, headers,
   target comparison, every hit verified, a block submitted per backend.
5. Report in `research/README.md`, status in `research/STATUS.md`.

## 2026-11-21: Round-17 characteristic explained

Done:
- `bmr research audit` (provenance): fingerprint now covers kernels,
  backends and the CLI; records store `binary_matches_commit`.
- The 503 / 1,048,576 round-17 followers are real, not an artifact. Rust
  (SplitMix64) and an independent Python/numpy port (PCG64) agree.
  Injecting the difference straight into a uniform state gives 2^-16.8 only
  because that check also fixed intermediate XOR differences.
- New signed-difference estimator (characteristic v3): only a', e' and W_t
  must show their XOR difference. Round 17 of the W15[31] trail costs 26 bits
  (sequential), 17 (grouped) or 11 (signed); measured 2^-11.03.
- New kind `characteristic-audit`: 11 exact bit conditions derived per
  trail, 0 counterexamples either way, marginals 0.4996 to 0.5003, no
  pairwise dependence, none implied, joint matches independence. W8[31] and
  W0[31] share W15[31]'s template; W15[0] is it rotated by one bit (+2 entry
  bits, 2^-13).
- New kind `trail-search` (Bitcoin objective, header words W0/W1/W3 only).
  Smoke run: positive control at 4 rounds (neighbour strategy 0.045x the
  work, the affine structure); 6..64 rounds at the null rate; best header
  trails reach round 5 only.

Next: full-size trail-search and audit runs, hardware audit, mining path
benchmark, ponytail review, final clean run, report.

## 2026-11-21: Scientific closure done

Done:
- Hardware audit: iterative cores simulated as well as pipelines (all 6
  variants, u = 1..32, exact); the record now has separate measured,
  simulated and estimated sections plus an assumptions table.
- `bmr benchmark mining`: live template to accepted block for CPU, GPU and
  combined; raw vs end-to-end throughput; every hit checked by `sha2`.
- Final clean run on `480c36f`; `bmr research audit` passes: 27 experiment
  records, 11 benchmarks, 6 with errata, nothing overwritten.
- Every deterministic experiment repeated its first-run digest; out-of-process
  reproduce matched for characteristic-audit-0001, trail-search-0001,
  reduced-round-0002.
- Registry id bug (`smt-%` matched `smt-scaling-*`) fixed in `dc48dfb`
  before it overwrote anything.
- Reports: `research/README.md` (full), `research/STATUS.md` (short),
  `research/differential-cryptanalysis/REPORT.md` (characteristic and the
  mining question).

Results that matter:
- Round-17 characteristic: 2^-11.010 (CI 2^-11.024..2^-10.996), 11 exact
  independent conditions, same template for all four trails.
- No mining advantage at 64 rounds: neighbour strategy A = 1.004 (0.983 to
  1.026), work 0.9997x; condition filter A = 1.010, about 81x slower.
- Reduced-round only: 4 rounds affine (0.045x work), 5 rounds
  anti-correlated (A = 0.69).

Current state: MVP complete and verified; research run closed and reported.

Next (see research/STATUS.md section 5): GPU kernel v2; derive the 5-round
anti-correlation, SMT scaling v3, second seeds; RTL + synthesis and measured
power.

## 2026-11-22: Breakthrough lab (structural-shortcut search)

Goal: find out whether SHA256d over the header has structure that lowers the
expected number of evaluations, not the cost per hash.

Done:
- `cpu-backend`: `Prepared::hash8`, a round-parameterised 8-lane AVX2
  evaluator with full output (parity-tested at 3..64 rounds).
- New kinds:
  - `nonce-atlas` (H-ATLAS-01): every 2^32 nonce of 16 templates at 64
    rounds, 4 templates each at 4/5/6/8 rounds; random-function moments,
    cube and sub-cube sums, and every subspace, byte, weight, linear
    (2^25 masks) and neighbour strategy, with discovery/held-out templates.
  - `trail-sat` (H-SAT-01): z3 minimum-weight characteristics from nonce and
    time words, each round measured; exact proofs of the 4- and 5-round H7
    identities.
  - `quantum-model` (H-QUANT-01): speculative model.
- `bmr research board` / `evolve`: `research/BOARD.md` from the registry and
  rule-based next experiments (frontier, replicate, escalate, model-gap,
  solver-budget, unexplored).
- Final clean run on `49a3e3c`: audit passes; every older kind reproduced its
  digest bit for bit; atlas digest identical in three full executions.
- Report: `research/breakthrough/REPORT.md`; STATUS rewritten.

Results that matter:
- 64 rounds: 0 of 58 atlas tests significant; held-out strategy
  amplification 0.999 (subspace, 95% CI 0.994..1.004) and no family's CI
  excludes 1. No mining shortcut.
- Solver-optimal nonce characteristics: 0, 11, 38, >= 50 bits through
  rounds 3..6; measured 2^-11.007 and 2^-35.7. Time freedom does not help.
- New at 5 rounds: H7 bits 1 and 0 lose degree over the nonce's low byte
  (zero-sum rates 0.5272 and 0.5038). Nothing at 6 or 8.

Caught and fixed before publishing:
- normal approximation on tiny counts;
- a solver window bug (late W3 counted for free);
- W0 unreachable under one midstate (erratum on trail-search-0001/0002);
- fingerprint missing the new modules;
- a nonce-atlas-0001 smoke record from uncommitted code (kept as history).

Current state:
- Records and docs are committed at `d43e899`, where the audit passes.
- The first BOARD.md showed the neighbour family's point estimate (work
  0.831, CI including 1) as "best held-out", which reads like a work
  reduction.
- Fixed in `board.rs`: the work column names a family only when its
  held-out CI excludes A = 1, the work line is readable, the label says
  "run seed(s)", and the `evolve` queue deduplicates commands. The board was
  regenerated from the same records.
- `board.rs` is fingerprinted, so at HEAD the audit reports every record as
  older code until the full suite is rerun. No experiment code changed.

Next:
1. Rerun the full suite from HEAD (about 3 h), or fold it into the rerun
   that GPU kernel v2 needs anyway after its merge.
2. GPU kernel v2 in its own worktree. The session started for it never
   finished setup; restart it.
3. `evolve` queue: smt at 5-7 rounds, trail-sat 4x budget, new-seed
   replications, neutral bits (B-15), differential-linear (B-17).

## 2026-11-22: GPU kernel v2

The session set up earlier for this never started (no messages, no
branch), so v2 was built here on `main`.

Done:
- `crates/gpu-backend/src/v2.rs` generates the WGSL as straight-line code:
  host-precomputed second-block rounds 0..2 (`pre` in the params), K,
  padding and IV folded, nonce-independent terms first, outer compression
  stopped after round 60 with full hashing only for top-word candidates.
  v1 (`gpu/wgsl/sha256d.wgsl`) is kept as the baseline.
- `bmr benchmark gpu` measures every kernel in one record.
- Baseline before the change: bench-gpu-0004 (v1, 499.8 MH/s at `751b455`).
- From the committed code (`5a9a6d2`): bench-gpu-0005, v1 502.7 MH/s, v2
  1.749 GH/s, **3.48x**; both kernels 0 digest mismatches over 65,536 lanes
  and identical search hits (978). bench-regtest-0007: 102 blocks mined by
  v2, all accepted by Bitcoin Core 32.1. Workgroup size 64/128/256: same rate.
- Cost per hash only: expected hashes per block unchanged (factor 1.0).

Current state: v2 is the default GPU kernel. The source fingerprint changed
(`v2.rs` added to it), so research records predate the current code until
the full suite is rerun.

Next (planning with the user, nothing started):
1. Real network: node sync, Stratum V1 client with BIP310 version rolling,
   testnet4 blocks, short mainnet solo-pool runs, a live economics record.
2. GPU v3: overt AsicBoost (version-rolled midstates share block 2), est.
   +10-15%, to be measured.
3. Homemade hardware: a Bitaxe-class BM1370 board if the user buys one;
   frequency/voltage tuning and measured J/TH.
4. Track 1 science in parallel: learned selection rule, miner-freedom model,
   solver calibration against published characteristics.

## 2026-11-22: Discovery wave (E3, E8, E1, E4) and the public repo

The user asked for the four strongest ideas at maximum effort. Re-ranked
all twelve: E3, E8 (with E12's economics), E1 and E4 stayed; E9
(cross-implementation fuzzing) was dropped because bitcoinfuzz already
does it; E6b needs a full UTXO set; E11 needs the user to change GPU clocks.

Done (`bmr research discovery` runs all four):
- E3 `work-sharing`: exact DAG of the header SHA256d, sums re-associated by
  dependency class, every batching pattern counted. Version rolling is the
  only one that shares work (11.6% at k = 4, 15.5% ceiling). GPU kernel v3
  shares the inner schedule across k version-rolled headers: k = 2, 4, 8,
  16 gave 1880, 1933, 1953, 1422 MH/s (dev harness, v2 1789); k = 8 kept.
  bench-gpu-0006: v1 505.8, v2 1752, v3 1914 MH/s; parity over 8 headers.
  `Work::version_rolled` applies BIP320 bits.
- E8 `header-atlas` + `bmr research sync-headers`: a minimal P2P client
  (version handshake, getheaders) downloaded 977,071 headers in about two
  minutes into `experiments/data/` (gitignored). Our own retarget and
  median-time-past code validates the whole chain. Results in STATUS.
- E1 `evolved-rules`: genetic programming over nonce, template and a probe
  hash. First dry run was invalid: consecutive low nonces share the top
  byte, which at 4 rounds fixes the hash number's top byte, so no rule
  could be scored and the positive-control test passed vacuously. Fixed by
  spreading the sample (n = i * 0x9e3779b1) and asserting hits exist.
  The recorded run rediscovered the 4-round affine shortcut by itself.
- E4 `grover-circuit`: the real header SHA256d as a reversible circuit,
  simulated exactly. Two bugs found before recording: the Pauli-noise
  state grew exponentially (each fault leaves per-input garbage; now an
  input with garbage after an oracle call counts as decohered), and a
  4-round template could hold no target hit at all, which made the
  iteration count infinite (now the template with the largest d is
  chosen and M = 0 is refused).
- Board: B-03 and B-17 link `evolved-rules`, B-13 `grover-circuit`, B-16
  `work-sharing`, B-01 `header-atlas`.
- Repo presentation in the Lines' style: `tools/logo.py` draws a 32x32
  pixel-art bitcoin turning in the dusk palette (banner.webp with
  banner.png for reduced motion, icon, sprite, social preview); README
  rewritten; description and eight topics set.

Current state: no idea has changed the number of hashes per block at 64
rounds. Records of this wave come from several commits; the full suite
must be rerun from one commit before the audit passes.

Next:
1. Mining with v3 for real: version rolling in the mining engine and a
   Stratum V1 client (BIP310), then testnet4 and short mainnet runs.
2. Second seeds for the new hypotheses; evolve rules with a larger budget
   at 5 rounds, where structure is known to exist.
3. Full-suite rerun from one commit.

## 2026-11-22: Wave 2 (X1, X4, X2)

The user read the two rediscoveries (4-round shortcut, AsicBoost) as
momentum and asked to go further. They are positive controls: both were
known. Three pushes:

- X1 (work-sharing v2, work-sharing-0002): the share of the r-round
  double hash's per-nonce work needed to decide the target, each target
  DAG checked against the reference: 4 rounds 9.3%, 5 rounds 33.7%,
  8 rounds 55.9%, 11 rounds 72.7%, 64 rounds 96.1%. The 4-round shortcut
  is dead code: the target e(r-4) reads outer words W0..W(r-4), so at
  4 rounds it reads one inner digest word (one inner round of the nonce),
  and from 11 rounds every word matters; at 64 only the early reject
  (3.9%) is left. That is why it cannot stretch to 64 rounds.
- X4 (header-atlas v2, header-atlas-0002): luck (hash / target) against
  every nonce bit, BIP320 version bit, low time bit and the previous
  block's luck over 977,066 real blocks: smallest p 0.016 (version bit
  14), Bonferroni threshold 1.7e-5 over 60 tests. Nothing miners choose
  predicts luck.
- X2 (evolved-rules at scale, evolved-rules-0002, reproduce off for its
  22-minute run): rounds 5, 6, 8, 64; population 3,000 for 150
  generations (450,000 rules each); 8 discovery and 56 held-out templates
  of 2^22 nonces. Best held-out A: 1.0009, 1.0118, 1.0032, 0.9994, none
  significant; at 64 rounds the top rule's interval is 0.991..1.005.

Current state: every lens at 64 rounds is null, and X1 shows exactly why
the reduced-round shortcuts end. Nothing found changes the number of
hashes per block.

## 2026-11-22: Template luck (H-LUCK-01)

The user wanted a bolder hypothesis that uses the lab's full machinery.
Chosen: the template is the biggest free choice a miner has (a new merkle
root costs one coinbase hash), and the lab had only tested 16 templates.
If hit rates differed between templates and persisted, choosing templates
would be a free multiplier.

Done:
- New kind `template-luck` (`crates/experiment-engine/src/template_luck.rs`,
  board entry B-18): every nonce of each template on the GPU (kernel v3,
  8 version-rolled templates per scan, every hit re-hashed on the CPU),
  hits at k and k + 8 bits split by nonce parity. Tests: dispersion against
  Poisson, even/odd correlation, top 10% chosen on even nonces re-measured
  on odd ones. Kill rule fixed before the run: all four at Bonferroni
  alpha 0.01/20. Unit test plants 5% luck in a quarter of the templates;
  every test finds it.
- template-luck-0001 from `7813595` (clean tree): 2,048 templates x 2^32
  nonces, 74 min. 64 rounds: D/df 0.956 (p 0.15), r -0.010, A = 1.0008
  (0.9978..1.0039) at 20 bits and 1.007 (0.960..1.057) at 28 bits; spread
  between templates <= 0.13% SD. 4 rounds (positive control): A = 9.85.
  5, 6, 8 rounds: clean. Verifier: GPU hits of template 0 below 2^26 equal
  the independent SHA-256 recount, hit for hit.
- Board bug fixed: a skipped in-process rerun (matched = null) was shown as
  "reproduced" (also evolved-rules-0002); now "not rerun in-process".

Current state: hypothesis dead at 64 rounds. Choosing templates does not
change the hit rate by more than 0.4%. Reproduction ran only for the quick
version; the full run is single-seed. board.rs changed after the record, so
the audit lists template-luck-0001 as older code until the next full rerun.

Side note, not significant: dispersion sits below 1 at 5, 6, 8 and 64
rounds (0.90, 0.88, 0.77, 0.96; 8 rounds p 0.006 against a Bonferroni
threshold of 5e-4). Under-dispersion means templates are more alike, never
luckier, so it cannot help mining. A new seed at 8 rounds would settle it.

## 2026-11-23: Pivot to altcoin PoW breaks (plan only)

The user's point: the lab did everything right but looked the wrong way.
Pandemic GPU miners mined Ethereum (Ethash, often through NiceHash paying in
BTC), never Bitcoin, and every historical mining "magic" (Equihash solvers,
Cuckoo Cycle TMTO, the ProgPoW small seed, Poseidon CICO bounties) happened
in altcoins. The lab never looked at them.

Done (no code, no experiments):
- Stock GPU mining checked against the user's tariff: R$1.03/kWh
  (R$232.57 for 226 kWh), about $0.175/kWh. Every coin on Kryptex's RX 7600
  list loses money; the best, Tari C29, needs 1.10x to break even, Pearl
  1.27x, Quantus 1.30x.
- Goal set by the user: an edge worth $300k/yr or more, not dollars a day.
  With one card, no capital and reinvestment up to about 40 cards at home,
  that means k of about 50 over the best public miner ($300k), 175 ($1M),
  1,700 ($10M), on a coin whose yearly emission is at least about $3M, $10M
  and $100M.
- Choices: break or shortcut over a miner business (business only as a
  low-effort fallback); mine quietly with share at most 10%, sell daily,
  report at the goal or an exit trigger; faster valid PoW only, node or
  consensus bugs go to bounties.
- Full plan, candidates (Quantus/Poseidon2, Tari C29, Pearl), breakability
  filter, kill rule (k < 50 dies), phases 0 to 4 and sources:
  [research/altcoins/PLAN.md](research/altcoins/PLAN.md).

Current state: plan written, nothing built. Next: phase 0, the atlas of PoW
coins (desk research), when the user says go.

## 2026-11-23: Altcoin plan v2 (Pearl-first, plan only)

Desk research on the v1 candidates (web + the coins' own source and papers)
flipped the ranking. Written up in
[research/altcoins/PLAN-v2.md](research/altcoins/PLAN-v2.md); v1's economics,
kill rule and ethics rules still hold.

Done (no code, no experiments):
- Read the PoW of all three v1 candidates. Quantus (QTC) is double Poseidon2
  over Goldilocks, 64-byte (U512) nonce below a target; cap ~$23-27M, volume
  ~$237k/day across one or two thin markets. Tari C29 is Cuckaroo29, 25% of a
  four-algorithm split on a smaller coin. Both fail v1's pot filter for the
  $300k goal; kept only as bounty/science targets.
- Pearl (PRL) is the one candidate with a real pot: ~24 EH/s network, about
  $1.63M/day emission (study price $0.76; PRL now ~$2.04). Its PoW is
  NoisyGEMM, int8 (INT7 operands, INT32 accumulate) matrix multiply where the
  miner chooses A and B; the transcript (XOR-reduced, rotl-13 partial sums,
  blake3 keyed compress) is hashed against target. Security is an explicit
  open conjecture (cuPOW, arXiv:2504.09971: hardness reduced to "a batch of
  low-rank random linear equations").
- Three facts make Pearl the plan: real pot; the RX 7600 (RDNA3 WMMA int8,
  ~43.5 TOPS) is good at the exact work and AMD public miners barely exist
  (the cuPOW study reports 41 shares as "the first ever mined on non-NVIDIA
  hardware"); and the young conjecture fits v1's breakable profile.

Plan v2 structure:
- Track A (floor): an RDNA3 WMMA int8 NoisyGEMM miner + cert path, mined
  directly, no dev fee. Rough day-0 net ~+$1.2/day on one card *if* the
  kernel reaches full efficiency and PRL holds. Kill gate G0: if stock-
  efficient AMD mining is net-negative at a conservative price after the real
  ZK-certificate cost, there is no floor on this coin at this tariff.
- Track B (upside): test the cuPOW conjecture for a structured-A,B shortcut
  in the transcript, using the work-sharing DAG, parameter-frontier and GP
  tooling the lab already has. Low odds, high payoff; a null still leaves
  Track A paying.
- Track C (fallback): node/consensus bugs to bounties (Pearl pays only
  acknowledgement; the paid Poseidon bounty pivoted to Poseidon1/KoalaBear,
  not Quantus's Poseidon2, so opportunistic only).

Biggest open unknowns flagged for phase 0: whether `vulkaninfo` exposes int8
cooperative-matrix on this gfx1102 driver; the real NoisyGEMM mainnet dims;
and the ZK-certificate cost per block/share, which may dominate the matmul
and change the whole economics.

Reused from the lab: experiment-engine, statistical-engine, the work-sharing
DAG, header-atlas, GP evolved-rules. Missing and to build: a Vulkan/HIP WMMA
int8 kernel (WGSL cannot express it), a NoisyGEMM reference with a reduced-
dim knob, the blake3/transcript verifier, the ZK cert path, and (only if
Quantus/Track C is pursued) Goldilocks prime-field support plus a Poseidon2
CICO solver.

Current state: v2 plan written, nothing built. Next: phase 0 Pearl atlas and
the G0 economics gate, when the user says go.

## 2026-11-23: Plan v2 reweighted to break-first, then the break refuted (desk only)

The user set the objective: win the most, soonest, max effort, time and
effort no object; day-0 cash flow not required. Reweighted
[research/altcoins/PLAN-v2.md](research/altcoins/PLAN-v2.md) to break-first
(the honest miner demoted to a test harness), then did the phase-0 source
read that the headline bet needed. The bet lost.

Done (no code; deep read of pearl-research-labs/pearl and /pips source):
- Pinned Pearl's PoW from source. NoisyGEMM: miner-chosen int8 A (M x K),
  B (N x K); deterministic rank-R noise (R in {64..1024}, dense factor on
  [-32,32) times a sparse one-+1/-1-per-row factor); the transcript is a
  running int32 prefix sum XOR-reduced over the whole tile every R columns,
  folded `rotl_xor<13>`, final keyed blake3 vs a work-scaled target
  (`pow_utils.hpp`, `collective_mainloop.hpp`, `check_jackpot_against_nbits`).
- Confirmed the headline low-rank-through-transcript attack is dead on the
  live INT protocol: the per-chunk reduction materializes the full bM x bN
  int32 tile at each of K/R checkpoints, so a rank-R product still costs
  O(M x N x K); XOR of int32 prefix sums is non-linear, no shortcut. The ZK
  cert (Starky STARK + 2 Plonky2 layers, constraint "matmul + reduction of
  noised slices equal JACKPOT_MSG", matrices Merkle-bound to
  `JOB_KEY = Blake3(BlockHeader || MiningConfiguration)`) pins the honest
  accumulation. Devs already shipped a rank penalty (`RankPenaltyForkHeight
  96251`, `PENALTY_BASE_RANK 128`) against this class.
- Chain params: target block time 194 s, hyperbolic emission (constant
  650226, ~half of 2.1e9 PRL in ~4 years, subsidy ~3,229.6 PRL at height 1),
  WTEMA difficulty (half-life 168 h). M/N/K/rank are miner-chosen within
  `sanity_checks.rs` bounds, not fixed by consensus.
- De-risked the harness: pool shares use PLAIN proofs (raw strips, verified
  in plaintext); only the per-block ZK certificate needs the Starky+Plonky2
  prover, which is the pool's job. A pool miner needs no ZK prover.

Surviving edges (all smaller than a break): (1) FP-protocol watch — PIP-3
(Draft, not live) drops the transcript, checks C' only, Jackpot Policy TBD;
if it forks in weak, low-rank C' grinding is a live break; (2) mining-config
optimization within the sanity box (bounded single-card edge); (3) AMD WMMA
kernel efficiency (does not multiply single-card revenue under global
difficulty; pays only at scale or as a dev-fee miner); (4) chip-constraint
soundness audit -> bounty only, Pearl pays acknowledgement.

Honest verdict: on one RX 7600, no scale, no business, no live crypto break,
there is no path to large money on Pearl. Large money needs the FP fork
landing weak (uncertain), a bounty-class soundness bug (low pay here), or
re-opening scale / a dev-fee miner business. Recorded in PLAN-v2.md under
"Phase 0 finding". Decision on direction is with the user; nothing built.

## 2026-11-23: Widened the program beyond Pearl (hypotheses + atlas, desk only)

The user's direction: forget bounties as a target (self-mine any shortcut,
validate, bounty only later); think out of the box, generate many hypotheses;
resources are one RX 7600 + effectively unlimited AI time + patience, no
capital. Also park a note on the dev-fee miner business for later thought.

Done (no code; web research + two new docs):
- [research/altcoins/HYPOTHESES.md](research/altcoins/HYPOTHESES.md): the wide
  search. Five reframes (PoW security << crypto security, so output-bias or a
  cheap below-target predicate is a break; our asymmetry is hypothesis
  throughput via a coin-agnostic pipeline; a 1.2-2x efficiency edge already
  pays and compounds; new-launch sniping is a timing edge; credited-vs-real
  work gap in flexible PoW). Seven break classes C1-C7 with the lab tool and
  kill signal for each.
- [research/altcoins/BUSINESS-MINER.md](research/altcoins/BUSINESS-MINER.md):
  notes on the dev-fee RDNA3 miner business (the only found path where the
  AMD-kernel strength becomes money without scale capital, by charging a fee
  on other people's cards), with its costs, risks and an open question, for
  the user to decide later.
- Atlas of young/exotic-PoW coins (subagent, sourced). Key reclassification:
  Quantus QPoW is not just double Poseidon2 — the detailed spec is an RSA-like
  group `g(h,s) = m^(h+s) mod n` (m 256-bit, n 512-bit composite) with
  acceptance on the XOR-distance of `Poseidon2_512(g)` to a fixed target. So
  the per-nonce bottleneck is a 512-bit modular multiply, and consecutive
  nonces differ by one multiply (`v_next = v_prev * m mod n`, already public).
  This opened a new taxonomy class, C7 (number-theoretic / group structure in
  modexp PoW).

Candidate shortlist (full table in the atlas):
- Tier 1 break rig: **Quantus (QTC)** — exposes C-impl (512-bit modmul kernel),
  C3 (Poseidon2 near-target bias), C7 (group). Youngest, unaudited (3
  conflicting specs), no published cryptanalysis, open AMD miner. Pot small
  (MC ~$14-27M, ~2,232 QTC/day, thin), so a self-mined win is capped; its real
  value is as the break rig whose C3 prime-field + C7 bignum tooling transfers
  to a future young big-pot algebraic/group coin.
- Tier 2 cash leg: **Spectre (SPR)** — SpectreX CPU-only, no public GPU miner;
  first RDNA3 kernel = clean efficiency win (micro-cap). **Kaspa-fork family**
  (Karlsen/Pyrin/Nexellia) — young HeavyHash tweaks, AMD tuning lags. Plus a
  GPU fair-launch watch (Quinvium, Doomsday, Colossus-X).
- Watch/study: Pearl (FP fork + noise/verify), PHICOIN (FP32 grinding, $59k
  pot = study only). Dead for edge: Ergo, Iron Fish, Kaspa, Alephium, Grin,
  Beam, Quai, Nexa, Radiant, Nimiq, Dynex, Dero.

Structural bind, recorded: young-and-breakable coins are all small/micro-cap;
the big pots are mature or ASIC-dominated with no lone-researcher edge. The
two do not yet coincide, so the plan is a break leg (Quantus rig, transferable
tooling) plus a cash leg (efficiency + launch edges that pay this card now),
waiting for a young big-pot algebraic/group coin.

Current state: three analysis docs written (HYPOTHESES, BUSINESS-MINER,
PLAN-v2 updated), nothing built. Pinning the authoritative current Quantus
mainnet spec from source (the (a) double-Poseidon2 vs (b) RSA-group vs (c)
migration ambiguity) before any Quantus work; it decides C3-heavy vs C7-heavy.

## 2026-11-23: Quantus spec pinned — RSA-group refuted, it is plain Poseidon2 (C3 + C-impl)

Pinned the live QPoW from source (Quantus-Network/chain `qpow-math/src/lib.rs`,
the qpow pallet, runtime configs, and Quantus-Network/qp-poseidon). The
RSA-group `m^(h+s) mod n` / XOR-distance scheme in the hackmd note is NOT in
the code (stale/aspirational); the SHA3->Poseidon2 migration is already done.
Live rule: `Poseidon2_sponge(block_hash[32] || nonce[64]) < U512::MAX /
difficulty`, one sponge with two squeezes (512-bit, big-endian), strict
compare. Poseidon2 over Goldilocks (2^64-2^32+1), width 12, rate 8, capacity
4, S-box x^7, 8 external + 22 internal rounds, constants seed
0x3141592653589793, MDS 4x4 [2 3 1 1;1 2 3 1;1 1 2 3;3 1 1 2]. Ethereum-style
retarget, genesis difficulty 99,999,999,999 (~2^36.5 work/block), floor 2^17.
Nonce 64 bytes, +1 increment, zero rejected. Bottleneck = the Poseidon2
permutation (118 x^7 S-boxes/perm; 5 perms/nonce, 3 with the midstate cache),
no modexp anywhere. Official miner is wgpu/WGSL + a native CUDA crate; no
AMD/ROCm path.

Correction to the prior entry: **C7 (number-theoretic/group) does NOT apply to
Quantus.** Fixed in HYPOTHESES.md (C7 kept in the taxonomy for a future
VDF/RSA/lattice coin; no live candidate). Quantus is now scored as C3
(algebraic output-bias vs nonce-choosable bits — the cheap nonce-atlas test,
the first kill/confirm of the whole break leg; full-round Poseidon2 is
believed secure so odds are modest, but it is the first low-degree GF(p)
target for tools that were null on SHA256d) plus C-impl (bounded AMD-kernel
edge). Caveat: the `main` branch ties to the Planck testnet; a live mainnet
deployment version and the current on-chain difficulty were not confirmed.

Cheapest first experiment identified: a Rust Poseidon2-Goldilocks reference
(from the pinned parameters, CPU-verified) plus the lab's nonce-atlas output-
bias battery over the top bits of the 512-bit output against nonce-choosable
bits, with the statistical-engine kill rules. Reuses the atlas machinery, no
GPU, no prime-field solver yet; confirms or kills the C3 hope fast. Not
started — awaiting the user's go to build.

## 2026-11-23: Objective reset to expected value; Pearl reopened by a ZK-cert audit

The user's steer: stop optimizing for cheap/fast; rank by `P(break) x
realizable payoff` and invest deep effort in high-EV targets even if hard and
slow. The bar is real returns ("a GPU every ~12 days", k ~ 53), not dollars a
day. Consequence recorded in HYPOTHESES.md ("Selection criterion"): the big
pots dismissed as mature/ASIC (Kaspa, Ergo, Alephium, Pearl) are back in
scope, because a mathematical shortcut beats ASICs too; Spectre/Kaspa-fork
efficiency and the dev-fee miner are demoted to fallback.

Launched a deep big-pot-structured-PoW hunt (Autolykos2/Ergo and kHeavyHash/
Kaspa deep-dives, plus a sweep for big-pot algebraic/matmul/lattice PoW) —
running.

Deep audit of Pearl's ZK certificate circuit (the previously-unread
zk-pow/src/circuit/chip/* constraints). The circuit is largely sound: matmul
reads are bound to the committed+hashed matrix dwords (MAT_ID, RAM logup);
noise is fully constrained and bound to job_key; the per-r-chunk K-sum and
jackpot schedule are complete (no chunk skippable, preprocessed+digest-checked
control bits); no grinding tolerance. But it surfaced two potential edges at
the node/consensus layer, OUTSIDE the AIR, both unconfirmed pending the node
code:
- **Rank penalty possibly not on the ZK-cert path.** check_rank_penalty
  (factor tile*(dot/rank)*128) is called by verify_plain_proof but NOT by
  prepare_verification, which verify_block uses. If block-cert validation uses
  that path, rank 1024 gives up to an 8x difficulty discount with no
  cryptanalysis — a flat consensus-gap edge on Pearl's huge pot. Highest-EV
  open thread.
- **A,B not bound to the job in-circuit** (only HASH_A/HASH_B commitments);
  miner picks A,B freely. The audit claimed a low-rank/A=0 cheapening, but on
  reconciliation the ZK trace still forces filling CUMSUM_TILE (bM*bN int32 at
  each of K/r checkpoints) = O(M*N*K) regardless of A's rank, and the jackpot
  XOR is nonlinear, so the prover's trace-fill cost is probably NOT reduced.
  The earlier "Pearl closed for honest computation" verdict (PLAN-v2) stands;
  unbound A,B is a latent weakness only if the node fails to re-derive/bind
  them — being checked.
- MoE certs may pass the ZK/verify_block path while a dense-only softfork
  (DenseOnlyForkHeight 91630) is active (verify_plain_proof rejects MoE,
  prepare_verification does not).

AIR-internal unknowns remain (blake3_air round constraints; Evaluator
constraint-vs-transition semantics). Reading the Pearl node consensus path now
to confirm/refute the three node-level items. Nothing built.

## 2026-11-23: Pearl closed for good; the structural law; EV-ranked targets

Both deep-dives returned. Results:

Pearl node audit — all three node-level items are CLOSED on mainnet:
- Rank penalty IS enforced, in Go (`CheckCertificateRules` ->
  `zkpow.CheckRankPenalty`), separate from the ZK verifier. Post
  `RankPenaltyForkHeight` 96251 the penalized bound applies; the ZK-path
  omission is covered by the Go check. The up-to-8x discount existed only below
  the fork height (moot on mainnet).
- MoE dense-only rule enforced in Go (`CheckCertificateRules`, past
  `DenseOnlyForkHeight` 91630).
- scale() saturation is a regtest/pool-side corner only; mainnet inputs are
  bounded by powLimit in Go.
So Pearl is fully closed (circuit sound, consensus closes the ZK-verifier
omissions). Unbound A,B is a non-issue for prover cost. Only the FP fork
(PIP-3, not live) is left to watch.

Big-pot structured-PoW hunt — the hard law: **exploitable structure and a big
pot do not coincide.** Findings:
- Kaspa kHeavyHash: math-inert (fixed linear map between two Keccak-f1600,
  nonce only in the first; the "broken" blogs are entropy/hardware, not
  sub-brute-force). Ergo Autolykos2: PRF-forced 32-index sum, not a free k-sum,
  Wagner inapplicable; now ~$17-26M. Both: hardware/memory edge only, no math
  break.
- The one giant pot with genuinely exploitable math is **Zcash (ZEC)**:
  Equihash 200,9 = generalized-birthday / Wagner k-tree, MC ~$20-24B,
  ~$700-900M/yr pot, solver frontier still moving (eprint 2025/2141,
  Alcock-Ren). But ASIC-dominated since 2018 and the most-studied GBP — beating
  ASICs needs a fundamental algorithmic leap. Lowest-p, highest-payoff
  moonshot. Horizen (ZEN, ~$93-137M) = same math, cheaper validation.
- Genuinely exploitable but small: Quantus (Poseidon2, $14-27M), Aleo
  (Poseidon/R1CS, ~$23M, could re-rate), Chia (class-group VDF = the one live
  C7, ~$17-20M), Neptune Cash (Tip5, unconfirmed). These are where a lone
  researcher's edge is real; money caps unless they re-rate.

Reframed the HYPOTHESES.md ranking around EV (Group 1 young-exploitable-upside:
Quantus/Aleo/Chia/Neptune; Group 2 moonshot: Zcash/Horizen; Group 3 fallback
cash; the confirmed negatives). The EV play is to build one coin-agnostic
algebraic/number-theory/GBP weapon (prime-field algebraic-engine, Poseidon/Tip5
CICO, k-tree solver, class-group) and aim it at the best young-exploitable
coin, mining+accumulating quietly so a break compounds with the coin's growth.
Decision pending from the user: Group 1, the Zcash moonshot, or both. Nothing
built.

## 2026-11-23: First build — Quantus QPoW reference + output-bias atlas (NULL)

First code of the altcoin program, in `crates/quantus-pow`. Committed.

Built and VALIDATED a bit-exact Rust reference of the live Quantus QPoW
(Goldilocks field, Poseidon2 width-12 with the literal qp-poseidon round
constants, `hash_squeeze_twice` sponge, the `block_hash||nonce` PoW hash).
13 tests pass, including qp-poseidon's own known-answer vectors (permutation
on zero and `[1..12]`, apply_mat4, external linear layer, exp7, and 9
`hash_bytes` digests). The harness runs on the real function.

Ran the output-bias atlas (the header-atlas method pointed at Quantus;
`attack.rs`, parallel): over sequential nonces, does any nonce bit predict the
512-bit output's smallness? Three lenses (top-bit uniformity, per-bit median
split with Bonferroni, held-out tail amplification), with a reduced-round
positive control.

Result: **null at full rounds.** 30M sequential nonces, full 8+22 schedule:
uniform chi2 p=0.711, min bit p=5.5e-2 (above Bonferroni 1.56e-3), held-out
tail A=0.999 CI[0.976,1.022] — any statistical mining edge above ~2.2% is
excluded. The 0-round pure-linear control is correctly flagged (chi2 p=0), so
the harness has power; statistical structure collapses after one external
round. Full write-up: [research/altcoins/QUANTUS-ATLAS.md](research/altcoins/QUANTUS-ATLAS.md).

Honest meaning: the cheap statistical lens finds nothing on Quantus, as it did
on SHA256d. "Young/unaudited" did not mean weak rounds — Quantus runs full,
believed-secure Poseidon2. The only remaining C3 surface is algebraic
(degree/CICO/Groebner over GF(p)), a heavy `algebraic-engine` prime-field
build with low expected payoff on full rounds, and Quantus's pot is small
regardless. The validated reference stands as the first reusable weapon
component. No break; decision point on whether the algebraic build is worth it
vs the Zcash k-tree moonshot or a pivot.

## 2026-11-23: Working Quantus miner + economics verdict (does not pay)

Built a working CPU miner on the validated reference (`miner.rs`,
`bin/mine.rs`): exact node rule, nonce search, benchmark. Solves real blocks
(difficulty-2^24 found in 9.8M hashes / 7.9s, re-verified) at **1.217 MH/s**
on the Xeon (28 threads). Committed `b6e0fe1`.

Live Quantus economics (herominers/Kryptex/CMC): difficulty ~3.253e14, reward
0.30 QTC, ~12-14.5s blocks, price ~$30.6, 24h volume ~$0.1-0.7M. Yield =
hashrate*86400/difficulty*0.30. At R$1.029/kWh (~$0.175):
- CPU 1.22 MH/s: $0.003/day gross, ~ -$0.7/day net. Dead.
- RX 7600 GPU, tuned, est. ~200-250 MH/s (no public AMD miner exists): ~$0.5-0.6/day
  gross, net ~ -$0.3 to -$0.1/day. Break-even ~310-420 MH/s. Below reach.
So Quantus does not pay on this hardware at this tariff even with a perfect
kernel, and the thin order book can't absorb selling. **The GPU kernel is not
worth building for Quantus.** Verdict written in QUANTUS-ATLAS.md.

Program bottom line (evidence, not pessimism): across this session every lens
is negative for the money goal. No break (Pearl closed; Quantus statistical
null; full-round primitives out of reach; Kaspa/Ergo math-inert). No profit
(every coin negative at $0.175/kWh; Quantus negative even optimally). Big pots
hardened; exploitable coins tiny and unprofitable — the structural law. On one
RX 7600, expensive power, no capital and no break, there is no path to real
money in GPU PoW mining now. The one money path that fits the lab's real asset
(fast kernels) without a break/capital/cheap-power is the dev-fee miner
business (earns from other people's cards via a fee; BUSINESS-MINER.md) — set
aside by the user. Honest recommendation: stop building miners-for-own-profit
(proven dead) and decide between the dev-fee business or redirecting. Not
continuing to build against the evidence without the user's call.
