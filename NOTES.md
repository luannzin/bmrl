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
