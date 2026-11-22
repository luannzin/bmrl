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
