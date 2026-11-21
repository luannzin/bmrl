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
