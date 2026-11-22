# Bitcoin Mining Research Lab (BMRL)

An executable research instrument for SHA-256 / SHA-256d and Bitcoin mining:
a from-spec SHA-256 with round tracing, a verified Bitcoin header engine,
CPU (scalar/AVX2) and GPU (wgpu/WGSL) nonce search, a Bitcoin Core regtest
miner, and an experiment framework that records hypotheses, evidence,
counterexamples, reproductions and negative results in SQLite.

Nothing here assumes a breakthrough exists. Every experiment states a null
hypothesis, is reproduced from its seed, is cross-checked by an independent
SHA-256 implementation, and keeps reduced-round results separate from
full-round claims.

## Quick start

```powershell
cargo build --release
.\target\release\bmr system
.\target\release\bmr verify sha256
.\target\release\bmr verify bitcoin-header
.\target\release\bmr benchmark compare
.\target\release\bmr mine regtest --backend gpu
.\target\release\bmr benchmark mining
.\target\release\bmr research all
.\target\release\bmr research structural
.\target\release\bmr research characteristic-audit
.\target\release\bmr research trail-search
.\target\release\bmr research breakthrough
.\target\release\bmr research hypotheses
.\target\release\bmr research audit
.\target\release\bmr research board
.\target\release\bmr research evolve
```

Where things stand: [research/STATUS.md](research/STATUS.md). Every result
with its record id: [research/README.md](research/README.md). The search for
structural shortcuts: [research/breakthrough/REPORT.md](research/breakthrough/REPORT.md)
and the hypothesis board [research/BOARD.md](research/BOARD.md). Progress
log: [NOTES.md](NOTES.md).

Add `--json` to any command for one machine-readable JSON document.
Exit status is non-zero when any check fails.

External tools (found automatically when present):

| Tool | Used by | Lookup |
| --- | --- | --- |
| Bitcoin Core `bitcoind` | `verify bitcoin-header`, `mine regtest` | `BMR_BITCOIND`, `tools/bitcoin-core/*/bin`, `PATH` |
| Python + `z3-solver` | `research smt`, `research smt-scaling` | `BMR_PYTHON` (default `python`) |
| Vulkan / DX12 / Metal GPU | GPU backend | wgpu adapter discovery (no CUDA) |

`tools/bitcoin-core/` holds Bitcoin Core 32.1 (`bitcoin-32.1-win64.zip`,
SHA-256 checked against the release `SHA256SUMS`). Results go to
`experiments/` (`BMR_DATA_DIR` overrides).

## What is measured where

Results never transfer between these primitives; every record names one.

| Primitive | Meaning |
| --- | --- |
| `sha256-compression` | One compression call: state + 64-byte block, with feed-forward |
| `sha256-message-schedule` | W0..W63 expansion alone |
| `sha256` | Full SHA-256 of a message (padding, chaining) |
| `sha256d` | SHA-256(SHA-256(x)) of arbitrary inputs |
| `bitcoin-header-sha256d` | SHA-256d of an 80-byte header as a function of the nonce (midstate form) |
| `bitcoin-header-sha256d-datapath` | Hardware datapaths computing the above |

Round-reduced variants cut the round loop of every compression call and keep
the message schedule and feed-forward. A configuration with fewer than 64
rounds is always reported as reduced-round; full-round configurations are
listed separately in each record (`scope.full_round_configurations`).

## Workspace

```
crates/
  sha256-core          FIPS 180-4 SHA-256, explicit 32-bit arithmetic, round count, tracing
  sha256d              double SHA-256 (full and reduced-round)
  bitcoin-header       80-byte headers, compact targets (Core SetCompact/GetCompact), midstate,
                       merkle roots, coinbase/BIP34/BIP141, block serialization
  mining-engine        Work/Backend interface, reference backend, JSON-RPC, regtest session
  cpu-backend          midstate / scalar (precompute + early reject) / AVX2 kernels, Rayon
  gpu-backend          wgpu compute (Vulkan/DX12/Metal), error scopes, device-loss detection
  differential-engine  avalanche, XOR differentials, characteristic trails (Lipmaa–Moriai)
  algebraic-engine     carry-free model, GF(2) schedule algebra, degree bounds, cube sums
  statistical-engine   SplitMix64 streams, binomial/chi-square/KS tests, intervals
  experiment-engine    experiment kinds, reproduction, verification, classification
  hardware-model       cycle-level pipeline simulator, dataflow resource counts, FPGA model
  verification         independent SHA-256 (constants derived from primes), suites
  research-storage     SQLite registry: experiments, benchmarks, hypotheses, evidence
apps/research-cli      the `bmr` binary
gpu/wgsl               SHA-256d search kernel
research/algebraic-models  Z3 models (Python)
experiments/           SQLite registry + one JSON file per experiment
```

## Correctness chain

1. `sha256-core` passes the NIST vectors (including one million `a`) and the
   FIPS 180-2 intermediate round states for `abc`.
2. `verification::independent` is a second SHA-256 written differently
   (constants derived from cube/square roots of primes, rotating register
   indices, 16-word schedule ring). It matches `sha256-core` on random
   messages and on every round count 0..=64, and both match the `sha2` crate.
3. Real main-network headers (blocks 0, 1, 100000 from its four txids, 125552)
   hash to their known block hashes through three paths and satisfy their own
   targets.
4. `bmr verify bitcoin-header` starts a regtest node, lets Bitcoin Core mine
   blocks itself, and checks every header field, hash, target and PoW against
   the node.
5. CPU kernels and the GPU kernel are compared with the reference on every
   lane (full digests) and on full hit sets; every nonce any backend reports
   is re-checked with the reference before use.
6. `bmr mine regtest` mines 102 blocks from `getblocktemplate`, submits them,
   and checks acceptance, the node's stored header and coinbase, subsidy,
   coinbase maturity at depths 1, 100 and 101, and fee collection from a
   wallet transaction.

## Research standard

Each experiment record (`experiments/results/<id>.json`, row in
`experiments/bmrl.sqlite`) contains: hypothesis and null hypothesis,
assumptions, baseline, implementation, dataset and seed, parameters,
environment (CPU, features, rustc, source fingerprint), observations with
confidence intervals, a digest of the deterministic results, an in-process
reproduction on a different thread count, independent verification,
counterexamples/witnesses, the data-derived result and conclusion.

Result labels:

- `negative`: no deviation from the baseline at the stated power.
- `reduced-round-only`: deviations only below 64 rounds; no mining relevance.
- `not-replicated`: a full-round deviation that vanished on a fresh seed (noise).
- `candidate-anomaly`: a full-round deviation that replicated. Still not a
  discovery; it requires methodology review and external replication.
- `model-estimate`: analytical model output, not a measurement.

Hypothesis status (`bmr research hypotheses`) is recomputed from all verified,
reproduced evidence; it is never set by hand. Only runs that pass
verification and reproduction count as evidence.

Two things are always reported separately: how fast hashes are computed
(engineering) and how many hashes a block needs (`expected_work_per_block_factor`,
which every optimization so far leaves at 1.0).

## Reproducing a result

```powershell
.\target\release\bmr research list
.\target\release\bmr research reproduce reduced-round-0001
```

`reproduce` reruns from the stored seed and parameters, compares the digest of
the deterministic results and stores the attempt in the `reproductions` table.
