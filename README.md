<p align="center">
  <picture>
    <source media="(prefers-reduced-motion: reduce)" srcset="assets/banner.png">
    <img src="assets/banner.webp" alt="BMRL: Bitcoin Mining Research Lab, with a turning pixel-art bitcoin" width="100%">
  </picture>
</p>

<p align="center">
  <a href="#what-it-found"><b>What it found</b></a> ·
  <a href="#run-it">Run it</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#how-a-result-counts">How a result counts</a>
</p>

I want to know if Bitcoin can be mined with fewer hashes than everyone else uses. So every idea
I have about it goes in here as an experiment: a hypothesis and its null, a seed, an independent
check, and a record in `experiments/` that stays whether the idea worked or not.

Two things never mix in the records. How fast a hash is computed is engineering, and the GPU
kernels here got 3.8 times faster. How many hashes a block needs is the real question, and nothing
has moved it at the full 64 rounds yet.

## What it found

| Idea | What happened | Record |
| --- | --- | --- |
| Faster GPU kernels | 506 MH/s (v1) to 1.752 GH/s (v2: precomputed rounds, unrolled, early reject) to 1.914 GH/s (v3: version rolling) on an RX 7600, every hit checked against the CPU | `bench-gpu-0006` |
| Batching headers, AsicBoost and beyond | A compiler counted the work every feasible batch of headers can share. Only version rolling shares anything: 11.6% of the per-nonce work at 4 headers, 15.5% at most. The GPU gets 9.2% at 8 | `work-sharing-0001` |
| Every block on the main chain | 977,066 headers downloaded over P2P and validated with this repo's own consensus code. Each block's hash divided by its target is uniform (KS p = 0.87), as a random function's would be. Miners leave fingerprints (nonce bit 7, version rolling in 95.9% of 2026 blocks), but none of it is in SHA-256 | `header-atlas-0001` |
| Every nonce of 16 templates | All 2^32 nonces each, 4 of them real blocks. No selection strategy beats exhaustive search on templates it never saw | `nonce-atlas-0002` |
| Evolved selection rules | Genetic programming tried 60,000 cheap rules per round count, over the nonce, the template and one probe hash. At 4 rounds it found the exact shortcut on its own, `bswap(bswap(n) + probe7)`, which keeps only hits: 64 times the hit rate on templates it never saw. From 5 rounds on, no rule beats chance on those templates | `evolved-rules-0001` |
| Grover on the real header SHA256d | The whole 64-round header SHA256d as a quantum circuit: 14,977 qubits and 82,496 Toffoli gates each way, checked on every input. Simulated Grover finds the hit with probability 0.9999, as the theory says. At about one error in 1,000 gates, today's hardware, even 4 rounds falls to a random guess, and a real block search needs fewer than one error in 10^17 | `grover-circuit-0001` |
| Differential trails, SAT, cubes | Structure ends at round 5 of the 128 a header goes through | `trail-sat-0001`, `characteristic-audit-0002` |
| What a block costs | The network does 9.87e20 hashes a second. At 1.914 GH/s my GPU expects 0.087 sats a day | `header-atlas-0001` |

The longer story, with every number's record: [research/STATUS.md](research/STATUS.md),
[research/README.md](research/README.md), [research/breakthrough/REPORT.md](research/breakthrough/REPORT.md)
and the board of every hypothesis, [research/BOARD.md](research/BOARD.md). What happened when:
[NOTES.md](NOTES.md).

## Run it

```powershell
cargo build --release
.\target\release\bmr verify sha256
.\target\release\bmr benchmark gpu
.\target\release\bmr mine regtest --backend gpu
.\target\release\bmr research sync-headers
.\target\release\bmr research discovery
.\target\release\bmr research audit
```

`benchmark gpu` measures every kernel against the CPU. `mine regtest` mines 102 blocks on a fresh
Bitcoin Core regtest chain and checks that the node accepts each one. `sync-headers` downloads the
main chain's headers from public nodes (about 78 MB) for `header-atlas`. `discovery` runs the four
newest experiments, and `audit` says whether every result comes from the code you're running. Add
`--json` to any command for one JSON document. A failed check exits non-zero.

Every other command is in `bmr --help`. The older experiment sets run as `bmr research all`,
`structural` and `breakthrough`.

| Tool | Used by | Found through |
| --- | --- | --- |
| Bitcoin Core `bitcoind` | `verify bitcoin-header`, `mine regtest`, `benchmark mining` | `BMR_BITCOIND`, `tools/bitcoin-core/*/bin`, `PATH` |
| Python with `z3-solver` | `smt`, `smt-scaling`, `trail-sat` | `BMR_PYTHON` (default `python`) |
| A Vulkan, DX12 or Metal GPU | the GPU backend | wgpu adapter discovery, no CUDA |

## How it works

```
crates/
  sha256-core          SHA-256 from FIPS 180-4, any round count, round tracing
  sha256d              double SHA-256, full and reduced-round
  bitcoin-header       headers, compact targets, retargets, midstate, merkle roots, coinbase, blocks
  mining-engine        Work and Backend, BIP320 version rolling, regtest mining, JSON-RPC, P2P headers
  cpu-backend          midstate, scalar (precompute and early reject) and AVX2 kernels
  gpu-backend          wgpu compute; v1 in gpu/wgsl, v2 and v3 generated as straight-line WGSL
  differential-engine  avalanche, XOR differentials, characteristic trails
  algebraic-engine     carry-free model, GF(2) schedule algebra, degree bounds, cube sums
  statistical-engine   SplitMix64 streams, binomial, chi-square and KS tests, intervals
  experiment-engine    19 experiment kinds, reproduction, verification, the research board
  hardware-model       pipeline simulator, resource counts, FPGA model
  verification         a second SHA-256 written differently, test suites
  research-storage     SQLite registry of experiments, benchmarks, hypotheses and evidence
apps/research-cli      the `bmr` binary
research/              reports and the Python solver models
experiments/           the registry and one JSON file per record
tools/logo.py          draws the mark and the banner
```

Every hash path is checked against something it doesn't share code with:

1. `sha256-core` passes the NIST vectors, one million `a` included, and the FIPS intermediate
   round states for `abc`.
2. `verification::independent` is a second SHA-256 with constants derived from the primes. It
   matches `sha256-core` and the `sha2` crate on random messages and at every round count.
3. Real main-chain headers hash to their known block hashes through three paths.
4. `bmr verify bitcoin-header` lets Bitcoin Core mine blocks and checks every field against it.
5. Every kernel is compared with the reference on full digests and on whole hit sets, and every
   nonce a backend reports is hashed again before it's used.
6. `header-atlas` checks links, proof of work, every retarget and the median-time rule over the
   whole chain.

## How a result counts

A record holds the hypothesis and its null, assumptions, baseline, seed, parameters, the machine
and a fingerprint of the source, results with confidence intervals, a digest of everything
deterministic, a rerun on a different thread count, a check by independent code, and the
counterexamples.

- `negative`: nothing departed from the baseline at the stated power.
- `reduced-round-only`: something did, below 64 rounds only. Bitcoin uses all 64.
- `not-replicated`: a 64-round deviation that went away on a fresh seed.
- `candidate-anomaly`: a 64-round deviation that came back. Still not a discovery until the method
  is reviewed and someone else reproduces it.
- `model-estimate` and `exact-analysis`: a model or an exact count, not a measurement.

A hypothesis' status is recomputed from its verified, reproduced evidence, never set by hand.
Records are never deleted or overwritten: a mistake gets an erratum and the record stays.

```powershell
.\target\release\bmr research list
.\target\release\bmr research reproduce header-atlas-0001
```
