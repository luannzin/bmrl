# Research report

Every result below is a record in `experiments/results/`, cited by id in
brackets, and comes from the final run on commit `480c36f`. `bmr research
audit` confirms that every experiment and benchmark kind has a current record
from that exact code, with earlier records kept as history. The default seed
is 1112363596.

"Deviation" means distinguishable from the random baseline at the record's
stated power. A round count below 64 always means a reduced-round variant;
those results are kept apart from full-round claims and never extrapolated.

**Bottom line: no result changes the expected work of Bitcoin mining.**
Every optimisation measured lowers the cost per hash and leaves the number of
hashes per block unchanged. Every structure found disappears long before
64 rounds, and none raises the probability of SHA256d(header) ≤ target.

## Confirmed findings

Correctness and engineering, all at full rounds.

| Finding | Evidence |
| --- | --- |
| SHA-256 and SHA-256d are correct | NIST vectors incl. one million `a`, FIPS 180-2 round states, three implementations agree on 10,000 random messages and on every round count 0 to 64 (`bmr verify sha256`) |
| The header engine is correct | Mainnet blocks 0, 1, 100000 (from its txids) and 125552; 21 headers mined by Bitcoin Core 32.1 parsed, hashed and PoW-checked field by field (`bmr verify bitcoin-header`) |
| CPU and GPU agree with the reference | 65,536 GPU digests and every hit over 2^22 nonces identical; CPU kernels identical at 1 and 4 threads [bench-gpu-0002] |
| Regtest mining works | 102 blocks from each of CPU and GPU accepted; reward immature at depth 1 and 100, mature at 101; template transaction fee collected [bench-regtest-0003, bench-regtest-0004] |
| The real mining path works end to end | Live template, coinbase and merkle rebuilt per extra nonce, full nonce space with the real target comparison; all 1,504 hits checked by the `sha2` crate over the serialized header; one block accepted per backend [bench-mining-0001] |

Measured throughput (Xeon E5-2680 v4, RX 7600):

| Backend | Raw SHA256d | End-to-end on a live template | Hits vs expected |
| --- | --- | --- | --- |
| CPU AVX2, 28 threads | 116.0 MH/s | 116.7 MH/s | 125, 0.89x |
| GPU (wgpu, Vulkan) | 491.8 MH/s | 508.1 MH/s | 642, 1.06x |
| CPU + GPU | 629.1 MH/s | 622.1 MH/s | 737, 0.99x |

The template work (coinbase, merkle root, midstate, extra-nonce rolls) is
too small to see. End-to-end and raw rates differ by run-to-run variation
only. The hit counts match expectation for Poisson counts of that size.
Single thread: reference 0.89 MH/s, midstate 1.34, scalar 1.41, AVX2 8.39
[bench-cpu-0002]. Energy was not measured: Windows exposes no CPU energy
counter and wgpu no GPU power counter.

## Negative findings

Searched for and not found, at the stated power.

| Question | Answer | Record |
| --- | --- | --- |
| Is full-round header SHA256d biased over the nonce? | No: bit frequencies, leading zeros and consecutive-nonce agreement uniform at 8, 12, 16, 20 and 64 rounds, 4.2M hashes each; 8-bit hit rate 0.003883, expected 0.003906 (CI 0.003824 to 0.003943) | statistical-0002 |
| Across 32 seeds? | No cell departs from uniform; the non-SHA control is calibrated. Full-round 8-bit hit ratios: SHA-256 of headers 0.990 (0.972 to 1.008), header SHA256d 1.004 (0.988 to 1.021), SHA256d of random inputs 1.007 (0.992 to 1.021) | multiseed-0002 |
| Does any structure survive to 64 rounds? | Avalanche is clean from 24 rounds. No repeated output difference at 64 rounds among 131,072 pairs. No single-bit trail followed beyond 2 rounds after entry. Cube sums are random from 6 rounds after entry. | reduced-round-0002, differential-0002, characteristic-0003, algebraic-0002 |
| Do neighbours of share hits find blocks more often? | No: A = 1.004 (0.983 to 1.026) at 64 rounds over 2^20 shares x 32 neighbours; work 0.9997x exhaustive | trail-search-0001 |
| Does filtering by trail conditions help? | No: A_C = 1.010 (0.990 to 1.031); the filter makes search about 81x slower | trail-search-0001 |
| Can an SMT solver beat brute force? | Only at 4 rounds (affine, below). From 8 rounds it is far slower; 16 rounds times out. | smt-0003, smt-scaling-0003 |
| Is the message schedule biased or correlated? | No biased bits and no correlated neighbouring words in W16..W63 | schedule-0003 |

## Reduced-round discoveries

Real structure, explained, and specific to the stated round counts. None of
it applies to 64-round SHA-256.

| Rounds | Structure | Record |
| --- | --- | --- |
| 4 per compression | H7 of the header hash is exactly K + bswap(nonce) mod 2^32, so the hash number's top byte depends only on the nonce's top byte. Z3 inverts it in 1.6 ms; neighbours of shares are target hits 192x as often; neighbour search needs 0.045x the work | smt-0003, trail-search-0001, unit test `four_round_h7_is_affine_in_the_nonce` |
| 5 per compression | Neighbours of share hits are 31% *less* likely to be target hits (A = 0.691, z = −28); the neighbour strategy costs 3.5% more | trail-search-0001 |
| 2 rounds after a 1-bit MSB difference enters | The pair follows the XOR trail with probability exactly 2^-11: 11 independent bit conditions from signed differences, 0 counterexamples in 83.9M pairs, the same template at every round | characteristic-audit-0001, [full report](differential-cryptanalysis/REPORT.md) |
| Up to 22 | First-order avalanche deviations; clean from 24 | reduced-round-0002 |
| Up to 5 after entry | Zero-sum cubes (algebraic degree below the cube dimension); proven degree bounds never contradicted | algebraic-0002 |
| Up to 4 | Agreement with the carry-free (XOR) model above 1/2: 52.4% after 1 round, 50.4% after 4 | algebraic-0002 |

The message schedule's linear structure is exact but carries no
reduced-round label. Every 16-word window of the linearized schedule has
GF(2) rank 512. The lightest expansion of a 1-bit message difference over
W16..W63 weighs 466 bits. The real and linearized schedules agree beyond
chance only up to W19 [schedule-0003].

## Corrected or invalidated findings

Kept in the registry with errata (`bmr research show <id>`, field `errata`).
None was deleted or overwritten.

| Record | What was wrong | Status |
| --- | --- | --- |
| schedule-0001 | Hand-written σ0(256) = 0x04000022 (correct: 0x00400022). The folded schedule was wrong on all inputs, so its timing is invalid; verification didn't check parity | Fixed: constants from calls, verification requires parity. schedule-0003: folding saves 19.6 ns of 116.8, 2.8% of one double compression on the generic path |
| characteristic-0001 | Sequential estimator, up to 15.9 bits too pessimistic | Superseded |
| characteristic-0002 | Grouped estimator, still up to 6.9 bits too pessimistic: it required intermediate XOR differences that don't need to hold | Superseded by the signed estimator, within 0.09 bits [characteristic-0003] |
| smt-scaling-0001 | Time budget spent on one encoding, so no encoding comparison | Superseded |
| smt-scaling-0002, -0003 | Solve times are heavy-tailed: an instance solves in 0.1 to 0.5 s or runs past a 2 to 4 s timeout. The adaptive timeout is too short, so frontiers and growth fits reflect the timeout | Interpretation withdrawn; measurements stand. "The encoding is the bottleneck" was never published |
| hardware-0001, -0002 | Register counts kept unused W61..W63 alive in early-reject designs | Fixed in hardware-0003 and later |
| Registry ids | `smt-%` matched `smt-scaling` ids, so `smt-0002` was skipped. The same bug could have overwritten a record once `characteristic-audit` existed | Fixed before any overwrite. 27 records, 27 identical files, start times monotonic |
| Audit criterion | "95% intervals overlap" falsely failed once at small counts | Replaced by a two-proportion test (p > 0.001) |

## Hardware: estimates versus measurements

| Kind | What | Values |
| --- | --- | --- |
| Measured | CPU, GPU, combined throughput | 116.0, 491.8, 629.1 MH/s raw (above) |
| Not measured | Power | Vendor ratings only: CPU 120 W TDP, GPU 165 W board power, giving at most 1.03 × 10^6 and 3.3 × 10^5 J/TH from the measured rates |
| Simulated, exact | 6 pipeline variants as full pipelines and as iterative cores with 1 to 32 round units | Every output identical to the reference and to the independent SHA-256; one nonce per cycle, or one per ceil(stages / u) cycles |
| Counted, exact | Midstate pipeline vs midstate + precompute + early reject + folding | 128 vs 122 stages, 1,201 vs 1,062 adders, 93,696 vs 81,824 register bits |
| **Estimated, not synthesized** | Best FPGA configuration under assumed clocks | Artix-7 XC7A100T: no full pipeline fits, 31 iterative cores, 0.15 to 0.20 GH/s. Kintex-7 XC7K325T: 3 pipelines, 0.60 to 0.75 GH/s. Virtex UltraScale+ XCVU9P: 17 pipelines, 5.1 to 6.8 GH/s. 10,600 to 54,000 J/TH |

The estimates rest on assumptions, all listed in the record
[hardware-0004]: 32 LUTs per 32-bit operator, no block RAM, assumed clock
ranges, 80% utilization, toggle energies of 0.3 to 1.5 pJ per LUT and
0.05 to 0.3 per FF, assumed static power. No RTL has been written or
synthesized, and no timing closed or board measured.

## Reproduction

```powershell
cargo build --release
.\target\release\bmr verify sha256
.\target\release\bmr verify bitcoin-header
.\target\release\bmr benchmark cpu
.\target\release\bmr benchmark gpu
.\target\release\bmr benchmark compare
.\target\release\bmr benchmark mining --search-seconds 20
.\target\release\bmr mine regtest --backend gpu
.\target\release\bmr research all
.\target\release\bmr research structural
.\target\release\bmr research characteristic-audit
.\target\release\bmr research trail-search
.\target\release\bmr research audit
.\target\release\bmr research reproduce characteristic-audit-0001
```

`research all` runs reduced-round, differential, statistical and smt.
`research structural` runs characteristic, algebraic, schedule, smt-scaling,
multiseed and hardware. Every record carries its own `reproduction_command`.
`research reproduce <id>` reruns a record from its seed and parameters and
compares digests. Done out of process for characteristic-audit-0001,
trail-search-0001 and reduced-round-0002: all three reproduced bit for bit.
The final run also repeated every deterministic experiment of the first run
on the same seed. Reduced-round, differential, statistical, smt, algebraic,
multiseed, schedule and hardware all gave the identical result digest.

## Open hypotheses and the experiments they justify

| Hypothesis | Status | Next experiment |
| --- | --- | --- |
| H-STAT-01, H-STAT-02, H-SCHED-01 | not supported, one seed | Rerun with a second seed; two negative seeds move them to `not-supported` |
| H-SMT-02 (solver scaling) | measurements stand, interpretation withdrawn | Fixed generous timeout, at least 10 instances per point, fraction solved with the median, the same instances for every encoding, a native SAT solver (CryptoMiniSat or kissat) |
| 5-round anti-correlation | measured, not explained | Derive it as was done for 4 rounds: which nonce bits feed H7 at 5 rounds, and why neighbours lose share-level zeros |
| W3[10] header trail 0.09 bits off | measured | Per-condition marginals with the padding fixed, to see which early-round state bit is not yet uniform |
| H-HW-01 (FPGA) | model only | Emit RTL for one round stage from the stage list, simulate it against the Rust model, synthesize with Yosys/nextpnr or Vivado |
| Energy | not measured | A wall-plug meter, or AMD ADLX telemetry for the GPU |
