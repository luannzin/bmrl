# Reproducibility

Every experiment is deterministic given its seed and parameters:

- Random inputs come from `SplitMix64::stream(seed, sample_index)`, so results
  do not depend on thread count or scheduling.
- Counts are integers reduced across threads; statistics are computed from the
  reduced counts.
- The deterministic part of each result is hashed (`result_digest`, SHA-256 of
  canonical JSON). Timing data is kept out of the digest.

Three levels of reproduction:

1. **In-process** (automatic): the framework reruns the experiment with the same
   seed on a Rayon pool with half the threads and compares digests
   (`reproduction.matched`). A mismatch sets status `failed-reproduction`, and
   the run is not counted as evidence. SMT kinds skip this step because solver
   timing is not reproducible; their brute-force grid and the validity of
   every solver answer are.
2. **On demand**: `bmr research reproduce <id>` reruns from the stored record
   and writes a row to the `reproductions` table, together with the current
   source fingerprint and definition version, so drift is visible.
3. **Independent seeds**: `bmr research <kind> --seed <n>` runs a fresh dataset.
   Hypothesis status needs negative results from at least two seeds before it
   becomes `not-supported`. `multiseed` runs 32 seeds inside one experiment.

Each record stores `environment.source_fingerprint`, a SHA-256 over every
source file that affects results. It works without git. When the workspace is
a git checkout, `environment.git_commit` is recorded as well.
