# The dev-fee miner business (notes to think about)

Not a plan, a note. The user asked to park this for later thought. It is the
only path found so far where the lab's real strength — building fast GPU
kernels — turns into money *without* capital for scale and *without* finding
a cryptographic break. Kept separate from the break program
([HYPOTHESES.md](HYPOTHESES.md), [PLAN-v2.md](PLAN-v2.md)) on purpose: this
earns from *other people's* cards, the break earns from ours.

## The idea in one line

Build the best (or the only good) miner for a GPU coin whose public miners
are weak, closed, or NVIDIA-only, charge a small dev fee, and earn
`fee x adoption x (network emission that coin pays GPUs)`.

## Why it could work here

- The lab already builds fast kernels: the Bitcoin SHA256d kernel went v1 to
  v2 at 3.48x in a day, with CPU-verified parity. Mining miners are exactly
  "fast kernel + pool plumbing + packaging."
- The one card is an AMD RX 7600 (RDNA3). The whole mining-miner market is
  NVIDIA-first; AMD support is routinely an afterthought, late, or missing
  (the Pearl research literally reported the first non-NVIDIA shares ever
  mined on that chain). An RDNA3-tuned miner serves an underserved side of
  the market.
- Income does not need a jackpot or a break. It compounds with adoption and
  needs no hardware beyond the dev machine.

## The money math (v1's P2, restated)

`income = dev_fee_fraction x adoption_share x E_gpu`, where `E_gpu` is the
annual value of the coin's emission that GPUs mine.

- Example: 1% fee x 30% of a coin whose GPUs earn $100M/yr = $300k/yr.
- Example, modest: 1.5% x 10% x $30M = $45k/yr.
- Precedents that did exactly this: Claymore, lolMiner, SRBMiner, Rigel,
  BzMiner, T-Rex, GMiner. Several became full-time incomes from a dev fee.

## What it takes (the honest cost)

- Fast, correct kernels per algorithm (the part the lab is good at).
- Pool plumbing: Stratum (V1/V2), reconnect/failover, share submission,
  `mining.set_difficulty`, extranonce/version rolling.
- Packaging: Windows + Linux builds, config, auto-switching, a watchdog, hash
  stats, temperature/clocks readout.
- A fee mechanism that cannot be trivially stripped (closed binaries; the fee
  is the business, so an open clone that removes it is the main threat).
- Trust and distribution: a miner is malware-shaped (closed binary, mines
  crypto, opens sockets). Adoption needs a reputation, a community
  (bitcointalk, Discord), antivirus whitelisting, and visible fairness.
- Ongoing support: new coins, forks, driver changes, user issues. This is a
  product with operations, not a research run. That is the real reason to
  think before committing: it trades the lab's research mode for a support
  burden.

## Risks

- Fee circumvention: an open-source competitor or a patched binary drops the
  fee to zero. Mitigate by being meaningfully faster, not just present.
- Coin risk: the target coin dies, forks its PoW, or goes ASIC, and the
  adoption evaporates.
- Trust lag: adoption is slow until reputation exists; the first months earn
  little.
- Legal/tax: dev-fee income is taxable (Receita Federal); see an accountant
  before it scales, same as the mining rule in PLAN.md.

## How it interlocks with the break program

- A legitimate *efficiency* edge (a faster honest kernel, overt version
  rolling, a better memory-access schedule) is a selling point and SHOULD
  ship in the miner.
- A *break* (valid PoW with far less work) must NOT ship — shipping it to
  users publishes it and burns it in weeks. The user's policy already says:
  mine a break quietly, validate, report/bounty later. The miner business and
  the break are therefore separate revenue lines that should not be mixed.
- The miner gives two free assets to the break program: a distribution/telemetry
  channel (what real miners run, real pool behavior) and a finished,
  battle-tested kernel + Stratum stack that phase-3 "quiet proof" needs anyway.

## Smallest first step (if ever pursued)

Pick ONE algorithm where AMD/RDNA3 support is weakest and the pot is real,
ship a dev-fee RDNA3 miner for it, measure adoption and fee income over a
month. Low commitment, real signal. Do not build a multi-algo suite up front.

## Open question for the user

The break program and this business compete for the same scarce input: the
lab's kernel-building time. Decide whether this is (a) a fallback only if the
break program nulls out, (b) a parallel line built now for cash flow while the
break program runs, or (c) off the table. Noted, not decided.
