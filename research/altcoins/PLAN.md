# Altcoin PoW breaks: plan

Written 2026-11-23, before any code. Nothing here is a result yet. Every
number below is either quoted from a source (listed at the end) or derived
from one, and phase 0 re-checks all of them.

## Why the lab turns away from Bitcoin

The lab asked whether Bitcoin can be mined with fewer hashes, and every lens
at 64 rounds came back null. That answer stands. It is also the wrong
question for making money, because SHA256d is the hardest target there is:
the most-attacked hash in existence, mined by ASICs about 5,000 times more
efficient per joule than this GPU (1.914 GH/s at 165 W board power is about
86,000 J/TH; an Antminer S21 is about 17.5 J/TH).

People did not mine Bitcoin on GPUs during the pandemic. They mined
Ethereum (Ethash). Ethash is memory-bound, so ASICs had a small edge and
GPUs ran most of the network, and the 2021 ETH price made one card worth
several dollars a day. Many used NiceHash, which pays in BTC, so they said
they mined bitcoin; the work was Ethash and other algorithms. The Merge
(15 September 2022) moved Ethereum to proof of stake and ended that market.
No GPU coin of that size exists now.

Every real "magic" mining win in history happened in altcoins, never in
Bitcoin:

- Equihash (Zcash, 2016): solver algorithm improvements gave 10x and more in
  months, because the PoW is a search problem, not a hash.
- Cuckoo Cycle (Grin): lean and mean miners, time-memory tradeoffs; John
  Tromp pays bounties for speedups.
- ProgPoW 0.9.2 (2020): the 64-bit seed was small enough to bypass the DAG,
  so memory hardness could be skipped; the spec was patched.
- Poseidon (Ethereum Foundation cryptanalysis initiative, 2024-25): bounties
  for CICO attacks on reduced-round instances, and some instances fell.

## Constraints

- Hardware: one AMD RX 7600. No capital.
- Power: R$232.57 for 226 kWh, so R$1.03/kWh, about $0.175/kWh at
  R$5.87/USD (close of 18 November 2026).
- Preference: experiments, speedups, shortcuts and breaks. No miner business
  to run, except as a low-effort fallback.
- Policy if a break is found: mine quietly until a target ($300k, $1M or
  $10M), sell every day, then report it.

## Stock GPU mining loses money here

Kryptex pool page for the RX 7600, updated 23 November 2026, revenue per
year at its listed hashrate and GPU power (its profit figures assume about
$0.04/kWh):

| Coin | GPU power | Revenue/year | Power/year at R$1.03 | Break-even tariff | M = cost / revenue |
| --- | --- | --- | --- | --- | --- |
| Pearl (PRL) | 120 W | $145.04 | ~$184 | $0.138/kWh | 1.27 |
| Tari C29 (XTM-C29) | 80 W | $112.05 | ~$123 | $0.160/kWh | 1.10 |
| Quantus (QTC), Poseidon2 | 85 W | $100.00 | ~$130 | $0.134/kWh | 1.30 |
| Xelis (XEL) | 75 W | $42.92 | ~$115 | ~$0.065/kWh | 2.7 |
| IronFish (IRON) | 75 W | $42.12 | ~$115 | ~$0.064/kWh | 2.7 |

Per day at R$1.03/kWh: Pearl -R$0.63, Tari C29 -R$0.18, Quantus -R$0.49.
Kryptex counts GPU watts only; at the wall add PSU losses and the rest of
the PC (often 40 to 60 W more), which pushes Tari's M to about 1.8.

For comparison, mining Bitcoin directly on this card yields 0.087 sats/day
before power (`header-atlas-0001`). Kryptex's 365-day average for the card
on GPU coins is about 347 sats/day after power, about 4,000 times more.

## The money math

Profit per year is about `n * (k * r - c)`:

- `n` cards,
- `k` the edge over the best public miner on the same card,
- `r` revenue per stock card per year (~$145, Pearl on an RX 7600),
- `c` power per card per year (120 W at R$1.03/kWh is about $184).

`r` is roughly the same on every GPU coin, because the market pushes
per-card revenue toward the marginal miner's power cost. Coin size only sets
the ceiling.

Without reinvesting, $300k/yr needs k of about 2,100 on one card, 210 on 10,
22 on 100, 3.3 on 1,000. Renting GPUs costs about $1,300/yr per card, so
renting needs k of at least 9 just to break even.

With one card and reinvestment the real threshold is k of about 50. At
k = 53 one card makes about $625/month and a new RX 7600 costs $259, so each
card pays for itself in about 12 days, and one card becomes about 40 in
roughly two months. Forty cards (about 6 kW at the wall) is the home
ceiling; the wiring has to be checked first.

| Goal at 40 cards | Edge k needed | Coin emission E needed at <= 10% share |
| --- | --- | --- |
| $300k/yr | ~53 | >= ~$3M/yr |
| $1M/yr | ~175 | >= ~$10M/yr |
| $10M/yr | ~1,700 | >= ~$100M/yr (rare among breakable coins) |

E is a coin's annual emission value: block reward plus fees, times blocks
per year, times price. Above about 10% of a network's hashrate a miner shows
up as "mystery hashrate"; Kaspa and Monero both saw stealth FPGA or ASIC
miners noticed, and Monero forked its PoW against ASICs. Selling $822/day
also needs daily volume of about $80k or more, or the price sinks.

The tension: microcaps (Pearl, Quantus, Tari C29) are the likeliest to have
a weak PoW, but their pot may be under $300k even at 100% share. Big coins
have big pots and strong PoW. The sweet spot is a mid-cap coin with a young
or exotic PoW, or a new launch the lab is ready for on day one.

## Kill rule

A track dies when its credible upper bound on k is below 50. A modest k
(1.3 to 50) is a fallback, not the goal: license the kernel to an existing
miner developer, which needs no business to run.

## Paths considered

- P1, break (k >= 1,000, one card is enough): long odds, real precedent,
  only in exotic PoWs (algebraic, graph search, memory tricks, matmul or
  useful work). Needs secrecy and has a half-life of months. Chosen.
- P2, miner business with a dev fee: income is fee x adoption x E_gpu, for
  example 1% x 30% x $100M = $300k. Precedent: Claymore, lolMiner, Rigel,
  BzMiner, SRBMiner. Needs CUDA/HIP, NVIDIA support, closed binaries and
  support work. Kept only as a fallback.
- P3, an edge on an owned fleet (k 3 to 20, 100 to 1,000 cards): needs
  capital and cheap power. Dropped: no capital.
- P4, bounties (one-off, $100k and more each): Ethereum Foundation Poseidon
  CICO bounties, Tromp's Cuckoo bounties, Immunefi or HackerOne for
  consensus or PoW-validation bugs in node software. Any node bug found goes
  here.

## Rules

- Legit: computing valid PoW with less work. That is what AsicBoost and
  stealth ASICs did.
- Out: a node or consensus bug that accepts invalid PoW. That is an exploit;
  it goes to a bounty and is never mined.
- Hashrate share at most 10%. Never near 50%, no selfish mining, no reorgs.
- At scale, mine solo on an own node (pools see hashrate) and sell at most
  1 to 2% of the coin's daily volume.
- Exit triggers: share above the cap, a PoW fork announced, mystery-hashrate
  talk in the community, a price crash. Then sell, stop and report.
- See an accountant about Receita Federal crypto rules before scaling.

## What makes a PoW breakable

1. Young: under two years old, little published cryptanalysis.
2. Hand-rolled or exotic: a custom chain, or a standard primitive used
   outside its security model (reduced rounds, small field, truncation).
3. Structure: field arithmetic, low degree, matrices.
4. Search-type PoW (graph, collision): the solver algorithm matters more
   than the hash.
5. Memory-hard with weak spots: predictable accesses, a small seed, a
   reusable table.
6. Immature miners: a naive reference and recent, closed public miners.
7. Pot: E of at least $3M a year and a real exchange order book.

A target needs most of 1 to 6 and must pass 7.

## First candidates (all unverified until phase 0)

- Quantus (QTC): Poseidon2, field arithmetic and algebraic by design. A PoW
  condition "output below target" is close to CICO, the exact problem the
  Ethereum Foundation bounties target, and it only needs about 2^50 to 2^60
  of work beaten, not 128-bit security. Best "WOOOW" candidate.
- Tari C29: probably Cuckaroo29, a graph search; lowest M.
- Pearl (PRL): 17.97 TH/s on a GPU is not a normal hash, possibly matmul or
  useful work. If it is matrix-based, RDNA3's WMMA units could beat generic
  miners.
- Secondary: Xelis, IronFish (FishHash), Ergo (Autolykos2), Ravencoin and
  other KawPow coins.

## Pipeline

### Phase 0: atlas (about a week, desk research, no code)

Per coin: algorithm, primitive type, launch date, published reviews and
audits, open bounties, best public miner on the RX 7600 and its fee, AMD
versus NVIDIA gap, E and the GPU-mined share of it, exchange liquidity,
upcoming fair launches. Score each coin by P(k >= 50) x min(pot, goal) and
pick 5 to 8.

### Phase 1: cheap sweep (one to two weeks, every pick, kill fast)

- S1, work profiler: where the prover's work goes (hash, memory, field
  arithmetic, graph); the nonce-independent share, generalizing the
  `work-sharing` compiler (AsicBoost for any PoW); prover versus verifier
  cost. Work concentrated in one exotic phase marks a target.
- S2, parameter frontier: find the reduced parameter where a shortcut works
  (the positive control), then plot how k decays toward full parameters,
  like Bitcoin's 4 to 5 round cliff. A curve that can reach full parameters
  goes deep; a collapsing one is killed.
- S3, evolved rules (GP) on reduced and full parameters. They found the
  4-round Bitcoin shortcut on their own.
- S4, mainnet atlas per coin: output bias against miner-choosable bits (the
  `header-atlas` method), plus stealth-miner fingerprints such as nonce
  patterns and hashrate jumps. A fingerprint means someone already has an
  edge: proof that a break exists, and a sign of competition.

### Phase 2: deep tracks (two to four weeks per target, at most two at once)

| Class | Attack | k potential |
| --- | --- | --- |
| Algebraic (Poseidon2, Quantus) | Groebner, resultant and CICO attacks on the PoW target, not on 128-bit security | enormous if it works |
| Graph search (Cuckoo, C29) | new trimming and solver algorithms, TMTO | 10 to 100x seen in young coins |
| Memory-hard (Autolykos, KawPow, FishHash, XelisHash) | small seeds, predictable accesses, cache reuse | huge if the seed is small (ProgPoW pattern) |
| Matmul or useful work (Pearl?) | inputs that make the work cheaper (low rank, structure) | unknown until the scheme is read |
| Hand-rolled chains | weak mixing, miner-choosable paths | varies |

### Phase 3: quiet proof (one week)

Mine on a public pool with the single card. Accepted shares are verification
by a third party. Measure k at the wall against the best public miner on the
same card. Continue only if k >= 50.

### Phase 4: scale

Reinvest daily up to 40 cards, move to an own solo node, keep the share
cap, sell daily, watch the exit triggers. Write the report while mining and
publish it at the goal or at an exit trigger.

## What the lab reuses and what it needs

Reused: `experiment-engine` records and kill rules, `statistical-engine`,
the work-sharing compiler, the GP for evolved rules, the z3/SAT path, wgpu
kernels with CPU verification, and the header-atlas method.

New, only when a target needs it: a generic `Pow` trait (a reference
implementation plus a reduced-parameter knob, one implementation per chosen
coin), prime-field support in `algebraic-engine` (only if the algebraic
track survives phase 1), graph solvers (only if a graph coin survives).

Board ids for this work: `H-ALT-xx`, same record format as the rest.

## Odds

Most tracks will die, as they did on Bitcoin. The likely outcome is several
nulls and maybe a modest k. k >= 50 is rare, but it has happened in young
coins (early Equihash, the ProgPoW seed). The main lever is testing many
coins cheaply and killing fast, which is what phase 1 is for.

## Sources

- Kryptex pool, RX 7600: https://pool.kryptex.com/device/gpu/amd/amd-radeon-rx-7600
- Kryptex hardware, RX 7600: https://www.kryptex.com/en/hardware/amd-rx-7600
- Changelly, most profitable crypto to mine 2026: https://changelly.com/blog/most-profitable-crypto-to-mine/
- Hashrate.no, RX 7600 (stale): https://www.hashrate.no/gpus/7600
- Brasil61, dollar closes at R$5.87 (18 November 2026): https://brasil61.com/n/dolar-fecha-em-alta-de-1-45-e-chega-a-r-5-87-bras2617492
- Brasil61, dollar at R$5.77 (17 November 2026): https://brasil61.com/n/dolar-fecha-cotado-a-r-5-77-e-registra-quarta-alta-consecutiva-bras2617486.amp
- Folha PE, dollar at R$5.86: https://www.folhape.com.br/economia/dolar-tem-5a-alta-e-atinge-r-586-com-riscos-ao-plp-do-ajuste-e/525028/
