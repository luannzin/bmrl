# Dev-fee GPU miner — the plan

Written 2026-11-23. The pivot: the break program nulled out (no break, no
single-card profit — see [QUANTUS-ATLAS.md](QUANTUS-ATLAS.md),
[HYPOTHESES.md](HYPOTHESES.md), [PLAN-v2.md](PLAN-v2.md)). The one money path
that fits the lab's real asset (building fast GPU kernels) without a break,
capital, or cheap power is a **dev-fee miner**: software other people run on
their cards, taking a small fee. Income = `fee x adoption x emission`, earned
from everyone's hashrate, not just this one RX 7600.

This file is the strategy and product spec. The buildable kickoff is in
[MINER-KICKOFF-PROMPT.md](MINER-KICKOFF-PROMPT.md) (paste into a fresh session
on the new private repo).

## Thesis and differentiator

The miner market is crowded (lolMiner, SRBMiner, T-Rex, GMiner, BzMiner,
Rigel; fees 0.7-2%) and **NVIDIA-first** — AMD support is routinely late,
slow, or missing. Fighting them head-on on Ethash/kHeavyHash is a loser's
game for a newcomer. The winning wedge is the opposite:

**Be the fastest — or the only — miner for coins the incumbents ignore, on
AMD, with a dashboard that does not suck, and an honest low fee.**

Three legs:
1. **Underserved coin first.** Pick a coin with real hashrate but no good
   miner for our hardware class. The research found two: **Quantus** (official
   miner is wgpu/WGSL + CUDA, *no AMD/ROCm path*) and **Spectre** (SpectreX,
   shipped *CPU-only, no GPU miner at all*). Owning a niche beats being
   miner #8 on Ethash.
2. **AMD-first (RDNA).** The whole market under-serves AMD. This RX 7600
   (RDNA3) is the dev box; tune for RDNA, support NVIDIA after.
3. **UX as a weapon.** Mining software UX is famously bad: cryptic `.bat`
   files, flag soup, ugly or absent dashboards. A clean one-command start, GPU
   auto-detect, and a genuinely good local web dashboard (live hashrate,
   earnings in coin and USD, temps, shares, and transparent fee) is a visible,
   real differentiator that costs incumbents nothing to ignore and us little
   to nail.

Honesty is part of the product: the fee is disclosed in the UI and the docs,
no hidden mining, no bundled junk. Trust is the whole game for a binary that
is, by shape, indistinguishable from malware.

## Identity and design — follow the luannzin presence (non-negotiable)

The miner is part of Luan's public presence, so it carries the same identity as
his other work. Read first: `luannzin-online-presence/CLAUDE.md` and `VOICE.md`,
luannzin.com's `DESIGN.md` + `IDENTITY.md` + its `luan-writing-way` skill
(`luannzin.com/.claude/skills/luan-writing-way/SKILL.md`), and the `lines`
repo's `DESIGN.md` (all under `C:\Users\luannzin\Documents`).

- **Visual family (the pixel look).** Join the family aesthetic of the Lines
  and siblings (Deskline, Sightline, PartyLine, Hostline, LanPet): a 32x32
  pixel-art mark in the **dusk palette** (`#3a2a6b`, `#7a3361`, `#e0703f`,
  `#ffd180` on `#110d24`) with a **4x4 Bayer dither**, drawn by a
  `tools/logo.py` (the family convention). The product name renders in the
  **5x7 pixel face**. One source per palette.
- **Dashboard = a "line" page in spirit.** Night field of dusk dots, the mark
  in its glow, the name in the pixel face, calm **ink tiers** for text (art
  leads, text stays quiet). Built with **coss UI (Base UI + Tailwind)**,
  dark/dusk. Not a generic admin template.
- **Native miner: Rust** (already the stack).
- **Design process:** every interface pass through the **`impeccable`** skill
  and the **`better-*`** skills (typography, layout, colours, ui, accessibility,
  writing, interface), motion through **`emil-design-eng`**. No AI-slop design.
  Think in magic, not in time.
- **Every user-facing word** (dashboard, README, errors, the fee notice, docs,
  any landing page) goes through **`VOICE.md`** then the **`luan-writing-way`**
  skill: first person, numbers not adjectives, no em dashes, no
  "powerful/seamless/blazing fast", no emoji in prose, British-leaning
  spelling. Public copy gets a Brazilian Portuguese twin. Never invent a
  reason, feeling or metric for him — ask one specific question.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`),
  **no `Co-Authored-By` line** (his rule).
- **Name:** his call — family-consistent (a sibling of the pixel family like
  LanPet, not necessarily a "-line"). Propose options; he decides.

## First coin: Quantus (QTC)

Chosen for execution, not for income size:
- **Head start:** a bit-exact, KAT-validated Quantus QPoW reference already
  exists in this repo, `crates/quantus-pow` (Goldilocks field, Poseidon2
  width-12, `hash_squeeze_twice`, the `block_hash||nonce < target` rule,
  validated against qp-poseidon's own test vectors). The GPU kernel is
  validated bit-for-bit against it — the same parity discipline the Bitcoin
  work used. This removes the biggest risk (a wrong hash = invalid shares =
  dead miner).
- **Real niche:** the Quantus network is ~27 TH/s; its AMD miners have no
  tuned option (only the generic wgpu path, or nothing). We can be *the* AMD
  Quantus miner.
- **Tractable kernel:** Poseidon2 is compute-bound and maps well to GPUs,
  unlike Spectre's branchy AstroBWTv3.

Income is modest here (Quantus emission ~1817 QTC/day ≈ $55k/day at ~$30.6; at
1% fee, capturing a few percent of its hashrate is tens of dollars/day), and
the coin does not pay *this* card at $0.175/kWh — but miners with cheaper power
do run it, and they are the customers. Quantus is coin #1 to ship and learn
on; income comes from breadth later. **Spectre is the high-upside coin #2**
(first-ever GPU miner = capture ~all new GPU hashrate) once the kernel skill
and the product shell exist.

## Monetization, honestly

`daily_$ = fee_fraction x (our_share_of_network_hashrate) x network_emission_$`.

- Quantus now: emission ≈ $55k/day. 1% fee x 2% capture = ~$11/day; x 10%
  capture = ~$55/day. Real but small; grows with adoption and more coins.
- The model scales by **adding coins/algos** (eventually profit-switching
  across whatever pays), each widening `adoption` and `emission`. The ceiling
  is the lolMiner model: a full-time income from fees across many algos.
- It does **not** need any coin to be profitable for us, only profitable for
  *some* miners who then choose our binary.

## Architecture

- **Language:** Rust (the lab's stack). 
- **GPU:** `wgpu` (already used in `crates/gpu-backend`), which runs on AMD via
  Vulkan, NVIDIA via Vulkan/DX12, Apple via Metal — one kernel, all vendors.
  Start here; drop to native Vulkan (`ash`) or HIP/rocWMMA later only if
  profiling shows the WGSL->SPIR-V path leaves AMD performance on the table.
- **Correctness oracle:** `quantus-pow`'s CPU reference. Every GPU kernel is
  parity-tested against it over many nonces before it is trusted; every found
  share is re-verified on the CPU before submission. Non-negotiable.
- **Shape:** a core crate (hashing + search), a pool client (Stratum), a
  device layer (wgpu), a control/stats layer, and the dashboard. Keep the
  hash/kernel isolated and reusable so coin #2 slots in beside coin #1.

### The kernel (the moat)

Goldilocks-Poseidon2 on RDNA3. Key practical point: **WGSL has no `u64`, but
RDNA3 via Vulkan supports the `SHADER_INT64` capability** — check
`wgpu::Features::SHADER_INT64` on the RX 7600 first. If present, the WGSL
kernel mirrors the CPU reference almost line for line (`reduce128`, `exp7`,
the 12-lane permutation, the sponge), which is the fastest path to a correct,
fast kernel. If absent, emulate `u64` with `u32` limb pairs (the official
`mining_u64.wgsl` is a reference for this). Either way, validate against the
CPU reference. Optimizations after correctness: the midstate cache (5 perms
-> 3 per nonce, already known), rejecting on the first squeeze, workgroup
sizing, and keeping the whole search on-GPU.

### The pool protocol

Quantus pools (herominers, kryptex, 2miners) speak a Stratum variant. The
exact method set and the share/job format are in the official
`Quantus-Network/quantus-miner` pool-client code — read it first and mirror
it. The miner must: subscribe/authorize, receive jobs (block template +
target), search, submit shares, handle `set_difficulty` and reconnect/failover.

### The dev fee (transparent)

Standard model: mine to the developer's address for `fee_fraction` of the time
(e.g. 60s of dev mining per 100 minutes = 1%), switching the pool
login/address briefly, then back. Show it live in the dashboard ("fee: 1%,
X minutes to next fee round, total contributed: Y"). Closed-source release
binary (the fee is the business); the hashing/kernel can still be inspectable
enough to earn trust. Never hide it.

## UX (the differentiator — get this genuinely right)

The user has never run mining software; assume the customer hasn't either.
- **Start:** one command, or a double-click. Auto-detect GPUs. A first-run
  wizard or a single commented config file (wallet, pool, coin) with sane
  defaults. No flag soup required.
- **Local web dashboard** (served on `localhost`, real-time via websocket):
  total and per-GPU hashrate with a live graph; accepted/rejected/stale
  shares; current coin and pool; **estimated earnings in coin/day and USD/day**
  (live price); GPU temperature, power, clocks, fan; uptime; a clear,
  always-visible **fee disclosure** (percent + total contributed); readable
  logs. Modern, clean, dark-mode, fast. This is where incumbents are weak.
- **Errors that help:** bad wallet format, unreachable pool, driver too old ->
  a plain-language message and the fix, never a raw stack trace.
- **Cross-platform:** Windows and Linux (miners use both). Signed builds and
  an antivirus-whitelist plan, because a mining binary trips AV by default.
- **Docs:** a short honest README — what it mines, the fee, how to start, how
  to read the dashboard.

## Roadmap

1. **MVP (coin #1, Quantus):** wgpu Goldilocks-Poseidon2 kernel validated
   bit-exact against the CPU reference; hashrate benchmark on the RX 7600;
   Stratum client to a live Quantus pool; real accepted shares; the dev-fee
   mechanism; the local dashboard; one-command start. Ship it, get a handful
   of AMD Quantus miners running it, watch fee income appear.
2. **Harden:** failover, watchdog/auto-restart, multi-GPU, stability, signed
   builds, AV whitelisting, a community presence (a thread, a Discord).
3. **Coin #2 (Spectre):** the first GPU miner for SpectreX — high upside
   (capture ~all GPU hashrate on a coin that has none). Reuses the shell.
4. **Breadth / profit-switch:** more algos, auto-switch to the most profitable,
   widening fee income across the GPU-mining economy. This is the lolMiner
   endgame.

## Risks

- **Fee circumvention:** an open clone or a patched binary drops the fee.
  Mitigate by being meaningfully faster/better, not merely present, and by
  owning niches where there is no alternative to clone.
- **Trust/adoption lag:** a closed mining binary looks like malware; adoption
  is slow until reputation exists. The dashboard, honesty, and AV whitelisting
  are the counter.
- **Coin risk:** the target coin dies, forks its PoW, or goes ASIC. Mitigate
  with multi-coin breadth.
- **Kernel risk (Spectre):** AstroBWTv3 may be genuinely hard to GPU-accelerate
  (that is likely why it is CPU-only). De-risk by doing Quantus first.
- **Legal/tax:** dev-fee income is taxable (Receita Federal). See an
  accountant before it scales.

## What NOT to do

- Do not fight lolMiner/SRBMiner on crowded algos (Ethash, kHeavyHash) at the
  start.
- Do not hide the fee, bundle anything, or ship an unvalidated kernel (a wrong
  hash means rejected shares and a dead reputation).
- Do not over-build: MVP is one coin, one pool, one clean dashboard. Breadth
  comes after the first real users.
