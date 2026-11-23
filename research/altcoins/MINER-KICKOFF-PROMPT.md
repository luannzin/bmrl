# Kickoff prompt — paste into a fresh session on the new private repo

> Everything the new session needs, cold. It assumes no prior context. Paste
> the block below as your first message in the new repo's chat.

---

We are building a **GPU cryptocurrency miner with a developer fee** — software
other people run on their GPUs that quietly mines ~1% of the time to our
address. Income is `fee × adoption × coin emission`, earned from everyone's
hashrate. Precedents: lolMiner, SRBMiner, T-Rex, GMiner (fees 0.7–2%).

**Who / setup:** I am new to mining and to this kind of software. Dev box is an
**AMD Radeon RX 7600 (RDNA3, gfx1102)** on **Windows** (a Linux target matters
too). Treat me as a beginner on mining specifics; explain choices briefly as
you go, but keep moving.

**The differentiator — make every decision serve these:**
1. **Underserved coin first.** We do NOT fight lolMiner/SRBMiner on crowded
   algos (Ethash, kHeavyHash). We start with **Quantus (QTC)**, whose official
   miner (`Quantus-Network/quantus-miner`) ships only wgpu/WGSL + a CUDA crate
   with **no AMD/ROCm-tuned path** — AMD miners have no good option. We become
   *the* AMD Quantus miner.
2. **AMD-first (RDNA).** Tune for this RX 7600; NVIDIA support comes after.
3. **UX as a weapon.** Mining software UX is terrible (`.bat` flag soup, ugly
   or no dashboard). Ours has one-command start, GPU auto-detect, and a genuinely
   good local web dashboard. This is a visible, real edge.
4. **Honesty.** The fee is shown in the UI and docs; no hidden mining, no
   bundled junk. Trust is everything for a binary shaped like malware.

**Identity & design (non-negotiable — this is my public presence).** Read
first, all under `C:\Users\luannzin\Documents`: `luannzin-online-presence/CLAUDE.md`
and `VOICE.md`; `luannzin.com/DESIGN.md`, `IDENTITY.md`, and its
`.claude/skills/luan-writing-way/SKILL.md`; the `lines` repo's `DESIGN.md`.
Then follow them:
- Join my pixel-art family (Deskline, Sightline, PartyLine, Hostline, LanPet):
  a 32x32 pixel-art mark in the **dusk palette** (`#3a2a6b`, `#7a3361`,
  `#e0703f`, `#ffd180` on `#110d24`) with a **4x4 Bayer dither**, drawn by a
  `tools/logo.py`; the name in the **5x7 pixel face**. One source per palette.
- Dashboard in **coss UI (Base UI + Tailwind)**, dusk/dark: a night field of
  dusk dots, the mark in its glow, calm ink tiers (art leads, text stays
  quiet). Not a generic admin template.
- Every interface pass through the **`impeccable`** skill, the **`better-*`**
  skills (typography, layout, colours, ui, accessibility, writing, interface),
  and **`emil-design-eng`** for motion. No AI-slop.
- Every user-facing word (dashboard, README, errors, the fee notice, docs)
  through **`VOICE.md`** then the **`luan-writing-way`** skill: first person,
  numbers not adjectives, no em dashes, no "powerful/seamless/blazing fast", no
  emoji in prose, British-leaning spelling, and a Brazilian Portuguese twin for
  public copy. Never invent a reason or metric for me — ask one question.
- Commits: **Conventional Commits, NO `Co-Authored-By` line.**
- Name: my call — propose family-consistent options (a sibling of the pixel
  family, not necessarily a "-line").

**The big asset — use it as the correctness oracle.** I already have a
**bit-exact, test-validated Quantus QPoW reference in Rust**, in my other
private repo `bmrl` at `crates/quantus-pow`. Copy that crate into this repo as
the reference. It implements, validated against `Quantus-Network/qp-poseidon`'s
own known-answer vectors:
- Goldilocks field `p = 2^64 − 2^32 + 1` with the fast `reduce128`.
- Poseidon2 width-12 permutation (rate 8, capacity 4, S-box x^7, 8 external +
  22 internal rounds) with the literal qp-poseidon round constants.
- The `hash_squeeze_twice` sponge and the PoW hash of `block_hash(32) ||
  nonce(64)`.
- The node validity rule: `target = U512::MAX / difficulty`, valid iff
  `U512::from_big_endian(hash) < target` (strict), plus a working CPU miner and
  benchmark (`miner.rs`, `bin/mine.rs`, ~1.2 MH/s on a 28-thread CPU).
If you cannot copy it, re-derive it from `Quantus-Network/chain`
(`qpow-math/src/lib.rs`) and `Quantus-Network/qp-poseidon` and re-validate
against qp-poseidon's test vectors before trusting any hash.

**Tech decisions (start here, change only with reason):**
- **Rust.** GPU via **`wgpu`** (AMD→Vulkan, NVIDIA→Vulkan/DX12, Apple→Metal):
  one kernel, every vendor. Drop to native Vulkan (`ash`) or HIP only if
  profiling later shows WGSL→SPIR-V leaves AMD performance on the table.
- **Parity discipline (non-negotiable):** every GPU kernel is validated
  bit-for-bit against the `quantus-pow` CPU reference over many nonces before
  it is trusted, and every candidate share is re-verified on the CPU before
  submission. A wrong hash = rejected shares = dead product.
- **`u64` on RDNA3:** WGSL has no native `u64`, but RDNA3/Vulkan supports the
  `SHADER_INT64` capability. **First, check `wgpu::Features::SHADER_INT64` on
  the RX 7600.** If present, the WGSL kernel can mirror the CPU reference
  (`reduce128`, `exp7`, the 12-lane permute, the sponge) almost directly — the
  fastest route to a correct, fast kernel. If absent, emulate `u64` with `u32`
  limb pairs (the official `mining_u64.wgsl` is a reference). Validate either
  way.

**First milestone — the MVP (do these in order):**
1. Scaffold the repo (workspace: a core hashing crate = copied `quantus-pow`,
   a pool-client crate, a wgpu device crate, a control/stats + dashboard crate).
   Pick a working product name.
2. **Read the official `Quantus-Network/quantus-miner` pool-client code** and
   mirror its pool protocol exactly (Stratum variant: subscribe/authorize,
   job = template + target, submit share, `set_difficulty`, reconnect/failover).
3. **Build the wgpu Goldilocks-Poseidon2 kernel.** Validate it bit-exact
   against the CPU reference over ≥1e6 nonces (zero mismatches) before anything
   else. Then benchmark MH/s on the RX 7600 and record it.
4. Wire the nonce search on-GPU, submit real shares to a live Quantus pool
   (herominers or kryptex), confirm accepted shares, re-verifying each hit on
   CPU first.
5. **The dev-fee mechanism**, transparent: mine to the dev address ~1% of the
   time (e.g. 60s per 100 min), shown live in the dashboard.
6. **The local web dashboard** (served on `localhost`, websocket, dark, fast):
   total + per-GPU hashrate graph; accepted/rejected/stale shares; current
   coin/pool; **estimated earnings QTC/day and USD/day** (live price); GPU
   temp/power/clocks/fan; uptime; an always-visible fee disclosure (percent +
   total contributed); readable logs.
7. One-command (or double-click) start, GPU auto-detect, a single commented
   config (wallet, pool, coin) with sane defaults, and plain-language errors
   (bad wallet, unreachable pool, old driver → the fix, not a stack trace).

**Acceptance for the MVP:** on the RX 7600, the miner hashes Quantus with a GPU
kernel proven bit-exact against the reference, connects to a live pool, gets
**accepted shares**, takes a visible 1% fee, and shows it all in a clean
dashboard started with one command.

**Dev-fee / release:** release binary is closed (the fee is the business), but
keep the hashing path inspectable enough to earn trust; sign builds and plan
for antivirus whitelisting (a mining binary trips AV by default).

**Roadmap after MVP:** harden (failover, watchdog, multi-GPU, stability,
community); then **coin #2 = Spectre (SpectreX)** — be the first-ever GPU miner
for it (it ships CPU-only), capturing ~all its GPU hashrate; then breadth /
profit-switching across algos (the lolMiner endgame).

**Do NOT:** fight incumbents on crowded algos at the start; hide the fee; bundle
anything; ship an unvalidated kernel; or over-build — MVP is one coin, one
pool, one clean dashboard, real accepted shares.

Start by reading the identity sources above and confirming the plan in one or
two lines (with 2-3 family-consistent name options and a one-line mark idea in
the dusk/Bayer look). Then scaffold the repo and copy in / re-create and
re-validate the `quantus-pow` reference. Keep me posted with short status lines
as you go.

---

(Full background, if you want it, lives in my `bmrl` repo:
`research/altcoins/MINER-PLAN.md`, `QUANTUS-ATLAS.md`, `HYPOTHESES.md`,
`BUSINESS-MINER.md`, and `crates/quantus-pow`.)
