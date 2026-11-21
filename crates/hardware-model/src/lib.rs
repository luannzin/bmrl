//! Hardware architecture exploration for Bitcoin header SHA-256d.
//!
//! * [`simulate`] runs a cycle-level model of a fully pipelined datapath (one
//!   round per stage, one nonce accepted per cycle) and returns every output
//!   with the cycle it appeared, so correctness, latency and steady-state
//!   throughput are checked against the software reference.
//! * [`resources`] counts datapath operators and register bits per pipeline
//!   from the same stage list, propagating which values vary with the nonce:
//!   with constant folding, any operator whose output is constant for a job
//!   is removed (it becomes a per-job precomputation).
//! * [`estimate`] turns counts into LUT/FF, devices, throughput and energy
//!   using explicit, user-visible cost parameters. Those parameters are
//!   assumptions; the estimates are models, not measurements.

#![forbid(unsafe_code)]

use algebraic_engine::schedule_dependence;
use bitcoin_header::HeaderMidstate;
use sha256_core::{IV, K, State, block_words, feed_forward, round, small_sigma0, small_sigma1};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arch {
    pub name: &'static str,
    /// Use the cached first-block compression (otherwise the pipeline computes block 1).
    pub midstate: bool,
    /// Second-block rounds computed once per job (W3 = nonce enters at round 3).
    pub precompute_rounds: usize,
    /// Stop the outer compression after round 60 and emit only H7 (= IV7 + e60).
    pub early_reject: bool,
    /// Remove operators and registers whose values are constant for a job.
    pub fold_constants: bool,
}

pub const VARIANTS: [Arch; 6] = [
    Arch { name: "no-midstate", midstate: false, precompute_rounds: 0, early_reject: false, fold_constants: false },
    Arch { name: "midstate", midstate: true, precompute_rounds: 0, early_reject: false, fold_constants: false },
    Arch { name: "midstate+precompute3", midstate: true, precompute_rounds: 3, early_reject: false, fold_constants: false },
    Arch { name: "midstate+precompute3+early-reject", midstate: true, precompute_rounds: 3, early_reject: true, fold_constants: false },
    Arch { name: "midstate+precompute3+early-reject+fold", midstate: true, precompute_rounds: 3, early_reject: true, fold_constants: true },
    Arch { name: "no-midstate+early-reject+fold", midstate: false, precompute_rounds: 0, early_reject: true, fold_constants: true },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block {
    First,
    Second,
    Outer,
}

#[derive(Clone, Copy, Debug)]
pub struct Stage {
    pub block: Block,
    pub t: usize,
}

pub fn stages(a: &Arch) -> Vec<Stage> {
    let mut s = Vec::new();
    if !a.midstate {
        s.extend((0..64).map(|t| Stage { block: Block::First, t }));
    }
    let start = if a.midstate { a.precompute_rounds } else { 0 };
    s.extend((start..64).map(|t| Stage { block: Block::Second, t }));
    s.extend((0..if a.early_reject { 61 } else { 64 }).map(|t| Stage { block: Block::Outer, t }));
    s
}

/// Per-job constants loaded into the datapath.
pub struct Job {
    header: [u8; 80],
    mid: HeaderMidstate,
    /// Second-block state after `precompute_rounds` rounds (nonce-independent).
    pre: State,
}

impl Job {
    pub fn new(header: [u8; 80], precompute_rounds: usize) -> Self {
        let mid = HeaderMidstate::new(&header);
        let w = mid.second_block(0);
        let mut pre = mid.state;
        for t in 0..precompute_rounds {
            assert!(t != 3, "round 3 consumes the nonce");
            pre = round(&pre, K[t], w[t]);
        }
        Self { header, mid, pre }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Digest(State),
    /// Most significant word of the hash number source: H7.
    H7(u32),
}

#[derive(Clone)]
struct Slot {
    nonce: u32,
    s: State,
    cv: State,
    w: [u32; 64],
    out: Option<Output>,
}

fn sched(w: &mut [u32; 64], t: usize) {
    if t >= 16 {
        w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
    }
}

fn enter_second(slot: &mut Slot, job: &Job, cv: State, start_state: State) {
    slot.cv = cv;
    slot.s = start_state;
    slot.w = [0; 64];
    slot.w[..16].copy_from_slice(&job.mid.second_block(slot.nonce));
}

fn apply(a: &Arch, st: Stage, mut x: Slot, job: &Job) -> Slot {
    match st.block {
        Block::First => {
            if st.t == 0 {
                x.cv = IV;
                x.s = IV;
                x.w = [0; 64];
                x.w[..16].copy_from_slice(&block_words(job.header[..64].try_into().expect("64 bytes")));
            }
            sched(&mut x.w, st.t);
            x.s = round(&x.s, K[st.t], x.w[st.t]);
            if st.t == 63 {
                let d = feed_forward(&x.cv, &x.s);
                enter_second(&mut x, job, d, d);
            }
        }
        Block::Second => {
            if a.midstate && st.t == a.precompute_rounds {
                enter_second(&mut x, job, job.mid.state, job.pre);
            }
            sched(&mut x.w, st.t);
            x.s = round(&x.s, K[st.t], x.w[st.t]);
            if st.t == 63 {
                let inner = feed_forward(&x.cv, &x.s);
                x.cv = IV;
                x.s = IV;
                x.w = [0; 64];
                x.w[..8].copy_from_slice(&inner);
                x.w[8] = 0x8000_0000;
                x.w[15] = 256;
            }
        }
        Block::Outer => {
            sched(&mut x.w, st.t);
            x.s = round(&x.s, K[st.t], x.w[st.t]);
            if a.early_reject && st.t == 60 {
                x.out = Some(Output::H7(IV[7].wrapping_add(x.s[4])));
            } else if st.t == 63 {
                x.out = Some(Output::Digest(feed_forward(&IV, &x.s)));
            }
        }
    }
    x
}

#[derive(Debug)]
pub struct SimResult {
    pub stages: usize,
    /// (nonce, output, cycle on which it left the pipeline)
    pub outputs: Vec<(u32, Output, u64)>,
    pub cycles: u64,
    /// Cycle of the first output (pipeline latency).
    pub latency: u64,
}

/// Feed `count` consecutive nonces from `start`, one per cycle.
pub fn simulate(a: &Arch, header: [u8; 80], start: u32, count: u32) -> SimResult {
    let job = Job::new(header, if a.midstate { a.precompute_rounds } else { 0 });
    let st = stages(a);
    let n = st.len();
    let mut regs: Vec<Option<Slot>> = vec![None; n];
    let mut outputs = Vec::with_capacity(count as usize);
    let mut fed = 0u32;
    let mut cycle = 0u64;
    while (outputs.len() as u32) < count {
        cycle += 1;
        // The value in the last register was produced at the end of the previous cycle.
        if let Some(x) = regs[n - 1].take() {
            outputs.push((x.nonce, x.out.expect("last stage produces output"), cycle - 1));
        }
        for i in (1..n).rev() {
            regs[i] = regs[i - 1].take().map(|x| apply(a, st[i], x, &job));
        }
        regs[0] = (fed < count).then(|| {
            let nonce = start.wrapping_add(fed);
            fed += 1;
            apply(a, st[0], Slot { nonce, s: [0; 8], cv: [0; 8], w: [0; 64], out: None }, &job)
        });
    }
    let latency = outputs.first().map_or(0, |o| o.2);
    let cycles = outputs.last().map_or(0, |o| o.2);
    SimResult { stages: n, outputs, cycles, latency }
}

/// Software reference for one nonce in the architecture's output format.
pub fn reference(a: &Arch, header: &[u8; 80], nonce: u32) -> Output {
    let h = HeaderMidstate::new(header).hash_words(nonce);
    if a.early_reject { Output::H7(h[7]) } else { Output::Digest(h) }
}

/// Operator and register counts for one pipeline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub stages: usize,
    pub adders: u64,
    /// Σ0, Σ1, σ0, σ1 (3-input XOR per bit).
    pub xor3: u64,
    pub ch: u64,
    pub maj: u64,
    pub register_bits: u64,
}

pub fn resources(a: &Arch) -> Resources {
    let fold = a.fold_constants;
    let mut r = Resources { stages: stages(a).len(), ..Default::default() };
    let count = |var: bool| -> u64 { (!fold || var) as u64 };
    let blocks: Vec<(Block, usize, usize)> = {
        let mut b = Vec::new();
        if !a.midstate {
            b.push((Block::First, 0, 64));
        }
        b.push((Block::Second, if a.midstate { a.precompute_rounds } else { 0 }, 64));
        b.push((Block::Outer, 0, if a.early_reject { 61 } else { 64 }));
        b
    };
    for (block, start, end) in blocks {
        // Which message words vary with the nonce, and which constants are zero.
        let (mut var_in, mut zero_in) = ([false; 16], [false; 16]);
        match block {
            Block::First => {}
            Block::Second => {
                var_in[3] = true;
                (5..15).for_each(|i| zero_in[i] = true);
            }
            Block::Outer => {
                (0..8).for_each(|i| var_in[i] = true);
                (9..15).for_each(|i| zero_in[i] = true);
            }
        }
        let sched = schedule_dependence(var_in, zero_in);
        let wvar = sched.variable;
        let mut svar = [false; 8];
        // Schedule words used in this block.
        for t in 16..end {
            r.adders += if fold { sched.adds[t] as u64 } else { 3 };
            r.xor3 += if fold { sched.sigmas[t] as u64 } else { 2 };
        }
        for t in start..end {
            let [a_, b_, c_, d_, e_, f_, g_, h_] = svar;
            let x1 = h_ || e_;
            let chv = e_ || f_ || g_;
            let x2 = x1 || chv;
            let t1 = x2 || wvar[t];
            let t2 = a_ || b_ || c_;
            r.xor3 += count(e_) + count(a_);
            r.ch += count(chv);
            r.maj += count(t2);
            // h + Σ1, + Ch, K + W, + (K + W), Σ0 + Maj, T1 + T2, d + T1
            r.adders += count(x1) + count(x2) + count(wvar[t]) + count(t1) + count(t2) + count(t1 || t2) + count(d_ || t1);
            svar = [t1 || t2, a_, b_, c_, d_ || t1, e_, f_, g_];
            // With folding, a stage whose state is still job-constant does not exist:
            // its work is per-job precomputation and the nonce is injected later.
            if fold && !svar.iter().any(|&v| v) {
                r.stages -= 1;
                continue;
            }
            // Registers after this stage: state words, the schedule window still
            // used by this block's remaining rounds (W_end.. never are), nonce.
            let live_w = ((t + 1)..=(t + 16).min(end - 1)).filter(|&j| !fold || wvar[j]).count() as u64;
            let state_bits = 32 * svar.iter().filter(|&&v| !fold || v).count() as u64;
            // Without midstate and folding, block 2's chaining value is a pipeline value.
            let cv_bits = if block == Block::Second && !a.midstate && !fold { 256 } else { 0 };
            r.register_bits += state_bits + 32 * live_w + 32 + cv_bits;
        }
        // Feed-forward adders at the end of the block (one per variable state word).
        r.adders += match (block, a.early_reject) {
            (Block::Outer, true) => 1,
            _ => svar.iter().filter(|&&v| !fold || v).count() as u64,
        };
    }
    r.adders += 1; // target comparator, counted as one 32-bit adder equivalent
    r
}

/// Cost parameters (assumptions, reported with every estimate).
#[derive(Clone, Copy, Debug)]
pub struct CostModel {
    /// LUTs per 32-bit operator (adder, XOR3 group, Ch, Maj).
    pub luts_per_word_op: f64,
    pub utilization: f64,
    /// Switching activity (fraction of nodes toggling per cycle).
    pub activity: f64,
    /// Dynamic energy per LUT / FF toggle, picojoules (low, high).
    pub pj_per_lut: (f64, f64),
    pub pj_per_ff: (f64, f64),
}

pub const DEFAULT_COST: CostModel =
    CostModel { luts_per_word_op: 32.0, utilization: 0.8, activity: 0.5, pj_per_lut: (0.3, 1.5), pj_per_ff: (0.05, 0.3) };

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub name: &'static str,
    /// Published resource counts (6-input LUTs, flip-flops).
    pub luts: u64,
    pub ffs: u64,
    /// Assumed clock range for one round per stage, MHz.
    pub mhz: (f64, f64),
    /// Assumed static power, watts.
    pub static_w: f64,
}

pub const DEVICES: [Device; 3] = [
    Device { name: "Xilinx Artix-7 XC7A100T", luts: 63_400, ffs: 126_800, mhz: (150.0, 200.0), static_w: 0.2 },
    Device { name: "Xilinx Kintex-7 XC7K325T", luts: 203_800, ffs: 407_600, mhz: (200.0, 250.0), static_w: 0.4 },
    Device { name: "Xilinx Virtex UltraScale+ XCVU9P", luts: 1_182_240, ffs: 2_364_480, mhz: (300.0, 400.0), static_w: 3.0 },
];

impl Resources {
    pub fn luts(&self, c: &CostModel) -> f64 {
        (self.adders + self.xor3 + self.ch + self.maj) as f64 * c.luts_per_word_op
    }

    /// Dynamic energy per hash for a fully pipelined design (pJ), low/high.
    pub fn pj_per_hash(&self, c: &CostModel) -> (f64, f64) {
        let l = self.luts(c);
        let f = self.register_bits as f64;
        (c.activity * (l * c.pj_per_lut.0 + f * c.pj_per_ff.0), c.activity * (l * c.pj_per_lut.1 + f * c.pj_per_ff.1))
    }
}

#[derive(Clone, Debug)]
pub struct Estimate {
    pub device: &'static str,
    pub pipelines: u64,
    /// Used when no full pipeline fits: iterative cores of `rounds_per_cycle` round units.
    pub iterative: Option<(u64, usize)>,
    pub hashes_per_second: (f64, f64),
    /// Joules per terahash (= picojoules per hash), low/high, including static power.
    pub joules_per_terahash: (f64, f64),
}

pub fn estimate(r: &Resources, d: &Device, c: &CostModel) -> Estimate {
    let lut = r.luts(c);
    let ff = r.register_bits as f64;
    let fit = ((c.utilization * d.luts as f64 / lut).floor()).min((c.utilization * d.ffs as f64 / ff).floor()) as u64;
    let (dyn_lo, dyn_hi) = r.pj_per_hash(c);
    let (hps, iterative) = if fit >= 1 {
        ((fit as f64 * d.mhz.0 * 1e6, fit as f64 * d.mhz.1 * 1e6), None)
    } else {
        // Iterative core: u round units + one schedule unit + state/window registers.
        let round_unit = 11.0 * c.luts_per_word_op; // 7 adders + Σ0 + Σ1 + Ch + Maj
        let sched_unit = 5.0 * c.luts_per_word_op;
        let best = [1usize, 2, 4, 8, 16, 32]
            .iter()
            .map(|&u| {
                let core = u as f64 * round_unit + sched_unit + 64.0;
                let cores = (c.utilization * d.luts as f64 / core).floor();
                let cycles = (r.stages as f64 / u as f64).ceil();
                (cores / cycles, cores as u64, u)
            })
            .fold((0.0, 0, 1), |a, b| if b.0 > a.0 { b } else { a });
        ((best.0 * d.mhz.0 * 1e6, best.0 * d.mhz.1 * 1e6), Some((best.1, best.2)))
    };
    // Static power spread over throughput; dynamic energy per hash from the pipeline model.
    let jth = (dyn_lo + d.static_w / hps.1 * 1e12, dyn_hi + d.static_w / hps.0 * 1e12);
    Estimate { device: d.name, pipelines: fit, iterative, hashes_per_second: hps, joules_per_terahash: jth }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> [u8; 80] {
        std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
    }

    #[test]
    fn every_variant_matches_reference_with_full_throughput() {
        for a in VARIANTS {
            let res = simulate(&a, header(), u32::MAX - 99, 300);
            assert_eq!(res.latency, res.stages as u64, "{}", a.name);
            // One output per cycle after the pipeline fills.
            assert_eq!(res.cycles, res.stages as u64 + 299, "{}", a.name);
            for (nonce, out, _) in &res.outputs {
                assert_eq!(*out, reference(&a, &header(), *nonce), "{} nonce {nonce:#x}", a.name);
            }
        }
    }

    #[test]
    fn folding_reduces_and_subsumes_midstate() {
        let r: Vec<Resources> = VARIANTS.iter().map(resources).collect();
        assert!(r[0].adders > r[1].adders && r[1].adders > r[2].adders && r[2].adders > r[3].adders);
        assert!(r[4].adders < r[3].adders && r[4].register_bits < r[3].register_bits);
        // Folding a no-midstate design removes block 1 entirely and the first
        // three second-block rounds: same datapath as explicit midstate + precompute.
        assert_eq!(r[5], r[4]);
        assert_eq!(r[4].stages, 122);
        // Early reject must not keep W61..W63 alive: fewer registers than without it.
        assert!(r[3].register_bits < r[2].register_bits);
    }
}
