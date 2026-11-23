//! Output-bias atlas for the Quantus QPoW hash: does any choosable nonce bit
//! predict the smallness of the 512-bit Poseidon2 output more often than
//! chance? That is the mining break (PoW security is ~2^37, far below
//! Poseidon2's full security, so a cheap below-target predictor would pay).
//!
//! Three lenses, all over a sequential nonce sweep (as real mining does):
//! 1. Uniformity of the top 8 output bits (chi-square GoF vs 256 equal bins).
//! 2. Per-nonce-bit median split: is P(output < 2^511 | bit=1) != bit=0?
//!    (two-proportion z, Bonferroni over the swept bits).
//! 3. Held-out tail amplification A: learn the single best (bit, value)
//!    selector for a rare tail hit on the first half, measure its amplification
//!    on the second half. A's 95% CI excluding 1 is a confirmed, out-of-sample
//!    edge.
//!
//! A reduced-round schedule is the positive control: few rounds leave the
//! output low-degree in the nonce, so lenses 2 and 3 must fire; full rounds
//! are expected null, as every lens was on SHA256d.

use crate::{qpow_hash_rounds, top64_be, Rounds};
use statistical_engine::{chi_square_gof, two_proportion_z, two_sided_p, wilson, Z95};

/// Swept low nonce bits (the counter bits that vary over the sweep).
pub const SWEEP_BITS: usize = 32;

#[derive(Clone)]
struct Acc {
    hist: [u64; 256],
    // median split over the whole sweep
    n1: [u64; SWEEP_BITS],
    small1: [u64; SWEEP_BITS],
    total: u64,
    total_small: u64,
    // tail hits on the discovery half (counter < cut)
    d_total: u64,
    d_hits: u64,
    d_n1: [u64; SWEEP_BITS],
    d_hits1: [u64; SWEEP_BITS],
    // tail hits on the holdout half (counter >= cut)
    h_total: u64,
    h_hits: u64,
    h_n1: [u64; SWEEP_BITS],
    h_hits1: [u64; SWEEP_BITS],
}

impl Acc {
    fn zero() -> Self {
        Acc {
            hist: [0; 256],
            n1: [0; SWEEP_BITS],
            small1: [0; SWEEP_BITS],
            total: 0,
            total_small: 0,
            d_total: 0,
            d_hits: 0,
            d_n1: [0; SWEEP_BITS],
            d_hits1: [0; SWEEP_BITS],
            h_total: 0,
            h_hits: 0,
            h_n1: [0; SWEEP_BITS],
            h_hits1: [0; SWEEP_BITS],
        }
    }

    fn merge(&mut self, o: &Acc) {
        for i in 0..256 {
            self.hist[i] += o.hist[i];
        }
        for b in 0..SWEEP_BITS {
            self.n1[b] += o.n1[b];
            self.small1[b] += o.small1[b];
            self.d_n1[b] += o.d_n1[b];
            self.d_hits1[b] += o.d_hits1[b];
            self.h_n1[b] += o.h_n1[b];
            self.h_hits1[b] += o.h_hits1[b];
        }
        self.total += o.total;
        self.total_small += o.total_small;
        self.d_total += o.d_total;
        self.d_hits += o.d_hits;
        self.h_total += o.h_total;
        self.h_hits += o.h_hits;
    }
}

const SMALL_CUT: u64 = 1u64 << 63; // output < 2^511  <=>  top bit of top64 is 0

fn process_range(block_hash: &[u8; 32], rounds: Rounds, lo: u64, hi: u64, cut: u64, tail_k: u32) -> Acc {
    let mut a = Acc::zero();
    let tail_cut: u64 = if tail_k == 0 { u64::MAX } else { 1u64 << (64 - tail_k) };
    let mut nonce = [0u8; 64];
    for ctr in lo..hi {
        nonce[56..64].copy_from_slice(&ctr.to_be_bytes());
        let h = qpow_hash_rounds(block_hash, &nonce, rounds);
        let t = top64_be(&h);
        let small = t < SMALL_CUT;
        let hit = t < tail_cut;
        a.hist[(t >> 56) as usize] += 1;
        a.total += 1;
        if small {
            a.total_small += 1;
        }
        let discovery = ctr < cut;
        if discovery {
            a.d_total += 1;
            if hit {
                a.d_hits += 1;
            }
        } else {
            a.h_total += 1;
            if hit {
                a.h_hits += 1;
            }
        }
        for b in 0..SWEEP_BITS {
            if (ctr >> b) & 1 == 1 {
                a.n1[b] += 1;
                if small {
                    a.small1[b] += 1;
                }
                if discovery {
                    a.d_n1[b] += 1;
                    if hit {
                        a.d_hits1[b] += 1;
                    }
                } else {
                    a.h_n1[b] += 1;
                    if hit {
                        a.h_hits1[b] += 1;
                    }
                }
            }
        }
    }
    a
}

#[derive(Clone, Debug)]
pub struct AtlasResult {
    pub rounds: Rounds,
    pub samples: u64,
    pub uniform_chi2_p: f64,
    pub min_bit_p: f64,
    pub bonferroni_alpha: f64,
    pub worst_bit: usize,
    pub tail_k: u32,
    pub holdout_base_rate: f64,
    pub best_bit: usize,
    pub best_val: u8,
    pub amplification: f64,
    pub amp_ci: (f64, f64),
    pub significant: bool,
}

impl std::fmt::Display for AtlasResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rounds(ei={},int={},et={}) n={}: uniform_chi2_p={:.3} | median-split min bit p={:.2e} (bit {}, Bonferroni alpha={:.2e}) | tail K={} base={:.3e} best selector bit {}={} A={:.3} CI[{:.3},{:.3}] -> {}",
            self.rounds.ext_init, self.rounds.n_int, self.rounds.ext_term, self.samples,
            self.uniform_chi2_p, self.min_bit_p, self.worst_bit, self.bonferroni_alpha,
            self.tail_k, self.holdout_base_rate, self.best_bit, self.best_val,
            self.amplification, self.amp_ci.0, self.amp_ci.1,
            if self.significant { "BIAS" } else { "null" },
        )
    }
}

/// Run the atlas over `samples` sequential nonces, parallel across cores.
pub fn run(block_hash: [u8; 32], rounds: Rounds, samples: u64, tail_k: u32) -> AtlasResult {
    let cut = samples / 2; // first half discovery, second half holdout
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).max(1) as u64;
    let chunk = samples.div_ceil(threads);
    let acc = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            let lo = t * chunk;
            let hi = (lo + chunk).min(samples);
            if lo >= hi {
                continue;
            }
            let bh = block_hash;
            handles.push(s.spawn(move || process_range(&bh, rounds, lo, hi, cut, tail_k)));
        }
        let mut acc = Acc::zero();
        for h in handles {
            acc.merge(&h.join().unwrap());
        }
        acc
    });

    // Lens 1: uniformity of the top 8 bits.
    let probs = [1.0 / 256.0; 256];
    let uniform_chi2_p = chi_square_gof(&acc.hist, &probs).p_value;

    // Lens 2: per-bit median split.
    let mut min_bit_p = 1.0;
    let mut worst_bit = 0;
    for b in 0..SWEEP_BITS {
        let (n1, s1) = (acc.n1[b], acc.small1[b]);
        let (n0, s0) = (acc.total - n1, acc.total_small - s1);
        if n1 == 0 || n0 == 0 {
            continue;
        }
        let z = two_proportion_z(s1, n1, s0, n0);
        let p = two_sided_p(z);
        if p < min_bit_p {
            min_bit_p = p;
            worst_bit = b;
        }
    }
    let bonferroni_alpha = 0.05 / SWEEP_BITS as f64;

    // Lens 3: held-out tail amplification. Learn the best (bit, val) on
    // discovery, evaluate on holdout.
    let mut best_bit = 0usize;
    let mut best_val = 1u8;
    let mut best_disc_rate = -1.0f64;
    for b in 0..SWEEP_BITS {
        for val in [1u8, 0u8] {
            let (n, hits) = if val == 1 {
                (acc.d_n1[b], acc.d_hits1[b])
            } else {
                (acc.d_total - acc.d_n1[b], acc.d_hits - acc.d_hits1[b])
            };
            if n == 0 {
                continue;
            }
            let rate = hits as f64 / n as f64;
            if rate > best_disc_rate {
                best_disc_rate = rate;
                best_bit = b;
                best_val = val;
            }
        }
    }
    let (hn, hhits) = if best_val == 1 {
        (acc.h_n1[best_bit], acc.h_hits1[best_bit])
    } else {
        (acc.h_total - acc.h_n1[best_bit], acc.h_hits - acc.h_hits1[best_bit])
    };
    let holdout_base_rate = if acc.h_total > 0 { acc.h_hits as f64 / acc.h_total as f64 } else { 0.0 };
    let (rate_lo, rate_hi) = wilson(hhits, hn, Z95);
    let amp = if holdout_base_rate > 0.0 && hn > 0 {
        (hhits as f64 / hn as f64) / holdout_base_rate
    } else {
        f64::NAN
    };
    let amp_ci = if holdout_base_rate > 0.0 {
        (rate_lo / holdout_base_rate, rate_hi / holdout_base_rate)
    } else {
        (f64::NAN, f64::NAN)
    };

    let significant = (min_bit_p < bonferroni_alpha) || (amp_ci.0 > 1.0) || (uniform_chi2_p < 1e-6);

    AtlasResult {
        rounds,
        samples,
        uniform_chi2_p,
        min_bit_p,
        bonferroni_alpha,
        worst_bit,
        tail_k,
        holdout_base_rate,
        best_bit,
        best_val,
        amplification: amp,
        amp_ci,
        significant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_control_linear_rounds_biased() {
        // Zero rounds = only the pre-round linear layer: the output is LINEAR
        // in the nonce, so it must be wildly biased. Sanity that the harness
        // detects a real edge.
        let r = Rounds { ext_init: 0, n_int: 0, ext_term: 0 };
        let res = run([0u8; 32], r, 1 << 16, 8);
        assert!(res.significant, "linear rounds must be flagged biased: {res}");
    }

    #[test]
    fn full_rounds_small_sample_runs() {
        // Smoke: full schedule runs and produces finite stats on a small n.
        let res = run([1u8; 32], Rounds::FULL, 1 << 14, 8);
        assert!(res.uniform_chi2_p.is_finite());
        assert!(res.min_bit_p >= 0.0);
    }
}
