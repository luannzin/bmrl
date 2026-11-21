//! XOR differential characteristics through all 64 rounds.
//!
//! [`xor_trail`] builds the carry-free characteristic of a message
//! difference: every modular addition is assumed to behave like XOR on the
//! differences, Ch/Maj take their most likely output difference. Each step
//! has a cost in bits:
//!
//! * addition `(α, β) -> α ^ β`: `hw((α | β) & 0x7fffffff)`
//!   (Lipmaa–Moriai 2001, uniform independent operands);
//! * Ch, Maj: one bit for every position whose output difference is not
//!   determined by the input differences.
//!
//! Summing costs assumes round independence (the standard Markov-cipher
//! heuristic). [`propagate`] measures how many real pairs follow the trail
//! round by round, so the heuristic is tested wherever the probability is
//! measurable, and records bit-level difference probabilities per round.

use super::{add_into, chunks, sample};
use rayon::prelude::*;
use sha256_core::{State, big_sigma0, big_sigma1, compress_traced, small_sigma0, small_sigma1};

const NO_MSB: u32 = 0x7fff_ffff;

/// Cost in bits of the carry-free transition of one modular addition.
pub fn add_cost(alpha: u32, beta: u32) -> u32 {
    ((alpha | beta) & NO_MSB).count_ones()
}

/// Carry-free difference and cost of a multi-operand modular sum.
///
/// `grouped`: operands without a difference are summed first (no cost), the
/// differing operands are combined pairwise, and the combined difference is
/// charged once against the zero-difference remainder. This respects
/// associativity of modular addition.
/// Not grouped: operands are added left to right, charging every addition
/// (the naive per-addition independence assumption).
pub fn sum_cost(diffs: &[u32], grouped: bool) -> (u32, u32) {
    if !grouped {
        let mut acc = diffs[0];
        let mut cost = 0;
        for &d in &diffs[1..] {
            cost += add_cost(acc, d);
            acc ^= d;
        }
        return (acc, cost);
    }
    let nonzero: Vec<u32> = diffs.iter().copied().filter(|&d| d != 0).collect();
    let Some((&first, rest)) = nonzero.split_first() else { return (0, 0) };
    let mut acc = first;
    let mut cost = 0;
    for &d in rest {
        cost += add_cost(acc, d);
        acc ^= d;
    }
    if nonzero.len() < diffs.len() {
        cost += add_cost(acc, 0);
    }
    (acc, cost)
}

/// Most likely output difference of Ch and its cost in bits.
pub fn ch_diff(de: u32, df: u32, dg: u32) -> (u32, u32) {
    // Determined only where e has no difference and f, g differ identically.
    let det = !de & !(df ^ dg);
    (det & df, (!det).count_ones())
}

/// Most likely output difference of Maj and its cost in bits.
pub fn maj_diff(da: u32, db: u32, dc: u32) -> (u32, u32) {
    // Determined where all three input differences agree.
    let det = !(da ^ db) & !(db ^ dc);
    (det & da, (!det).count_ones())
}

#[derive(Clone, Debug)]
pub struct Trail {
    /// Predicted schedule differences ΔW_t.
    pub delta_w: [u32; 64],
    /// Predicted state difference; index 0 = input, t + 1 = after round t.
    pub states: Vec<State>,
    /// Cost of round t including ΔW_t, grouped estimator (see [`sum_cost`]).
    pub round_cost: Vec<u32>,
    /// Same with the naive sequential per-addition estimator.
    pub round_cost_sequential: Vec<u32>,
    /// Same with the signed-difference estimator (see [`modular_cost`]).
    pub round_cost_modular: Vec<u32>,
}

/// Signed-difference cost of a modular sum that must output the XOR of its
/// operands' differences.
///
/// When the nonzero operand differences sit on disjoint bits, the sum's
/// modular difference is a sum of ±2^i over exactly those bits, with each
/// sign set by the operand's bit value. The output then carries exactly those
/// XOR bits if and only if each output bit i equals its source operand's
/// bit i: one condition per non-MSB bit, whatever happens to intermediate
/// XOR differences inside the sum. Overlapping differences fall back to the
/// grouped estimate.
pub fn modular_cost(diffs: &[u32]) -> (u32, u32) {
    let mut seen = 0u32;
    for &d in diffs {
        if seen & d != 0 {
            return sum_cost(diffs, true);
        }
        seen |= d;
    }
    (seen, (seen & NO_MSB).count_ones())
}

fn cumulative(costs: &[u32]) -> Vec<f64> {
    let mut acc = vec![0.0];
    for c in costs {
        acc.push(acc.last().copied().unwrap_or(0.0) - *c as f64);
    }
    acc
}

impl Trail {
    /// Estimated log2 probability of following the trail through round t
    /// (index t + 1), grouped estimator.
    pub fn cumulative_log2(&self) -> Vec<f64> {
        cumulative(&self.round_cost)
    }

    pub fn cumulative_log2_sequential(&self) -> Vec<f64> {
        cumulative(&self.round_cost_sequential)
    }

    pub fn cumulative_log2_modular(&self) -> Vec<f64> {
        cumulative(&self.round_cost_modular)
    }
}

pub fn xor_trail(delta: &[u32; 16], rounds: usize) -> Trail {
    assert!(rounds <= 64);
    let mut dw = [0u32; 64];
    // Schedule cost per estimator: grouped, sequential, modular.
    let mut sched = [[0u32; 64]; 3];
    dw[..16].copy_from_slice(delta);
    for t in 16..64 {
        let terms = [small_sigma1(dw[t - 2]), dw[t - 7], small_sigma0(dw[t - 15]), dw[t - 16]];
        let (d, cg) = sum_cost(&terms, true);
        sched[0][t] = cg;
        sched[1][t] = sum_cost(&terms, false).1;
        sched[2][t] = modular_cost(&terms).1;
        dw[t] = d;
    }
    let mut states = vec![[0u32; 8]];
    let mut costs = [Vec::with_capacity(rounds), Vec::with_capacity(rounds), Vec::with_capacity(rounds)];
    for t in 0..rounds {
        let [a, b, c, d, e, f, g, h] = *states.last().expect("non-empty");
        let (chd, chc) = ch_diff(e, f, g);
        let (mj, mjc) = maj_diff(a, b, c);
        let (s1, s0) = (big_sigma1(e), big_sigma0(a));
        // T1 = h + Σ1(e) + Ch + K_t + W_t ; T2 = Σ0(a) + Maj ; a' = T1 + T2 ; e' = d + T1
        let t1_ops = [h, s1, chd, 0, dw[t]];
        for (k, grouped) in [true, false].into_iter().enumerate() {
            let (t1, c1) = sum_cost(&t1_ops, grouped);
            let (t2, c2) = sum_cost(&[s0, mj], grouped);
            let c3 = sum_cost(&[t1, t2], grouped).1;
            let c4 = sum_cost(&[d, t1], grouped).1;
            costs[k].push(sched[k][t] + chc + mjc + c1 + c2 + c3 + c4);
        }
        // Signed differences: only the round's outputs a' and e' must show their XOR difference.
        let (na, ca) = modular_cost(&[h, s1, chd, 0, dw[t], s0, mj]);
        let (ne, ce) = modular_cost(&[d, h, s1, chd, 0, dw[t]]);
        costs[2].push(sched[2][t] + chc + mjc + ca + ce);
        states.push([na, a, b, c, ne, e, f, g]);
    }
    let [round_cost, round_cost_sequential, round_cost_modular] = costs;
    Trail { delta_w: dw, states, round_cost, round_cost_sequential, round_cost_modular }
}

/// Empirical propagation of a message difference.
#[derive(Clone, Debug)]
pub struct Propagation {
    pub rounds: usize,
    pub samples: u64,
    pub bit_samples: u64,
    /// `follow[t]`: pairs whose schedule and state differences matched the
    /// trail through state index t (`follow[0] == samples`).
    pub follow: Vec<u64>,
    /// `bit_ones[t * 256 + i]`: pairs (of the first `bit_samples`) whose state
    /// difference has bit i set at state index t (bit i = bit i%32 of word i/32).
    pub bit_ones: Vec<u64>,
    pub trail: Trail,
}

pub fn propagate(delta: [u32; 16], rounds: usize, samples: u64, bit_samples: u64, seed: u64) -> Propagation {
    let trail = xor_trail(&delta, rounds);
    let width = (rounds + 1) * 256;
    let bit_samples = bit_samples.min(samples);
    let empty = || (vec![0u64; rounds + 1], vec![0u64; width]);
    let (follow, bit_ones) = chunks(samples)
        .map(|range| {
            let (mut follow, mut bits) = empty();
            for i in range {
                let (cv, m) = sample(seed, i);
                let m2: [u32; 16] = std::array::from_fn(|k| m[k] ^ delta[k]);
                let (p, q) = (compress_traced(&cv, &m, rounds), compress_traced(&cv, &m2, rounds));
                let mut following = true;
                for t in 0..=rounds {
                    let d: State = std::array::from_fn(|k| p.states[t][k] ^ q.states[t][k]);
                    if following && t > 0 {
                        following = (p.schedule[t - 1] ^ q.schedule[t - 1]) == trail.delta_w[t - 1] && d == trail.states[t];
                    }
                    if following {
                        follow[t] += 1;
                    }
                    if i < bit_samples {
                        for (w, word) in d.iter().enumerate() {
                            let mut x = *word;
                            while x != 0 {
                                bits[t * 256 + w * 32 + x.trailing_zeros() as usize] += 1;
                                x &= x - 1;
                            }
                        }
                    } else if !following {
                        break;
                    }
                }
            }
            (follow, bits)
        })
        .reduce(empty, |(mut fa, mut ba), (fb, bb)| {
            add_into(&mut fa, &fb);
            add_into(&mut ba, &bb);
            (fa, ba)
        });
    Propagation { rounds, samples, bit_samples, follow, bit_ones, trail }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addition_cost_matches_exhaustive_8bit_analogue() {
        // Check the Lipmaa–Moriai count on 32-bit words by sampling.
        let (alpha, beta) = (0x0000_0005u32, 0x0000_0001u32);
        let mut hits = 0u32;
        let n = 1 << 16;
        let mut x = 0x1234_5678u32;
        for _ in 0..n {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let y = x.rotate_left(13).wrapping_mul(0x9e37_79b9);
            if ((x ^ alpha).wrapping_add(y ^ beta)) ^ x.wrapping_add(y) == alpha ^ beta {
                hits += 1;
            }
        }
        let p = hits as f64 / n as f64;
        let predicted = 0.5f64.powi(add_cost(alpha, beta) as i32);
        assert!((p - predicted).abs() < 0.02, "p {p} predicted {predicted}");
    }

    #[test]
    fn grouped_sum_charges_a_lone_difference_once() {
        // One differing operand among five: grouped charges it once, sequential four times.
        assert_eq!(sum_cost(&[0, 0b111, 0, 0, 0], true), (0b111, 3));
        assert_eq!(sum_cost(&[0, 0b111, 0, 0, 0], false), (0b111, 12));
        assert_eq!(sum_cost(&[0, 0, 0], true), (0, 0));
        // MSB differences are free in both.
        assert_eq!(sum_cost(&[0x8000_0000, 0, 0], true).1, 0);
    }

    #[test]
    fn round_17_costs_of_the_w15_msb_trail() {
        // ΔW15[31] enters at round 15 for free; round 16 (index 17) costs
        // 26 bits sequential, 17 grouped, 11 signed (measured: 2^-11.03).
        let mut delta = [0u32; 16];
        delta[15] = 0x8000_0000;
        let t = xor_trail(&delta, 17);
        assert_eq!((t.round_cost_sequential[16], t.round_cost[16], t.round_cost_modular[16]), (26, 17, 11));
        assert_eq!(modular_cost(&[0, 0b101, 0, 0b010]), (0b111, 3));
        // Overlapping differences fall back to the grouped estimate.
        assert_eq!(modular_cost(&[0b11, 0b01]), sum_cost(&[0b11, 0b01], true));
    }

    #[test]
    fn msb_difference_in_last_word_is_free_for_one_round() {
        let mut delta = [0u32; 16];
        delta[15] = 0x8000_0000;
        let t = xor_trail(&delta, 16);
        assert_eq!(t.states[16], [0x8000_0000, 0, 0, 0, 0x8000_0000, 0, 0, 0]);
        assert_eq!(t.round_cost[15], 0);
        let p = propagate(delta, 16, 256, 256, 1);
        assert_eq!(p.follow[16], 256);
    }

    #[test]
    fn following_count_is_monotone() {
        let mut delta = [0u32; 16];
        delta[0] = 1;
        let p = propagate(delta, 12, 2048, 64, 2);
        assert!(p.follow.windows(2).all(|w| w[1] <= w[0]));
        assert_eq!(p.follow[0], 2048);
    }
}
