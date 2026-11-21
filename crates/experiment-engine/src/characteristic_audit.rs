//! Audit of the measurable XOR characteristics: why do so many pairs follow
//! the round-17 trail of a W15 MSB difference?
//!
//! For each target (difference, last round), the audit
//! 1. compares three cost estimates (sequential, grouped, signed) with the
//!    measured frequency over several independent seeds and a larger sample;
//! 2. derives the exact bit conditions of the last round from signed
//!    differences and checks, pair by pair, that they hold exactly when the
//!    pair follows the trail (a mismatch in either direction is a
//!    counterexample and is reported, never hidden);
//! 3. compares the joint frequency of the conditions with the product of
//!    their marginals (dependence between conditions);
//! 4. reruns everything in an independent Python/numpy implementation with a
//!    different random generator.
//!
//! Only the measured round counts are discussed. Nothing is extrapolated.

use crate::smt::run_script;
use crate::{Definition, Outcome, Verification, hex_words, p_u64};
use anyhow::{Context, Result};
use differential_engine::characteristic::{Trail, ch_diff, maj_diff, xor_trail};
use differential_engine::sample;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{K, State, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use statistical_engine::{SplitMix64, Z95, wilson};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-CHAR-02",
        primitive: crate::primitive::COMPRESSION,
        name: "Audit of measurable XOR characteristics: estimates, exact conditions, seeds, independent code",
        version: 1,
        hypothesis: "The frequency with which pairs follow the measurable single-bit XOR trails (2^-11 at round 17 for a W15 MSB difference) is fully explained by exact bit conditions derived from signed differences, holds across independent seeds and an independent implementation, and is not an artifact.",
        null_hypothesis: "The observed frequency is an artifact (sample generator, implementation bug, or unexplained dependency): it changes across seeds or implementations, or the derived conditions do not characterise following.",
        assumptions: &[
            "Pairs follow the trail when every schedule difference and every state difference matches it at every round up to the target.",
            "Exact conditions are derived only when the last round's operand differences sit on disjoint bits and Ch/Maj cases are single-difference ones; otherwise they are reported as not derived.",
            "Seeds are independent SplitMix64 streams; the Python check uses numpy PCG64.",
            "Wilson 95% intervals; implementations agree when their intervals overlap.",
        ],
        baseline: "The three estimators of the characteristic experiment (sequential, grouped, signed).",
        methodology: "Per target and seed, trace samples_per_seed random pairs through the target round; count prefix followers, followers, pairs satisfying the derived conditions and both mismatch directions; record each condition's marginal frequency. Then run research/differential-cryptanalysis/trail_audit.py, which rebuilds the trail and its costs from the definitions and counts followers with numpy.",
        implementation: &["experiment_engine::characteristic_audit", "differential_engine::characteristic", "research/differential-cryptanalysis/trail_audit.py"],
        dataset: "Seed s uses SplitMix64::stream(derived(seed, s), i) for pair i; Python uses PCG64(s) for its own seeds.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "targets": [
            { "word": 15, "bit": 31, "rounds": 17 },
            { "word": 15, "bit": 0, "rounds": 17 },
            { "word": 8, "bit": 31, "rounds": 10 },
            { "word": 0, "bit": 31, "rounds": 2 },
        ],
        "seeds": if quick { 2 } else { 5 },
        "samples_per_seed": if quick { 1 << 16 } else { 1 << 24 },
        "python_seeds": if quick { 1 } else { 2 },
        "python_samples": if quick { 1 << 16 } else { 1 << 22 },
        "reproduce": true,
    })
}

/// One bit condition of the last round, evaluated on the first message of a pair.
#[derive(Clone, Debug)]
pub(crate) struct Cond {
    label: String,
    /// Value source: which word, which bit; compared against `rhs`.
    lhs: Src,
    rhs: Src,
    /// `true`: lhs bit must equal rhs bit; `false`: must differ.
    equal: bool,
}

/// A bit of a value available at the last round.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Src {
    /// State word k (a..h = 0..7) before the round.
    State(usize, u32),
    /// Σ1(e), Σ0(a) before the round.
    Sigma1E(u32),
    Sigma0A(u32),
    /// Message-schedule word t.
    W(usize, u32),
    /// New a, new e after the round.
    NewA(u32),
    NewE(u32),
    /// Constant 0 / 1.
    Const(bool),
}

/// Values of the first message of a pair at the last round.
pub(crate) struct Snapshot<'a> {
    /// State entering the round.
    pub s: &'a State,
    pub w: &'a [u32; 64],
    /// a and e leaving the round.
    pub new_a: u32,
    pub new_e: u32,
}

impl Src {
    fn bit(self, x: &Snapshot) -> bool {
        let b = |v: u32, i: u32| v >> i & 1 == 1;
        match self {
            Src::State(k, i) => b(x.s[k], i),
            Src::Sigma1E(i) => b(big_sigma1(x.s[4]), i),
            Src::Sigma0A(i) => b(big_sigma0(x.s[0]), i),
            Src::W(t, i) => b(x.w[t], i),
            Src::NewA(i) => b(x.new_a, i),
            Src::NewE(i) => b(x.new_e, i),
            Src::Const(v) => v,
        }
    }

    fn name(self) -> String {
        const N: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];
        match self {
            Src::State(k, i) => format!("{}[{i}]", N[k]),
            Src::Sigma1E(i) => format!("Σ1(e)[{i}]"),
            Src::Sigma0A(i) => format!("Σ0(a)[{i}]"),
            Src::W(t, i) => format!("W{t}[{i}]"),
            Src::NewA(i) => format!("a'[{i}]"),
            Src::NewE(i) => format!("e'[{i}]"),
            Src::Const(v) => (v as u8).to_string(),
        }
    }
}

/// Signed-difference conditions for a sum that must output the XOR of its
/// operands' differences: output bit i equals the bit of the operand that
/// carries the difference at i. `None` when operand differences overlap.
fn sum_conditions(ops: &[(u32, fn(u32) -> Src)], out: fn(u32) -> Src, label: &str) -> Option<Vec<Cond>> {
    let mut seen = 0u32;
    let mut conds = Vec::new();
    for &(diff, src) in ops {
        if seen & diff != 0 {
            return None;
        }
        seen |= diff;
        for i in (0..31).filter(|i| diff >> i & 1 == 1) {
            conds.push(Cond { label: label.into(), lhs: out(i), rhs: src(i), equal: true });
        }
    }
    Some(conds)
}

/// Exact conditions of round `t` (state index t to t + 1) for the trail.
pub(crate) fn derive(trail: &Trail, t: usize) -> Option<Vec<Cond>> {
    let [da, db, dc, dd, de, df, dg, dh] = trail.states[t];
    let dw = trail.delta_w[t];
    let mut conds = Vec::new();
    // Ch: undetermined bits, single-difference cases only.
    let (chd, _) = ch_diff(de, df, dg);
    for i in 0..32 {
        let (e, f, g) = (de >> i & 1, df >> i & 1, dg >> i & 1);
        let c = match (e, f, g) {
            (0, 0, 0) | (0, 1, 1) => continue,
            (1, 0, 0) => Cond { label: "Ch".into(), lhs: Src::State(5, i), rhs: Src::State(6, i), equal: true },
            (0, 1, 0) => Cond { label: "Ch".into(), lhs: Src::State(4, i), rhs: Src::Const(false), equal: true },
            (0, 0, 1) => Cond { label: "Ch".into(), lhs: Src::State(4, i), rhs: Src::Const(true), equal: true },
            _ => return None,
        };
        conds.push(c);
    }
    // Maj: undetermined bits (not all three differences equal).
    let (mjd, _) = maj_diff(da, db, dc);
    for i in 0..32 {
        let d = [da >> i & 1, db >> i & 1, dc >> i & 1];
        let ones = d.iter().sum::<u32>();
        if ones == 0 || ones == 3 {
            continue;
        }
        // One difference: the two words without one must be equal (output
        // difference is their XOR). Two differences: the two differing words
        // must differ (output difference is 1 exactly when they are equal).
        let pick: Vec<usize> = (0..3).filter(|&k| (d[k] == 1) == (ones == 2)).collect();
        conds.push(Cond { label: "Maj".into(), lhs: Src::State(pick[0], i), rhs: Src::State(pick[1], i), equal: ones == 1 });
    }
    // An expanded schedule word with a difference would need its own
    // conditions; not derived rather than guessed (unused by the default targets).
    if t >= 16 && dw != 0 {
        return None;
    }
    let s1 = big_sigma1(de);
    let s0 = big_sigma0(da);
    // a' =h + Σ1(e) + Ch + K + W + Σ0(a) + Maj ; e' = d + h + Σ1(e) + Ch + K + W
    let a_ops: Vec<(u32, fn(u32) -> Src)> = vec![
        (dh, |i| Src::State(7, i)),
        (s1, Src::Sigma1E),
        (chd, |_| Src::Const(false)),
        (dw, |i| Src::W(usize::MAX, i)),
        (s0, Src::Sigma0A),
        (mjd, |_| Src::Const(false)),
    ];
    let e_ops: Vec<(u32, fn(u32) -> Src)> = vec![
        (dd, |i| Src::State(3, i)),
        (dh, |i| Src::State(7, i)),
        (s1, Src::Sigma1E),
        (chd, |_| Src::Const(false)),
        (dw, |i| Src::W(usize::MAX, i)),
    ];
    conds.extend(sum_conditions(&a_ops, Src::NewA, "a' = T1 + T2")?);
    conds.extend(sum_conditions(&e_ops, Src::NewE, "e' = d + T1")?);
    // Resolve the placeholder W index to the round's word.
    for c in &mut conds {
        for s in [&mut c.lhs, &mut c.rhs] {
            if let Src::W(usize::MAX, i) = *s {
                *s = Src::W(t, i);
            }
        }
    }
    Some(conds)
}

struct Counts {
    prefix: u64,
    follow: u64,
    cond_not_follow: u64,
    follow_not_cond: u64,
    /// `masks[m]`: prefix pairs whose set of satisfied conditions is exactly `m`.
    masks: Vec<u64>,
    /// First counterexample sample index in each direction.
    first_cx: [Option<u64>; 2],
}

/// Evaluate every condition; bit j of the result is set when condition j holds.
pub(crate) fn condition_mask(conds: &[Cond], snap: &Snapshot) -> usize {
    conds.iter().enumerate().fold(0, |m, (j, c)| m | ((((c.lhs.bit(snap) == c.rhs.bit(snap)) == c.equal) as usize) << j))
}

/// Joint structure of the conditions from the histogram of satisfied sets.
fn structure(masks: &[u64], conds: &[Cond]) -> Value {
    let nc = conds.len();
    let full = (1usize << nc) - 1;
    let n: u64 = masks.iter().sum();
    let nf = n as f64;
    let count_where = |pred: &dyn Fn(usize) -> bool| -> u64 { masks.iter().enumerate().filter(|(m, _)| pred(*m)).map(|(_, c)| c).sum() };
    let marg: Vec<u64> = (0..nc).map(|j| count_where(&|m| m >> j & 1 == 1)).collect();
    // Pairwise independence: phi coefficient, z ≈ phi * sqrt(n).
    let pairs = nc * (nc - 1) / 2;
    let threshold = statistical_engine::z_for_two_sided(0.01 / pairs.max(1) as f64);
    let (mut max_z, mut dependent_pairs) = (0.0f64, Vec::new());
    for i in 0..nc {
        for j in i + 1..nc {
            let nij = count_where(&|m| m >> i & 1 == 1 && m >> j & 1 == 1) as f64;
            let (mi, mj) = (marg[i] as f64, marg[j] as f64);
            let phi = (nf * nij - mi * mj) / (mi * (nf - mi) * mj * (nf - mj)).sqrt();
            let z = phi * nf.sqrt();
            max_z = max_z.max(z.abs());
            if z.abs() > threshold {
                dependent_pairs.push(json!([i, j, z]));
            }
        }
    }
    // Redundancy: is condition j implied by all the others?
    let redundancy: Vec<Value> = (0..nc)
        .map(|j| {
            let rest = masks[full] + masks[full ^ (1 << j)];
            let (lo, hi) = wilson(masks[full], rest, Z95);
            json!({ "condition": j, "p_given_all_others": masks[full] as f64 / rest as f64, "ci95": [lo, hi], "implied": lo > 0.99 })
        })
        .collect();
    // All 2^nc satisfied-sets against independent conditions with the observed marginals.
    let probs: Vec<f64> = (0..=full)
        .map(|m| (0..nc).map(|j| { let p = marg[j] as f64 / nf; if m >> j & 1 == 1 { p } else { 1.0 - p } }).product())
        .collect();
    let gof = statistical_engine::chi_square_gof(masks, &probs);
    json!({
        "pairs_examined": n,
        "marginals": conds.iter().zip(&marg).map(|(c, m)| json!({
            "condition": format!("{} {} {}", c.lhs.name(), if c.equal { "=" } else { "≠" }, c.rhs.name()),
            "from": c.label, "p": *m as f64 / nf, "ci95": wilson(*m, n, Z95),
        })).collect::<Vec<_>>(),
        "pairwise_max_abs_z": max_z,
        "pairwise_threshold_z": threshold,
        "dependent_pairs": dependent_pairs,
        "redundancy": redundancy,
        "implied_conditions": redundancy.iter().filter(|r| r["implied"] == true).count(),
        "joint_vs_independent_chi_square": { "statistic": gof.statistic, "df": gof.df, "p_value": gof.p_value },
        "joint": masks[full] as f64 / nf,
        "product_of_marginals": probs[full],
    })
}

/// Condition template with bit positions rotated by `rot` (to compare trails).
fn template(conds: &[Cond], rot: u32) -> Vec<String> {
    let mut v: Vec<String> = conds
        .iter()
        .map(|c| {
            let r = |s: Src| match s {
                Src::State(k, i) => Src::State(k, (i + rot) % 32),
                Src::Sigma1E(i) => Src::Sigma1E((i + rot) % 32),
                Src::Sigma0A(i) => Src::Sigma0A((i + rot) % 32),
                Src::W(_, i) => Src::W(0, (i + rot) % 32),
                Src::NewA(i) => Src::NewA((i + rot) % 32),
                Src::NewE(i) => Src::NewE((i + rot) % 32),
                Src::Const(b) => Src::Const(b),
            };
            format!("{} {} {}", r(c.lhs).name(), if c.equal { "=" } else { "≠" }, r(c.rhs).name())
        })
        .collect();
    v.sort();
    v
}

/// Significance level for "two measurements agree" (seeds, implementations).
const AGREE_ALPHA: f64 = 1e-3;

fn derived(seed: u64, s: u64) -> u64 {
    SplitMix64::stream(seed, 0xa0d1_0000 + s).next_u64()
}

/// Trace pairs of seed `seed_s` through `rounds` rounds.
fn count(trail: &Trail, delta: &[u32; 16], rounds: usize, conds: Option<&[Cond]>, seed_s: u64, n: u64) -> Counts {
    let nc = conds.map_or(0, <[Cond]>::len);
    assert!(nc <= 16, "at most 16 conditions are tracked jointly");
    let empty = || Counts { prefix: 0, follow: 0, cond_not_follow: 0, follow_not_cond: 0, masks: vec![0; 1 << nc], first_cx: [None, None] };
    (0..n.div_ceil(4096))
        .into_par_iter()
        .map(|chunk| {
            let mut c = empty();
            for i in chunk * 4096..((chunk + 1) * 4096).min(n) {
                let (cv, m) = sample(seed_s, i);
                let mut w1 = [0u32; 64];
                let mut w2 = [0u32; 64];
                w1[..16].copy_from_slice(&m);
                for k in 0..16 {
                    w2[k] = m[k] ^ delta[k];
                }
                let (mut s1, mut s2) = (cv, cv);
                // State of message 1 entering the last round, and whether the pair
                // followed the trail up to that point.
                let (mut before, mut prefix_ok) = (cv, true);
                let mut ok = true;
                for t in 0..rounds {
                    if t >= 16 {
                        for w in [&mut w1, &mut w2] {
                            w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
                        }
                    }
                    if t + 1 == rounds {
                        before = s1;
                        prefix_ok = ok;
                    }
                    s1 = step(&s1, t, w1[t]);
                    s2 = step(&s2, t, w2[t]);
                    ok &= (w1[t] ^ w2[t]) == trail.delta_w[t] && (0..8).all(|k| s1[k] ^ s2[k] == trail.states[t + 1][k]);
                }
                if !prefix_ok {
                    continue;
                }
                c.prefix += 1;
                if ok {
                    c.follow += 1;
                }
                if let Some(conds) = conds {
                    let snap = Snapshot { s: &before, w: &w1, new_a: s1[0], new_e: s1[4] };
                    let mask = condition_mask(conds, &snap);
                    c.masks[mask] += 1;
                    let all = mask == (1 << nc) - 1;
                    if all && !ok {
                        c.cond_not_follow += 1;
                        c.first_cx[0].get_or_insert(i);
                    }
                    if ok && !all {
                        c.follow_not_cond += 1;
                        c.first_cx[1].get_or_insert(i);
                    }
                }
            }
            c
        })
        .reduce(empty, |mut a, b| {
            a.prefix += b.prefix;
            a.follow += b.follow;
            a.cond_not_follow += b.cond_not_follow;
            a.follow_not_cond += b.follow_not_cond;
            a.masks.iter_mut().zip(&b.masks).for_each(|(x, y)| *x += y);
            for k in 0..2 {
                a.first_cx[k] = match (a.first_cx[k], b.first_cx[k]) {
                    (Some(x), Some(y)) => Some(x.min(y)),
                    (x, y) => x.or(y),
                };
            }
            a
        })
}

fn step(s: &State, t: usize, w: u32) -> State {
    let [a, b, c, d, e, f, g, h] = *s;
    let t1 = h.wrapping_add(big_sigma1(e)).wrapping_add(ch(e, f, g)).wrapping_add(K[t]).wrapping_add(w);
    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
    [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
}

fn ci_json(k: u64, n: u64) -> Value {
    let (lo, hi) = wilson(k, n, Z95);
    json!({ "count": k, "of": n, "p": k as f64 / n as f64, "log2_p": if k > 0 { Some((k as f64 / n as f64).log2()) } else { None }, "ci95": [lo, hi], "log2_ci95": [if lo > 0.0 { Some(lo.log2()) } else { None }, if hi > 0.0 { Some(hi.log2()) } else { None }] })
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let seeds = p_u64(params, "seeds")?;
    let n = p_u64(params, "samples_per_seed")?;
    let py_seeds: Vec<u64> = (0..p_u64(params, "python_seeds")?).map(|s| seed.wrapping_add(1000 + s)).collect();
    let py_n = p_u64(params, "python_samples")?;
    let (mut obs, mut det, mut flags, mut cx, mut summary) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut templates: Vec<Option<Vec<Cond>>> = Vec::new();
    for tgt in params["targets"].as_array().context("targets must be an array")? {
        let word = tgt["word"].as_u64().filter(|&w| w < 16).context("word 0..16")? as usize;
        let bit = tgt["bit"].as_u64().filter(|&b| b < 32).context("bit 0..32")? as u32;
        let rounds = tgt["rounds"].as_u64().filter(|&r| (1..64).contains(&r)).context("rounds 1..64")? as usize;
        let mut delta = [0u32; 16];
        delta[word] = 1 << bit;
        let trail = xor_trail(&delta, rounds);
        let conds = derive(&trail, rounds - 1);
        let est = |c: &[u32]| -(c.iter().sum::<u32>() as f64);
        let estimates = json!({
            "sequential_log2": est(&trail.round_cost_sequential),
            "grouped_log2": est(&trail.round_cost),
            "signed_log2": est(&trail.round_cost_modular),
            "last_round_costs": { "sequential": trail.round_cost_sequential[rounds - 1], "grouped": trail.round_cost[rounds - 1], "signed": trail.round_cost_modular[rounds - 1] },
        });

        let mut per_seed = Vec::new();
        let (mut tot_prefix, mut tot_follow, mut cnf, mut fnc) = (0, 0, 0, 0);
        let mut masks = vec![0u64; 1 << conds.as_ref().map_or(0, Vec::len)];
        let mut seed_follow = Vec::new();
        for s in 0..seeds {
            let ss = derived(seed, s);
            let c = count(&trail, &delta, rounds, conds.as_deref(), ss, n);
            tot_prefix += c.prefix;
            tot_follow += c.follow;
            cnf += c.cond_not_follow;
            fnc += c.follow_not_cond;
            masks.iter_mut().zip(&c.masks).for_each(|(x, y)| *x += y);
            seed_follow.push(c.follow);
            for (dir, idx) in c.first_cx.iter().enumerate() {
                if let Some(i) = idx {
                    let (cv, m) = sample(ss, *i);
                    cx.push(json!({
                        "type": if dir == 0 { "conditions-hold-but-pair-does-not-follow" } else { "pair-follows-but-conditions-fail" },
                        "delta": { "word": word, "bit": bit }, "rounds": rounds, "seed": ss, "sample_index": i,
                        "chaining_value": hex_words(&cv), "message": hex_words(&m), "scope": "reduced-round",
                    }));
                }
            }
            per_seed.push(json!({ "seed": ss, "pairs": n, "follow": ci_json(c.follow, n), "prefix": c.prefix }));
            det.push(json!([word, bit, rounds, ss, c.prefix, c.follow, c.cond_not_follow, c.follow_not_cond, c.masks]));
        }
        let pooled_n = seeds * n;
        let pooled = ci_json(tot_follow, pooled_n);
        let (lo, hi) = wilson(tot_follow, pooled_n, Z95);
        let inside = |l2: f64| (lo..=hi).contains(&2f64.powf(l2));
        // Seed-to-seed homogeneity: chi-square of per-seed counts against the pooled rate.
        let pooled_p = tot_follow as f64 / pooled_n as f64;
        let hom_stat: f64 = seed_follow.iter().map(|&k| (k as f64 - n as f64 * pooled_p).powi(2) / (n as f64 * pooled_p * (1.0 - pooled_p)).max(1e-300)).sum();
        let hom_p = if seeds > 1 { statistical_engine::chi2_sf(hom_stat, (seeds - 1) as f64) } else { 1.0 };
        let seeds_consistent = hom_p > AGREE_ALPHA;
        let joint_structure = conds.as_ref().map(|cs| structure(&masks, cs));
        templates.push(conds.clone());

        // Independent implementation.
        let py = run_script(
            "differential-cryptanalysis/trail_audit.py",
            &json!({ "word": word, "bit": bit, "rounds": rounds, "samples": py_n, "seeds": py_seeds }),
        )?;
        let py_follow: u64 = py["runs"].as_array().into_iter().flatten().filter_map(|r| r["followers"][rounds].as_u64()).sum();
        let py_total = py_n * py_seeds.len() as u64;
        let agree_p = statistical_engine::two_sided_p(statistical_engine::two_proportion_z(tot_follow, pooled_n, py_follow, py_total));
        let trail_match = py["trail"]["delta_w"] == json!(trail.delta_w[..rounds])
            && py["trail"]["states"] == json!(trail.states.iter().take(rounds + 1).collect::<Vec<_>>());
        let costs_match = py["costs"]["sequential"] == json!(trail.round_cost_sequential)
            && py["costs"]["grouped"] == json!(trail.round_cost)
            && py["costs"]["signed"] == json!(trail.round_cost_modular);
        let rates_agree = agree_p > AGREE_ALPHA;

        let explained = estimates["signed_log2"].as_f64().is_some_and(inside);
        let exact = conds.is_some() && cnf == 0 && fnc == 0;
        let verdict = match (explained, exact, rates_agree && trail_match && costs_match, seeds_consistent) {
            (true, true, true, true) => "structural: exact signed-difference conditions explain the frequency; independent code and seeds agree",
            (_, _, false, _) => "unresolved: independent implementation disagrees",
            (_, _, _, false) => "unresolved: seeds disagree beyond their intervals",
            (_, false, _, _) => "partly explained: derived conditions are not exact (see counterexamples)",
            (false, true, _, _) => "partly explained: conditions exact but the signed estimate misses the measured rate (dependent conditions)",
        };
        flags.push((rounds, tot_follow >= 2));
        summary.push(format!(
            "W{word}[{bit}] through round {rounds}: {tot_follow} of {pooled_n} pairs over {seeds} seeds, 2^{:.2} (95% CI 2^{:.2}..2^{:.2}); estimates 2^{} sequential, 2^{} grouped, 2^{} signed; {} exact conditions{}; Python/numpy (PCG64) 2^{:.2} over {py_total} pairs; {verdict}.",
            pooled_p.log2(), lo.log2(), hi.log2(),
            estimates["sequential_log2"], estimates["grouped_log2"], estimates["signed_log2"],
            conds.as_ref().map_or("no".into(), |c| c.len().to_string()),
            if conds.is_some() { format!(", counterexamples {cnf} (conditions hold, no follow) / {fnc} (follow, conditions fail)") } else { String::new() },
            (py_follow as f64 / py_total as f64).log2(),
        ));
        obs.push(json!({
            "target": { "word": word, "bit": bit, "rounds": rounds },
            "trail_state_differences": trail.states.iter().skip(rounds.saturating_sub(2)).take(3).map(|s| hex_words(s)).collect::<Vec<_>>(),
            "trail_schedule_differences": trail.delta_w[..rounds].iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>(),
            "estimates": estimates,
            "measured": { "pooled": pooled, "per_seed": per_seed, "seed_homogeneity_p": hom_p, "seeds_consistent": seeds_consistent, "prefix_pairs": tot_prefix },
            "exact_conditions": conds.as_ref().map(|cs| cs.iter().map(|c| format!("{}: {} {} {}", c.label, c.lhs.name(), if c.equal { "=" } else { "≠" }, c.rhs.name())).collect::<Vec<_>>()),
            "equivalence": { "conditions_hold": conds.as_ref().and_then(|_| masks.last()), "conditions_hold_but_no_follow": cnf, "follow_but_conditions_fail": fnc, "exact": exact },
            "joint_structure": joint_structure,
            "independent_implementation": {
                "generator": py["generator"], "numpy": py["numpy"], "pairs": py_total, "follow": ci_json(py_follow, py_total),
                "trail_matches": trail_match, "costs_match": costs_match, "agreement_p": agree_p, "rates_agree": rates_agree,
            },
            "verdict": verdict,
        }));
    }
    // Shared structure: is each trail's condition set the first one's, up to a rotation of bit positions?
    if let Some(Some(first)) = templates.first() {
        let reference = template(first, 0);
        for (o, conds) in obs.iter_mut().zip(&templates) {
            o["template_rotation_vs_first_target"] = json!(conds.as_ref().and_then(|c| (0..32).find(|&r| template(c, r) == reference)));
        }
    }
    summary.push("Reduced-round only: every number above is for the stated round, with no extrapolation to other round counts.".into());
    let mut out = Outcome::new(json!(obs), json!(det), flags, summary);
    out.counterexamples = cx;
    Ok(out)
}

/// Agreement between the Rust and the independent Python implementation.
pub fn verify(_: &Value, _: u64, outcome: &Outcome) -> Result<Verification> {
    let mut problems = Vec::new();
    for o in outcome.observations.as_array().into_iter().flatten() {
        let ind = &o["independent_implementation"];
        let tag = format!("W{}[{}]@{}", o["target"]["word"], o["target"]["bit"], o["target"]["rounds"]);
        for key in ["trail_matches", "costs_match", "rates_agree"] {
            if ind[key] != true {
                problems.push(format!("{tag}: {key} false"));
            }
        }
    }
    Ok(Verification {
        method: "independent Python/numpy implementation (PCG64 generator) rebuilds the trail and all three cost estimates from their definitions and measures the follow rate; Rust and Python must agree on trail and costs exactly, and on the rate by a two-proportion test (p > 0.001)".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "trail, costs and rates agree for every target".into() } else { problems.join("; ") },
    })
}
