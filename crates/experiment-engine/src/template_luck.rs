//! Template luck: does the hit rate depend on the block template?
//!
//! The miner chooses the template for free: the coinbase sets the merkle
//! root, the merkle root and the version set the midstate. nonce-atlas tested
//! 16 templates one at a time against the random-function null; this kind
//! measures the spread between thousands of them. If some templates hit more
//! often over their whole nonce space, and the excess persists (selected on
//! even nonces, re-measured on odd ones), choosing templates would multiply
//! the hit rate at no hashing cost.
//!
//! Per template every nonce in 0..2^nonce_bits is evaluated (64 rounds: GPU
//! kernel v3, 8 version-rolled templates per nonce, every hit re-hashed on the
//! CPU; reduced rounds: CPU, positive controls) and the hits at k and at
//! k + deep leading zero bits are split by nonce parity. Tests: dispersion of
//! the totals against Poisson (two-sided), even/odd correlation, and the
//! amplification of the top `select` fraction chosen on even nonces and
//! measured on odd ones, at k and at k + deep bits.

use crate::nonce_atlas::{leading_zeros, poisson_p, prepared, synthetic};
use crate::{Definition, FULL_ROUNDS, Outcome, Verification, ci_json, p_f64, p_rounds, p_u64};
use anyhow::{Context, Result, ensure};
use bitcoin_header::BlockHeader;
use gpu_backend::{GpuBackend, Kernel};
use mining_engine::{Work, target_with_zero_bits};
use rayon::prelude::*;
use serde_json::{Value, json};
use statistical_engine::{Z95, chi2_sf, two_sided_p, wilson};
use std::time::{Duration, Instant};

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-LUCK-01",
        primitive: crate::primitive::HEADER,
        name: "Template luck: hit-rate spread between block templates, selected on even nonces and measured on odd ones",
        version: 1,
        hypothesis: "The probability that SHA256d(header) meets a target depends on the block template (merkle root, version), which the miner chooses for free: hit counts over whole nonce spaces vary between templates more than Poisson, and templates selected for many hits on even nonces also hit more often on odd nonces, at the selection target and at a deeper one.",
        null_hypothesis: "Every template's hit count over its nonce space is Poisson(nonces * 2^-k), independent between templates and between even and odd nonces: choosing templates does not change P(hash <= target).",
        assumptions: &[
            "Templates: synthetic headers (nonce_atlas::synthetic) and their 8 BIP320 version-rolled variants, so each group of 8 shares prev hash, merkle root, time and bits and differs in its midstate.",
            "A hit at k bits: the hash, read as Bitcoin's 256-bit number, has >= k leading zero bits (probability exactly 2^-k per nonce for a random function).",
            "Templates are compared at a shallow target (k bits) and a deeper one (k + deep bits). An effect present only at the real block target (~76 bits) and at neither of these is outside what this run can see.",
            "Selection: the top `select` fraction of templates by even-nonce hits (ties by index). Under the null their odd-nonce hits are Poisson(m * nonces/2 * 2^-k) whatever the selection did; A = observed / expected.",
            "Dispersion: D = sum (c - lambda)^2 / lambda over templates with the exact lambda, against chi-square(T); valid for large lambda (quick runs only check the pipeline).",
            "64 rounds run on the GPU (kernel v3, every hit re-hashed on the CPU); reduced rounds cut all three compressions to r rounds and are positive controls, never evidence about 64 rounds.",
            "Nonces 0..2^nonce_bits in order; reduced rounds use a smaller range, where the 4-round map is known to be far from random.",
            "Significance: Bonferroni over the four primary tests of every round count.",
        ],
        baseline: "Any template hits with probability 2^-k per nonce, so choosing templates gives A = 1 and leaves the expected work per block unchanged.",
        methodology: "Enumerate every nonce of every template; count hits at k and k + deep bits by nonce parity. Per round count: dispersion D of the totals (two-sided chi-square, plus a 95% upper bound on the template-to-template SD of the hit rate), Pearson r of even vs odd counts (Fisher z), and the top `select` fraction by even hits re-measured on odd nonces (and the reverse) with Wilson intervals and exact Poisson p-values.",
        implementation: &["experiment_engine::template_luck", "gpu_backend::Kernel::V3 (GpuBackend::scan_members)", "cpu_backend::Prepared::{hash8, hash_words}"],
        dataset: "Group g: nonce_atlas::synthetic(seed ^ 0x1ac4, g); template 8g + m: that header version-rolled by m (Work::version_rolled).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [4, 5, 6, 8, 64],
        "templates": if quick { 16 } else { 2048 },
        "nonce_bits": if quick { 20 } else { 32 },
        "k": if quick { 10 } else { 20 },
        "reduced_templates": if quick { 16 } else { 256 },
        "reduced_nonce_bits": if quick { 16 } else { 24 },
        "reduced_k": if quick { 6 } else { 12 },
        "deep": if quick { 2 } else { 8 },
        "select": 0.1,
        "check_bits": if quick { 16 } else { 26 },
        "alpha": 0.01,
        "reproduce": quick,
    })
}

/// Hits of one template by nonce parity, at k and at k + deep bits.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct Counts {
    even: u64,
    odd: u64,
    deep_even: u64,
    deep_odd: u64,
}

impl Counts {
    fn add(&mut self, nonce: u32, lz: u32, k: u32, deep: u32) {
        if lz < k {
            return;
        }
        let d = lz >= k + deep;
        if nonce & 1 == 0 {
            self.even += 1;
            self.deep_even += d as u64;
        } else {
            self.odd += 1;
            self.deep_odd += d as u64;
        }
    }

    fn merge(mut self, o: Counts) -> Counts {
        self.even += o.even;
        self.odd += o.odd;
        self.deep_even += o.deep_even;
        self.deep_odd += o.deep_odd;
        self
    }
}

/// Group `g`'s base template (version-roll member 0).
fn base(seed: u64, g: usize, k: u32) -> Work {
    Work::new(BlockHeader::deserialize(&synthetic(seed ^ 0x1ac4, g as u64).header), target_with_zero_bits(k))
}

fn template(seed: u64, j: usize, k: u32) -> Work {
    base(seed, j / 8, k).version_rolled((j % 8) as u32)
}

/// Every nonce of `0..2^nonce_bits` on the CPU at `rounds`.
fn cpu_counts(work: &Work, rounds: usize, nonce_bits: u32, k: u32, deep: u32) -> Counts {
    let p = prepared(&work.header_bytes(), rounds);
    (0..1u32 << (nonce_bits - 3))
        .into_par_iter()
        .fold(Counts::default, |mut c, g| {
            let out = p.hash8(8 * g);
            for lane in 0..8 {
                let h: [u32; 8] = std::array::from_fn(|w| out[w][lane]);
                c.add(8 * g + lane as u32, leading_zeros(&h), k, deep);
            }
            c
        })
        .reduce(Counts::default, Counts::merge)
}

/// Every nonce of every template at 64 rounds on the GPU; also returns
/// template 0's hits below 2^check_bits for the verifier.
fn gpu_counts(seed: u64, templates: usize, nonce_bits: u32, k: u32, deep: u32, check_bits: u32) -> Result<(Vec<Counts>, Vec<u32>, String)> {
    let g = GpuBackend::with_kernel(None, Kernel::V3)?;
    g.calibrate(Duration::from_millis(800))?;
    let (mut out, mut check) = (Vec::with_capacity(templates), Vec::new());
    let t0 = Instant::now();
    for group in 0..templates / 8 {
        let works = g.members_of(&base(seed, group, k));
        let (hits, _) = g.scan_members(&works, 0, 1 << nonce_bits, usize::MAX)?;
        let preps: Vec<_> = works.iter().map(|w| prepared(&w.header_bytes(), FULL_ROUNDS)).collect();
        let lz: Vec<u32> = hits.par_iter().map(|&(m, n)| leading_zeros(&preps[m as usize].hash_words(n))).collect();
        let mut c = [Counts::default(); 8];
        for (&(m, n), &z) in hits.iter().zip(&lz) {
            ensure!(z >= k, "GPU reported nonce {n:#010x} of template {} with {z} < {k} leading zeros", group * 8 + m as usize);
            c[m as usize].add(n, z, k, deep);
            if group == 0 && m == 0 && (n as u64) < 1 << check_bits {
                check.push(n);
            }
        }
        out.extend(c);
        if (group + 1) % 16 == 0 {
            eprintln!("template-luck: {} / {templates} templates, {:.0} s", out.len(), t0.elapsed().as_secs_f64());
        }
    }
    Ok((out, check, format!("{} ({:?})", g.adapter().name, g.adapter().backend)))
}

fn pearson(x: &[f64], y: &[f64]) -> Option<f64> {
    let n = x.len() as f64;
    let (mx, my) = (x.iter().sum::<f64>() / n, y.iter().sum::<f64>() / n);
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for (a, b) in x.iter().zip(y) {
        sxy += (a - mx) * (b - my);
        sxx += (a - mx) * (a - mx);
        syy += (b - my) * (b - my);
    }
    (sxx > 0.0 && syy > 0.0).then(|| sxy / (sxx * syy).sqrt())
}

/// Top `select` fraction by `pick`, re-measured with `measure` (hits at k) and `deep`.
fn selection(c: &[Counts], nonces: u64, k: u32, deep: u32, select: f64, pick: fn(&Counts) -> u64, measure: fn(&Counts) -> (u64, u64)) -> (Value, f64, f64) {
    let mut order: Vec<usize> = (0..c.len()).collect();
    order.sort_by_key(|&i| (std::cmp::Reverse(pick(&c[i])), i));
    let m = ((select * c.len() as f64).ceil() as usize).clamp(1, c.len());
    let (hits, deep_hits) = order[..m].iter().fold((0, 0), |(h, d), &i| {
        let (a, b) = measure(&c[i]);
        (h + a, d + b)
    });
    let trials = m as u64 * nonces / 2;
    let (p, p_deep) = (poisson_p(hits, trials as f64 / 2f64.powi(k as i32)), poisson_p(deep_hits, trials as f64 / 2f64.powi((k + deep) as i32)));
    // Amplification = hit rate / 2^-bits, with the Wilson interval scaled the same way.
    let amp = |h: u64, bits: u32| {
        let s = 2f64.powi(bits as i32);
        let (lo, hi) = wilson(h, trials, Z95);
        json!({ "hits": ci_json(h, trials), "A": h as f64 / trials as f64 * s, "A_ci95": [lo * s, hi * s] })
    };
    let v = json!({
        "templates": m,
        "at_k": { "amplification": amp(hits, k), "poisson_p": p },
        "at_k_plus_deep": { "amplification": amp(deep_hits, k + deep), "poisson_p": p_deep },
    });
    (v, p, p_deep)
}

/// Every statistic of one round count; returns the result and its four primary p-values.
fn analyse(c: &[Counts], nonces: u64, k: u32, deep: u32, select: f64) -> (Value, [f64; 4]) {
    let t = c.len() as f64;
    let lambda = nonces as f64 * 2f64.powi(-(k as i32));
    let d: f64 = c.iter().map(|x| ((x.even + x.odd) as f64 - lambda).powi(2) / lambda).sum();
    let over = chi2_sf(d, t);
    let p_disp = (2.0 * over.min(1.0 - over)).min(1.0);
    // E[D] = T (1 + lambda s^2) for a relative rate SD s between templates; one-sided 95% bound.
    let sd_upper = ((d - t + 1.645 * (2.0 * t).sqrt()).max(0.0) / (t * lambda)).sqrt();
    let (e, o): (Vec<f64>, Vec<f64>) = c.iter().map(|x| (x.even as f64, x.odd as f64)).unzip();
    let r = pearson(&e, &o);
    let p_corr = r.filter(|_| t > 3.0).map_or(1.0, |r| two_sided_p(r.clamp(-0.999_999, 0.999_999).atanh() * (t - 3.0).sqrt()));
    let (fwd, p_sel, p_deep) = selection(c, nonces, k, deep, select, |x| x.even, |x| (x.odd, x.deep_odd));
    let (rev, _, _) = selection(c, nonces, k, deep, select, |x| x.odd, |x| (x.even, x.deep_even));
    let v = json!({
        "templates": c.len(),
        "nonces_per_template": nonces,
        "k": k,
        "deep": deep,
        "lambda": lambda,
        "dispersion": { "D": d, "df": t, "D_over_df": d / t, "p_two_sided": p_disp, "rate_sd_upper95": sd_upper },
        "even_odd": { "pearson_r": r, "p": p_corr },
        "select_even_measure_odd": fwd,
        "select_odd_measure_even": rev,
        "counts": c.iter().map(|x| [x.even, x.odd, x.deep_even, x.deep_odd]).collect::<Vec<_>>(),
    });
    (v, [p_disp, p_corr, p_sel, p_deep])
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let (templates, nonce_bits, k) = (p_u64(params, "templates")? as usize, p_u64(params, "nonce_bits")? as u32, p_u64(params, "k")? as u32);
    let (rt, rnb, rk) = (p_u64(params, "reduced_templates")? as usize, p_u64(params, "reduced_nonce_bits")? as u32, p_u64(params, "reduced_k")? as u32);
    let (deep, select, alpha, check_bits) = (p_u64(params, "deep")? as u32, p_f64(params, "select")?, p_f64(params, "alpha")?, p_u64(params, "check_bits")? as u32);
    ensure!(templates >= 8 && templates % 8 == 0, "templates must be a positive multiple of 8 (GPU groups)");
    ensure!(rt >= 1 && (3..=32).contains(&nonce_bits) && (3..=32).contains(&rnb), "need templates and 3..=32 nonce bits");
    ensure!(k + deep < 64 && rk + deep < 64 && select > 0.0 && select <= 1.0 && check_bits <= nonce_bits, "bad k, deep, select or check_bits");
    let bonferroni = alpha / (4 * rounds.len()) as f64;
    let (mut by_rounds, mut flags, mut summary, mut check, mut gpu) = (Vec::new(), Vec::new(), Vec::new(), Value::Null, Value::Null);
    for &r in &rounds {
        let (counts, nb, kk) = if r == FULL_ROUNDS {
            let (c, nonces, name) = gpu_counts(seed, templates, nonce_bits, k, deep, check_bits)?;
            check = json!({ "template": 0, "bits": check_bits, "hits": nonces });
            gpu = json!(name);
            (c, nonce_bits, k)
        } else {
            ((0..rt).map(|j| cpu_counts(&template(seed, j, rk), r, rnb, rk, deep)).collect(), rnb, rk)
        };
        let (mut v, ps) = analyse(&counts, 1 << nb, kk, deep, select);
        let deviation = ps.iter().any(|&p| p < bonferroni);
        v["rounds"] = json!(r);
        v["deviation"] = json!(deviation);
        let num = |x: &Value| x.as_f64().unwrap_or(f64::NAN);
        let amp = |key: &str| {
            let a = &v["select_even_measure_odd"][key]["amplification"];
            format!("A = {:.4} ({:.4}..{:.4})", num(&a["A"]), num(&a["A_ci95"][0]), num(&a["A_ci95"][1]))
        };
        summary.push(format!(
            "{r} rounds ({} templates x 2^{nb} nonces, k = {kk}): dispersion D/df = {:.4} (p = {:.3e}, template rate SD <= {:.4} at 95%); even/odd r = {} (p = {:.3e}); top {:.0}% by even-nonce hits on odd nonces: {} at {kk} bits, {} at {} bits; {}.",
            counts.len(),
            num(&v["dispersion"]["D_over_df"]),
            ps[0],
            num(&v["dispersion"]["rate_sd_upper95"]),
            v["even_odd"]["pearson_r"].as_f64().map_or("undefined".into(), |x| format!("{x:.4}")),
            ps[1],
            select * 100.0,
            amp("at_k"),
            amp("at_k_plus_deep"),
            kk + deep,
            if deviation { "deviation at the Bonferroni level" } else { "no deviation" },
        ));
        flags.push((r, deviation));
        by_rounds.push(v);
    }
    if let Some(v) = by_rounds.iter().find(|v| v["rounds"] == FULL_ROUNDS) {
        let hi = v["select_even_measure_odd"]["at_k"]["amplification"]["A_ci95"][1].as_f64().unwrap_or(f64::NAN);
        summary.push(format!("Mining: choosing templates by their measured hit rate gives at most A = {hi:.4} (95% upper bound) at 64 rounds; {}.", if v["deviation"] == true { "a deviation needs the confirmation run before any claim" } else { "the expected work per block is unchanged" }));
    }
    let deterministic = json!({ "by_rounds": by_rounds, "check": check });
    let observations = json!({ "by_rounds": by_rounds, "check": check, "gpu": gpu, "bonferroni_alpha": bonferroni });
    Ok(Outcome::new(observations, deterministic, flags, summary))
}

/// Leading zero bits of the hash number (little-endian digest bytes), exact below 128.
fn lz_bytes(d: &[u8; 32]) -> u32 {
    u128::from_le_bytes(d[16..].try_into().expect("16 bytes")).leading_zeros()
}

/// Template `work`'s counts over `0..2^nonce_bits` with the independent SHA-256.
fn independent_counts(work: &Work, rounds: usize, nonce_bits: u32, k: u32, deep: u32) -> (Counts, Vec<u32>) {
    let ind = verification::independent::Sha256::default();
    let header = work.header_bytes();
    let hits: Vec<(u32, u32)> = (0..1u32 << nonce_bits)
        .into_par_iter()
        .filter_map(|n| {
            let mut h = header;
            h[76..80].copy_from_slice(&n.to_le_bytes());
            let z = lz_bytes(&ind.sha256d(&h, rounds));
            (z >= k).then_some((n, z))
        })
        .collect();
    let mut c = Counts::default();
    hits.iter().for_each(|&(n, z)| c.add(n, z, k, deep));
    (c, hits.into_iter().map(|(n, _)| n).collect())
}

/// Template 0 recounted with the independent SHA-256: the whole reduced-round
/// range, and the first 2^check_bits nonces at 64 rounds (every hit and every miss).
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let rounds = p_rounds(params)?;
    let deep = p_u64(params, "deep")? as u32;
    let (k, rk, rnb) = (p_u64(params, "k")? as u32, p_u64(params, "reduced_k")? as u32, p_u64(params, "reduced_nonce_bits")? as u32);
    let mut problems = Vec::new();
    for (i, &r) in rounds.iter().enumerate() {
        let v = &outcome.observations["by_rounds"][i];
        if r == FULL_ROUNDS {
            let check = &outcome.observations["check"];
            let bits = check["bits"].as_u64().context("no check range")? as u32;
            let gpu: Vec<u64> = check["hits"].as_array().context("no check hits")?.iter().filter_map(Value::as_u64).collect();
            let (_, ind) = independent_counts(&template(seed, 0, k), r, bits, k, deep);
            if ind.iter().map(|&n| n as u64).collect::<Vec<_>>() != gpu {
                problems.push(format!("64 rounds: GPU hits of template 0 below 2^{bits} differ from the independent recount ({} vs {})", gpu.len(), ind.len()));
            }
        } else {
            let (c, _) = independent_counts(&template(seed, 0, rk), r, rnb, rk, deep);
            let want = json!([c.even, c.odd, c.deep_even, c.deep_odd]);
            if v["counts"][0] != want {
                problems.push(format!("{r} rounds: template 0 counts {} differ from the independent recount {want}", v["counts"][0]));
            }
        }
    }
    Ok(Verification {
        method: "template 0 recounted with verification::independent::Sha256 (own constants, own compression): every nonce of the reduced-round range, and every nonce below 2^check_bits at 64 rounds compared hit for hit with the GPU".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "all recounts match".into() } else { problems.join("; ") },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use statistical_engine::SplitMix64;

    /// Poisson-ish counts with and without a planted per-template rate.
    fn counts(seed: u64, t: usize, nonces: u64, k: u32, spread: f64) -> Vec<Counts> {
        let mut rng = SplitMix64::stream(seed, 0);
        let p = 2f64.powi(-(k as i32));
        (0..t)
            .map(|i| {
                let rate = p * if i % 4 == 0 { 1.0 + spread } else { 1.0 };
                // Normal approximation of Binomial(nonces/2, rate) per half; fine at these means.
                let mut half = || {
                    let mu = nonces as f64 / 2.0 * rate;
                    let (u1, u2) = ((rng.next_u32() as f64 + 1.0) / 4294967297.0, rng.next_u32() as f64 / 4294967296.0);
                    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                    (mu + z * mu.sqrt()).round().max(0.0) as u64
                };
                let (even, odd) = (half(), half());
                Counts { even, odd, deep_even: even / 256, deep_odd: odd / 256 }
            })
            .collect()
    }

    #[test]
    fn null_passes_and_planted_template_luck_is_found() {
        let (nonces, k) = (1u64 << 32, 20);
        let (null, ps) = analyse(&counts(1, 2048, nonces, k, 0.0), nonces, k, 8, 0.1);
        assert!(ps[0] > 1e-4 && ps[1] > 1e-4 && ps[2] > 1e-4, "{null}");
        let a = null["select_even_measure_odd"]["at_k"]["amplification"]["A"].as_f64().unwrap();
        assert!((a - 1.0).abs() < 0.01, "{a}");
        // A quarter of the templates 5% luckier: found by dispersion, correlation and selection.
        let (lucky, ps) = analyse(&counts(2, 2048, nonces, k, 0.05), nonces, k, 8, 0.1);
        assert!(ps[0] < 1e-6 && ps[1] < 1e-6 && ps[2] < 1e-6, "{lucky}");
        let a = lucky["select_even_measure_odd"]["at_k"]["amplification"]["A"].as_f64().unwrap();
        assert!(a > 1.02, "{a}");
    }

    #[test]
    fn cpu_counts_match_the_independent_recount() {
        for r in [4, 5, 64] {
            let w = template(9, 3, 6);
            assert_eq!(cpu_counts(&w, r, 14, 6, 2), independent_counts(&w, r, 14, 6, 2).0, "{r} rounds");
        }
    }
}
