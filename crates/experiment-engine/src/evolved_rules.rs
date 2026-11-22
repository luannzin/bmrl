//! Evolved nonce-selection rules: genetic programming searches for a cheap
//! rule that picks nonces more likely to meet the target, the nonlinear
//! family the nonce atlas left untested.
//!
//! A rule is a small expression over the nonce (and its byte swap), the
//! template's midstate, its second-block state after round 2, and a probe
//! (the reduced-round digest of the template at nonce 0, one hash per
//! template), with SHA-256's own operations available (Sigma, sigma, Ch, Maj,
//! add, xor, rotations). Its predicate keeps a nonce when the expression has
//! j leading zero bits, or a chosen bit clear. Hashing only the kept nonces
//! costs 1/A of the exhaustive work per hit, where A is the rule's hit-rate
//! amplification; the rule itself costs a few operations against about 3,000
//! per hash.
//!
//! Rules are evolved on discovery templates only. The best distinct rules of
//! each round count are then measured once on held-out templates, which
//! decide; the search's own scores are inflated by the search itself.

use crate::nonce_atlas::{prepared, synthetic};
use crate::{Definition, Outcome, Verification, p_rounds, p_u64};
use anyhow::Result;
use bitcoin_header::HeaderMidstate;
use rayon::prelude::*;
use serde_json::{Value, json};
use sha256_core::{K, big_sigma0, big_sigma1, ch, maj, round, small_sigma0, small_sigma1};
use statistical_engine::{SplitMix64, Z95, two_sided_p, wilson};
use std::fmt;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-EVOLVE-01",
        primitive: crate::primitive::HEADER,
        name: "Evolved cheap nonce-selection rules (genetic programming), held-out tested",
        version: 1,
        hypothesis: "A cheap expression over the nonce, template constants and a one-hash template probe selects nonces that meet a leading-zero target more often than the rest, on templates the search never saw.",
        null_hypothesis: "Every evolved rule's held-out amplification is 1 within its confidence interval (at 64 rounds, and at every round count where the header map behaves like a random function).",
        assumptions: &[
            "Rule language: terminals nonce, bswap(nonce), midstate words, second-block state after round 2, probe digest words (reduced-round SHA256d of the template at nonce 0) and constants; operations not, bswap, rotr, shr, shl, Sigma0, Sigma1, sigma0, sigma1, xor, and, or, add, sub, Ch, Maj; at most max_size nodes.",
            "Predicate: the expression has j leading zero bits (keeps 2^-j of nonces) or bit b is clear (keeps half).",
            "Hit level: the hash number's top k bits are zero; fitness uses k = fitness_k on the first 2^fitness_bits nonces of each discovery template; held-out tests use all 2^nonce_bits nonces at k = fitness_k and k = 8.",
            "Templates are synthetic (as in the nonce atlas) and every round count cuts all three compressions; reduced-round results say nothing about 64 rounds.",
            "Held-out p-values are one-sided binomial normal approximations with a Bonferroni correction over every held-out test of the run (alpha 0.001).",
        ],
        baseline: "A = 1: a selection rule that ignores the hash keeps hits at the overall rate.",
        methodology: "Per round count: compute the top 16 bits of the hash number for every nonce of each template; evolve a population of rules (tournament selection, subtree crossover and mutation, elitism, parsimony penalty) for a fixed number of generations; keep the best distinct rules; measure each once on the held-out templates.",
        implementation: &["experiment_engine::evolved_rules", "cpu_backend::Prepared::hash8"],
        dataset: "Templates: nonce_atlas::synthetic(seed, i), discovery i < discovery_templates, held-out after; GP randomness SplitMix64::stream(seed ^ rounds, 0).",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "rounds": [4, 5, 6, 8, 64],
        "nonce_bits": if quick { 16 } else { 21 },
        "fitness_bits": if quick { 14 } else { 19 },
        "discovery_templates": if quick { 2 } else { 6 },
        "heldout_templates": if quick { 2 } else { 6 },
        "population": if quick { 48 } else { 1000 },
        "generations": if quick { 4 } else { 60 },
        "hall_of_fame": if quick { 3 } else { 10 },
        "max_size": 15,
        "fitness_k": 6,
        "reproduce": true,
    })
}

// ------------------------------------------------------------- rules

#[derive(Clone, Copy, Debug, PartialEq)]
enum Un {
    Not,
    Bswap,
    Rotr(u32),
    Shr(u32),
    Shl(u32),
    BigS0,
    BigS1,
    SmallS0,
    SmallS1,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Bin {
    Xor,
    And,
    Or,
    Add,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tern {
    Ch,
    Maj,
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Nonce,
    BswapNonce,
    Mid(usize),
    Pre(usize),
    Probe(usize),
    Const(u32),
    Un(Un, Box<Expr>),
    Bin(Bin, Box<Expr>, Box<Expr>),
    Tern(Tern, Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Pred {
    /// The value has `j` leading zero bits.
    Top(u32),
    /// Bit `b` of the value is clear.
    Bit(u32),
}

#[derive(Clone, Debug, PartialEq)]
struct Rule {
    expr: Expr,
    pred: Pred,
}

impl Un {
    fn apply(self, x: u32) -> u32 {
        match self {
            Un::Not => !x,
            Un::Bswap => x.swap_bytes(),
            Un::Rotr(c) => x.rotate_right(c),
            Un::Shr(c) => x >> c,
            Un::Shl(c) => x << c,
            Un::BigS0 => big_sigma0(x),
            Un::BigS1 => big_sigma1(x),
            Un::SmallS0 => small_sigma0(x),
            Un::SmallS1 => small_sigma1(x),
        }
    }
}

impl Bin {
    fn apply(self, a: u32, b: u32) -> u32 {
        match self {
            Bin::Xor => a ^ b,
            Bin::And => a & b,
            Bin::Or => a | b,
            Bin::Add => a.wrapping_add(b),
            Bin::Sub => a.wrapping_sub(b),
        }
    }
}

impl Tern {
    fn apply(self, a: u32, b: u32, c: u32) -> u32 {
        match self {
            Tern::Ch => ch(a, b, c),
            Tern::Maj => maj(a, b, c),
        }
    }
}

impl Pred {
    fn keeps(self, v: u32) -> bool {
        match self {
            Pred::Top(j) => v >> (32 - j) == 0,
            Pred::Bit(b) => v >> b & 1 == 0,
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Nonce => write!(f, "n"),
            Expr::BswapNonce => write!(f, "bswap(n)"),
            Expr::Mid(i) => write!(f, "mid{i}"),
            Expr::Pre(i) => write!(f, "pre{i}"),
            Expr::Probe(i) => write!(f, "probe{i}"),
            Expr::Const(c) => write!(f, "{c:#x}"),
            Expr::Un(op, a) => match op {
                Un::Rotr(c) => write!(f, "rotr({a}, {c})"),
                Un::Shr(c) => write!(f, "({a} >> {c})"),
                Un::Shl(c) => write!(f, "({a} << {c})"),
                _ => write!(f, "{}({a})", format!("{op:?}").to_lowercase()),
            },
            Expr::Bin(op, a, b) => {
                let s = match op {
                    Bin::Xor => "^",
                    Bin::And => "&",
                    Bin::Or => "|",
                    Bin::Add => "+",
                    Bin::Sub => "-",
                };
                write!(f, "({a} {s} {b})")
            }
            Expr::Tern(op, a, b, c) => write!(f, "{}({a}, {b}, {c})", format!("{op:?}").to_lowercase()),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pred {
            Pred::Top(j) => write!(f, "keep if {} has {j} leading zero bits", self.expr),
            Pred::Bit(b) => write!(f, "keep if bit {b} of {} is 0", self.expr),
        }
    }
}

impl Expr {
    fn size(&self) -> usize {
        match self {
            Expr::Un(_, a) => 1 + a.size(),
            Expr::Bin(_, a, b) => 1 + a.size() + b.size(),
            Expr::Tern(_, a, b, c) => 1 + a.size() + b.size() + c.size(),
            _ => 1,
        }
    }

    /// Scalar evaluation (the reference for the vectorised path).
    fn eval1(&self, t: &Data, n: u32) -> u32 {
        match self {
            Expr::Nonce => n,
            Expr::BswapNonce => n.swap_bytes(),
            Expr::Mid(i) => t.mid[*i],
            Expr::Pre(i) => t.pre[*i],
            Expr::Probe(i) => t.probe[*i],
            Expr::Const(c) => *c,
            Expr::Un(op, a) => op.apply(a.eval1(t, n)),
            Expr::Bin(op, a, b) => op.apply(a.eval1(t, n), b.eval1(t, n)),
            Expr::Tern(op, a, b, c) => op.apply(a.eval1(t, n), b.eval1(t, n), c.eval1(t, n)),
        }
    }

    /// Values for sample indices `base .. base + out.len()` (nonces [`nonce`] of them), `pool` holding spare buffers.
    fn eval_chunk(&self, t: &Data, base: u32, out: &mut [u32], pool: &mut Vec<Vec<u32>>) {
        let len = out.len();
        let take = |pool: &mut Vec<Vec<u32>>| {
            let mut b = pool.pop().unwrap_or_default();
            b.resize(len, 0);
            b
        };
        match self {
            Expr::Nonce => out.iter_mut().enumerate().for_each(|(i, o)| *o = nonce(base.wrapping_add(i as u32))),
            Expr::BswapNonce => out.iter_mut().enumerate().for_each(|(i, o)| *o = nonce(base.wrapping_add(i as u32)).swap_bytes()),
            Expr::Mid(_) | Expr::Pre(_) | Expr::Probe(_) | Expr::Const(_) => out.fill(self.eval1(t, 0)),
            Expr::Un(op, a) => {
                a.eval_chunk(t, base, out, pool);
                out.iter_mut().for_each(|o| *o = op.apply(*o));
            }
            Expr::Bin(op, a, b) => {
                a.eval_chunk(t, base, out, pool);
                let mut y = take(pool);
                b.eval_chunk(t, base, &mut y, pool);
                out.iter_mut().zip(&y).for_each(|(o, &y)| *o = op.apply(*o, y));
                pool.push(y);
            }
            Expr::Tern(op, a, b, c) => {
                a.eval_chunk(t, base, out, pool);
                let (mut y, mut z) = (take(pool), take(pool));
                b.eval_chunk(t, base, &mut y, pool);
                c.eval_chunk(t, base, &mut z, pool);
                out.iter_mut().zip(y.iter().zip(&z)).for_each(|(o, (&y, &z))| *o = op.apply(*o, y, z));
                pool.push(y);
                pool.push(z);
            }
        }
    }

    /// Number of nodes in preorder and access by index.
    fn node(&self, i: &mut usize) -> Option<&Expr> {
        if *i == 0 {
            return Some(self);
        }
        *i -= 1;
        match self {
            Expr::Un(_, a) => a.node(i),
            Expr::Bin(_, a, b) => a.node(i).or_else(|| b.node(i)),
            Expr::Tern(_, a, b, c) => a.node(i).or_else(|| b.node(i)).or_else(|| c.node(i)),
            _ => None,
        }
    }

    fn replace(&mut self, i: &mut usize, with: &Expr) -> bool {
        if *i == 0 {
            *self = with.clone();
            return true;
        }
        *i -= 1;
        match self {
            Expr::Un(_, a) => a.replace(i, with),
            Expr::Bin(_, a, b) => a.replace(i, with) || b.replace(i, with),
            Expr::Tern(_, a, b, c) => a.replace(i, with) || b.replace(i, with) || c.replace(i, with),
            _ => false,
        }
    }
}

fn pick(rng: &mut SplitMix64, n: u32) -> u32 {
    rng.next_u32() % n
}

fn random_leaf(rng: &mut SplitMix64) -> Expr {
    match pick(rng, 10) {
        0 | 1 => Expr::Nonce,
        2 | 3 => Expr::BswapNonce,
        4 => Expr::Mid(pick(rng, 8) as usize),
        5 => Expr::Pre(pick(rng, 8) as usize),
        6 | 7 => Expr::Probe(pick(rng, 8) as usize),
        8 => Expr::Const(K[pick(rng, 64) as usize]),
        _ => Expr::Const(rng.next_u32()),
    }
}

fn random_expr(rng: &mut SplitMix64, depth: u32) -> Expr {
    if depth == 0 || pick(rng, 4) == 0 {
        return random_leaf(rng);
    }
    let sub = |rng: &mut SplitMix64| Box::new(random_expr(rng, depth - 1));
    match pick(rng, 16) {
        0 => Expr::Un(Un::Not, sub(rng)),
        1 => Expr::Un(Un::Bswap, sub(rng)),
        2 => Expr::Un(Un::Rotr(1 + pick(rng, 31)), sub(rng)),
        3 => Expr::Un(Un::Shr(1 + pick(rng, 31)), sub(rng)),
        4 => Expr::Un(Un::Shl(1 + pick(rng, 31)), sub(rng)),
        5 => Expr::Un([Un::BigS0, Un::BigS1, Un::SmallS0, Un::SmallS1][pick(rng, 4) as usize], sub(rng)),
        6 | 7 => Expr::Bin(Bin::Xor, sub(rng), sub(rng)),
        8 => Expr::Bin(Bin::And, sub(rng), sub(rng)),
        9 => Expr::Bin(Bin::Or, sub(rng), sub(rng)),
        10..=12 => Expr::Bin(Bin::Add, sub(rng), sub(rng)),
        13 => Expr::Bin(Bin::Sub, sub(rng), sub(rng)),
        14 => Expr::Tern(Tern::Ch, sub(rng), sub(rng), sub(rng)),
        _ => Expr::Tern(Tern::Maj, sub(rng), sub(rng), sub(rng)),
    }
}

fn random_pred(rng: &mut SplitMix64) -> Pred {
    if pick(rng, 2) == 0 { Pred::Top(1 + pick(rng, 8)) } else { Pred::Bit(pick(rng, 32)) }
}

fn random_rule(rng: &mut SplitMix64, max_size: usize) -> Rule {
    loop {
        let depth = 1 + pick(rng, 4);
        let r = Rule { expr: random_expr(rng, depth), pred: random_pred(rng) };
        if r.expr.size() <= max_size {
            return r;
        }
    }
}

fn mutate(rng: &mut SplitMix64, r: &Rule, max_size: usize) -> Rule {
    let mut out = r.clone();
    if pick(rng, 5) == 0 {
        out.pred = random_pred(rng);
        return out;
    }
    let mut i = pick(rng, r.expr.size() as u32) as usize;
    let depth = 1 + pick(rng, 3);
    out.expr.replace(&mut i, &random_expr(rng, depth));
    if out.expr.size() <= max_size { out } else { r.clone() }
}

fn crossover(rng: &mut SplitMix64, a: &Rule, b: &Rule, max_size: usize) -> Rule {
    let mut j = pick(rng, b.expr.size() as u32) as usize;
    let donor = b.expr.node(&mut j).expect("index below size").clone();
    let mut out = a.clone();
    let mut i = pick(rng, a.expr.size() as u32) as usize;
    out.expr.replace(&mut i, &donor);
    if out.expr.size() <= max_size { out } else { a.clone() }
}

// ------------------------------------------------------------- data

/// Sample index to nonce: an odd multiplier spreads the sample over all
/// 2^32 nonces (consecutive low nonces share their top byte, which at 4
/// rounds fixes the hash number's top byte).
fn nonce(i: u32) -> u32 {
    i.wrapping_mul(0x9e37_79b1)
}

/// One template at one round count.
struct Data {
    mid: [u32; 8],
    pre: [u32; 8],
    probe: [u32; 8],
    /// Top 16 bits of the hash number for every sample index.
    top16: Vec<u16>,
}

fn data(header: &[u8; 80], rounds: usize, nonce_bits: u32) -> Data {
    let p = prepared(header, rounds);
    let hm = HeaderMidstate::with_rounds(header, rounds);
    let mut pre = hm.state;
    for (t, &w) in hm.tail.iter().enumerate() {
        pre = round(&pre, K[t], w);
    }
    let top16 = (0..1u32 << nonce_bits).into_par_iter().map(|i| (p.hash_words(nonce(i))[7].swap_bytes() >> 16) as u16).collect();
    Data { mid: hm.state, pre, probe: p.hash_words(0), top16 }
}

/// (kept, kept hits at level k for each k) over nonces `0..n`.
fn count(r: &Rule, t: &Data, n: usize, ks: &[u32]) -> (u64, Vec<u64>) {
    const CHUNK: usize = 1024;
    let mut pool = Vec::new();
    let mut v = vec![0u32; CHUNK];
    let (mut kept, mut hits) = (0u64, vec![0u64; ks.len()]);
    for base in (0..n).step_by(CHUNK) {
        let len = CHUNK.min(n - base);
        r.expr.eval_chunk(t, base as u32, &mut v[..len], &mut pool);
        for (i, &x) in v[..len].iter().enumerate() {
            if r.pred.keeps(x) {
                kept += 1;
                let y = t.top16[base + i];
                for (h, &k) in hits.iter_mut().zip(ks) {
                    *h += u64::from(y >> (16 - k) == 0);
                }
            }
        }
    }
    (kept, hits)
}

fn base_hits(t: &Data, n: usize, k: u32) -> u64 {
    t.top16[..n].iter().filter(|&&y| y >> (16 - k) == 0).count() as u64
}

/// Pooled amplification over templates: (kept, kept hits, expected kept hits).
fn pooled(r: &Rule, ts: &[Data], n: usize, k: u32) -> (u64, u64, f64) {
    ts.iter().fold((0, 0, 0.0), |(s, h, e), t| {
        let (kept, hits) = count(r, t, n, &[k]);
        (s + kept, h + hits[0], e + kept as f64 * base_hits(t, n, k) as f64 / n as f64)
    })
}

fn z_of(hits: u64, expected: f64) -> f64 {
    if expected <= 0.0 { 0.0 } else { (hits as f64 - expected) / expected.sqrt() }
}

fn fitness(r: &Rule, ts: &[Data], n: usize, k: u32) -> f64 {
    let (kept, hits, expected) = pooled(r, ts, n, k);
    if kept < 256 || expected < 16.0 {
        return -1e9;
    }
    z_of(hits, expected) - 0.05 * r.expr.size() as f64
}

// ------------------------------------------------------------- experiment

struct Gp {
    population: usize,
    generations: usize,
    hall: usize,
    max_size: usize,
    k: u32,
    fit_n: usize,
}

/// Best distinct rules found, with their discovery fitness, and the number of evaluations.
fn evolve(gp: &Gp, disc: &[Data], seed: u64) -> (Vec<(Rule, f64)>, u64) {
    let mut rng = SplitMix64::stream(seed, 0);
    let mut pop: Vec<Rule> = (0..gp.population).map(|_| random_rule(&mut rng, gp.max_size)).collect();
    let mut hall: Vec<(Rule, f64, String)> = Vec::new();
    let mut evals = 0u64;
    for _ in 0..gp.generations {
        let fits: Vec<f64> = pop.par_iter().map(|r| fitness(r, disc, gp.fit_n, gp.k)).collect();
        evals += pop.len() as u64;
        for (r, &f) in pop.iter().zip(&fits) {
            let key = r.to_string();
            if !hall.iter().any(|h| h.2 == key) {
                hall.push((r.clone(), f, key));
            }
        }
        hall.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
        hall.truncate(gp.hall);
        let mut order: Vec<usize> = (0..pop.len()).collect();
        order.sort_by(|&a, &b| fits[b].total_cmp(&fits[a]).then(a.cmp(&b)));
        let tournament = |rng: &mut SplitMix64| (0..5).map(|_| pick(rng, pop.len() as u32) as usize).max_by(|&a, &b| fits[a].total_cmp(&fits[b]).then(b.cmp(&a))).expect("five picks");
        let mut next: Vec<Rule> = order.iter().take(5).map(|&i| pop[i].clone()).collect();
        while next.len() < gp.population {
            let a = tournament(&mut rng);
            let child = if pick(&mut rng, 10) < 7 {
                let b = tournament(&mut rng);
                crossover(&mut rng, &pop[a], &pop[b], gp.max_size)
            } else {
                mutate(&mut rng, &pop[a], gp.max_size)
            };
            next.push(child);
        }
        pop = next;
    }
    (hall.into_iter().map(|(r, f, _)| (r, f)).collect(), evals)
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let rounds = p_rounds(params)?;
    let nb = p_u64(params, "nonce_bits")? as u32;
    let fb = (p_u64(params, "fitness_bits")? as u32).min(nb);
    let (nd, nh) = (p_u64(params, "discovery_templates")?, p_u64(params, "heldout_templates")?);
    anyhow::ensure!((12..=26).contains(&nb) && nd >= 1 && nh >= 1, "need 12 <= nonce_bits <= 26 and at least one template of each kind");
    let gp = Gp {
        population: p_u64(params, "population")? as usize,
        generations: p_u64(params, "generations")? as usize,
        hall: p_u64(params, "hall_of_fame")? as usize,
        max_size: p_u64(params, "max_size")? as usize,
        k: p_u64(params, "fitness_k")? as u32,
        fit_n: 1 << fb,
    };
    anyhow::ensure!(gp.population >= 8 && (1..=16).contains(&gp.k), "population >= 8 and 1 <= fitness_k <= 16");
    let ks = [gp.k, 8];
    let tests = (gp.hall * ks.len() * rounds.len()) as f64;
    let threshold = 0.001 / tests;
    let n = 1usize << nb;
    let mut rows = Vec::new();
    let mut flags = Vec::new();
    let mut summary = Vec::new();
    for &r in &rounds {
        let headers: Vec<[u8; 80]> = (0..nd + nh).map(|i| synthetic(seed, i).header).collect();
        let all: Vec<Data> = headers.iter().map(|h| data(h, r, nb)).collect();
        let (disc, held) = all.split_at(nd as usize);
        let (hall, evals) = evolve(&gp, disc, seed ^ (r as u64) << 32);
        let mut deviation = false;
        let mut best_held: Option<(f64, String)> = None;
        let rules: Vec<Value> = hall
            .iter()
            .map(|(rule, fit)| {
                let held_k: Vec<Value> = ks
                    .iter()
                    .map(|&k| {
                        let (kept, hits, expected) = pooled(rule, held, n, k);
                        let p_all = expected / kept.max(1) as f64;
                        let a = if expected > 0.0 { hits as f64 / expected } else { 0.0 };
                        let (lo, hi) = wilson(hits, kept, Z95);
                        let z = z_of(hits, expected);
                        let p = if z > 0.0 { two_sided_p(z) / 2.0 } else { 1.0 };
                        if p < threshold && a > 1.0 {
                            deviation = true;
                        }
                        if k == gp.k && best_held.as_ref().is_none_or(|b| a > b.0) {
                            best_held = Some((a, rule.to_string()));
                        }
                        json!({ "k": k, "kept": kept, "hits": hits, "expected": expected, "amplification": a,
                                "amplification_ci95": [lo / p_all.max(f64::MIN_POSITIVE), hi / p_all.max(f64::MIN_POSITIVE)], "z": z, "p_one_sided": p })
                    })
                    .collect();
                json!({ "rule": rule.to_string(), "size": rule.expr.size(), "discovery_fitness": fit, "heldout": held_k })
            })
            .collect();
        let best_disc = hall.first().map(|(r, f)| (r.to_string(), *f)).unwrap_or_default();
        let (ba, brule) = best_held.unwrap_or((1.0, String::new()));
        summary.push(format!("{r} rounds: {evals} rules evolved; best discovery fitness {:.1}; best held-out amplification at k = {} is {ba:.4} (`{brule}`); {}.",
            best_disc.1, gp.k, if deviation { "held-out deviation" } else { "no held-out rule beats A = 1" }));
        flags.push((r, deviation));
        rows.push(json!({ "rounds": r, "evaluations": evals, "rules": rules, "deviation": deviation }));
    }
    summary.push(format!("Held-out tests: {tests} (rules x hit levels x round counts), Bonferroni threshold {threshold:.1e}. Work per hit with a rule is 1/A of exhaustive search."));
    let obs = json!({ "by_rounds": rows, "bonferroni_threshold": threshold });
    Ok(Outcome::new(obs.clone(), obs, flags, summary))
}

/// Recompute the top 16 bits with the independent SHA-256 for the first
/// nonces of the first template, and each round's best rule with the scalar
/// evaluator against the vectorised one.
pub fn verify(params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let rounds = p_rounds(params)?;
    let ind = verification::independent::Sha256::default();
    let header = synthetic(seed, 0).header;
    let mut problems = Vec::new();
    for &r in &rounds {
        let d = data(&header, r, 12);
        for i in 0..256u32 {
            let mut h = header;
            h[76..80].copy_from_slice(&nonce(i).to_le_bytes());
            let digest = ind.sha256d(&h, r);
            let top = (digest[31] as u16) << 8 | digest[30] as u16;
            if top != d.top16[i as usize] {
                problems.push(format!("{r} rounds: top bits differ at sample {i}"));
                break;
            }
        }
        // Every evolved rule is a tree of the same node types: check the evaluators on random rules.
        let mut rng = SplitMix64::stream(seed ^ 0x7e57, r as u64);
        for _ in 0..64 {
            let rule = random_rule(&mut rng, 15);
            let mut v = vec![0u32; 1024];
            rule.expr.eval_chunk(&d, 3000, &mut v, &mut Vec::new());
            if (0..1024u32).any(|i| v[i as usize] != rule.expr.eval1(&d, nonce(3000 + i))) {
                problems.push(format!("{r} rounds: vectorised and scalar evaluation differ for `{rule}`"));
                break;
            }
        }
    }
    if outcome.observations["by_rounds"].as_array().is_none_or(|a| a.len() != rounds.len()) {
        problems.push("missing round counts in the outcome".into());
    }
    Ok(Verification {
        method: "top 16 hash-number bits recomputed with verification::independent for 256 nonces per round count; vectorised rule evaluation checked against scalar evaluation on 64 random rules per round count".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "independent hashes and both evaluators agree".into() } else { problems.join("; ") },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive control: at 4 rounds H7 = C + bswap(n) with C = H7(0), so the rule
    /// "bswap(bswap(n) + probe7) has 8 leading zero bits" keeps exactly the 8-bit hits.
    #[test]
    fn probe_rule_captures_the_four_round_affine_map() {
        let header = synthetic(1, 0).header;
        let d = data(&header, 4, 16);
        let rule = Rule {
            expr: Expr::Un(Un::Bswap, Box::new(Expr::Bin(Bin::Add, Box::new(Expr::BswapNonce), Box::new(Expr::Probe(7))))),
            pred: Pred::Top(8),
        };
        let (kept, hits) = count(&rule, &d, 1 << 16, &[8]);
        assert!(hits[0] > 100, "the sample contains 8-bit hits ({})", hits[0]);
        assert_eq!(kept, hits[0], "every kept nonce is an 8-bit hit");
        assert_eq!(hits[0], base_hits(&d, 1 << 16, 8), "and every 8-bit hit is kept");
    }
}
