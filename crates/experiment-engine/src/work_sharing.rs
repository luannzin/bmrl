//! AsicBoost++: which batches of headers can share SHA256d work, found by a
//! compiler instead of by hand.
//!
//! The header computation is built as an expression DAG over its inputs:
//! the midstate (MID), the merkle tail W0, the time W1 and the nonce W3 (the
//! bits word and the padding are template constants). Every node knows which
//! inputs it depends on. Constants are folded, equal nodes are shared, and
//! every modular sum is re-associated so that terms of the same dependency
//! class are added together first.
//!
//! A batch is k headers scanned with the same nonce that differ in the
//! inputs M (for example M = {MID}: BIP320 version rolling, the overt form of
//! AsicBoost). Per nonce, a node that does not depend on W3 is template
//! precomputation (amortised over 2^32 nonces); a node that depends on W3 but
//! not on M is computed once for the whole batch; the rest once per header.
//! The counts are exact properties of the computation; the cost weights per
//! operation are a model, and the GPU speedup is measured separately
//! (`bmr benchmark gpu`).

use crate::{Definition, Outcome, Verification};
use anyhow::Result;
use serde_json::{Value, json};
use sha256_core::{IV, K, big_sigma0, big_sigma1, ch, maj, small_sigma0, small_sigma1};
use statistical_engine::SplitMix64;
use std::collections::HashMap;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-SHARE-01",
        primitive: crate::primitive::HEADER,
        name: "Work shared across batches of headers (AsicBoost and beyond), by exact DAG analysis",
        version: 1,
        hypothesis: "Some way of batching headers that a miner can produce (version rolling, time rolling, extranonce changes or combinations) lets the batch share more of the per-nonce SHA256d work than overt AsicBoost's message-schedule sharing.",
        null_hypothesis: "Version rolling (shared second-block message) is the best sharing pattern; every other feasible pattern shares less of the per-nonce work.",
        assumptions: &[
            "Batch members use the same nonce and differ only in the inputs of the pattern; template precomputation (anything independent of the nonce) is free.",
            "Word-level sharing only: two members share a node only if all of its inputs are identical. Bit-level partial sharing is not modelled.",
            "Outputs needed per nonce: e60 of the outer compression (the early reject); the full digest is computed only for the rare candidates and is not counted.",
            "Cost weights are a model: primitive ops (rotate, shift, xor, and, or, add = 1) and an RDNA3 estimate (Sigma 4, sigma 4, Ch 1, Maj 2, add 1).",
            "Feasibility of each pattern follows Bitcoin consensus: version rolling has 16 free bits (BIP320), time a few thousand valid values, a merkle-tail change alone needs a 224-bit partial merkle-root collision.",
        ],
        baseline: "k = 1: every per-nonce node computed once per header (the v2 kernel's work).",
        methodology: "Build the header SHA256d DAG once per pattern (sums re-associated by dependency class for that pattern), check it against the reference SHA-256 on random headers, keep the nodes the early reject needs, classify each node and count operations per header for k = 1, 2, 4, 8, 16.",
        implementation: &["experiment_engine::work_sharing"],
        dataset: "Random headers for the DAG check: SplitMix64::stream(seed, i).",
    }
}

pub fn default_params(_quick: bool) -> Value {
    json!({ "batch_sizes": [1, 2, 4, 8, 16], "check_headers": 256, "reproduce": true })
}

/// Input dependency bits.
const MID: u8 = 1;
const W0: u8 = 2;
const W1: u8 = 4;
const W3: u8 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Op {
    Add,
    BigSigma0,
    BigSigma1,
    SmallSigma0,
    SmallSigma1,
    Ch,
    Maj,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Add => "add",
            Op::BigSigma0 => "Sigma0",
            Op::BigSigma1 => "Sigma1",
            Op::SmallSigma0 => "sigma0",
            Op::SmallSigma1 => "sigma1",
            Op::Ch => "ch",
            Op::Maj => "maj",
        }
    }

    /// (primitive ops, RDNA3 estimate)
    fn cost(self) -> (u64, u64) {
        match self {
            Op::Add => (1, 1),
            Op::BigSigma0 | Op::BigSigma1 | Op::SmallSigma0 | Op::SmallSigma1 => (5, 4),
            Op::Ch => (3, 1),
            Op::Maj => (4, 2),
        }
    }

    fn eval(self, a: u32, b: u32, c: u32) -> u32 {
        match self {
            Op::Add => a.wrapping_add(b),
            Op::BigSigma0 => big_sigma0(a),
            Op::BigSigma1 => big_sigma1(a),
            Op::SmallSigma0 => small_sigma0(a),
            Op::SmallSigma1 => small_sigma1(a),
            Op::Ch => ch(a, b, c),
            Op::Maj => maj(a, b, c),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Val {
    Const(u32),
    Node(usize),
}

enum Node {
    Input(usize),
    Op(Op, [Val; 3]),
}

/// Hash-consed DAG with constant folding.
struct Dag {
    nodes: Vec<Node>,
    deps: Vec<u8>,
    memo: HashMap<(Op, [Val; 3]), Val>,
    /// Inputs in which batch members differ.
    members: u8,
}

impl Dag {
    fn new(members: u8) -> Self {
        Self { nodes: vec![], deps: vec![], memo: HashMap::new(), members }
    }

    /// 0: template precomputation (no nonce), 1: shared by the batch, 2: per member.
    fn rank(&self, deps: u8) -> u8 {
        if deps & W3 == 0 {
            0
        } else if deps & self.members == 0 {
            1
        } else {
            2
        }
    }

    fn input(&mut self, index: usize, deps: u8) -> Val {
        self.nodes.push(Node::Input(index));
        self.deps.push(deps);
        Val::Node(self.nodes.len() - 1)
    }

    fn deps_of(&self, v: Val) -> u8 {
        match v {
            Val::Const(_) => 0,
            Val::Node(i) => self.deps[i],
        }
    }

    fn op(&mut self, op: Op, a: Val, b: Val, c: Val) -> Val {
        if let (Val::Const(x), Val::Const(y), Val::Const(z)) = (a, b, c) {
            return Val::Const(op.eval(x, y, z));
        }
        let mut args = [a, b, c];
        if op == Op::Add && args[0] > args[1] {
            args.swap(0, 1); // commutative: one canonical order
        }
        if let Some(&v) = self.memo.get(&(op, args)) {
            return v;
        }
        let deps = args.iter().fold(0, |d, &v| d | self.deps_of(v));
        self.nodes.push(Node::Op(op, args));
        self.deps.push(deps);
        let v = Val::Node(self.nodes.len() - 1);
        self.memo.insert((op, args), v);
        v
    }

    fn unary(&mut self, op: Op, a: Val) -> Val {
        self.op(op, a, Val::Const(0), Val::Const(0))
    }

    /// Modular sum of `terms`: constants folded, then terms of the same
    /// dependency class added together, classes combined cheapest first.
    fn sum(&mut self, terms: &[Val]) -> Val {
        let mut k = 0u32;
        let mut by_rank: Vec<(u8, u8, Val)> = Vec::new();
        for &t in terms {
            match t {
                Val::Const(x) => k = k.wrapping_add(x),
                v => {
                    let d = self.deps_of(v);
                    by_rank.push((self.rank(d), d, v));
                }
            }
        }
        by_rank.sort_by_key(|&(r, d, v)| (r, d, v));
        let mut acc: Option<Val> = (k != 0).then_some(Val::Const(k));
        for (_, _, v) in by_rank {
            acc = Some(match acc {
                None => v,
                Some(a) => self.op(Op::Add, a, v, Val::Const(0)),
            });
        }
        acc.unwrap_or(Val::Const(0))
    }

    fn eval(&self, out: Val, inputs: &[u32]) -> u32 {
        let mut vals = vec![0u32; self.nodes.len()];
        let get = |vals: &[u32], v: Val| match v {
            Val::Const(x) => x,
            Val::Node(i) => vals[i],
        };
        for (i, n) in self.nodes.iter().enumerate() {
            vals[i] = match n {
                Node::Input(j) => inputs[*j],
                Node::Op(op, [a, b, c]) => op.eval(get(&vals, *a), get(&vals, *b), get(&vals, *c)),
            };
        }
        get(&vals, out)
    }
}

/// Inputs: mid0..mid7 (0..8), W0 (8), W1 (9), W2 (10), W3 (11).
const N_INPUTS: usize = 12;

/// Rounds of one compression over `w` (grown on demand); returns the state after the last round.
fn compress(g: &mut Dag, mut s: [Val; 8], w: &mut Vec<Val>, rounds: usize) -> [Val; 8] {
    for t in 0..rounds {
        if t == w.len() {
            let terms = [g.unary(Op::SmallSigma1, w[t - 2]), w[t - 7], g.unary(Op::SmallSigma0, w[t - 15]), w[t - 16]];
            let word = g.sum(&terms);
            w.push(word);
        }
        let [a, b, c, d, e, f, gg, h] = s;
        let s1 = g.unary(Op::BigSigma1, e);
        let chv = g.op(Op::Ch, e, f, gg);
        let t1 = g.sum(&[h, s1, chv, Val::Const(K[t]), w[t]]);
        let s0 = g.unary(Op::BigSigma0, a);
        let mj = g.op(Op::Maj, a, b, c);
        let new_e = g.sum(&[d, t1]);
        let new_a = g.sum(&[t1, s0, mj]);
        s = [new_a, a, b, c, new_e, e, f, gg];
    }
    s
}

/// The header DAG up to outer round `outer_rounds - 1`; returns (dag, e of the last outer round, full outer state).
fn header_dag(members: u8, outer_rounds: usize) -> (Dag, Val, [Val; 8]) {
    let mut g = Dag::new(members);
    let mid: [Val; 8] = std::array::from_fn(|i| g.input(i, MID));
    let w0 = g.input(8, W0);
    let w1 = g.input(9, W1);
    let w2 = g.input(10, 0);
    let w3 = g.input(11, W3);
    let mut w = vec![w0, w1, w2, w3, Val::Const(0x8000_0000)];
    w.resize(15, Val::Const(0));
    w.push(Val::Const(640));
    let s = compress(&mut g, mid, &mut w, 64);
    let mut w2v: Vec<Val> = (0..8).map(|i| g.sum(&[mid[i], s[i]])).collect();
    w2v.push(Val::Const(0x8000_0000));
    w2v.resize(15, Val::Const(0));
    w2v.push(Val::Const(256));
    let s2 = compress(&mut g, IV.map(Val::Const), &mut w2v, outer_rounds);
    (g, s2[4], s2)
}

/// Nodes reachable from `out`.
fn live(g: &Dag, out: Val) -> Vec<bool> {
    let mut keep = vec![false; g.nodes.len()];
    if let Val::Node(i) = out {
        keep[i] = true;
    }
    for i in (0..g.nodes.len()).rev() {
        if keep[i]
            && let Node::Op(_, args) = &g.nodes[i]
        {
            for a in args {
                if let Val::Node(j) = a {
                    keep[*j] = true;
                }
            }
        }
    }
    keep
}

struct Pattern {
    name: &'static str,
    members_differ_in: u8,
    feasibility: &'static str,
}

const PATTERNS: [Pattern; 7] = [
    Pattern { name: "version rolling (overt AsicBoost)", members_differ_in: MID, feasibility: "free: 16 BIP320 version bits per template, a new midstate per version" },
    Pattern { name: "time rolling", members_differ_in: W1, feasibility: "limited: about 2^13 valid times, same midstate" },
    Pattern { name: "extranonce (new merkle root)", members_differ_in: MID | W0, feasibility: "free: a new coinbase and merkle path per member" },
    Pattern { name: "version + time rolling", members_differ_in: MID | W1, feasibility: "free x limited" },
    Pattern { name: "extranonce + time", members_differ_in: MID | W0 | W1, feasibility: "free x limited" },
    Pattern { name: "merkle tail only (covert AsicBoost reversed)", members_differ_in: W0, feasibility: "infeasible: same midstate with a different merkle tail needs a 224-bit partial merkle-root collision" },
    Pattern { name: "merkle tail + time", members_differ_in: W0 | W1, feasibility: "infeasible (as above)" },
];

/// Per-nonce op counts of one pattern: (shared per batch, per member) as (primitive, rdna3, by op).
fn analyse(p: &Pattern) -> (Dag, Val, Value, (u64, u64), (u64, u64)) {
    let m = p.members_differ_in;
    let (g, e60, _) = header_dag(m, 61);
    let keep = live(&g, e60);
    let mut shared = (0u64, 0u64);
    let mut member = (0u64, 0u64);
    let mut by_op: HashMap<(&str, &str), u64> = HashMap::new();
    for (i, n) in g.nodes.iter().enumerate() {
        let Node::Op(op, _) = n else { continue };
        let d = g.deps[i];
        if !keep[i] || d & W3 == 0 {
            continue;
        }
        let (prim, rdna) = op.cost();
        let class = if d & m == 0 { "shared" } else { "member" };
        let slot = if d & m == 0 { &mut shared } else { &mut member };
        slot.0 += prim;
        slot.1 += rdna;
        *by_op.entry((class, op.name())).or_default() += 1;
    }
    let mut ops: Vec<Value> = by_op.into_iter().map(|((c, o), n)| json!({ "class": c, "op": o, "count": n })).collect();
    ops.sort_by_key(|v| (v["class"].as_str().unwrap_or("").to_string(), v["op"].as_str().unwrap_or("").to_string()));
    (g, e60, json!(ops), shared, member)
}

/// e60 of the outer compression by the reference implementation.
fn reference_e60(x: &[u32; N_INPUTS]) -> u32 {
    let mid: [u32; 8] = x[..8].try_into().expect("8 words");
    let mut m = [0u32; 16];
    m[..4].copy_from_slice(&x[8..12]);
    m[4] = 0x8000_0000;
    m[15] = 640;
    // compress_words includes the feed-forward.
    let inner = sha256_core::compress_words(&mid, &m, 64);
    let mut m2 = [0u32; 16];
    m2[..8].copy_from_slice(&inner);
    m2[8] = 0x8000_0000;
    m2[15] = 256;
    sha256_core::compress_words(&IV, &m2, 61)[4].wrapping_sub(IV[4])
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let ks: Vec<u64> = params["batch_sizes"].as_array().map(|a| a.iter().filter_map(Value::as_u64).filter(|&k| k >= 1).collect()).unwrap_or_default();
    anyhow::ensure!(!ks.is_empty(), "batch_sizes must list positive integers");
    let checks = crate::p_u64(params, "check_headers")?;
    let mut rows = Vec::new();
    let mut baseline = None;
    let mut best: Option<(f64, String)> = None;
    for p in &PATTERNS {
        let (g, e60, ops, shared, member) = analyse(p);
        let mut rng = SplitMix64::stream(seed, p.members_differ_in as u64);
        let mismatches = (0..checks)
            .filter(|_| {
                let x: [u32; N_INPUTS] = rng.words();
                g.eval(e60, &x) != reference_e60(&x)
            })
            .count();
        let per_header = |k: u64| ((shared.0 as f64 / k as f64 + member.0 as f64), (shared.1 as f64 / k as f64 + member.1 as f64));
        let base = *baseline.get_or_insert(per_header(1));
        let by_k: Vec<Value> = ks
            .iter()
            .map(|&k| {
                let (prim, rdna) = per_header(k);
                json!({ "k": k, "primitive_ops_per_header": prim, "rdna3_ops_per_header": rdna,
                        "saving_primitive": 1.0 - prim / base.0, "saving_rdna3": 1.0 - rdna / base.1 })
            })
            .collect();
        let feasible = !p.feasibility.starts_with("infeasible");
        let kmax = *ks.iter().max().expect("non-empty");
        let saving = 1.0 - per_header(kmax).1 / base.1;
        if feasible && best.as_ref().is_none_or(|b| saving > b.0) {
            best = Some((saving, p.name.to_string()));
        }
        rows.push(json!({
            "pattern": p.name, "members_differ_in": p.members_differ_in, "feasibility": p.feasibility, "feasible": feasible,
            "shared_ops": { "primitive": shared.0, "rdna3": shared.1 }, "member_ops": { "primitive": member.0, "rdna3": member.1 },
            "ops": ops, "by_batch_size": by_k, "dag_check": { "headers": checks, "e60_mismatches": mismatches },
        }));
    }
    let base = baseline.expect("at least one pattern");
    let (best_saving, best_name) = best.unwrap_or((0.0, "none".into()));
    let k4 = |r: &Value| r["by_batch_size"].as_array().and_then(|a| a.iter().find(|x| x["k"] == 4)).map(|x| x["saving_rdna3"].as_f64().unwrap_or(0.0));
    let line = |r: &Value| format!("{}: shared {} / per-member {} RDNA3 ops{}", r["pattern"].as_str().unwrap_or(""), r["shared_ops"]["rdna3"], r["member_ops"]["rdna3"],
        k4(r).map(|s| format!(", k = 4 saves {:.1}%", 100.0 * s)).unwrap_or_default());
    let mut summary = vec![format!("Per-nonce work of one header with early reject: {:.0} primitive ops, {:.0} RDNA3 ops (exact DAG count, constants folded).", base.0, base.1)];
    summary.extend(rows.iter().map(line));
    summary.push(format!("Best feasible pattern at k = {}: {best_name}, {:.1}% of the per-nonce work saved (RDNA3 weights). Every saving is cost per hash; the number of hashes per block is unchanged.", ks.iter().max().unwrap_or(&1), 100.0 * best_saving));
    let obs = json!({ "baseline_per_header": { "primitive": base.0, "rdna3": base.1 }, "patterns": rows, "best_feasible": { "pattern": best_name, "saving_rdna3_at_max_k": best_saving } });
    let mut o = Outcome::new(obs.clone(), obs, vec![], summary);
    o.result = Some("exact-analysis");
    Ok(o)
}

/// Every pattern's DAG must reproduce the reference e60 on every checked header,
/// and the full-digest DAG must equal the reference header hash.
pub fn verify(_params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
    let mut problems: Vec<String> = outcome.observations["patterns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["dag_check"]["e60_mismatches"] != 0)
        .map(|r| format!("{}: {} e60 mismatches", r["pattern"], r["dag_check"]["e60_mismatches"]))
        .collect();
    let (g, _, full) = header_dag(0, 64);
    let mut rng = SplitMix64::stream(seed ^ 0xf011, 0);
    for _ in 0..64 {
        let nonce = rng.next_u32();
        let mut header = [0u8; 80];
        for (i, b) in header.iter_mut().enumerate() {
            *b = rng.next_u32() as u8 ^ i as u8;
        }
        let hm = bitcoin_header::HeaderMidstate::new(&header);
        let mut inputs = [0u32; N_INPUTS];
        inputs[..8].copy_from_slice(&hm.state);
        inputs[8..11].copy_from_slice(&hm.tail);
        inputs[11] = nonce.swap_bytes();
        let want = hm.hash_words(nonce);
        let got: Vec<u32> = (0..8).map(|i| g.eval(full[i], &inputs).wrapping_add(IV[i])).collect();
        if got != want {
            problems.push(format!("full digest mismatch for nonce {nonce:#x}"));
            break;
        }
    }
    Ok(Verification {
        method: "every pattern's DAG evaluated against the reference SHA-256 e60 on random inputs; the full-digest DAG against bitcoin_header::HeaderMidstate::hash_words on 64 random headers".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "all DAGs match the reference".into() } else { problems.join("; ") },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_rolling_shares_the_inner_schedule() {
        let (_, _, _, shared, member) = analyse(&PATTERNS[0]);
        assert!(shared.0 > 0 && member.0 > shared.0, "shared {shared:?} member {member:?}");
    }
}
