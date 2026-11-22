//! Breakthrough research board and hypothesis evolution.
//!
//! The board joins two things. The curated part, written once per entry and
//! reviewed like code: the hypothesis, its mathematical basis, the structure
//! family it belongs to and which experiment kinds test it (or, for
//! analytical entries, the exact derivation). The derived part, recomputed
//! from the registry on every build and never hand-edited: current evidence,
//! counterexamples, rounds covered, the measured work factor at 64 rounds,
//! verification status, computational cost and the next experiment.
//!
//! The next experiment comes from [`proposals`], a small rule set over the
//! records: extend a reduced-round frontier, replicate single-seed results,
//! escalate any full-round candidate, re-measure what a model could not
//! confirm, retry solver timeouts with a larger budget, and design an
//! experiment for structure families nothing has tested. Proposals that
//! repeat an existing record (same kind, seed and parameters) are dropped,
//! and executable ones carry the exact command, so `bmr research evolve
//! --run N` closes the loop.

use crate::{DEFAULT_SEED, FULL_ROUNDS, Kind, merge_params};
use anyhow::Result;
use research_storage::Store;
use serde_json::{Value, json};

pub struct Entry {
    pub id: &'static str,
    pub family: &'static str,
    pub title: &'static str,
    pub hypothesis: &'static str,
    pub basis: &'static str,
    /// Experiment kinds whose records are this entry's evidence.
    pub kinds: &'static [&'static str],
    /// Exact derivation, for entries settled (or argued) analytically.
    pub derivation: Option<&'static str>,
    /// Speculative model: never experimental evidence.
    pub speculative: bool,
    /// For untested families: what a first experiment would measure.
    pub design: Option<&'static str>,
}

pub const ENTRIES: &[Entry] = &[
    Entry {
        id: "B-01", family: "statistical bias", title: "Output bias of full-round header SHA256d",
        hypothesis: "Some output bit, word or leading-zero count of SHA256d(header) is biased over the nonce, so the target event has probability other than 2^-k per evaluation.",
        basis: "A relative bias e in the event 'k leading zero bits' changes the expected work per block by 1/(1 + e). Sampling tests bound e directly; the exhaustive atlas counts the event over every nonce of each template.",
        kinds: &["statistical", "multiseed", "nonce-atlas", "header-atlas"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-02", family: "random-function structure", title: "Per-template nonce map versus a random function",
        hypothesis: "For a fixed template, nonce -> top hash word is not a random function: its image size, preimages of 0 or cube sums depart from the exact random-function moments.",
        basis: "A permutation-like map (image 2^32) would put a 32-bit share in every template; a collapsing one would remove shares. n balls in 2^32 bins give exact moments (image (1 - 1/e) 2^32, sd 20,433). At 4 rounds the map is a bijection, the positive control.",
        kinds: &["nonce-atlas"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-03", family: "input selection / conditional probability", title: "Selecting nonces without hashing them",
        hypothesis: "A class of nonces chosen without evaluating SHA256d (fixed bits, linear half-spaces, byte values, Hamming weight, trail conditions) meets the target more often than the rest.",
        basis: "Each candidate still costs one SHA256d, so a class with held-out amplification A needs 1/A of the exhaustive work per hit. The atlas scores every linear half-space over two 24-bit projections (2^25 masks) and 3k class strategies over every nonce, then re-measures each family's winner on held-out templates.",
        kinds: &["nonce-atlas", "trail-search", "evolved-rules"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-04", family: "differential (output level)", title: "Neighbours of hits",
        hypothesis: "Given a hit x, some neighbour x ^ D or x + d (or a group of them) is a hit more often than 2^-k.",
        basis: "A neighbour relation with conditional hit probability A 2^-k costs 1/A of the exhaustive work per neighbour evaluated. The atlas counts hit pairs for 1,552 low-weight differences and their groups and scans all 2^32 - 1 XOR and 2^31 modular differences among higher hits; trail-search measures share-to-target neighbours.",
        kinds: &["nonce-atlas", "trail-search"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-05", family: "differential (internal)", title: "XOR characteristics through the compression",
        hypothesis: "A message-difference characteristic survives enough rounds of the compression to bias output differences.",
        basis: "Signed-difference cost model: one MSB difference costs exactly 11 bit conditions per round after entry (measured 2^-11.010, 83.9M pairs, five seeds, independent code). Costs add up per round under the Markov assumption, which is measured where the probability allows.",
        kinds: &["differential", "characteristic", "characteristic-audit"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-06", family: "differential (solver search)", title: "Solver-optimal characteristics from miner-controlled words",
        hypothesis: "A SAT-optimal characteristic over every difference in the nonce (or the nonce and time) follows the second header block past round 5 with probability >= 2^-32.",
        basis: "z3 minimises the weight over all differences in W3 (or W1, W3) in a signed carry-free model with cancellations and free Ch/Maj choices, round count by round count; every returned round is measured on real transitions. One template offers 2^31 pairs per difference, so weight > 32 leaves no conforming pair per template. W0 is excluded: under one midstate it cannot differ without a 224-bit merkle-root collision.",
        kinds: &["trail-sat"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-07", family: "algebraic degree / cube sums", title: "Low degree in the nonce variables",
        hypothesis: "Output bits have low algebraic degree in the nonce bits, giving zero-sums or cube-attack shortcuts.",
        basis: "Degree < k in k cube variables makes the cube sum zero. The atlas computes every aligned low-bit sub-cube sum of dimension 8..32 and the 31-dimensional halves exactly, per output bit at dimension 8; algebraic gives proven degree bounds.",
        kinds: &["algebraic", "nonce-atlas"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-08", family: "message-schedule relations", title: "Schedule structure",
        hypothesis: "Linear or statistical relations in W16..W63 reduce the work of evaluating related headers.",
        basis: "Exact GF(2) rank of the linearized schedule (512 for every 16-word window), lightest expansions of a 1-bit difference (466 bits), agreement of the real and linearized schedules.",
        kinds: &["schedule"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-09", family: "solver inversion (SAT/SMT)", title: "Solving the target condition",
        hypothesis: "A bit-vector solver finds a nonce meeting the target faster than brute force.",
        basis: "QF_BV model of the reduced-round header with the nonce symbolic; time to a verified nonce against single-core brute force for the same target.",
        kinds: &["smt", "smt-scaling"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-10", family: "reduced-round exact structure", title: "Exact structure at 4 and 5 rounds",
        hypothesis: "The exact reduced-round structure (affine H7 at 4 rounds, a two-layer H7 at 5) becomes a strategy that still works at more rounds.",
        basis: "Proved for all templates by z3: H7_4 = K + bswap(n); H7_5 = K + bswap(n) + S1(X) + Ch(X, IV4, IV5), X = C + mid0 + A5(n), A5 one inner round of n. Since IV4 is odd and IV5 even, bit 0 of H7_5 is c ^ X0 ^ X6 ^ X11 ^ X25: low degree in the nonce's low byte, seen as the H7 bit 0 and 1 cube deficiency at 5 rounds.",
        kinds: &["nonce-atlas", "trail-sat"], derivation: None, speculative: false, design: None,
    },
    Entry {
        id: "B-11", family: "partial evaluation / early abort", title: "Deciding the target before the last rounds",
        hypothesis: "The target bits can be predicted from a state earlier than outer round 60.",
        basis: "Register shift: H7 = IV7 + e60 and H6 = IV6 + e61 after the outer compression, and e60 = d59 + T1_59 needs the whole state entering round 60.",
        kinds: &["hardware"],
        derivation: Some("Exact: the 32 most significant bits of the hash number are first available after outer round 60. The CPU kernel and the hardware datapaths already stop there. That saves at most 3 of 125 rounds (2.4%) per hash and never changes the number of hashes."),
        speculative: false, design: None,
    },
    Entry {
        id: "B-12", family: "header construction", title: "Generic SHA256d versus Bitcoin's header",
        hypothesis: "Bitcoin's fixed header fields create structure that generic SHA256d lacks and that lowers the number of evaluations.",
        basis: "Fixed per template: the midstate, W2 (bits) and W4..W15 (padding) of block 2, and W8..W15 of the outer block. The nonce enters only at round 3 (as bswap(nonce)), the time at round 1, the merkle tail at round 0; version rolling changes the midstate.",
        kinds: &["nonce-atlas", "hardware"],
        derivation: Some("Exact: every consequence of the fixed fields (midstate, 3 precomputed rounds, W16 and W17 constant, early reject) lowers cost per hash only. The header encoding is injective, so distinct (template, extranonce, time, version, nonce) never repeat work; equal outcomes need an inner-digest collision (about 2^-256 per pair)."),
        speculative: false, design: None,
    },
    Entry {
        id: "B-13", family: "quantum search", title: "Grover search with a reversible SHA256d oracle",
        hypothesis: "Grover search needs fewer oracle queries than classical evaluations and finishes within the block interval on a feasible number of machines.",
        basis: "Grover needs (pi/4) sqrt(2^d) iterations; P machines need (pi/4) sqrt(2^d / P) each. Meeting a 600 s deadline forces P ~ 2^d (pi t_iter / 4T)^2, so total queries grow back toward linear in 2^d.",
        kinds: &["quantum-model", "grover-circuit"], derivation: None, speculative: true, design: None,
    },
    Entry {
        id: "B-14", family: "reversible / specialized circuits", title: "Energy per hash, not hashes per block",
        hypothesis: "Reversible or specialized circuits reduce the cost of mining enough to matter.",
        basis: "Landauer's bound and exact datapath counts give energy per hash; any circuit, however efficient, still evaluates every candidate.",
        kinds: &["hardware", "quantum-model"], derivation: None, speculative: true, design: None,
    },
    Entry {
        id: "B-15", family: "meet-in-the-middle / backward search", title: "Splitting the computation",
        hypothesis: "A meet-in-the-middle or backward computation from the target state reduces the search.",
        basis: "MITM preimage attacks on reduced SHA-256 need message words that influence only one chunk. Here the outer block's message is the inner digest (eight pseudo-random words the miner does not choose) and block 2's free words W1 (time) and W3 (nonce) both enter in the first four rounds (W0 is tied to block 1 through the merkle root).",
        kinds: &[],
        derivation: Some("Argued, not tested: no chunk separation exists in either compression, so no MITM split is available to the miner."),
        speculative: false,
        design: Some("Probabilistic neutral bits: for r rounds of block 2, find nonce bits whose flip leaves the round-r state unchanged in a chosen bit set with probability well above 1/2; a backward chunk needs such bits."),
    },
    Entry {
        id: "B-16", family: "message reuse across templates", title: "AsicBoost-type schedule sharing",
        hypothesis: "Reusing work across templates (shared second-block schedules) lowers the number of evaluations.",
        basis: "Merkle roots whose last four bytes collide (covert) or BIP320 version rolling (overt) give several midstates one shared second-block message, so the schedule is computed once for all of them. work-sharing counts every batching pattern exactly; bmr benchmark gpu measures kernel v3.",
        kinds: &["work-sharing"],
        derivation: Some("Exact: the sharing removes schedule work (cost per hash); every midstate still needs its own compression per nonce, so the number of evaluations is unchanged."),
        speculative: false, design: None,
    },
    Entry {
        id: "B-17", family: "learned and combined distinguishers", title: "Boomerang, differential-linear and learned distinguishers",
        hypothesis: "A combined (boomerang, differential-linear) or machine-learned distinguisher reaches more rounds of the header function than single characteristics.",
        basis: "These combine short characteristics; they distinguish reduced-round SHA-256 compression from random but need chosen pairs or quartets, not single inputs.",
        kinds: &["evolved-rules"], derivation: None, speculative: false,
        design: Some("Differential-linear: for the nonce MSB difference (2^-11 per round) and each output bit of H7 at 6-8 rounds, measure the correlation of the output difference over 2^30 pairs; then ask whether any correlation changes single-input hit rates (the atlas's linear family is the single-input test)."),
    },
    Entry {
        id: "B-18", family: "template choice", title: "Lucky templates",
        hypothesis: "Some block templates (merkle root, version: free for the miner) hit the target more often over their whole nonce space, persistently, so choosing templates raises the hit rate per hash.",
        basis: "The miner can produce new templates for one SHA-256 of the coinbase. If the hit rate varied between templates and the variation persisted from even to odd nonces, the top templates would carry an amplification A at no hashing cost. template-luck scans every nonce of thousands of templates on the GPU and bounds the template-to-template spread.",
        kinds: &["template-luck"], derivation: None, speculative: false, design: None,
    },
];

fn latest<'a>(recs: &'a [Value], kind: &str) -> Option<&'a Value> {
    recs.iter().rev().find(|r| r["kind"] == kind && r["status"] == "completed")
}

/// Work factor at 64 rounds, where an experiment measures one.
fn work_at_full_rounds(rec: &Value) -> Option<Value> {
    match rec["kind"].as_str()? {
        "nonce-atlas" => {
            let c = rec["observations"]["configurations"].as_array()?.iter().find(|c| c["rounds"] == FULL_ROUNDS)?;
            let fams: Vec<Value> = ["subspace", "byte", "weight", "neighbour", "linear"]
                .iter()
                .filter_map(|f| {
                    let h = &c["strategies"][*f]["best_usable"]["held_out"];
                    let a = h["A"].as_f64()?;
                    // A reduction needs the held-out interval above 1 (linear has a z instead of an interval).
                    let reduces = h["ci95"][0].as_f64().map_or(h["z"].as_f64().is_some_and(|z| z > statistical_engine::Z95), |lo| lo > 1.0);
                    Some(json!({ "family": f, "strategy": c["strategies"][*f]["best_usable"]["strategy"], "held_out_amplification": a,
                                 "held_out_amplification_ci95": h["ci95"], "held_out_z": h["z"], "work_factor": (a > 0.0).then(|| 1.0 / a), "significant_reduction": reduces }))
                })
                .collect();
            Some(json!({ "measure": "held-out work per hit of each family's best discovery strategy (1 = exhaustive)", "families": fams }))
        }
        "trail-search" => {
            let o = rec["observations"]["target_search"].as_array()?.iter().find(|o| o["rounds"] == FULL_ROUNDS)?;
            Some(json!({ "measure": "neighbour strategy work per target hit over exhaustive", "value": o["expected_work_per_target_hit"]["neighbour_over_exhaustive"] }))
        }
        _ => None,
    }
}

fn rounds_of(rec: &Value) -> (Vec<u64>, Vec<u64>) {
    let mut tested: Vec<u64> = Vec::new();
    let mut deviating: Vec<u64> = Vec::new();
    for c in rec["configurations"].as_array().into_iter().flatten() {
        if let Some(r) = c["rounds"].as_u64() {
            tested.push(r);
            if c["deviation_detected"] == true {
                deviating.push(r);
            }
        }
    }
    for v in [&mut tested, &mut deviating] {
        v.sort_unstable();
        v.dedup();
    }
    (tested, deviating)
}

/// Rule-based next experiments for one entry (see the module documentation).
pub fn proposals(store: &Store, recs: &[Value], e: &Entry) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    let done = |kind: &str, params: &Value, seed: u64| recs.iter().any(|r| r["kind"] == kind && r["seed"] == seed && &r["params"] == params);
    let mut push = |kind: &str, base: &Value, over: Value, seed: u64, rule: &str, why: String, priority: f64, cost: f64| {
        let params = merge_params(base.clone(), &over);
        if done(kind, &params, seed) {
            return;
        }
        let command = format!("bmr research {kind} --seed {seed} --params '{}'", serde_json::to_string(&over).unwrap_or_default());
        out.push(json!({ "entry": e.id, "rule": rule, "kind": kind, "seed": seed, "overrides": over, "executable": true, "command": command,
                         "rationale": why, "priority": priority / (cost + 10.0).log10(), "estimated_seconds": cost }));
    };
    for &kind in e.kinds {
        let Some(rec) = latest(recs, kind) else {
            if let Some(k) = Kind::parse(kind) {
                push(kind, &k.default_params(false), json!({}), DEFAULT_SEED, "missing", format!("no completed {kind} record"), 50.0, 60.0);
            }
            continue;
        };
        let base = rec["params"].clone();
        let seed = rec["seed"].as_u64().unwrap_or(DEFAULT_SEED);
        let cost = rec["duration_seconds"].as_f64().unwrap_or(60.0);
        if rec["candidate_anomaly"] == true {
            push(kind, &base, json!({}), seed ^ 0x5eed_0002, "escalate", format!("{} is a full-round candidate: rerun on a new seed, then an external implementation", rec["id"]), 100.0, cost);
        }
        // Frontier: rounds strictly between the last deviating and the first clean count.
        let (tested, deviating) = rounds_of(rec);
        if let Some(&d) = deviating.iter().filter(|&&r| r < FULL_ROUNDS as u64).max()
            && base["rounds"].is_array()
            && let Some(&c) = tested.iter().find(|&&r| r > d && !deviating.contains(&r))
        {
            let gap: Vec<u64> = (d + 1..c).take(4).collect();
            if !gap.is_empty() {
                push(kind, &base, json!({ "rounds": gap }), seed, "frontier", format!("{}: last deviation at {d} rounds, first clean at {c}; the rounds between are untested", rec["id"]), 30.0, cost * gap.len() as f64 / tested.len().max(1) as f64);
            }
        }
        // Replication: a hypothesis whose evidence rests on one seed.
        let hid = rec["hypothesis_id"].as_str().unwrap_or("");
        let seeds: std::collections::BTreeSet<String> = store.hypothesis_evidence(hid)?.iter().filter_map(|v| v["seed"].as_str().map(String::from)).collect();
        if seeds.len() < 2 && rec["result"] != "model-estimate" {
            push(kind, &base, json!({}), seed ^ 0x5eed_0002, "replicate", format!("{hid} rests on {} seed(s)", seeds.len()), 10.0, cost);
        }
        // Model gaps and solver budgets (trail-sat).
        if kind == "trail-sat" {
            let gaps = rec["counterexamples"].as_array().map_or(0, Vec::len);
            if gaps > 0 {
                let m = base["round_samples_max_log2"].as_u64().unwrap_or(33) + 3;
                push(kind, &base, json!({ "round_samples_max_log2": m }), seed, "model-gap", format!("{gaps} round(s) of solver characteristics had no measured follower"), 20.0, cost * 8.0);
            }
            let timed_out = rec["observations"]["characteristics"].as_array().into_iter().flatten().any(|s| s["characteristics"].as_array().into_iter().flatten().any(|c| c["status"] == "timeout"));
            if timed_out {
                let (t, b) = (base["timeout_ms"].as_u64().unwrap_or(600_000) * 4, base["budget_ms"].as_u64().unwrap_or(2_400_000) * 4);
                push(kind, &base, json!({ "timeout_ms": t, "budget_ms": b }), seed, "solver-budget", "the weight bound search timed out; the optimum beyond is unknown".into(), 15.0, cost * 4.0);
            }
        }
    }
    if let Some(d) = e.design {
        let why = if e.kinds.is_empty() { "no experiment tests this family yet" } else { "this part of the family is not tested yet" };
        out.push(json!({ "entry": e.id, "rule": "unexplored", "executable": false, "rationale": format!("{}: {why}", e.family), "design": d, "priority": 25.0 }));
    }
    out.sort_by(|a, b| b["priority"].as_f64().unwrap_or(0.0).total_cmp(&a["priority"].as_f64().unwrap_or(0.0)));
    Ok(out)
}

fn verification_status(recs: &[&Value], seeds: usize, e: &Entry) -> String {
    if e.speculative {
        return "speculative model (not evidence)".into();
    }
    if recs.is_empty() {
        return if e.derivation.is_some() { "analytical".into() } else { "untested".into() };
    }
    if recs.iter().any(|r| r["verification"]["passed"] != true) {
        return "FAILED verification".into();
    }
    if recs.iter().any(|r| r["candidate_anomaly"] == true) {
        return "candidate anomaly, unconfirmed".into();
    }
    let reproduced = recs.iter().all(|r| r["reproduction"]["matched"] != false);
    format!("verified{}, {seeds} run seed(s)", if reproduced { ", reproduced" } else { ", NOT reproduced" })
}

/// Build the board from the registry.
pub fn build(store: &Store) -> Result<Value> {
    let recs = store.all_experiments()?;
    let mut entries = Vec::new();
    for e in ENTRIES {
        let current: Vec<&Value> = e.kinds.iter().filter_map(|k| latest(&recs, k)).collect();
        let mut seeds = std::collections::BTreeSet::new();
        let mut cost = 0.0;
        for k in e.kinds {
            for r in recs.iter().filter(|r| r["kind"] == *k) {
                cost += r["duration_seconds"].as_f64().unwrap_or(0.0);
            }
        }
        for r in &current {
            for ev in store.hypothesis_evidence(r["hypothesis_id"].as_str().unwrap_or(""))? {
                if let Some(s) = ev["seed"].as_str() {
                    seeds.insert(s.to_string());
                }
            }
        }
        let evidence: Vec<Value> = current
            .iter()
            .map(|r| {
                let (tested, deviating) = rounds_of(r);
                json!({
                    "id": r["id"], "kind": r["kind"], "result": r["result"], "hypothesis_status": r["hypothesis_status"],
                    "conclusion": r["conclusion"], "rounds_tested": tested, "rounds_with_deviation": deviating,
                    "counterexamples": r["counterexamples"].as_array().map_or(0, Vec::len),
                    "counterexample_sample": r["counterexamples"].as_array().map(|c| c.iter().take(3).cloned().collect::<Vec<_>>()),
                    "work_at_64_rounds": work_at_full_rounds(r),
                })
            })
            .collect();
        let props = proposals(store, &recs, e)?;
        entries.push(json!({
            "id": e.id, "family": e.family, "title": e.title, "hypothesis": e.hypothesis, "basis": e.basis,
            "experiments": e.kinds, "derivation": e.derivation, "speculative": e.speculative,
            "evidence": evidence, "verification": verification_status(&current, seeds.len(), e),
            "cost_seconds": cost, "next": props,
        }));
    }
    Ok(json!({ "generated_at": research_storage::now_iso(), "records": recs.len(), "entries": entries }))
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Every proposal across the board, best first; one entry per command
/// (several entries can propose the same run).
pub fn queue(board: &Value) -> Vec<Value> {
    let mut q: Vec<Value> = board["entries"].as_array().into_iter().flatten().flat_map(|e| e["next"].as_array().cloned().unwrap_or_default()).collect();
    q.sort_by(|a, b| b["priority"].as_f64().unwrap_or(0.0).total_cmp(&a["priority"].as_f64().unwrap_or(0.0)));
    let mut seen = std::collections::HashSet::new();
    q.retain(|p| seen.insert(p["command"].as_str().or(p["design"].as_str()).unwrap_or("").to_string()));
    q
}

/// Markdown rendering of the board.
pub fn render(board: &Value) -> String {
    let mut s = String::from("# Breakthrough research board\n\n");
    s.push_str(&format!(
        "Generated by `bmr research board` from {} experiment records at {}. Curated text (hypothesis, basis, derivation) lives in `crates/experiment-engine/src/board.rs`; everything else is recomputed from the registry. Do not edit this file by hand.\n\n",
        board["records"], board["generated_at"].as_str().unwrap_or("")
    ));
    s.push_str("A result is never called a mining shortcut because of reduced-round structure, statistical deviation or throughput: only a held-out work factor below 1 at 64 rounds, reproduced, would be one.\n\n");
    s.push_str("| ID | Family | Rounds covered | Work at 64 rounds | Verification | Next |\n| --- | --- | --- | --- | --- | --- |\n");
    for e in board["entries"].as_array().into_iter().flatten() {
        let mut rounds: Vec<u64> = e["evidence"].as_array().into_iter().flatten().flat_map(|v| v["rounds_tested"].as_array().cloned().unwrap_or_default()).filter_map(|r| r.as_u64()).collect();
        rounds.sort_unstable();
        rounds.dedup();
        // Only a held-out interval above A = 1 counts as a reduction; point estimates never do.
        let work = e["evidence"].as_array().into_iter().flatten().find_map(|v| {
            let w = &v["work_at_64_rounds"];
            if let Some(f) = w["families"].as_array() {
                let sig: Vec<&str> = f.iter().filter(|x| x["significant_reduction"] == true).filter_map(|x| x["family"].as_str()).collect();
                Some(if sig.is_empty() { "none: every held-out CI includes A = 1".into() } else { format!("CANDIDATE: {}", sig.join(", ")) })
            } else {
                w["value"].as_f64().map(|x| format!("neighbour strategy {x:.4}x exhaustive"))
            }
        });
        let next = e["next"].as_array().and_then(|n| n.first()).map_or("-".to_string(), |n| format!("{}: {}", n["rule"].as_str().unwrap_or(""), n["rationale"].as_str().unwrap_or("")));
        let rounds = if rounds.is_empty() { "-".to_string() } else { format!("{rounds:?}") };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            e["id"].as_str().unwrap_or(""), cell(e["family"].as_str().unwrap_or("")), rounds,
            work.unwrap_or_else(|| if e["derivation"].is_string() { "exact: none".into() } else { "n/a".into() }),
            cell(e["verification"].as_str().unwrap_or("")), cell(&next),
        ));
    }
    for e in board["entries"].as_array().into_iter().flatten() {
        s.push_str(&format!("\n## {} {}\n\n", e["id"].as_str().unwrap_or(""), e["title"].as_str().unwrap_or("")));
        s.push_str(&format!("- **Family:** {}{}\n", e["family"].as_str().unwrap_or(""), if e["speculative"] == true { " (speculative model, kept apart from experimental evidence)" } else { "" }));
        s.push_str(&format!("- **Hypothesis:** {}\n", e["hypothesis"].as_str().unwrap_or("")));
        s.push_str(&format!("- **Mathematical basis:** {}\n", e["basis"].as_str().unwrap_or("")));
        if let Some(d) = e["derivation"].as_str() {
            s.push_str(&format!("- **Derivation:** {d}\n"));
        }
        let kinds: Vec<String> = e["experiments"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(|k| format!("`bmr research {k}`"))).collect();
        s.push_str(&format!("- **Experiment:** {}\n", if kinds.is_empty() { "none yet".into() } else { kinds.join(", ") }));
        s.push_str("- **Current evidence:**\n");
        let ev = e["evidence"].as_array().cloned().unwrap_or_default();
        if ev.is_empty() {
            s.push_str("  - none\n");
        }
        for v in &ev {
            s.push_str(&format!("  - `{}` ({}): {}\n", v["id"].as_str().unwrap_or(""), v["result"].as_str().unwrap_or(""), cell(v["conclusion"].as_str().unwrap_or(""))));
        }
        let cx: u64 = ev.iter().filter_map(|v| v["counterexamples"].as_u64()).sum();
        s.push_str(&format!("- **Counterexamples / witnesses:** {cx}{}\n", ev.iter().find_map(|v| v["counterexample_sample"].as_array().filter(|a| !a.is_empty()).map(|a| format!(", e.g. `{}`", serde_json::to_string(&a[0]).unwrap_or_default()))).unwrap_or_default()));
        let rounds: Vec<String> = ev.iter().map(|v| format!("{} tested {} deviating {}", v["id"].as_str().unwrap_or(""), v["rounds_tested"], v["rounds_with_deviation"])).collect();
        s.push_str(&format!("- **Rounds covered:** {}\n", if rounds.is_empty() { "-".into() } else { rounds.join("; ") }));
        let works: Vec<String> = ev
            .iter()
            .filter_map(|v| {
                let w = &v["work_at_64_rounds"];
                if let Some(f) = w["families"].as_array() {
                    let parts: Vec<String> = f
                        .iter()
                        .map(|x| {
                            let ci = x["held_out_amplification_ci95"].as_array().map_or_else(
                                || format!("z {:.2}", x["held_out_z"].as_f64().unwrap_or(f64::NAN)),
                                |c| format!("95% CI {:.3}..{:.3}", c[0].as_f64().unwrap_or(f64::NAN), c[1].as_f64().unwrap_or(f64::NAN)),
                            );
                            format!("{} `{}`: held-out A {:.4} ({ci})", x["family"].as_str().unwrap_or(""), x["strategy"].as_str().unwrap_or(""), x["held_out_amplification"].as_f64().unwrap_or(f64::NAN))
                        })
                        .collect();
                    Some(format!("{} at 64 rounds, work per hit = 1/A: {}", v["id"].as_str().unwrap_or(""), parts.join("; ")))
                } else {
                    w["value"].as_f64().map(|x| format!("{} at 64 rounds: neighbour strategy {x:.4}x the exhaustive work", v["id"].as_str().unwrap_or("")))
                }
            })
            .collect();
        s.push_str(&format!("- **Expected work reduction:** {}\n", if works.is_empty() { "none claimed".into() } else { works.join("; ") }));
        s.push_str(&format!("- **Verification status:** {}\n", e["verification"].as_str().unwrap_or("")));
        s.push_str(&format!("- **Cost so far:** {:.0} s of experiment time\n", e["cost_seconds"].as_f64().unwrap_or(0.0)));
        let next: Vec<String> = e["next"].as_array().into_iter().flatten().take(3).map(|n| match n["command"].as_str() {
            Some(c) => format!("{} ({}): `{c}`", n["rationale"].as_str().unwrap_or(""), n["rule"].as_str().unwrap_or("")),
            None => format!("{} ({}): {}", n["rationale"].as_str().unwrap_or(""), n["rule"].as_str().unwrap_or(""), n["design"].as_str().unwrap_or("")),
        }).collect();
        s.push_str(&format!("- **Next experiment:** {}\n", if next.is_empty() { "none proposed".into() } else { next.join("; ") }));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_have_unique_ids_and_known_kinds() {
        let mut ids: Vec<&str> = ENTRIES.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ENTRIES.len());
        for e in ENTRIES {
            assert!(e.kinds.iter().all(|k| Kind::parse(k).is_some()), "{}: unknown kind", e.id);
            assert!(!e.kinds.is_empty() || e.derivation.is_some() || e.design.is_some(), "{}: no evidence source", e.id);
        }
    }

    #[test]
    fn work_column_ignores_point_estimates_inside_the_interval() {
        let rec = |ci: Value, z: f64| {
            json!({ "kind": "nonce-atlas", "id": "nonce-atlas-0009", "observations": { "configurations": [{ "rounds": 64, "strategies": {
                "neighbour": { "best_usable": { "strategy": "x ^ 0x22", "held_out": { "A": 1.2, "ci95": ci } } },
                "linear": { "best_usable": { "strategy": "parity", "held_out": { "A": 1.001, "z": z } } } } }] } })
        };
        let board = |r: Value| json!({ "records": 1, "generated_at": "t", "entries": [{ "id": "B-X", "family": "f", "title": "t", "verification": "v", "next": [],
            "evidence": [{ "id": "nonce-atlas-0009", "rounds_tested": [64], "work_at_64_rounds": work_at_full_rounds(&r) }] }] });
        // A point estimate of 1.2 (work 0.83) whose interval includes 1 is not a reduction.
        assert!(render(&board(rec(json!([0.55, 2.62]), 0.3))).contains("| none: every held-out CI includes A = 1 |"));
        assert!(render(&board(rec(json!([1.05, 1.4]), 0.3))).contains("CANDIDATE: neighbour"));
        assert!(render(&board(rec(json!([0.55, 2.62]), 2.5))).contains("CANDIDATE: linear"));
    }

    #[test]
    fn proposals_extend_frontiers_and_skip_existing_runs() {
        let dir = std::env::temp_dir().join(format!("bmrl-board-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let params = json!({ "rounds": [4, 8, 64] });
        let rec = json!({
            "id": "nonce-atlas-0001", "kind": "nonce-atlas", "status": "completed", "seed": DEFAULT_SEED, "params": params, "hypothesis_id": "H-X",
            "duration_seconds": 100.0, "result": "reduced-round-only",
            "configurations": [{ "rounds": 4, "deviation_detected": true }, { "rounds": 8, "deviation_detected": false }, { "rounds": 64, "deviation_detected": false }],
        });
        let e = &ENTRIES[1];
        let p = proposals(&store, std::slice::from_ref(&rec), e).unwrap();
        let frontier = p.iter().find(|x| x["rule"] == "frontier").expect("frontier proposal");
        assert_eq!(frontier["overrides"]["rounds"], json!([5, 6, 7]));
        assert!(p.iter().any(|x| x["rule"] == "replicate"));
        // Once the frontier run exists (an older record with those parameters), it is not proposed again.
        let mut done = rec.clone();
        done["params"] = json!({ "rounds": [5, 6, 7] });
        done["id"] = json!("nonce-atlas-0000");
        let p2 = proposals(&store, &[done, rec], e).unwrap();
        assert!(p2.iter().all(|x| x["rule"] != "frontier"));
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
