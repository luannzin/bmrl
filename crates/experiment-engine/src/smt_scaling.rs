//! SAT/SMT scaling study: progressively larger reduced-round SHA-256d
//! nonce-search models (rounds r, target bits k), two encodings, adaptive
//! timeouts, solver profiling and bottleneck diagnosis.
//!
//! The question that decides whether a solver could ever matter for mining:
//! does solver cost grow slower in k than brute force (2^k)? Absolute times at
//! small k are dominated by fixed overhead, so the study records both the
//! per-bit growth rate and where (if anywhere) the solver beat brute force in
//! absolute terms. Only the latter counts as evidence.

use crate::smt::{answer_problem, brute, nonce_valid, run_script};
use crate::{Definition, Outcome, Verification, p_u64};
use anyhow::{Context, Result};
use bitcoin_header::HeaderMidstate;
use serde_json::{Value, json};
use statistical_engine::{SplitMix64, linear_fit};
use std::collections::BTreeMap;
use std::time::Instant;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-SMT-02",
        primitive: crate::primitive::HEADER,
        name: "Scaling of SAT/SMT nonce search with rounds and target difficulty",
        // v2: encodings alternate per (r, k) point; v1 spent the whole budget on the first encoding.
        version: 2,
        hypothesis: "For some round count r, the cost of SAT/SMT nonce search on r-round SHA-256d grows more slowly in the target size k than brute force (factor 2 per bit), or beats brute force outright.",
        null_hypothesis: "Solver cost per additional target bit is at least that of brute force, and the solver is never faster in absolute terms.",
        assumptions: &[
            "Same model as H-SMT-01; two encodings: word-level QF_BV and bit-blasted pure SAT.",
            "Adaptive timeout per encoding: 8x its previous solve time at the same r, clamped to [min, max]; a (r, k) point with every instance timing out ends that r for that encoding; an r with no solved k ends the encoding. Encodings alternate at every point so the budget is shared.",
            "Growth rates are least-squares slopes of log2(median solve seconds) vs k over solved points with solve time >= 50 ms (to exclude fixed overhead); extrapolated crossovers are heuristic.",
            "Brute force: single thread, generic reduced-round midstate path.",
            "Solver statistics are Z3's internal counters (sat conflicts, decisions).",
        ],
        baseline: "Single-thread brute force; measured slope of log2(hashes to first hit) vs k (expected 1).",
        methodology: "Grid over encodings x rounds x target bits with several random headers per point, adaptive timeouts and a global time budget. Each solve reports build time, solve time, DAG size, solver counters and (once per r) the bit-blasted CNF size. Timeouts are diagnosed by comparing growth of model size and growth of solve time across r.",
        implementation: &["research/algebraic-models/smt_scaling.py", "research/algebraic-models/smt_reduced_round.py"],
        dataset: "`instances` random headers per point from SplitMix64::stream(seed, instance).",
    }
}

pub fn default_params(quick: bool) -> Value {
    if quick {
        json!({
            "encodings": ["qfbv", "bitblast-sat"], "rounds": [4, 6], "zero_bits": [2, 4, 6],
            "instances": 1, "min_timeout_ms": 2000, "max_timeout_ms": 5000, "budget_seconds": 60,
            "cnf_stats_max_rounds": 6, "reproduce": false,
        })
    } else {
        json!({
            "encodings": ["qfbv", "bitblast-sat"], "rounds": [4, 6, 8, 10, 12, 16], "zero_bits": [2, 4, 6, 8, 10, 12, 14, 16],
            "instances": 3, "min_timeout_ms": 2000, "max_timeout_ms": 30000, "budget_seconds": 900,
            "cnf_stats_max_rounds": 10, "reproduce": false,
        })
    }
}

fn list<T>(params: &Value, key: &str, f: impl Fn(&Value) -> Option<T>) -> Result<Vec<T>> {
    params[key].as_array().with_context(|| format!("{key} must be an array"))?.iter().map(|v| f(v).with_context(|| format!("bad entry in {key}"))).collect()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn sat_conflicts(stats: &Value) -> Option<f64> {
    stats.get("sat conflicts").or_else(|| stats.get("conflicts")).and_then(Value::as_f64)
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let encodings = list(params, "encodings", |v| v.as_str().map(str::to_string))?;
    let rounds = list(params, "rounds", |v| v.as_u64().map(|r| r as usize).filter(|&r| r <= 64))?;
    let ks = list(params, "zero_bits", |v| v.as_u64().map(|k| k as u32).filter(|k| (1..=32).contains(k)))?;
    let instances = p_u64(params, "instances")?;
    let (min_t, max_t) = (p_u64(params, "min_timeout_ms")?, p_u64(params, "max_timeout_ms")?);
    let budget = p_u64(params, "budget_seconds")? as f64;
    let cnf_max = p_u64(params, "cnf_stats_max_rounds")? as usize;
    let Some(z3) = crate::smt::z3_version() else {
        return Ok(Outcome::skipped("python with z3-solver not available (pip install z3-solver)".into()));
    };
    let started = Instant::now();

    // Deterministic brute-force grid (the reproducible part of this experiment).
    let mut brute_grid = BTreeMap::new();
    for &r in &rounds {
        for &k in &ks {
            for i in 0..instances {
                let header: [u8; 80] = SplitMix64::stream(seed, i).bytes();
                let mid = HeaderMidstate::with_rounds(&header, r);
                brute_grid.insert((r, k, i), (brute(&mid, k), header, mid));
            }
        }
    }

    let mut points = Vec::new();
    let mut frontier = Vec::new();
    let mut cnf_by_round: BTreeMap<usize, Value> = BTreeMap::new();
    let mut budget_hit = false;
    // Encodings alternate at every (r, k) point so the time budget is shared
    // fairly (v1 ran them one after another and the budget ran out in the first).
    let mut active: Vec<&String> = encodings.iter().collect();
    'grid: for &r in &rounds {
        // Per encoding at this r: (previous solve time, frontier reached, any k solved).
        let mut state: BTreeMap<&String, (Option<f64>, bool, bool)> = active.iter().map(|e| (*e, (None, false, false))).collect();
        for &k in &ks {
            for &enc in &active {
                let (prev, done, solved_any) = state.get_mut(enc).expect("state per active encoding");
                if *done {
                    continue;
                }
                if started.elapsed().as_secs_f64() > budget {
                    budget_hit = true;
                    break 'grid;
                }
                let timeout = prev.map_or(min_t, |s| ((s * 8000.0) as u64).clamp(min_t, max_t));
                let mut times = Vec::new();
                let mut all_unknown = true;
                for i in 0..instances {
                    let (b, header, mid) = &brute_grid[&(r, k, i)];
                    let want_cnf = r <= cnf_max && !cnf_by_round.contains_key(&r);
                    let inst = json!({
                        "midstate": mid.state, "tail": mid.tail, "rounds": r, "zero_bits": k, "timeout_ms": timeout,
                        "seed": seed.wrapping_add(i), "encoding": enc, "cnf_stats": want_cnf,
                    });
                    let s = run_script("smt_scaling.py", &inst)?;
                    if want_cnf && !s["cnf"].is_null() {
                        cnf_by_round.insert(r, s["cnf"].clone());
                    }
                    let status = s["status"].as_str().unwrap_or("error").to_string();
                    let solve = s["solve_seconds"].as_f64().unwrap_or(f64::NAN);
                    let nonce = s["nonce"].as_u64().map(|n| n as u32);
                    let valid = nonce.map(|n| nonce_valid(header, mid, r, k, n));
                    if status == "sat" {
                        times.push(solve);
                    }
                    all_unknown &= status != "sat" && status != "unsat";
                    points.push(json!({
                        "encoding": enc, "rounds": r, "zero_bits": k, "instance": i, "timeout_ms": timeout,
                        "status": status, "nonce": nonce, "nonce_valid": valid,
                        "build_seconds": s["build_seconds"], "solve_seconds": solve, "dag_nodes": s["dag_nodes"],
                        "sat_conflicts": sat_conflicts(&s["stats"]), "sat_decisions": s["stats"].get("sat decisions"),
                        "memory_mb": s["stats"].get("max memory"), "reason_unknown": s["reason_unknown"],
                        "brute_force": { "nonce": b.nonce, "hashes": b.hashes, "seconds": b.seconds },
                        "solver_faster_than_brute_force": status == "sat" && valid == Some(true) && solve < b.seconds,
                    }));
                }
                if all_unknown {
                    frontier.push(json!({ "encoding": enc, "rounds": r, "zero_bits": k, "timeout_ms": timeout }));
                    *done = true;
                } else {
                    *solved_any = true;
                    *prev = times.iter().copied().reduce(f64::max).or(*prev);
                }
            }
        }
        // An encoding that solved nothing at this r is not tried at larger r.
        active.retain(|e| state[e].2);
        if active.is_empty() {
            break;
        }
    }

    // Growth-rate fits per (encoding, r).
    let mut fits = Vec::new();
    let mut flags = Vec::new();
    for enc in &encodings {
        for &r in &rounds {
            let pts: Vec<&Value> = points.iter().filter(|p| p["encoding"] == enc.as_str() && p["rounds"] == r).collect();
            if pts.is_empty() {
                continue;
            }
            let mut xs = Vec::new();
            let mut ys = Vec::new();
            let mut cx = Vec::new();
            let mut cy = Vec::new();
            for &k in &ks {
                let at: Vec<&&Value> = pts.iter().filter(|p| p["zero_bits"] == k && p["status"] == "sat").collect();
                if at.len() as u64 != instances {
                    continue;
                }
                let t = median(at.iter().filter_map(|p| p["solve_seconds"].as_f64()).collect());
                if t >= 0.05 {
                    xs.push(k as f64);
                    ys.push(t.log2());
                }
                let c: Vec<f64> = at.iter().filter_map(|p| p["sat_conflicts"].as_f64()).collect();
                if c.len() == at.len() && !c.is_empty() {
                    cx.push(k as f64);
                    cy.push(median(c).max(1.0).log2());
                }
            }
            let bx: Vec<f64> = ks.iter().map(|&k| k as f64).collect();
            let by: Vec<f64> = ks.iter().map(|&k| {
                let h: Vec<f64> = (0..instances).map(|i| brute_grid[&(r, k, i)].0.hashes as f64).collect();
                (h.iter().sum::<f64>() / h.len() as f64).log2()
            }).collect();
            let fit = |x: &[f64], y: &[f64]| if x.len() >= 3 { linear_fit(x, y) } else { None };
            let time_fit = fit(&xs, &ys);
            let conflict_fit = fit(&cx, &cy);
            let brute_fit = linear_fit(&bx, &by);
            let beat = pts.iter().any(|p| p["solver_faster_than_brute_force"] == true);
            flags.push((r, beat));
            fits.push(json!({
                "encoding": enc, "rounds": r,
                "time_slope_bits_per_bit": time_fit.map(|f| f.0), "time_slope_se": time_fit.map(|f| f.2), "time_points": xs.len(),
                "conflict_slope_bits_per_bit": conflict_fit.map(|f| f.0), "conflict_points": cx.len(),
                "brute_force_slope": brute_fit.map(|f| f.0),
                "solver_beat_brute_force": beat,
            }));
        }
    }

    // Bottleneck diagnosis from model size vs solve time across r.
    let mut diagnosis = Vec::new();
    for enc in &encodings {
        let solved: Vec<&Value> = points.iter().filter(|p| p["encoding"] == enc.as_str() && p["status"] == "sat" && p["zero_bits"] == ks[0]).collect();
        if let (Some(first), Some(last)) = (solved.first(), solved.last()) {
            let (r0, r1) = (first["rounds"].as_u64().unwrap_or(0) as usize, last["rounds"].as_u64().unwrap_or(0) as usize);
            let size = |r: usize| cnf_by_round.get(&r).and_then(|c| c["clauses"].as_f64());
            let time_growth = last["solve_seconds"].as_f64().unwrap_or(0.0) / first["solve_seconds"].as_f64().unwrap_or(1.0).max(1e-6);
            let size_growth = size(r1).zip(size(r0)).map(|(a, b)| a / b.max(1.0));
            let build_share = points
                .iter()
                .filter(|p| p["encoding"] == enc.as_str() && p["status"] == "unknown")
                .filter_map(|p| Some(p["build_seconds"].as_f64()? / (p["timeout_ms"].as_f64()? / 1000.0)))
                .fold(0.0f64, f64::max);
            let verdict = if build_share > 0.5 {
                "model construction dominates: encoding/front-end is the bottleneck"
            } else if size_growth.is_some_and(|g| time_growth > 4.0 * g) {
                "solve time grows much faster than model size: search hardness, not encoding size, is the bottleneck"
            } else {
                "insufficient contrast between size and time growth to attribute the bottleneck"
            };
            diagnosis.push(json!({
                "encoding": enc, "from_rounds": r0, "to_rounds": r1, "zero_bits": ks[0],
                "solve_time_growth": time_growth, "cnf_clause_growth": size_growth, "max_build_share_of_timeout": build_share,
                "verdict": verdict,
            }));
        }
    }

    let mut summary = vec![format!(
        "{} solver runs over encodings {encodings:?}; frontier (first point where every instance timed out): {}.",
        points.len(),
        if frontier.is_empty() { "none reached".to_string() } else { frontier.iter().map(|f| format!("{} r={} k={}", f["encoding"].as_str().unwrap_or(""), f["rounds"], f["zero_bits"])).collect::<Vec<_>>().join(", ") }
    )];
    for f in &fits {
        if let Some(s) = f["time_slope_bits_per_bit"].as_f64() {
            summary.push(format!(
                "{} r={}: solve time grows 2^{s:.2} per target bit (se {:.2}, {} points) vs brute force 2^{:.2}.",
                f["encoding"].as_str().unwrap_or(""), f["rounds"], f["time_slope_se"].as_f64().unwrap_or(f64::NAN), f["time_points"], f["brute_force_slope"].as_f64().unwrap_or(f64::NAN)
            ));
        }
    }
    for d in &diagnosis {
        summary.push(format!("{}: {}.", d["encoding"].as_str().unwrap_or(""), d["verdict"].as_str().unwrap_or("")));
    }
    if budget_hit {
        summary.push(format!("Time budget of {budget} s exhausted; grid incomplete."));
    }
    let det: Vec<Value> = brute_grid.iter().map(|((r, k, i), (b, _, _))| json!([r, k, i, b.nonce, b.hashes])).collect();
    Ok(Outcome::new(
        json!({ "points": points, "fits": fits, "frontier": frontier, "cnf_size_by_rounds": cnf_by_round, "diagnosis": diagnosis, "budget_exhausted": budget_hit, "z3_version": z3 }),
        json!(det),
        flags,
        summary,
    ))
}

pub fn verify(_: &Value, _: u64, outcome: &Outcome) -> Result<Verification> {
    let problems: Vec<String> = outcome.observations["points"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let problem = answer_problem(&p["status"], &p["nonce_valid"], &p["brute_force"]["nonce"])?;
            Some(format!("{} r{} k{} i{}: {problem}", p["encoding"].as_str().unwrap_or(""), p["rounds"], p["zero_bits"], p["instance"]))
        })
        .collect();
    Ok(Verification {
        method: "every solver nonce recomputed with sha256-core (midstate) and verification::independent (full header); unsat answers checked against brute force".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { format!("{} points consistent", outcome.observations["points"].as_array().map_or(0, Vec::len)) } else { problems.join("; ") },
    })
}
