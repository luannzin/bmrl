//! Experiment framework.
//!
//! An experiment kind supplies a fixed [`Definition`] (hypothesis,
//! assumptions, baseline, methodology), default parameters, a deterministic
//! `execute` and an independent `verify`. The framework adds everything the
//! research standard requires and the kinds must not be able to skip:
//!
//! * the record is persisted *before* execution, so crashes leave a trace;
//! * environment, source fingerprint, seed and parameters are stored;
//! * in-process reproduction reruns the experiment with a different thread
//!   count and compares a SHA-256 digest of the deterministic results;
//! * independent verification recomputes a subset with a second SHA-256
//!   implementation (`verification::independent`);
//! * a deviation at full 64 rounds is never reported directly: it is rerun
//!   with a fresh seed and only a replicated deviation becomes a
//!   `candidate-anomaly` (still not a discovery: it requires external review);
//! * classification and conclusion are derived from data, never hand-written.

pub mod algebraic;
pub mod characteristic;
pub mod characteristic_audit;
pub mod differential;
pub mod env;
pub mod hardware;
pub mod multiseed;
pub mod reduced_round;
pub mod schedule;
pub mod smt;
pub mod smt_scaling;
pub mod statistical;
pub mod trail_search;

use anyhow::{Context, Result, bail};
use research_storage::{Store, now_iso};
use serde_json::{Value, json};
use std::time::Instant;

/// Default seed for every experiment ("BMRL" in ASCII).
pub const DEFAULT_SEED: u64 = 0x424d_524c;
pub const FULL_ROUNDS: usize = 64;
/// Seed perturbation for confirmation runs of full-round deviations.
const CONFIRMATION_SEED_XOR: u64 = 0xc0f1_4a7e_5eed_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    ReducedRound,
    Differential,
    Statistical,
    Smt,
    Characteristic,
    Algebraic,
    Schedule,
    SmtScaling,
    Multiseed,
    Hardware,
    CharacteristicAudit,
    TrailSearch,
}

/// What exactly an experiment measures. Results never transfer between these.
pub mod primitive {
    /// One SHA-256 compression call (state + 64-byte block, feed-forward).
    pub const COMPRESSION: &str = "sha256-compression";
    /// The SHA-256 message schedule (W0..W63) on its own.
    pub const SCHEDULE: &str = "sha256-message-schedule";
    /// SHA-256 of a whole message (padding, chaining).
    pub const SHA256: &str = "sha256";
    /// SHA-256(SHA-256(x)) of arbitrary inputs.
    pub const SHA256D: &str = "sha256d";
    /// SHA-256d of an 80-byte Bitcoin header as a function of the nonce (midstate form).
    pub const HEADER: &str = "bitcoin-header-sha256d";
    /// Hardware datapaths computing bitcoin-header-sha256d.
    pub const HARDWARE: &str = "bitcoin-header-sha256d-datapath";
}

pub struct Definition {
    /// Stable id in the hypothesis registry.
    pub hypothesis_id: &'static str,
    /// One of [`primitive`]; may list several, comma-separated.
    pub primitive: &'static str,
    pub name: &'static str,
    /// Bump when methodology or parameters' meaning change.
    pub version: u32,
    pub hypothesis: &'static str,
    pub null_hypothesis: &'static str,
    pub assumptions: &'static [&'static str],
    pub baseline: &'static str,
    pub methodology: &'static str,
    pub implementation: &'static [&'static str],
    pub dataset: &'static str,
}

/// Result of one execution.
pub struct Outcome {
    pub observations: Value,
    /// The part that must be bit-identical on reproduction.
    pub deterministic: Value,
    /// One entry per tested configuration: (rounds, deviation from baseline detected).
    pub flags: Vec<(usize, bool)>,
    /// Data-derived sentences for the conclusion.
    pub summary: Vec<String>,
    /// Set when a prerequisite (e.g. the solver) is unavailable.
    pub skipped: Option<String>,
    /// Concrete witnesses (inputs reproducing a structure, or refuting a claim).
    pub counterexamples: Vec<Value>,
    /// Result label for kinds that are not round-based tests (e.g. `model-estimate`).
    pub result: Option<&'static str>,
}

impl Outcome {
    pub fn new(observations: Value, deterministic: Value, flags: Vec<(usize, bool)>, summary: Vec<String>) -> Self {
        Self { observations, deterministic, flags, summary, skipped: None, counterexamples: vec![], result: None }
    }

    pub fn skipped(reason: String) -> Self {
        let mut o = Self::new(Value::Null, Value::Null, vec![], vec![]);
        o.skipped = Some(reason);
        o
    }
}

pub struct Verification {
    pub method: String,
    pub passed: bool,
    pub detail: String,
}

impl Kind {
    pub const ALL: [Kind; 12] = [
        Kind::ReducedRound,
        Kind::Differential,
        Kind::Statistical,
        Kind::Smt,
        Kind::Characteristic,
        Kind::Algebraic,
        Kind::Schedule,
        Kind::SmtScaling,
        Kind::Multiseed,
        Kind::Hardware,
        Kind::CharacteristicAudit,
        Kind::TrailSearch,
    ];
    /// The MVP experiment set (`bmr research all`).
    pub const MVP: [Kind; 4] = [Kind::ReducedRound, Kind::Differential, Kind::Statistical, Kind::Smt];
    /// SHA-256 Structural Exploration initiative (`bmr research structural`).
    pub const STRUCTURAL: [Kind; 6] =
        [Kind::Characteristic, Kind::Algebraic, Kind::Schedule, Kind::SmtScaling, Kind::Multiseed, Kind::Hardware];

    fn module(self) -> &'static Module {
        &MODULES[self as usize]
    }

    pub fn id(self) -> &'static str {
        self.module().id
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.id() == s)
    }

    pub fn definition(self) -> Definition {
        (self.module().definition)()
    }

    /// Default parameters; `quick` shrinks sample sizes for smoke tests.
    pub fn default_params(self, quick: bool) -> Value {
        (self.module().default_params)(quick)
    }

    pub fn execute(self, params: &Value, seed: u64) -> Result<Outcome> {
        (self.module().execute)(params, seed)
    }

    pub fn verify(self, params: &Value, seed: u64, outcome: &Outcome) -> Result<Verification> {
        (self.module().verify)(params, seed, outcome)
    }
}

/// One experiment kind's entry points.
struct Module {
    id: &'static str,
    definition: fn() -> Definition,
    default_params: fn(bool) -> Value,
    execute: fn(&Value, u64) -> Result<Outcome>,
    verify: fn(&Value, u64, &Outcome) -> Result<Verification>,
}

macro_rules! module {
    ($id:literal, $m:ident) => {
        Module { id: $id, definition: $m::definition, default_params: $m::default_params, execute: $m::execute, verify: $m::verify }
    };
}

/// Indexed by `Kind as usize`, in declaration order.
const MODULES: [Module; 12] = [
    module!("reduced-round", reduced_round),
    module!("differential", differential),
    module!("statistical", statistical),
    module!("smt", smt),
    module!("characteristic", characteristic),
    module!("algebraic", algebraic),
    module!("schedule", schedule),
    module!("smt-scaling", smt_scaling),
    module!("multiseed", multiseed),
    module!("hardware", hardware),
    module!("characteristic-audit", characteristic_audit),
    module!("trail-search", trail_search),
];

/// Parameter helpers shared by the kinds.
pub(crate) fn p_u64(params: &Value, key: &str) -> Result<u64> {
    params[key].as_u64().with_context(|| format!("parameter {key} must be an unsigned integer"))
}

pub(crate) fn p_f64(params: &Value, key: &str) -> Result<f64> {
    params[key].as_f64().with_context(|| format!("parameter {key} must be a number"))
}

pub(crate) fn p_rounds(params: &Value) -> Result<Vec<usize>> {
    let rounds: Vec<usize> = params["rounds"]
        .as_array()
        .context("parameter rounds must be an array")?
        .iter()
        .map(|r| r.as_u64().map(|r| r as usize).filter(|&r| r <= FULL_ROUNDS).context("rounds must be 0..=64"))
        .collect::<Result<_>>()?;
    anyhow::ensure!(!rounds.is_empty(), "rounds must not be empty");
    Ok(rounds)
}

/// Merge `overrides` into `defaults` (top-level keys only).
pub fn merge_params(mut defaults: Value, overrides: &Value) -> Value {
    if let (Some(d), Some(o)) = (defaults.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            d.insert(k.clone(), v.clone());
        }
    }
    defaults
}

pub fn digest(v: &Value) -> String {
    // serde_json maps are ordered by key, so this serialization is canonical.
    let text = serde_json::to_string(v).expect("JSON value serializes");
    bitcoin_header::hex_encode(&sha256_core::sha256(text.as_bytes()))
}

/// `k` of `n` with its rate and Wilson 95% interval (also in log2 when positive).
pub(crate) fn ci_json(k: u64, n: u64) -> Value {
    let (lo, hi) = statistical_engine::wilson(k, n, statistical_engine::Z95);
    let p = k as f64 / n.max(1) as f64;
    let log2 = |x: f64| (x > 0.0).then(|| x.log2());
    json!({ "count": k, "of": n, "p": p, "log2_p": log2(p), "ci95": [lo, hi], "log2_ci95": [log2(lo), log2(hi)] })
}

pub(crate) fn hex_words(w: &[u32]) -> String {
    w.iter().map(|x| format!("{x:08x}")).collect()
}

fn reproduction_command(kind: Kind, params: &Value, seed: u64) -> String {
    format!("bmr research {} --seed {seed} --params '{}'", kind.id(), serde_json::to_string(params).unwrap_or_default())
}

/// Run `f` on a dedicated pool with a different thread count than the default.
fn on_other_pool<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T> {
    let n = rayon::current_num_threads();
    let threads = if n > 1 { (n / 2).max(1) } else { 2 };
    Ok(rayon::ThreadPoolBuilder::new().num_threads(threads).build()?.install(f))
}

fn classify(flags: &[(usize, bool)], confirmed: Option<bool>) -> (&'static str, bool) {
    let full = flags.iter().any(|&(r, d)| r == FULL_ROUNDS && d);
    let reduced = flags.iter().any(|&(r, d)| r < FULL_ROUNDS && d);
    match (full, confirmed) {
        (true, Some(true)) => ("candidate-anomaly", true),
        (true, _) => ("not-replicated", false),
        (false, _) if reduced => ("reduced-round-only", false),
        _ => ("negative", false),
    }
}

fn conclusion(result: &str, summary: &[String]) -> String {
    let lead = match result {
        "negative" => "NEGATIVE RESULT: no deviation from the baseline was detected in any tested configuration at the stated sample size and significance level.",
        "reduced-round-only" => "REDUCED-ROUND ONLY: deviations were detected only for reduced-round variants. These say nothing about full 64-round SHA-256/SHA-256d and give no mining advantage; full-round configurations (where tested) showed no deviation.",
        "model-estimate" => "MODEL ESTIMATE: figures below come from an analytical model with stated assumptions, validated only where noted; they are not measurements.",
        "not-replicated" => "NOT REPLICATED: a full-round deviation appeared but vanished on a fresh seed; treated as statistical noise.",
        "candidate-anomaly" => "CANDIDATE ANOMALY (unconfirmed): a full-round deviation replicated on a fresh seed. This is NOT a discovery: it requires review of the methodology, a larger independent run and an external implementation before any claim.",
        _ => "",
    };
    std::iter::once(lead.to_string()).chain(summary.iter().cloned()).collect::<Vec<_>>().join(" ")
}

/// Execute, verify, reproduce, classify and persist one experiment.
pub fn run(store: &Store, kind: Kind, overrides: &Value, seed: u64, quick: bool) -> Result<Value> {
    let def = kind.definition();
    let params = merge_params(kind.default_params(quick), overrides);
    let id = store.next_experiment_id(kind.id())?;
    let t0 = Instant::now();
    store.upsert_hypothesis(def.hypothesis_id, kind.id(), def.primitive, def.hypothesis, def.null_hypothesis)?;
    let mut rec = json!({
        "id": id,
        "kind": kind.id(),
        "hypothesis_id": def.hypothesis_id,
        "primitive": def.primitive,
        "name": def.name,
        "definition_version": def.version,
        "status": "running",
        "hypothesis": def.hypothesis,
        "null_hypothesis": def.null_hypothesis,
        "assumptions": def.assumptions,
        "baseline": def.baseline,
        "methodology": def.methodology,
        "implementation": def.implementation,
        "dataset": { "description": def.dataset, "generator": "SplitMix64::stream(seed, sample_index)", "seed": seed },
        "seed": seed,
        "samples": params.get("samples").cloned().unwrap_or(Value::Null),
        "params": params,
        "environment": env::environment(),
        "started_at": now_iso(),
        "reproduction_command": reproduction_command(kind, &params, seed),
    });
    store.save_experiment(&rec)?;

    let finish = |rec: &mut Value, status: &str| {
        rec["status"] = json!(status);
        rec["finished_at"] = json!(now_iso());
        rec["duration_seconds"] = json!(t0.elapsed().as_secs_f64());
    };

    let outcome = match kind.execute(&params, seed) {
        Ok(o) => o,
        Err(e) => {
            finish(&mut rec, "failed");
            rec["error"] = json!(format!("{e:#}"));
            rec["result"] = json!("error");
            store.save_experiment(&rec)?;
            return Err(e.context(format!("experiment {id} failed (record kept)")));
        }
    };
    if let Some(reason) = &outcome.skipped {
        finish(&mut rec, "skipped");
        rec["result"] = json!("skipped");
        rec["conclusion"] = json!(format!("Not run: {reason}"));
        rec["path"] = json!(store.save_experiment(&rec)?.display().to_string());
        return Ok(rec);
    }

    let result_digest = digest(&outcome.deterministic);
    let verification = kind.verify(&params, seed, &outcome)?;

    let reproduction = if params["reproduce"].as_bool().unwrap_or(true) {
        let again = on_other_pool(|| kind.execute(&params, seed))??;
        let d = digest(&again.deterministic);
        json!({
            "method": "full rerun with identical seed and parameters on a separate Rayon pool with a different thread count; SHA-256 of the canonical deterministic results compared",
            "threads": rayon::current_num_threads().max(2) / 2,
            "digest": d,
            "matched": d == result_digest,
        })
    } else {
        json!({ "method": "not run in-process for this kind; use `bmr research reproduce <id>`", "matched": null })
    };

    let full_hit = outcome.flags.iter().any(|&(r, d)| r == FULL_ROUNDS && d);
    let confirmation = if full_hit {
        let mut p = params.clone();
        p["rounds"] = json!([FULL_ROUNDS]);
        let seed2 = seed ^ CONFIRMATION_SEED_XOR;
        let c = kind.execute(&p, seed2)?;
        let replicated = c.flags.iter().any(|&(_, d)| d);
        Some(json!({ "seed": seed2, "replicated": replicated, "observations": c.observations }))
    } else {
        None
    };
    let (result, candidate) = match outcome.result {
        Some(r) => (r, false),
        None => classify(&outcome.flags, confirmation.as_ref().map(|c| c["replicated"] == true)),
    };

    finish(&mut rec, "completed");
    rec["observations"] = outcome.observations;
    rec["configurations"] =
        json!(outcome.flags.iter().map(|&(r, d)| json!({ "rounds": r, "deviation_detected": d })).collect::<Vec<_>>());
    // Reduced-round and full-round findings are never pooled.
    let split = |full: bool| -> Value {
        json!(outcome.flags.iter().filter(|f| (f.0 == FULL_ROUNDS) == full).map(|&(r, d)| json!({ "rounds": r, "deviation_detected": d })).collect::<Vec<_>>())
    };
    let full_tested = outcome.flags.iter().any(|f| f.0 == FULL_ROUNDS);
    let full_deviation = outcome.flags.iter().any(|&(r, d)| r == FULL_ROUNDS && d);
    rec["scope"] = json!({
        "primitive": def.primitive,
        "reduced_round_configurations": split(false),
        "full_round_configurations": split(true),
        "full_round_tested": full_tested,
        "full_round_claim": if !full_tested { "none (full rounds not tested)" } else if candidate { "candidate anomaly, unconfirmed" } else if full_deviation { "deviation not replicated: noise" } else { "no deviation detected" },
    });
    rec["counterexamples"] = json!(outcome.counterexamples);
    rec["result_digest"] = json!(result_digest);
    rec["verification"] = json!({ "method": verification.method, "passed": verification.passed, "detail": verification.detail });
    rec["reproduction"] = reproduction;
    rec["confirmation"] = confirmation.unwrap_or(Value::Null);
    rec["result"] = json!(result);
    rec["candidate_anomaly"] = json!(candidate);
    rec["conclusion"] = json!(conclusion(result, &outcome.summary));
    if !verification.passed {
        rec["status"] = json!("failed-verification");
    } else if rec["reproduction"]["matched"] == false {
        rec["status"] = json!("failed-reproduction");
    }
    // Only verified, reproduced runs count as evidence.
    if rec["status"] == "completed" {
        let scope = if outcome.result.is_some() {
            "model"
        } else if full_tested {
            "reduced-and-full-round"
        } else {
            "reduced-round-only-tested"
        };
        let status = store.add_evidence(
            def.hypothesis_id,
            &id,
            result,
            scope,
            Some(seed),
            rec["conclusion"].as_str().unwrap_or(""),
            &rec["counterexamples"],
        )?;
        rec["hypothesis_status"] = json!(status);
    }
    rec["path"] = json!(store.save_experiment(&rec)?.display().to_string());
    Ok(rec)
}

/// Benchmark kinds a complete run must contain.
pub const BENCHMARK_KINDS: [&str; 5] = ["cpu", "gpu", "compare", "regtest", "mining"];

/// Provenance audit of the registry against this binary. Nothing is changed:
/// the latest completed record of each kind produced by this exact code (same
/// source fingerprint, committed, clean tree) is "current"; everything else is
/// history, kept with the reason it is not current.
pub fn audit(store: &Store) -> Result<Value> {
    let fp = env::source_fingerprint();
    let matches_commit = env::binary_matches_commit();
    let from_this_code = |r: &Value| r["environment"]["source_fingerprint"] == fp.as_str() && r["environment"]["binary_matches_commit"] == true;
    let reason = |r: &Value| -> &'static str {
        if r["environment"]["source_fingerprint"] != fp.as_str() {
            "older code"
        } else if r["environment"]["binary_matches_commit"] != true {
            "uncommitted code"
        } else if r["status"] != "completed" {
            "not completed"
        } else {
            "superseded by a later run"
        }
    };
    let exps = store.all_experiments()?;
    let mut kinds = Vec::new();
    let mut missing = Vec::new();
    for kind in Kind::ALL {
        let recs: Vec<&Value> = exps.iter().filter(|r| r["kind"] == kind.id()).collect();
        let current = recs.iter().rev().find(|r| from_this_code(r) && r["status"] == "completed");
        let cur_id = current.and_then(|r| r["id"].as_str());
        if cur_id.is_none() {
            missing.push(kind.id().to_string());
        }
        let history: Vec<Value> = recs
            .iter()
            .filter(|r| r["id"].as_str() != cur_id)
            .map(|r| json!({ "id": r["id"], "reason": reason(r), "errata": r["errata"].as_array().map_or(0, Vec::len) }))
            .collect();
        kinds.push(json!({ "kind": kind.id(), "current": cur_id, "result": current.map(|r| r["result"].clone()), "history": history }));
    }
    let benches = store.all_benchmarks()?;
    let mut bench_kinds = Vec::new();
    for kind in BENCHMARK_KINDS {
        let recs: Vec<&Value> = benches.iter().filter(|(k, _)| k == kind).map(|(_, r)| r).collect();
        let current = recs.iter().rev().find(|r| from_this_code(r)).and_then(|r| r["id"].as_str());
        if current.is_none() {
            missing.push(format!("benchmark {kind}"));
        }
        bench_kinds.push(json!({ "kind": kind, "current": current, "history": recs.iter().filter_map(|r| r["id"].as_str()).filter(|id| Some(*id) != current).collect::<Vec<_>>() }));
    }
    let errata: Vec<Value> = exps.iter().filter(|r| r["errata"].is_array()).map(|r| json!({ "id": r["id"], "notes": r["errata"].as_array().map_or(0, Vec::len) })).collect();
    Ok(json!({
        "source_fingerprint": fp,
        "git_commit": env::git_commit(),
        "binary_matches_commit": matches_commit,
        "experiments": kinds,
        "benchmarks": bench_kinds,
        "records_with_errata": errata,
        "total_experiment_records": exps.len(),
        "total_benchmark_records": benches.len(),
        "missing_current": missing,
        "passed": matches_commit && missing.is_empty(),
    }))
}

/// Rerun a stored experiment from its recorded seed and parameters.
pub fn reproduce(store: &Store, id: &str) -> Result<Value> {
    let rec = store.get_experiment(id)?.with_context(|| format!("no experiment {id}"))?;
    let kind = rec["kind"].as_str().and_then(Kind::parse).context("record has unknown kind")?;
    let seed = rec["seed"].as_u64().context("record has no seed")?;
    let Some(original) = rec["result_digest"].as_str() else {
        bail!("experiment {id} has no result digest (status {})", rec["status"]);
    };
    let current_version = kind.definition().version as u64;
    let outcome = kind.execute(&rec["params"], seed)?;
    let d = digest(&outcome.deterministic);
    let out = json!({
        "experiment_id": id,
        "original_digest": original,
        "digest": d,
        "matched": d == original,
        "definition_version_recorded": rec["definition_version"],
        "definition_version_current": current_version,
        "source_fingerprint_recorded": rec["environment"]["source_fingerprint"],
        "environment": env::environment(),
        "created_at": now_iso(),
    });
    store.save_reproduction(id, d == original, &out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_table_matches_kind_order() {
        let ids: Vec<&str> = Kind::ALL.iter().map(|k| k.id()).collect();
        assert_eq!(ids, ["reduced-round", "differential", "statistical", "smt", "characteristic", "algebraic", "schedule", "smt-scaling", "multiseed", "hardware", "characteristic-audit", "trail-search"]);
        assert!(Kind::ALL.iter().enumerate().all(|(i, k)| *k as usize == i));
    }

    #[test]
    fn classification_never_promotes_unreplicated_full_round_hits() {
        assert_eq!(classify(&[(64, true)], Some(false)).0, "not-replicated");
        assert_eq!(classify(&[(64, true)], None).0, "not-replicated");
        assert_eq!(classify(&[(64, true)], Some(true)), ("candidate-anomaly", true));
        assert_eq!(classify(&[(8, true), (64, false)], None).0, "reduced-round-only");
        assert_eq!(classify(&[(8, false), (64, false)], None).0, "negative");
    }

    #[test]
    fn quick_structural_experiments_complete_and_register_evidence() {
        let dir = std::env::temp_dir().join(format!("bmrl-struct-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        for kind in Kind::STRUCTURAL.into_iter().chain([Kind::CharacteristicAudit, Kind::TrailSearch]) {
            let rec = run(&store, kind, &json!({}), 11, true).unwrap();
            if rec["status"] == "skipped" {
                eprintln!("{} skipped: {}", kind.id(), rec["conclusion"]);
                continue;
            }
            assert_eq!(rec["status"], "completed", "{}: {}", kind.id(), serde_json::to_string_pretty(&rec).unwrap());
            assert_eq!(rec["verification"]["passed"], true, "{}", kind.id());
            assert!(rec["hypothesis_status"].is_string(), "{}", kind.id());
            assert!(rec["scope"]["primitive"].is_string());
        }
        assert!(store.list_hypotheses().unwrap().len() >= 5);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quick_experiments_are_reproducible_and_verified() {
        let dir = std::env::temp_dir().join(format!("bmrl-exp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        for kind in [Kind::ReducedRound, Kind::Differential, Kind::Statistical] {
            let rec = run(&store, kind, &json!({}), 7, true).unwrap();
            assert_eq!(rec["status"], "completed", "{}: {}", kind.id(), rec);
            assert_eq!(rec["verification"]["passed"], true);
            assert_eq!(rec["reproduction"]["matched"], true);
            let again = reproduce(&store, rec["id"].as_str().unwrap()).unwrap();
            assert_eq!(again["matched"], true);
        }
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
