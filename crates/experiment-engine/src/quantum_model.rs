//! Unconventional search models, kept apart from measurements: Grover search
//! with a reversible SHA256d oracle, and the Landauer bound for reversible
//! classical hashing.
//!
//! Every figure is a model estimate from stated assumptions. The oracle's
//! operation counts are not re-derived here: they come from the hardware
//! model's exact operator count of the header datapath (`hardware_model::resources`),
//! converted with standard reversible-circuit costs.

use crate::{Definition, Outcome, Verification, p_f64};
use anyhow::Result;
use hardware_model::{VARIANTS, resources};
use serde_json::{Value, json};
use std::f64::consts::PI;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-QUANT-01",
        primitive: crate::primitive::HARDWARE,
        name: "Quantum (Grover) and reversible search models for the Bitcoin target",
        version: 1,
        hypothesis: "Grover search with a reversible SHA256d oracle finds a block with fewer oracle queries than classical search needs evaluations, and does so within the 600 s block interval on a feasible number of machines.",
        null_hypothesis: "The query reduction is real but, under the block-interval constraint and the oracle's cost, parallel Grover needs an infeasible number of machines and total gate work far above classical hashing.",
        assumptions: &[
            "SPECULATIVE MODEL: no error-corrected quantum computer of this size exists; nothing here is measured.",
            "Oracle = midstate + 3 precomputed rounds + early reject + constant folding (the hardware model's cheapest exact datapath), computed and uncomputed once per Grover iteration.",
            "Reversible costs: n-bit modular ripple-carry adder 2n - 2 Toffoli (Cuccaro et al. 2004); Ch and Maj 1 Toffoli per bit; Sigma functions CNOT-only; target check over d bits 2d - 3 Toffoli; 7 T gates per Toffoli.",
            "Toffoli depth: 3 sequential 32-bit adders per round, 2n each; logical Toffoli time 1, 10 or 100 microseconds (assumed range).",
            "Grover iterations (pi/4) sqrt(N/M) with the number of solutions known (optimistic for the quantum side); P machines split the space, each needing (pi/4) sqrt(N/(M P)).",
            "Landauer bound kT ln 2 at 300 K per erased bit; erased bits per hash approximated by the datapath's gate outputs (5 per adder bit, 2 per Ch/Maj/XOR3 bit).",
        ],
        baseline: "Classical search: 2^d SHA256d evaluations per block for a target with d leading zero bits.",
        methodology: "Operator counts from hardware_model::resources for the cheapest exact variant; reversible gate counts, depth and qubit estimates; Grover iterations, serial time, machines needed to finish within the block interval, and total oracle queries, for each difficulty and Toffoli time.",
        implementation: &["experiment_engine::quantum_model", "hardware_model::resources"],
        dataset: "None (analytical).",
    }
}

pub fn default_params(_quick: bool) -> Value {
    json!({
        "difficulty_bits": [32.0, 64.0, 72.0, 76.0, 78.0, 80.0],
        "toffoli_time_us": [1.0, 10.0, 100.0],
        "block_seconds": 600.0,
        "reproduce": true,
    })
}

/// Reversible cost of one Grover oracle call (compute, check, uncompute).
fn oracle(d: f64) -> Value {
    let arch = VARIANTS[4];
    let r = resources(&arch);
    let n = 32.0;
    let toffoli_compute = (2.0 * n - 2.0) * r.adders as f64 + n * (r.ch + r.maj) as f64;
    let check = 2.0 * d - 3.0;
    let toffoli = 2.0 * toffoli_compute + check;
    let depth = 2.0 * r.stages as f64 * 3.0 * 2.0 * n;
    json!({
        "datapath": arch.name, "stages": r.stages, "adders": r.adders, "ch": r.ch, "maj": r.maj, "xor3": r.xor3,
        "register_bits": r.register_bits,
        "toffoli": toffoli, "t_gates": 7.0 * toffoli, "toffoli_depth": depth,
        // Register bits of the pipeline plus one carry ancilla word per adder in flight and the search register.
        "logical_qubits_estimate": r.register_bits as f64 + 3.0 * n + d,
    })
}

pub fn execute(params: &Value, _seed: u64) -> Result<Outcome> {
    let ds: Vec<f64> = params["difficulty_bits"].as_array().map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
    let ts: Vec<f64> = params["toffoli_time_us"].as_array().map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
    let block = p_f64(params, "block_seconds")?;
    anyhow::ensure!(!ds.is_empty() && !ts.is_empty() && block > 0.0, "need difficulty_bits, toffoli_time_us and block_seconds");
    let mut rows = Vec::new();
    for &d in &ds {
        let o = oracle(d);
        let depth = o["toffoli_depth"].as_f64().unwrap_or(0.0);
        let toffoli = o["toffoli"].as_f64().unwrap_or(0.0);
        let classical = 2f64.powf(d);
        let iterations = PI / 4.0 * 2f64.powf(d / 2.0);
        let per_time: Vec<Value> = ts
            .iter()
            .map(|&t_us| {
                let t_iter = depth * t_us * 1e-6;
                let serial = iterations * t_iter;
                // P machines finish in time when (pi/4) sqrt(2^d / P) t_iter <= block.
                let machines = (classical * (PI / 4.0 * t_iter / block).powi(2)).max(1.0);
                let queries = machines * PI / 4.0 * (classical / machines).sqrt();
                json!({
                    "toffoli_time_us": t_us, "seconds_per_iteration": t_iter, "serial_seconds": serial, "serial_years": serial / 3.156e7,
                    "machines_for_block_interval": machines, "total_oracle_queries": queries, "queries_over_classical_evaluations": queries / classical,
                    "total_toffoli": queries * toffoli,
                })
            })
            .collect();
        rows.push(json!({ "difficulty_bits": d, "classical_evaluations": classical, "grover_iterations_serial": iterations, "oracle": o, "by_toffoli_time": per_time }));
    }
    // Landauer bound for irreversible classical hashing with the same datapath.
    let r = resources(&VARIANTS[4]);
    let erased = 32.0 * (5.0 * r.adders as f64 + 2.0 * (r.ch + r.maj + r.xor3) as f64);
    let kt_ln2 = 1.380_649e-23 * 300.0 * 2f64.ln();
    let landauer = json!({ "erased_bits_per_hash_estimate": erased, "joules_per_hash": erased * kt_ln2, "joules_per_terahash": erased * kt_ln2 * 1e12,
                           "note": "A reversible implementation could approach or beat this bound per hash; it changes energy per hash, never the number of hashes." });
    let top = rows.last().cloned().unwrap_or(Value::Null);
    let fast = &top["by_toffoli_time"][0];
    let summary = vec![
        format!("Grover oracle (one iteration): {:.3e} Toffoli, {:.3e} T gates, Toffoli depth {:.3e}, about {:.0} logical qubits.",
            top["oracle"]["toffoli"].as_f64().unwrap_or(0.0), top["oracle"]["t_gates"].as_f64().unwrap_or(0.0), top["oracle"]["toffoli_depth"].as_f64().unwrap_or(0.0), top["oracle"]["logical_qubits_estimate"].as_f64().unwrap_or(0.0)),
        format!("At d = {} bits and 1 us per logical Toffoli: one machine needs {:.3e} years; finishing within {block} s takes {:.3e} machines and {:.3e} oracle queries ({:.3e} of the classical evaluations) at {:.3e} Toffoli in total.",
            top["difficulty_bits"], fast["serial_years"].as_f64().unwrap_or(0.0), fast["machines_for_block_interval"].as_f64().unwrap_or(0.0),
            fast["total_oracle_queries"].as_f64().unwrap_or(0.0), fast["queries_over_classical_evaluations"].as_f64().unwrap_or(0.0), fast["total_toffoli"].as_f64().unwrap_or(0.0)),
        format!("Landauer bound for the same datapath: {:.3e} J per terahash; it bounds energy per hash, not the number of hashes.", landauer["joules_per_terahash"].as_f64().unwrap_or(0.0)),
    ];
    let obs = json!({ "rows": rows, "landauer": landauer, "status": "speculative model, not a measurement" });
    let mut o = Outcome::new(obs.clone(), obs, vec![], summary);
    o.result = Some("model-estimate");
    Ok(o)
}

/// Cross-check the operator count against a direct count of the oracle's
/// rounds, and the Grover formulas against a brute-force optimum of the
/// success probability sin^2((2k + 1) theta).
pub fn verify(_params: &Value, _seed: u64, _outcome: &Outcome) -> Result<Verification> {
    let mut problems = Vec::new();
    let r = resources(&VARIANTS[1]);
    // Midstate, no folding: second block 64 rounds + outer 64 rounds, 7 adders each, 48 schedule words x 3,
    // 8 feed-forward adders per block, one comparator.
    let direct = 2 * (64 * 7 + 48 * 3 + 8) + 1;
    if r.adders != direct {
        problems.push(format!("midstate adders {} != direct count {direct}", r.adders));
    }
    // Grover: for N/M = 2^20 the optimal k maximising sin^2((2k+1) theta) is within 1 of (pi/4) sqrt(N/M).
    let theta = (2f64.powi(-10)).asin();
    let best = (0..2000u32).max_by(|&a, &b| ((2 * a + 1) as f64 * theta).sin().powi(2).total_cmp(&((2 * b + 1) as f64 * theta).sin().powi(2))).unwrap_or(0);
    if (best as f64 - PI / 4.0 * 1024.0).abs() > 1.0 {
        problems.push(format!("Grover optimum {best} vs (pi/4) 2^10"));
    }
    Ok(Verification {
        method: "hardware-model adder count vs a direct count of the midstate datapath; Grover iteration formula vs brute-force maximisation of the success probability".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { "operator count and Grover iteration count confirmed".into() } else { problems.join("; ") },
    })
}
