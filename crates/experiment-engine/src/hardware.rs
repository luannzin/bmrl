//! Hardware architecture exploration: verified pipeline variants, resource
//! counts derived from the dataflow, FPGA feasibility and throughput/energy
//! models compared with the measured CPU/GPU baselines.

use crate::{Definition, Outcome, Verification, p_u64};
use anyhow::Result;
use hardware_model::{CostModel, DEFAULT_COST, DEVICES, Output, VARIANTS, estimate, reference, resources, simulate, simulate_iterative};
use serde_json::{Value, json};
use statistical_engine::SplitMix64;

pub fn definition() -> Definition {
    Definition {
        hypothesis_id: "H-HW-01",
        primitive: crate::primitive::HARDWARE,
        name: "Pipelined SHA-256d datapaths: correctness, resources, FPGA throughput and energy model",
        // v2: iterative cores simulated too; record split into measured / simulated / estimated + assumptions.
        version: 2,
        hypothesis: "A fully pipelined SHA-256d datapath using midstate, precomputation, early reject and constant folding fits commodity FPGAs and delivers more hashes per second and per joule than the measured CPU and GPU baselines of this lab.",
        null_hypothesis: "No modelled FPGA configuration exceeds the measured CPU/GPU throughput or their energy efficiency bound.",
        assumptions: &[
            "Every architecture variant is simulated cycle by cycle and must reproduce the software SHA-256d for every nonce; resource counts come from the same stage list.",
            "One SHA-256 round per pipeline stage; 32 LUTs per 32-bit operator (adder, Σ/σ group, Ch, Maj); registers counted bit by bit; 80% utilization.",
            "Clock ranges per device family and per-toggle energies (activity 0.5) are ASSUMPTIONS, not vendor power-tool output or measurements.",
            "Device LUT/FF counts are published datasheet figures.",
            "CPU/GPU energy bounds use vendor TDP/board power (specification, not measured) divided by measured hash rate; the ASIC point is a vendor specification.",
        ],
        baseline: "Measured CPU (best kernel, all threads) and GPU (WGSL) hash rates from the benchmark registry.",
        methodology: "Simulate each variant on random headers, compare every output with the reference, record latency and steady-state throughput. Count operators/registers with and without constant folding. Map to devices under the cost model; when no full pipeline fits, choose the best iterative core (u rounds per cycle). Compare with measured baselines.",
        implementation: &["hardware_model::{simulate, resources, estimate}"],
        dataset: "Random 80-byte headers from SplitMix64::stream(seed, i); consecutive nonces.",
    }
}

pub fn default_params(quick: bool) -> Value {
    json!({
        "sim_nonces": if quick { 512 } else { 4096 },
        "headers": if quick { 1 } else { 4 },
        "cost": {
            "luts_per_word_op": DEFAULT_COST.luts_per_word_op,
            "utilization": DEFAULT_COST.utilization,
            "activity": DEFAULT_COST.activity,
            "pj_per_lut": [DEFAULT_COST.pj_per_lut.0, DEFAULT_COST.pj_per_lut.1],
            "pj_per_ff": [DEFAULT_COST.pj_per_ff.0, DEFAULT_COST.pj_per_ff.1],
        },
        "reference_power_w": { "cpu": 120.0, "cpu_source": "Intel Xeon E5-2680 v4 TDP (specification)", "gpu": 165.0, "gpu_source": "AMD Radeon RX 7600 total board power (specification)" },
        "asic_reference": { "name": "Bitmain Antminer S21 (vendor specification)", "joules_per_terahash": 17.5 },
        "reproduce": true,
    })
}

fn cost(params: &Value) -> CostModel {
    let c = &params["cost"];
    let pair = |v: &Value, d: (f64, f64)| (v[0].as_f64().unwrap_or(d.0), v[1].as_f64().unwrap_or(d.1));
    CostModel {
        luts_per_word_op: c["luts_per_word_op"].as_f64().unwrap_or(DEFAULT_COST.luts_per_word_op),
        utilization: c["utilization"].as_f64().unwrap_or(DEFAULT_COST.utilization),
        activity: c["activity"].as_f64().unwrap_or(DEFAULT_COST.activity),
        pj_per_lut: pair(&c["pj_per_lut"], DEFAULT_COST.pj_per_lut),
        pj_per_ff: pair(&c["pj_per_ff"], DEFAULT_COST.pj_per_ff),
    }
}

/// Latest measured CPU / GPU hash rates from the benchmark registry.
fn measured() -> (Option<f64>, Option<f64>, Option<String>, Option<String>) {
    let Ok(store) = research_storage::Store::open_default() else { return (None, None, None, None) };
    let rows = store.list_benchmarks(500).unwrap_or_default();
    let latest = |pred: &dyn Fn(&Value) -> bool| rows.iter().find(|r| pred(r)).cloned();
    let cpu = latest(&|r| r["parallel"]["hashes_per_second"].is_number());
    let gpu = latest(&|r| r["hashes_per_second"].is_number() && r["adapter"].is_object());
    (
        cpu.as_ref().and_then(|r| r["parallel"]["hashes_per_second"].as_f64()),
        gpu.as_ref().and_then(|r| r["hashes_per_second"].as_f64()),
        cpu.and_then(|r| r["id"].as_str().map(str::to_string)),
        gpu.and_then(|r| r["id"].as_str().map(str::to_string)),
    )
}

pub fn execute(params: &Value, seed: u64) -> Result<Outcome> {
    let n = p_u64(params, "sim_nonces")? as u32;
    let headers = p_u64(params, "headers")?;
    let c = cost(params);
    let (mut simulated, mut estimated) = (Vec::new(), Vec::new());
    let mut det = Vec::new();
    let mut best: Option<(f64, f64, String, String)> = None;
    for a in VARIANTS {
        let mut mismatches = 0u64;
        let (mut latency, mut cycles) = (0, 0);
        for h in 0..headers {
            let header: [u8; 80] = SplitMix64::stream(seed, h).bytes();
            let start = SplitMix64::stream(seed ^ 0x40, h).next_u32();
            let sim = simulate(&a, header, start, n);
            mismatches += sim.outputs.iter().filter(|(nonce, out, _)| *out != reference(&a, &header, *nonce)).count() as u64;
            latency = sim.latency;
            cycles = sim.cycles;
        }
        // Iterative cores (u round units, state fed back), the fallback when no
        // full pipeline fits: simulated too, so every modelled design is checked.
        let header0: [u8; 80] = SplitMix64::stream(seed, 0).bytes();
        let iterative: Vec<Value> = [1usize, 2, 4, 8, 16, 32]
            .iter()
            .map(|&u| {
                let sim = simulate_iterative(&a, u, header0, 0, 64);
                let bad = sim.outputs.iter().filter(|(nonce, out, _)| *out != reference(&a, &header0, *nonce)).count();
                mismatches += bad as u64;
                json!({ "rounds_per_cycle": u, "nonces": 64, "mismatches": bad, "cycles_per_nonce": sim.cycles as f64 / 64.0 })
            })
            .collect();
        let r = resources(&a);
        let estimates: Vec<Value> = DEVICES
            .iter()
            .map(|d| {
                let e = estimate(&r, d, &c);
                if best.as_ref().is_none_or(|b| e.hashes_per_second.1 > b.0) {
                    best = Some((e.hashes_per_second.1, e.joules_per_terahash.0, d.name.to_string(), a.name.to_string()));
                }
                json!({
                    "device": e.device, "full_pipelines": e.pipelines,
                    "iterative_cores": e.iterative.map(|(cores, u)| json!({ "cores": cores, "rounds_per_cycle": u })),
                    "hashes_per_second": [e.hashes_per_second.0, e.hashes_per_second.1],
                    "joules_per_terahash": [e.joules_per_terahash.0, e.joules_per_terahash.1],
                })
            })
            .collect();
        det.push(json!({ "variant": a.name, "mismatches": mismatches, "latency": latency, "resources": [r.stages, r.adders, r.xor3, r.ch, r.maj, r.register_bits], "estimates": estimates }));
        simulated.push(json!({
            "variant": a.name,
            "pipeline": {
                "headers": headers, "nonces_per_header": n,
                "latency_cycles": latency, "cycles": cycles,
                "steady_state_nonces_per_cycle": n as f64 / (cycles - latency + 1) as f64,
                "output": if a.early_reject { "H7 only (early reject)" } else { "full digest" },
            },
            "iterative_cores": iterative,
            "mismatches_total": mismatches,
            "counted": {
                "active_stages": r.stages, "adders_32bit": r.adders, "xor3_words": r.xor3, "ch_words": r.ch, "maj_words": r.maj,
                "register_bits": r.register_bits,
            },
        }));
        estimated.push(json!({
            "variant": a.name,
            "luts": r.luts(&c),
            "dynamic_pj_per_hash": [r.pj_per_hash(&c).0, r.pj_per_hash(&c).1],
            "devices": estimates,
        }));
    }
    let base = resources(&VARIANTS[1]);
    let folded = resources(&VARIANTS[4]);
    let (cpu_hps, gpu_hps, cpu_id, gpu_id) = measured();
    let pw = &params["reference_power_w"];
    let bound = |hps: Option<f64>, w: Option<f64>| hps.zip(w).map(|(h, w)| w / h * 1e12);
    let measured = json!({
        "cpu": { "benchmark": cpu_id, "hashes_per_second": cpu_hps, "kind": "measured" },
        "gpu": { "benchmark": gpu_id, "hashes_per_second": gpu_hps, "kind": "measured" },
        "power_note": "No power was measured. The J/TH bounds below divide vendor power ratings by measured hash rates.",
        "cpu_joules_per_terahash_rating_bound": bound(cpu_hps, pw["cpu"].as_f64()), "cpu_power_source": pw["cpu_source"],
        "gpu_joules_per_terahash_rating_bound": bound(gpu_hps, pw["gpu"].as_f64()), "gpu_power_source": pw["gpu_source"],
        "asic_reference": params["asic_reference"],
    });
    let assumptions = json!([
        { "quantity": "pipeline depth (stages)", "kind": "simulated, exact", "detail": "from the cycle model of each variant; folded designs skip job-constant stages" },
        { "quantity": "throughput per pipeline / core", "kind": "simulated, exact", "detail": "1 nonce per cycle for a full pipeline; 1 nonce per ceil(stages / u) cycles for an iterative core with u round units" },
        { "quantity": "operators and register bits", "kind": "counted from the simulated dataflow", "detail": "32-bit adders, Σ/σ groups, Ch, Maj; per-job constants (midstate, round constants) are not counted as registers" },
        { "quantity": "area in LUTs", "kind": "assumed", "detail": format!("{} LUTs per 32-bit operator; no routing, control, I/O or carry-chain effects", c.luts_per_word_op) },
        { "quantity": "memory", "kind": "model choice", "detail": "no block RAM: constants and job values are wired or held in registers" },
        { "quantity": "clock frequency", "kind": "assumed", "detail": DEVICES.iter().map(|d| format!("{}: {}-{} MHz", d.name, d.mhz.0, d.mhz.1)).collect::<Vec<_>>().join("; ") + "; not from timing analysis" },
        { "quantity": "utilization", "kind": "assumed", "detail": c.utilization },
        { "quantity": "dynamic energy", "kind": "assumed", "detail": format!("activity {}, {}-{} pJ per LUT toggle, {}-{} pJ per FF toggle", c.activity, c.pj_per_lut.0, c.pj_per_lut.1, c.pj_per_ff.0, c.pj_per_ff.1) },
        { "quantity": "static power", "kind": "assumed", "detail": DEVICES.iter().map(|d| format!("{}: {} W", d.name, d.static_w)).collect::<Vec<_>>().join("; ") },
        { "quantity": "device capacity", "kind": "published datasheet", "detail": DEVICES.iter().map(|d| format!("{}: {} LUTs, {} FFs", d.name, d.luts, d.ffs)).collect::<Vec<_>>().join("; ") },
        { "quantity": "CPU and GPU hash rates", "kind": "measured", "detail": "latest benchmark records from this lab" },
        { "quantity": "CPU, GPU and ASIC power", "kind": "vendor specification, not measured", "detail": "TDP / board power / ASIC J/TH rating" },
    ]);
    let best_model = best.as_ref().map(|b| json!({ "device": b.2, "variant": b.3, "hashes_per_second_high": b.0, "joules_per_terahash_low": b.1 }));
    let mut summary = vec![
        format!(
            "All {} variants reproduce the reference on every simulated nonce, both as full pipelines (one nonce per cycle) and as iterative cores with 1 to 32 round units (mismatches: {}).",
            VARIANTS.len(),
            det.iter().map(|d| d["mismatches"].as_u64().unwrap_or(0)).sum::<u64>()
        ),
        format!(
            "Midstate pipeline: {} stages, {} adders, {} register bits; with precompute + early reject + constant folding: {} stages, {} adders ({:.1}% fewer), {} register bits ({:.1}% fewer).",
            base.stages, base.adders, base.register_bits, folded.stages, folded.adders,
            100.0 * (1.0 - folded.adders as f64 / base.adders as f64), folded.register_bits,
            100.0 * (1.0 - folded.register_bits as f64 / base.register_bits as f64)
        ),
        "Constant folding applied to a design without midstate removes block 1 and the first three second-block rounds automatically, giving exactly the midstate + precompute datapath.".into(),
    ];
    if let Some(b) = &best {
        summary.push(format!(
            "ESTIMATE, not synthesized or measured: best modelled FPGA configuration {} on {} at up to {:.2} GH/s under the assumed clock.",
            b.3, b.2, b.0 / 1e9
        ));
    }
    summary.push(format!(
        "MEASURED for comparison: CPU {} MH/s, GPU {} MH/s (benchmark records {} and {}).",
        cpu_hps.map_or("n/a".into(), |c| format!("{:.1}", c / 1e6)),
        gpu_hps.map_or("n/a".into(), |g| format!("{:.1}", g / 1e6)),
        cpu_id.as_deref().unwrap_or("none"),
        gpu_id.as_deref().unwrap_or("none"),
    ));
    summary.push("Clock, area per operator, energy per toggle and static power are assumptions; no RTL was synthesized, no timing closed, no board measured.".into());
    let mut out = Outcome::new(
        json!({
            "measured": measured,
            "simulated": simulated,
            "estimated": { "status": "estimate: not synthesized, not measured", "variants": estimated, "best": best_model },
            "assumptions": assumptions,
            "cost_model": params["cost"],
        }),
        json!(det),
        vec![],
        summary,
    );
    out.result = Some("model-estimate");
    Ok(out)
}

/// Re-simulate every variant on a fresh header and check outputs against the
/// independent SHA-256 over the full 80-byte header.
pub fn verify(_: &Value, _: u64, _: &Outcome) -> Result<Verification> {
    let ind = verification::independent::Sha256::default();
    let mut header: [u8; 80] = SplitMix64::stream(0xfeed, 7).bytes();
    let mut problems = Vec::new();
    for a in VARIANTS {
        let mut outputs = simulate(&a, header, 1000, 256).outputs;
        outputs.extend(simulate_iterative(&a, 4, header, 5000, 64).outputs);
        for (nonce, out, _) in &outputs {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let d = ind.sha256d(&header, 64);
            let words: [u32; 8] = std::array::from_fn(|i| u32::from_be_bytes(d[4 * i..4 * i + 4].try_into().expect("4 bytes")));
            let expected = if a.early_reject { Output::H7(words[7]) } else { Output::Digest(words) };
            if *out != expected {
                problems.push(format!("{} nonce {nonce}", a.name));
            }
        }
    }
    if resources(&VARIANTS[4]) != resources(&VARIANTS[5]) {
        problems.push("folded no-midstate design differs from folded midstate design".into());
    }
    problems.truncate(10);
    Ok(Verification {
        method: "every variant re-simulated on an unseen header as a full pipeline and as a 4-round-unit iterative core; outputs compared with the independent SHA-256 over the full serialized header; folding consistency (no-midstate folds to midstate) checked".into(),
        passed: problems.is_empty(),
        detail: if problems.is_empty() { format!("{} variants x (256 pipelined + 64 iterative) nonces identical", VARIANTS.len()) } else { problems.join("; ") },
    })
}
