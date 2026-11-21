//! `bmr` — Bitcoin Mining Research Lab command line.
//!
//! Every command prints human-readable text, or one JSON document with
//! `--json` for agents and scripts. Non-zero exit status on any failed check.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use cpu_backend::{CpuBackend, Kernel, Prepared, scan_range};
use experiment_engine::{DEFAULT_SEED, Kind, env};
use gpu_backend::GpuBackend;
use mining_engine::{Backend, ReferenceBackend, regtest, scan_verified, synthetic_work};
use research_storage::{Store, now_iso, workspace_root};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "bmr", version, about = "Bitcoin Mining Research Lab")]
struct Cli {
    /// Print one machine-readable JSON document.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hardware, toolchain and dependency discovery.
    System,
    #[command(subcommand)]
    Verify(VerifyCmd),
    #[command(subcommand)]
    Benchmark(BenchCmd),
    #[command(subcommand)]
    Research(ResearchCmd),
    #[command(subcommand)]
    Mine(MineCmd),
}

#[derive(Subcommand)]
enum VerifyCmd {
    /// SHA-256 / SHA-256d against NIST vectors, the sha2 crate and an independent implementation.
    Sha256 {
        #[arg(long, default_value_t = 10_000)]
        random: u64,
        #[arg(long, default_value_t = DEFAULT_SEED)]
        seed: u64,
    },
    /// Header engine against real main-network blocks and a live Bitcoin Core regtest node.
    BitcoinHeader {
        /// Skip the Bitcoin Core cross-check.
        #[arg(long)]
        no_node: bool,
        #[arg(long)]
        bitcoind: Option<PathBuf>,
        /// Blocks for the node to mine before comparing headers.
        #[arg(long, default_value_t = 20)]
        blocks: u32,
    },
}

#[derive(Args, Clone)]
struct BenchOpts {
    /// Seconds per measurement.
    #[arg(long, default_value_t = 3.0)]
    seconds: f64,
    /// CPU threads (0 = all logical CPUs).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// GPU API: auto, vulkan, dx12, metal.
    #[arg(long)]
    gpu_backend: Option<String>,
}

#[derive(Subcommand)]
enum BenchCmd {
    /// Every CPU kernel single-threaded, best kernel on all threads.
    Cpu(BenchOpts),
    /// GPU throughput with CPU parity checks.
    Gpu(BenchOpts),
    /// CPU vs GPU, alone and concurrently.
    Compare(BenchOpts),
}

#[derive(Args, Clone)]
struct ResearchOpts {
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,
    /// Small sample sizes (smoke test).
    #[arg(long)]
    quick: bool,
    /// JSON object overriding default parameters, e.g. '{"samples": 4096}'.
    #[arg(long)]
    params: Option<String>,
}

#[derive(Subcommand)]
enum ResearchCmd {
    /// Single-bit XOR differentials through reduced-round compression.
    Differential(ResearchOpts),
    /// Avalanche criterion by round count.
    ReducedRound(ResearchOpts),
    /// Uniformity of SHA-256d header hashes over the nonce.
    Statistical(ResearchOpts),
    /// Z3 nonce search vs brute force on reduced-round SHA-256d.
    Smt(ResearchOpts),
    /// Run the MVP experiments (reduced-round, differential, statistical, smt).
    All(ResearchOpts),
    /// XOR characteristics through 64 rounds: estimated vs empirical probability, bit propagation.
    Characteristic(ResearchOpts),
    /// GF(2) degree bounds, cube sums and carry contribution.
    Algebraic(ResearchOpts),
    /// Message-schedule rank, low-weight differences, statistics, header redundancy.
    Schedule(ResearchOpts),
    /// SAT/SMT scaling with rounds and target bits, adaptive timeouts, profiling.
    SmtScaling(ResearchOpts),
    /// Multi-seed tests of SHA-256 / SHA-256d / header hashing against a random-function control.
    Multiseed(ResearchOpts),
    /// Pipelined datapath simulation, resources and FPGA throughput/energy model.
    Hardware(ResearchOpts),
    /// SHA-256 Structural Exploration: run all six structural experiments.
    Structural(ResearchOpts),
    /// Audit of the measurable XOR characteristics: estimates, exact conditions, seeds, independent code.
    CharacteristicAudit(ResearchOpts),
    /// Trail-to-search conversion: trail search, neighbour and condition strategies for SHA256d <= target.
    TrailSearch(ResearchOpts),
    /// Hypothesis registry with evidence-derived status.
    Hypotheses,
    /// One hypothesis with all evidence and counterexamples.
    Hypothesis { id: String },
    /// List stored experiments.
    List {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Print a stored experiment record.
    Show { id: String },
    /// Rerun a stored experiment from its seed and parameters and compare digests.
    Reproduce { id: String },
    /// Check that every experiment and benchmark kind has a result from this exact, committed code.
    Audit,
    /// Append an erratum to a stored experiment (records are otherwise immutable).
    Erratum {
        id: String,
        #[arg(long)]
        note: String,
    },
}

#[derive(Subcommand)]
enum MineCmd {
    /// Mine on a fresh Bitcoin Core regtest chain: templates, PoW, submit, acceptance, maturity.
    Regtest {
        /// cpu or gpu.
        #[arg(long, default_value = "cpu")]
        backend: String,
        #[arg(long)]
        bitcoind: Option<PathBuf>,
        /// Empty directory for the node (default: fresh temp dir).
        #[arg(long)]
        datadir: Option<PathBuf>,
        /// Keep the node's data directory afterwards.
        #[arg(long)]
        keep: bool,
        #[arg(long, default_value_t = 0)]
        threads: usize,
        #[arg(long)]
        gpu_backend: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let json_out = cli.json;
    match dispatch(cli) {
        Ok((value, ok)) => {
            if json_out {
                println!("{}", serde_json::to_string_pretty(&value).expect("serializable"));
            }
            std::process::exit(if ok { 0 } else { 1 });
        }
        Err(e) => {
            if json_out {
                println!("{}", json!({ "error": format!("{e:#}") }));
            } else {
                eprintln!("error: {e:#}");
            }
            std::process::exit(2);
        }
    }
}

/// Returns the JSON document and whether every check passed.
fn dispatch(cli: Cli) -> Result<(Value, bool)> {
    let human = !cli.json;
    match cli.command {
        Command::System => system(human),
        Command::Verify(VerifyCmd::Sha256 { random, seed }) => verify_sha256(human, random, seed),
        Command::Verify(VerifyCmd::BitcoinHeader { no_node, bitcoind, blocks }) => verify_header(human, no_node, bitcoind, blocks),
        Command::Benchmark(BenchCmd::Cpu(o)) => bench_cpu(human, &o),
        Command::Benchmark(BenchCmd::Gpu(o)) => bench_gpu(human, &o),
        Command::Benchmark(BenchCmd::Compare(o)) => bench_compare(human, &o),
        Command::Research(cmd) => research(human, cmd),
        Command::Mine(MineCmd::Regtest { backend, bitcoind, datadir, keep, threads, gpu_backend }) => {
            mine_regtest(human, &backend, bitcoind, datadir, keep, threads, gpu_backend.as_deref())
        }
    }
}

macro_rules! say {
    ($human:expr, $($arg:tt)*) => { if $human { println!($($arg)*); } };
}

fn fmt_rate(h: f64) -> String {
    match h {
        h if h >= 1e9 => format!("{:.3} GH/s", h / 1e9),
        h if h >= 1e6 => format!("{:.2} MH/s", h / 1e6),
        h if h >= 1e3 => format!("{:.2} kH/s", h / 1e3),
        h => format!("{h:.1} H/s"),
    }
}

// ---------------------------------------------------------------- system

fn adapter_json(a: &gpu_backend::AdapterInfo) -> Value {
    json!({
        "name": a.name, "api": format!("{:?}", a.backend), "type": format!("{:?}", a.device_type),
        "driver": a.driver, "driver_info": a.driver_info,
        "vendor_id": format!("{:#06x}", a.vendor), "device_id": format!("{:#06x}", a.device),
    })
}

fn system(human: bool) -> Result<(Value, bool)> {
    let environment = env::environment();
    let adapters: Vec<Value> = gpu_backend::list_adapters().iter().map(adapter_json).collect();
    let selected = GpuBackend::new(None).map(|g| format!("{} ({:?})", g.adapter().name, g.adapter().backend)).map_err(|e| format!("{e:#}"));
    let bitcoind = regtest::find_bitcoind(&workspace_root());
    let v = json!({
        "environment": environment,
        "cpu_kernels": Kernel::ALL.iter().map(|k| json!({ "name": k.name(), "available": k.available() })).collect::<Vec<_>>(),
        "gpu_adapters": adapters,
        "gpu_selected": selected.as_ref().ok(),
        "gpu_error": selected.as_ref().err(),
        "bitcoind": bitcoind.as_ref().map(|p| p.display().to_string()),
        "bitcoind_version": bitcoind.as_deref().and_then(regtest::bitcoind_version),
        "z3": experiment_engine::smt::z3_version(),
        "data_dir": research_storage::data_dir().display().to_string(),
    });
    say!(human, "CPU      {} ({} logical, {})", environment["cpu"].as_str().unwrap_or("?"), environment["logical_cpus"], environment["cpu_features"]);
    say!(human, "Kernels  {}", Kernel::ALL.iter().map(|k| format!("{}{}", k.name(), if k.available() { "" } else { " (unavailable)" })).collect::<Vec<_>>().join(", "));
    for a in &adapters {
        say!(human, "GPU      {} [{} {}] driver {} {}", a["name"].as_str().unwrap_or(""), a["api"].as_str().unwrap_or(""), a["type"].as_str().unwrap_or(""), a["driver"].as_str().unwrap_or(""), a["driver_info"].as_str().unwrap_or(""));
    }
    match &selected {
        Ok(name) => say!(human, "Selected {name}"),
        Err(e) => say!(human, "Selected none: {e}"),
    }
    say!(human, "Core     {}", v["bitcoind_version"].as_str().or(v["bitcoind"].as_str()).unwrap_or("not found (set BMR_BITCOIND)"));
    say!(human, "Z3       {}", v["z3"].as_str().unwrap_or("not available (pip install z3-solver)"));
    say!(human, "Rust     {} [{}]", environment["rustc"].as_str().unwrap_or(""), environment["profile"].as_str().unwrap_or(""));
    say!(human, "Data     {}", v["data_dir"].as_str().unwrap_or(""));
    Ok((v, true))
}

// ---------------------------------------------------------------- verify

fn print_checks(human: bool, checks: &[verification::Check]) {
    for c in checks {
        say!(human, "{} {}  ({})", if c.passed { "PASS" } else { "FAIL" }, c.name, c.detail);
    }
}

fn verify_sha256(human: bool, random: u64, seed: u64) -> Result<(Value, bool)> {
    let r = verification::sha256_suite(random, seed);
    print_checks(human, &r.checks);
    let ok = r.passed();
    say!(human, "{}", if ok { "sha256: all checks passed" } else { "sha256: FAILED" });
    Ok((json!({ "passed": ok, "checks": r.checks }), ok))
}

fn verify_header(human: bool, no_node: bool, bitcoind: Option<PathBuf>, blocks: u32) -> Result<(Value, bool)> {
    let r = verification::header_suite();
    print_checks(human, &r.checks);
    let mut ok = r.passed();
    let node = if no_node {
        json!({ "skipped": "--no-node" })
    } else if let Some(exe) = bitcoind.or_else(|| regtest::find_bitcoind(&workspace_root())) {
        let dir = regtest::temp_datadir("verify")?;
        let res = regtest::validate_core_headers(&exe, &dir, blocks);
        let _ = std::fs::remove_dir_all(&dir);
        let res = res?;
        ok &= res["passed"] == true;
        say!(human, "{} bitcoin-core cross-check  ({} headers mined by {} parsed, hashed and PoW-checked; failures: {})",
            if res["passed"] == true { "PASS" } else { "FAIL" }, res["headers_checked"], res["node"].as_str().unwrap_or("node"), res["failures"]);
        res
    } else {
        say!(human, "SKIP bitcoin-core cross-check (bitcoind not found; set BMR_BITCOIND)");
        json!({ "skipped": "bitcoind not found" })
    };
    say!(human, "{}", if ok { "bitcoin-header: all checks passed" } else { "bitcoin-header: FAILED" });
    Ok((json!({ "passed": ok, "checks": r.checks, "bitcoin_core": node }), ok))
}

// ---------------------------------------------------------------- benchmarks

/// Run `step` (returning hashes done) until `seconds` elapse.
fn measure(seconds: f64, mut step: impl FnMut(u64) -> Result<u64>) -> Result<(u64, f64)> {
    let t = Instant::now();
    let mut n = 0;
    while t.elapsed().as_secs_f64() < seconds {
        n += step(n)?;
    }
    Ok((n, t.elapsed().as_secs_f64()))
}

/// Package energy counter (Linux RAPL), joules.
fn rapl_joules() -> Option<f64> {
    let text = std::fs::read_to_string("/sys/class/powercap/intel-rapl:0/energy_uj").ok()?;
    text.trim().parse::<f64>().ok().map(|uj| uj / 1e6)
}

/// Nonce start for the i-th batch, wrapping before the end of the nonce space.
fn batch_start(done: u64, batch: u64) -> u32 {
    (done % ((1u64 << 32) - batch)) as u32
}

fn cpu_measurements(o: &BenchOpts) -> Result<Value> {
    // 32 zero bits: realistic early-reject rate, essentially no hits.
    let work = synthetic_work(1, 32);
    let p = Prepared::new(&work);
    let mut kernels = Vec::new();
    let (n, s) = measure(o.seconds, |done| {
        Ok(ReferenceBackend.scan(&work, batch_start(done, 1 << 12), 1 << 12, usize::MAX)?.hashes)
    })?;
    let reference = n as f64 / s;
    kernels.push(json!({ "kernel": "reference", "threads": 1, "hashes_per_second": reference, "compressions_per_nonce": 3.0 }));
    for k in Kernel::ALL.into_iter().filter(|k| k.available()) {
        let (n, s) = measure(o.seconds, |done| {
            let mut out = Vec::new();
            scan_range(k, &p, &work, batch_start(done, 1 << 14), 1 << 14, &mut out);
            Ok(1 << 14)
        })?;
        let cpn = if k == Kernel::Midstate { 2.0 } else { 122.0 / 64.0 };
        kernels.push(json!({ "kernel": k.name(), "threads": 1, "hashes_per_second": n as f64 / s, "speedup_vs_reference": n as f64 / s / reference, "compressions_per_nonce": cpn }));
    }
    let backend = CpuBackend::new(Kernel::best(), o.threads)?;
    let e0 = rapl_joules();
    let (n, s) = measure(o.seconds, |done| Ok(backend.scan(&work, batch_start(done, 1 << 24), 1 << 24, usize::MAX)?.hashes))?;
    let energy = match (e0, rapl_joules()) {
        (Some(a), Some(b)) if b > a => json!({ "source": "RAPL package-0", "joules": b - a, "joules_per_hash": (b - a) / n as f64, "watts": (b - a) / s }),
        _ => json!({ "source": null, "note": "no CPU energy counter readable on this platform (RAPL is Linux-only); energy not measured" }),
    };
    let parity = {
        let w = synthetic_work(0x7a, 12);
        let reference_scan = ReferenceBackend.scan(&w, 0, 1 << 20, usize::MAX)?;
        let got = scan_verified(&backend, &w, 0, 1 << 20)?;
        json!({ "nonces": 1 << 20, "zero_bits": 12, "hits": got.found.len(), "matches_reference": got == reference_scan })
    };
    Ok(json!({
        "work": "synthetic header, target with 32 leading zero bits",
        "kernels": kernels,
        "parallel": { "kernel": backend.kernel().name(), "threads": backend.threads(), "hashes_per_second": n as f64 / s, "hashes": n, "seconds": s },
        "energy": energy,
        "parity": parity,
        "expected_work_per_block_factor": 1.0,
        "note": "Midstate, precomputation and early reject lower the cost per nonce; every nonce is still evaluated, so the expected number of hashes per block is unchanged (factor 1.0).",
    }))
}

fn save_bench(kind: &str, mut v: Value) -> Result<Value> {
    v["environment"] = env::environment();
    v["created_at"] = json!(now_iso());
    let store = Store::open_default()?;
    store.save_benchmark(kind, &mut v)?;
    Ok(v)
}

fn bench_cpu(human: bool, o: &BenchOpts) -> Result<(Value, bool)> {
    let v = save_bench("cpu", cpu_measurements(o)?)?;
    for k in v["kernels"].as_array().into_iter().flatten() {
        say!(human, "{:<10} 1 thread   {:>14}  ({:.2}x reference, {:.2} compressions/nonce)", k["kernel"].as_str().unwrap_or(""), fmt_rate(k["hashes_per_second"].as_f64().unwrap_or(0.0)), k["speedup_vs_reference"].as_f64().unwrap_or(1.0), k["compressions_per_nonce"].as_f64().unwrap_or(0.0));
    }
    let par = &v["parallel"];
    say!(human, "{:<10} {} threads {:>14}", par["kernel"].as_str().unwrap_or(""), par["threads"], fmt_rate(par["hashes_per_second"].as_f64().unwrap_or(0.0)));
    say!(human, "parity     {} hits over 2^20 nonces, matches reference: {}", v["parity"]["hits"], v["parity"]["matches_reference"]);
    say!(human, "energy     {}", v["energy"]["note"].as_str().map(str::to_string).unwrap_or_else(|| format!("{:.3e} J/hash", v["energy"]["joules_per_hash"].as_f64().unwrap_or(0.0))));
    say!(human, "saved      {}", v["id"].as_str().unwrap_or(""));
    let ok = v["parity"]["matches_reference"] == true;
    Ok((v, ok))
}

fn gpu_parity(g: &GpuBackend, cpu: &CpuBackend) -> Result<Value> {
    // Digest parity on every lane, across the end of the nonce space.
    let w = synthetic_work(0x9a51, 0);
    let count = 1u32 << 16;
    let start = u32::MAX - count + 1;
    let gpu_hashes = g.hash_dump(&w, start, count)?;
    let mismatches = gpu_hashes.iter().enumerate().filter(|(i, h)| **h != w.midstate.hash_words(start.wrapping_add(*i as u32))).count();
    // Search parity at a 12-bit target.
    let w12 = synthetic_work(0x5ea4, 12);
    let gpu = scan_verified(g, &w12, 0, 1 << 22)?;
    let cpu_scan = scan_verified(cpu, &w12, 0, 1 << 22)?;
    Ok(json!({
        "digest_lanes": count,
        "digest_mismatches": mismatches,
        "search_nonces": 1u64 << 22,
        "search_hits_gpu": gpu.found.len(),
        "search_hits_cpu": cpu_scan.found.len(),
        "search_identical": gpu.found == cpu_scan.found,
        "passed": mismatches == 0 && gpu.found == cpu_scan.found,
    }))
}

fn gpu_throughput(g: &GpuBackend, seconds: f64) -> Result<(u64, f64)> {
    let work = synthetic_work(1, 32);
    let batch = g.batch() as u64;
    measure(seconds, |done| Ok(g.scan(&work, batch_start(done, batch), batch, usize::MAX)?.hashes))
}

fn bench_gpu(human: bool, o: &BenchOpts) -> Result<(Value, bool)> {
    let g = GpuBackend::new(o.gpu_backend.as_deref())?;
    let a = g.adapter();
    say!(human, "adapter    {} [{:?}] driver {} {}", a.name, a.backend, a.driver, a.driver_info);
    g.calibrate(Duration::from_millis(250))?;
    let cpu = CpuBackend::new(Kernel::best(), o.threads)?;
    let parity = gpu_parity(&g, &cpu)?;
    let (n, s) = gpu_throughput(&g, o.seconds)?;
    let v = save_bench("gpu", json!({
        "adapter": adapter_json(a),
        "kernel": "gpu/wgsl/sha256d.wgsl (straightforward midstate kernel, no early reject)",
        "batch_nonces": g.batch(),
        "hashes_per_second": n as f64 / s,
        "hashes": n,
        "seconds": s,
        "parity": parity,
        "energy": { "source": null, "note": "no GPU power counter exposed through wgpu; energy not measured" },
        "expected_work_per_block_factor": 1.0,
    }))?;
    say!(human, "batch      {} nonces/dispatch", g.batch());
    say!(human, "gpu        {}", fmt_rate(v["hashes_per_second"].as_f64().unwrap_or(0.0)));
    say!(human, "parity     {} digest lanes, {} mismatches; search {} vs {} hits, identical: {}", parity["digest_lanes"], parity["digest_mismatches"], parity["search_hits_gpu"], parity["search_hits_cpu"], parity["search_identical"]);
    say!(human, "saved      {}", v["id"].as_str().unwrap_or(""));
    let ok = parity["passed"] == true;
    Ok((v, ok))
}

fn bench_compare(human: bool, o: &BenchOpts) -> Result<(Value, bool)> {
    let g = GpuBackend::new(o.gpu_backend.as_deref())?;
    g.calibrate(Duration::from_millis(250))?;
    let cpu = CpuBackend::new(Kernel::best(), o.threads)?;
    let parity = gpu_parity(&g, &cpu)?;
    let work = synthetic_work(1, 32);
    let (cn, cs) = measure(o.seconds, |done| Ok(cpu.scan(&work, batch_start(done, 1 << 24), 1 << 24, usize::MAX)?.hashes))?;
    let (gn, gs) = gpu_throughput(&g, o.seconds)?;
    let (cpu_rate, gpu_rate) = (cn as f64 / cs, gn as f64 / gs);
    // Concurrent: GPU driven from one thread, CPU backend on the remaining threads.
    let cpu_threads = cpu.threads().saturating_sub(1).max(1);
    let cpu2 = CpuBackend::new(Kernel::best(), cpu_threads)?;
    let (gpu_conc, cpu_conc) = std::thread::scope(|s| {
        let gh = s.spawn(|| gpu_throughput(&g, o.seconds));
        let c = measure(o.seconds, |done| Ok(cpu2.scan(&work, batch_start(done, 1 << 24), 1 << 24, usize::MAX)?.hashes));
        (gh.join().expect("gpu thread"), c)
    });
    let (gpu_conc, cpu_conc) = (gpu_conc?, cpu_conc?);
    let combined = gpu_conc.0 as f64 / gpu_conc.1 + cpu_conc.0 as f64 / cpu_conc.1;
    let a = g.adapter();
    let v = save_bench("compare", json!({
        "cpu": { "kernel": cpu.kernel().name(), "threads": cpu.threads(), "hashes_per_second": cpu_rate },
        "gpu": { "adapter": adapter_json(a), "hashes_per_second": gpu_rate },
        "gpu_over_cpu": gpu_rate / cpu_rate,
        "concurrent": { "cpu_threads": cpu_threads, "cpu_hashes_per_second": cpu_conc.0 as f64 / cpu_conc.1, "gpu_hashes_per_second": gpu_conc.0 as f64 / gpu_conc.1, "combined_hashes_per_second": combined },
        "parity": parity,
        "expected_work_per_block_factor": 1.0,
    }))?;
    say!(human, "cpu        {} ({} x{})", fmt_rate(cpu_rate), cpu.kernel().name(), cpu.threads());
    say!(human, "gpu        {} ({})", fmt_rate(gpu_rate), a.name);
    say!(human, "ratio      gpu/cpu = {:.2}", gpu_rate / cpu_rate);
    say!(human, "concurrent {} (cpu x{} + gpu)", fmt_rate(combined), cpu_threads);
    say!(human, "parity     {}", if parity["passed"] == true { "identical" } else { "MISMATCH" });
    say!(human, "saved      {}", v["id"].as_str().unwrap_or(""));
    let ok = parity["passed"] == true;
    Ok((v, ok))
}

// ---------------------------------------------------------------- research

fn print_experiment(human: bool, rec: &Value) {
    if !human {
        return;
    }
    println!("{}  {}", rec["id"].as_str().unwrap_or(""), rec["name"].as_str().unwrap_or(""));
    println!("  primitive     {}", rec["primitive"].as_str().unwrap_or(""));
    println!("  status        {}  result: {}", rec["status"].as_str().unwrap_or(""), rec["result"].as_str().unwrap_or(""));
    if let Some(claim) = rec["scope"]["full_round_claim"].as_str() {
        println!("  full rounds   {claim}");
    }
    if let Some(h) = rec["hypothesis_status"].as_str() {
        println!("  hypothesis    {} -> {h}", rec["hypothesis_id"].as_str().unwrap_or(""));
    }
    if let Some(cx) = rec["counterexamples"].as_array().filter(|c| !c.is_empty()) {
        println!("  witnesses     {} concrete counterexample/witness records", cx.len());
    }
    if let Some(cfgs) = rec["configurations"].as_array().filter(|c| !c.is_empty()) {
        let rounds = |want: bool| -> std::collections::BTreeSet<u64> {
            cfgs.iter().filter(|c| c["deviation_detected"] == want).filter_map(|c| c["rounds"].as_u64()).collect()
        };
        println!("  deviation at  rounds {:?} (distinct round counts)", rounds(true));
        println!("  clean at      rounds {:?}", rounds(false));
    }
    if rec["verification"].is_object() {
        println!("  verification  {}  {}", rec["verification"]["passed"], rec["verification"]["detail"].as_str().unwrap_or(""));
        println!("  reproduction  matched: {}", rec["reproduction"]["matched"]);
    }
    if let Some(d) = rec["duration_seconds"].as_f64() {
        println!("  duration      {d:.1} s");
    }
    println!("  conclusion    {}", rec["conclusion"].as_str().or(rec["error"].as_str()).unwrap_or(""));
    if let Some(p) = rec["path"].as_str() {
        println!("  record        {p}");
    }
}

fn run_kind(human: bool, store: &Store, kind: Kind, o: &ResearchOpts) -> Result<Value> {
    let overrides: Value = match &o.params {
        Some(text) => serde_json::from_str(text).context("--params must be a JSON object")?,
        None => json!({}),
    };
    say!(human, "running {} (seed {}{})...", kind.id(), o.seed, if o.quick { ", quick" } else { "" });
    let rec = experiment_engine::run(store, kind, &overrides, o.seed, o.quick)?;
    print_experiment(human, &rec);
    Ok(rec)
}

fn experiment_ok(rec: &Value) -> bool {
    matches!(rec["status"].as_str(), Some("completed") | Some("skipped"))
}

fn research(human: bool, cmd: ResearchCmd) -> Result<(Value, bool)> {
    let store = Store::open_default()?;
    let cmd_name = if matches!(cmd, ResearchCmd::Structural(_)) { "structural" } else { "" };
    let single = |kind, o: &ResearchOpts| -> Result<(Value, bool)> {
        let rec = run_kind(human, &store, kind, o)?;
        let ok = experiment_ok(&rec);
        Ok((rec, ok))
    };
    match cmd {
        ResearchCmd::Differential(o) => single(Kind::Differential, &o),
        ResearchCmd::ReducedRound(o) => single(Kind::ReducedRound, &o),
        ResearchCmd::Statistical(o) => single(Kind::Statistical, &o),
        ResearchCmd::Smt(o) => single(Kind::Smt, &o),
        ResearchCmd::Characteristic(o) => single(Kind::Characteristic, &o),
        ResearchCmd::Algebraic(o) => single(Kind::Algebraic, &o),
        ResearchCmd::Schedule(o) => single(Kind::Schedule, &o),
        ResearchCmd::SmtScaling(o) => single(Kind::SmtScaling, &o),
        ResearchCmd::Multiseed(o) => single(Kind::Multiseed, &o),
        ResearchCmd::Hardware(o) => single(Kind::Hardware, &o),
        ResearchCmd::CharacteristicAudit(o) => single(Kind::CharacteristicAudit, &o),
        ResearchCmd::TrailSearch(o) => single(Kind::TrailSearch, &o),
        ResearchCmd::Hypotheses => {
            let rows = store.list_hypotheses()?;
            for h in &rows {
                say!(human, "{:<11} {:<30} {:<44} evidence={}", h["id"].as_str().unwrap_or(""), h["status"].as_str().unwrap_or(""), h["primitive"].as_str().unwrap_or(""), h["evidence_count"]);
            }
            Ok((json!(rows), true))
        }
        ResearchCmd::Hypothesis { id } => {
            let all = store.list_hypotheses()?;
            let h = all.into_iter().find(|h| h["id"] == id.as_str()).with_context(|| format!("no hypothesis {id}"))?;
            let evidence = store.hypothesis_evidence(&id)?;
            say!(human, "{} [{}] {}\n  {}", id, h["primitive"].as_str().unwrap_or(""), h["status"].as_str().unwrap_or(""), h["statement"].as_str().unwrap_or(""));
            for e in &evidence {
                say!(human, "  {} {:<20} {:<26} seed {}  counterexamples: {}", e["experiment_id"].as_str().unwrap_or(""), e["verdict"].as_str().unwrap_or(""), e["scope"].as_str().unwrap_or(""), e["seed"].as_str().unwrap_or("-"), e["counterexamples"].as_array().map_or(0, Vec::len));
            }
            Ok((json!({ "hypothesis": h, "evidence": evidence }), true))
        }
        ResearchCmd::All(o) | ResearchCmd::Structural(o) if o.params.is_some() => {
            bail!("--params is per experiment kind; run kinds individually to override parameters")
        }
        ResearchCmd::All(o) | ResearchCmd::Structural(o) => {
            let kinds: &[Kind] = if matches!(cmd_name, "structural") { &Kind::STRUCTURAL } else { &Kind::MVP };
            let mut recs = Vec::new();
            for &kind in kinds {
                let rec = run_kind(human, &store, kind, &o)?;
                say!(human, "");
                recs.push(rec);
            }
            let ok = recs.iter().all(experiment_ok);
            let summary: Vec<Value> = recs.iter().map(|r| json!({ "id": r["id"], "kind": r["kind"], "status": r["status"], "result": r["result"] })).collect();
            say!(human, "summary: {}", summary.iter().map(|s| format!("{} {} [{}]", s["id"].as_str().unwrap_or(""), s["result"].as_str().unwrap_or(""), s["status"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(", "));
            Ok((json!({ "experiments": recs, "summary": summary }), ok))
        }
        ResearchCmd::List { kind, limit } => {
            let rows = store.list_experiments(kind.as_deref(), limit)?;
            for r in &rows {
                say!(human, "{:<20} {:<20} {:<22} verified={:<5} reproduced={:<5} {}", r["id"].as_str().unwrap_or(""), r["status"].as_str().unwrap_or(""), r["result"].as_str().unwrap_or("-"), r["verified"], r["reproduced"], r["started_at"].as_str().unwrap_or(""));
            }
            Ok((json!(rows), true))
        }
        ResearchCmd::Show { id } => {
            let rec = store.get_experiment(&id)?.with_context(|| format!("no experiment {id}"))?;
            say!(human, "{}", serde_json::to_string_pretty(&rec)?);
            Ok((rec, true))
        }
        ResearchCmd::Audit => {
            let a = experiment_engine::audit(&store)?;
            say!(human, "code        {} (commit {}, binary matches commit: {})", &a["source_fingerprint"].as_str().unwrap_or("")[..16], a["git_commit"].as_str().unwrap_or("none"), a["binary_matches_commit"]);
            for k in a["experiments"].as_array().into_iter().flatten().chain(a["benchmarks"].as_array().into_iter().flatten()) {
                let hist = k["history"].as_array().map_or(0, Vec::len);
                say!(human, "{:<16} current {:<22} history {hist}", k["kind"].as_str().unwrap_or(""), k["current"].as_str().unwrap_or("MISSING"));
            }
            say!(human, "records     {} experiments, {} benchmarks, {} with errata", a["total_experiment_records"], a["total_benchmark_records"], a["records_with_errata"].as_array().map_or(0, Vec::len));
            say!(human, "{}", if a["passed"] == true { "audit: every kind has a current result from this committed code" } else { "audit: FAILED (see missing_current / binary_matches_commit)" });
            let ok = a["passed"] == true;
            Ok((a, ok))
        }
        ResearchCmd::Erratum { id, note } => {
            let rec = store.add_erratum(&id, &note)?;
            say!(human, "{id}: erratum recorded ({} total)", rec["errata"].as_array().map_or(0, Vec::len));
            Ok((json!({ "id": id, "errata": rec["errata"] }), true))
        }
        ResearchCmd::Reproduce { id } => {
            let r = experiment_engine::reproduce(&store, &id)?;
            say!(human, "{id}: digest {} vs recorded {}: {}", r["digest"].as_str().unwrap_or(""), r["original_digest"].as_str().unwrap_or(""), if r["matched"] == true { "REPRODUCED" } else { "NOT REPRODUCED" });
            let ok = r["matched"] == true;
            Ok((r, ok))
        }
    }
}

// ---------------------------------------------------------------- mining

fn mine_regtest(human: bool, backend: &str, bitcoind: Option<PathBuf>, datadir: Option<PathBuf>, keep: bool, threads: usize, gpu_api: Option<&str>) -> Result<(Value, bool)> {
    let exe = bitcoind
        .or_else(|| regtest::find_bitcoind(&workspace_root()))
        .context("bitcoind not found: pass --bitcoind or set BMR_BITCOIND")?;
    let engine: Box<dyn Backend> = match backend {
        "cpu" => Box::new(CpuBackend::new(Kernel::best(), threads)?),
        "gpu" => Box::new(GpuBackend::new(gpu_api)?),
        other => bail!("unknown backend {other:?} (cpu, gpu)"),
    };
    let (dir, temp) = match datadir {
        Some(d) => (d, false),
        None => (regtest::temp_datadir("regtest")?, true),
    };
    say!(human, "node       {} ({})", exe.display(), regtest::bitcoind_version(&exe).unwrap_or_default());
    say!(human, "datadir    {}", dir.display());
    say!(human, "backend    {}", engine.name());
    let result = regtest::run_session(&exe, engine.as_ref(), &dir);
    if temp && !keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    let mut v = result?;
    for c in v["checks"].as_array().into_iter().flatten() {
        say!(human, "{} {}  ({})", if c["passed"] == true { "PASS" } else { "FAIL" }, c["name"].as_str().unwrap_or(""), c["detail"].as_str().unwrap_or(""));
    }
    say!(human, "mined      {} blocks in {:.1} s, {} hashes, all accepted by {}", v["blocks_mined"], v["seconds"].as_f64().unwrap_or(0.0), v["hashes"], v["node"].as_str().unwrap_or("node"));
    v["datadir"] = json!(if keep || !temp { Some(dir.display().to_string()) } else { None });
    let v = save_bench("regtest", v)?;
    say!(human, "saved      {}", v["id"].as_str().unwrap_or(""));
    let ok = v["all_accepted"] == true;
    Ok((v, ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_start_stays_in_range() {
        for done in [0u64, 1 << 31, (1 << 32) - 1, 1 << 40] {
            let b = 1u64 << 24;
            assert!(batch_start(done, b) as u64 + b <= 1 << 32);
        }
    }

    #[test]
    fn cli_parses_all_documented_commands() {
        for args in [
            "bmr system", "bmr verify sha256", "bmr verify bitcoin-header", "bmr benchmark cpu", "bmr benchmark gpu",
            "bmr benchmark compare", "bmr research differential", "bmr research reduced-round", "bmr research statistical",
            "bmr research all", "bmr mine regtest", "bmr --json research smt --quick", "bmr research reproduce x",
            "bmr research characteristic", "bmr research algebraic", "bmr research schedule", "bmr research smt-scaling",
            "bmr research multiseed", "bmr research hardware", "bmr research structural --quick", "bmr research hypotheses",
            "bmr research hypothesis H-CHAR-01",
        ] {
            assert!(Cli::try_parse_from(args.split(' ')).is_ok(), "{args}");
        }
    }
}
