//! Quantus QPoW miner benchmark + a real solve at a chosen difficulty.
//!
//! Usage: mine [bench_hashes_per_thread] [solve_difficulty]
//! defaults: 1_000_000 per thread, difficulty 2^24.

use quantus_pow::miner::{is_valid, nonce_of, target_be};
use quantus_pow::qpow_hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let per_thread: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let difficulty: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1 << 24);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).max(1);
    let block_hash = [0u8; 32];

    // ---- Hashrate benchmark ----
    let total = per_thread * threads as u64;
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            let bh = block_hash;
            s.spawn(move || {
                let base = (t as u64) << 40; // disjoint ranges, no overlap
                let mut sink = 0u64;
                for i in 0..per_thread {
                    let h = qpow_hash(&bh, &nonce_of(base + i));
                    sink ^= h[0] as u64; // keep the compiler from eliding the work
                }
                std::hint::black_box(sink);
            });
        }
    });
    let secs = t0.elapsed().as_secs_f64();
    let hs = total as f64 / secs;
    println!("Quantus QPoW miner  (CPU, {threads} threads)");
    println!(
        "bench: {total} hashes in {secs:.2}s = {:.3} MH/s  ({:.0} H/s/thread)",
        hs / 1e6,
        hs / threads as f64
    );

    // ---- Real solve at `difficulty` ----
    let target = target_be(difficulty);
    let found = AtomicU64::new(u64::MAX);
    let stop = AtomicBool::new(false);
    let count = AtomicU64::new(0);
    let t1 = Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            let bh = block_hash;
            let target = &target;
            let found = &found;
            let stop = &stop;
            let count = &count;
            s.spawn(move || {
                let mut ctr = t as u64;
                let stride = threads as u64;
                let mut local = 0u64;
                let mut nonce = [0u8; 64];
                loop {
                    if local % 4096 == 0 && stop.load(Ordering::Relaxed) {
                        break;
                    }
                    nonce[56..64].copy_from_slice(&ctr.to_be_bytes());
                    let h = qpow_hash(&bh, &nonce);
                    local += 1;
                    if is_valid(&h, target) {
                        found.store(ctr, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                    ctr = ctr.wrapping_add(stride);
                }
                count.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    let solve_secs = t1.elapsed().as_secs_f64();
    let hashes = count.load(Ordering::Relaxed);
    let nonce_ctr = found.load(Ordering::SeqCst);

    println!(
        "\nsolve: difficulty 2^{:.1} (= {difficulty}), expected ~{difficulty} hashes",
        (difficulty as f64).log2()
    );
    if nonce_ctr != u64::MAX {
        let h = qpow_hash(&block_hash, &nonce_of(nonce_ctr));
        let valid = is_valid(&h, &target);
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        println!("  FOUND nonce counter = {nonce_ctr} in {hashes} hashes, {solve_secs:.2}s");
        println!("  hash = {hex}");
        println!("  independent re-check is_valid = {valid}");
    } else {
        println!("  no solution in the searched range");
    }
}
