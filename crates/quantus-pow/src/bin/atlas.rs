//! Quantus QPoW output-bias atlas. Runs a reduced-round frontier (positive
//! controls) up to the full live schedule, printing each lens's verdict.
//!
//! Usage: atlas [samples] [tail_k]   (defaults 2_000_000 and 10)

use quantus_pow::{attack, Rounds};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    let tail_k: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let block_hash = [0u8; 32];

    let schedules = [
        Rounds { ext_init: 0, n_int: 0, ext_term: 0 }, // linear (pure control)
        Rounds { ext_init: 1, n_int: 0, ext_term: 0 }, // degree 7
        Rounds { ext_init: 2, n_int: 0, ext_term: 0 },
        Rounds { ext_init: 4, n_int: 0, ext_term: 0 },
        Rounds { ext_init: 4, n_int: 4, ext_term: 0 },
        Rounds { ext_init: 4, n_int: 11, ext_term: 4 },
        Rounds::FULL, // live Quantus
    ];

    println!("Quantus QPoW output-bias atlas  (block_hash=0, sequential nonces)");
    println!("samples(full)={samples}  tail_k={tail_k}  bits swept={}", attack::SWEEP_BITS);
    for r in schedules {
        let n = if r == Rounds::FULL { samples } else { samples.min(1 << 20) };
        let res = attack::run(block_hash, r, n, tail_k);
        println!("{res}");
    }
}
