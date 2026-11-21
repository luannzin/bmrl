//! Criterion micro-benchmark of single-thread kernels: `cargo bench -p cpu-backend`.

use cpu_backend::{Kernel, Prepared, scan_range};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mining_engine::{Backend, ReferenceBackend, synthetic_work};

fn kernels(c: &mut Criterion) {
    // 32 zero bits: realistic early-reject rate, essentially no hits.
    let work = synthetic_work(1, 32);
    let p = Prepared::new(&work);
    const N: u32 = 1 << 12;
    let mut g = c.benchmark_group("sha256d-nonce-scan");
    g.throughput(Throughput::Elements(N as u64));
    g.bench_function("reference", |b| b.iter(|| ReferenceBackend.scan(&work, 0, N as u64, usize::MAX).unwrap()));
    for k in Kernel::ALL.into_iter().filter(|k| k.available()) {
        g.bench_function(k.name(), |b| {
            b.iter(|| {
                let mut out = Vec::new();
                scan_range(k, &p, &work, 0, N, &mut out);
                out
            })
        });
    }
    g.finish();
}

criterion_group!(benches, kernels);
criterion_main!(benches);
