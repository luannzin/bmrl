# Native Vulkan experiments

Status: not started.

The production GPU path (`crates/gpu-backend`, `gpu/wgsl/sha256d.wgsl`) already
runs on Vulkan through wgpu, and on the RX 7600 it selects the Vulkan adapter
(AMD proprietary driver, LLPC compiler). A native Vulkan/SPIR-V path is only
worth building if profiling shows wgpu or the WGSL-to-SPIR-V translation is
the bottleneck. The first step is a comparison point: compile the same kernel
with `glslangValidator`/`naga` to SPIR-V, inspect the ISA with Radeon GPU
Analyzer, and compare with `bmr benchmark gpu`.

The candidate kernel experiments listed here earlier (early reject after
outer round 60, host-precomputed rounds 0..2, nonce-independent schedule
terms hoisted) are done in kernel v2 (`crates/gpu-backend/src/v2.rs`), which
generates fully unrolled WGSL; `bmr benchmark gpu` measures it against v1
with parity checks. Workgroup sizes 64, 128 and 256 gave the same rate.
