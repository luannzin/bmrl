# Native Vulkan experiments

Status: not started.

The production GPU path (`crates/gpu-backend`, `gpu/wgsl/sha256d.wgsl`) already
runs on Vulkan through wgpu, and on the RX 7600 it selects the Vulkan adapter
(AMD proprietary driver, LLPC compiler). A native Vulkan/SPIR-V path is only
worth building if profiling shows wgpu or the WGSL-to-SPIR-V translation is
the bottleneck. The first step is a comparison point: compile the same kernel
with `glslangValidator`/`naga` to SPIR-V, inspect the ISA with Radeon GPU
Analyzer, and compare with `bmr benchmark gpu`.

Candidate kernel experiments, each to be measured against the verified WGSL
baseline with `bmr benchmark gpu` parity checks:

- early reject after outer round 60 (as in the CPU scalar kernel),
- precomputing W16/W17 and the first three second-block rounds on the host,
- several nonces per invocation to amortise the midstate loads.
