# Hardware research

The working implementation is `crates/hardware-model` (run with
`bmr research hardware`):

- a cycle-level simulator of fully pipelined SHA-256d datapaths (one round per
  stage, one nonce per cycle) that checks every output against the software
  reference and the independent SHA-256;
- resource counts (32-bit adders, Σ/σ, Ch, Maj, register bits) derived from
  the simulated stage list, with optional constant folding of job-constant
  logic;
- an FPGA mapping for three device classes and a throughput/energy model with
  explicit, editable assumptions (`--params '{"cost": {...}}'`).

Variants: `no-midstate`, `midstate`, `+precompute3`, `+early-reject`,
`+fold`, and `no-midstate+early-reject+fold`. The last one is a consistency
check: folding job-constant logic in a design without midstate must re-derive
midstate and the precomputed rounds, and it does.

`fpga/` and `rtl/` are reserved for synthesizable RTL. No RTL is checked in
yet. The next step is to emit Verilog for one round stage from the same stage
list, simulate it against the Rust model, and get real resource and timing
numbers from a synthesis tool (Yosys/nextpnr or Vivado). Neither a simulator
nor a synthesis tool is installed on this machine. Until that runs, every
hardware number in the registry is a `model-estimate`.
