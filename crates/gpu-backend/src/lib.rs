//! wgpu/WGSL SHA-256d nonce search.
//!
//! Runs `gpu/wgsl/sha256d.wgsl` through wgpu on Vulkan, DX12 or Metal, so AMD,
//! NVIDIA, Intel and Apple GPUs share one code path (no CUDA assumption).
//!
//! Error handling: shader/pipeline creation is wrapped in a validation error
//! scope; device loss and uncaptured errors are recorded and surface as
//! `Err` on the next dispatch; every wait has a timeout. Hits returned by
//! [`GpuBackend::scan`] are re-verified on the CPU by `mining_engine`.

use anyhow::{Context, Result, anyhow, bail, ensure};
use mining_engine::{Backend, Scan, Work};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

pub const SHADER: &str = include_str!("../../../gpu/wgsl/sha256d.wgsl");
const WORKGROUP: u32 = 256;
/// Hit slots per dispatch; a dispatch with more hits is split and rerun.
const CAPACITY: u32 = 4096;
const PARAM_WORDS: usize = 28;
/// Most digests one `hash_dump` call returns.
pub const DUMP_MAX: u32 = 1 << 20;
const WAIT: Duration = Duration::from_secs(20);

/// Adapter description for discovery output.
#[derive(Clone, Debug)]
pub struct AdapterSummary {
    pub name: String,
    pub backend: String,
    pub device_type: String,
    pub driver: String,
    pub driver_info: String,
    pub vendor_id: u32,
    pub device_id: u32,
}

fn summarize(info: &wgpu::AdapterInfo) -> AdapterSummary {
    AdapterSummary {
        name: info.name.clone(),
        backend: format!("{:?}", info.backend),
        device_type: format!("{:?}", info.device_type),
        driver: info.driver.clone(),
        driver_info: info.driver_info.clone(),
        vendor_id: info.vendor,
        device_id: info.device,
    }
}

fn parse_backends(filter: Option<&str>) -> Result<wgpu::Backends> {
    Ok(match filter.map(str::to_ascii_lowercase).as_deref() {
        None | Some("auto") | Some("all") => wgpu::Backends::PRIMARY,
        Some("vulkan") => wgpu::Backends::VULKAN,
        Some("dx12") => wgpu::Backends::DX12,
        Some("metal") => wgpu::Backends::METAL,
        Some(other) => bail!("unknown GPU backend {other:?} (auto, vulkan, dx12, metal)"),
    })
}

fn instance(backends: wgpu::Backends) -> wgpu::Instance {
    wgpu::Instance::new(wgpu::InstanceDescriptor { backends, ..wgpu::InstanceDescriptor::new_without_display_handle() })
}

/// Every adapter wgpu can see on every backend.
pub fn list_adapters() -> Vec<AdapterSummary> {
    let all = wgpu::Backends::all();
    pollster::block_on(instance(all).enumerate_adapters(all)).iter().map(|a| summarize(&a.get_info())).collect()
}

struct Buffers {
    params: wgpu::Buffer,
    found: wgpu::Buffer,
    found_read: wgpu::Buffer,
    dump: wgpu::Buffer,
    dump_read: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
}

pub struct GpuBackend {
    device: wgpu::Device,
    queue: wgpu::Queue,
    info: wgpu::AdapterInfo,
    search: wgpu::ComputePipeline,
    dump: wgpu::ComputePipeline,
    max_groups: u32,
    /// Nonces per dispatch; tuned by [`GpuBackend::calibrate`].
    batch: AtomicU32,
    fault: Arc<Mutex<Option<String>>>,
    /// Serializes use of the shared buffers.
    buffers: Mutex<Buffers>,
}

impl GpuBackend {
    /// Open the best GPU for `backend` (`None`/"auto": discrete first, Vulkan preferred).
    pub fn new(backend: Option<&str>) -> Result<Self> {
        let backends = parse_backends(backend)?;
        let adapter = pollster::block_on(instance(backends).enumerate_adapters(backends))
            .into_iter()
            .filter(|a| matches!(a.get_info().device_type, wgpu::DeviceType::DiscreteGpu | wgpu::DeviceType::IntegratedGpu))
            .max_by_key(|a| {
                let i = a.get_info();
                (i.device_type == wgpu::DeviceType::DiscreteGpu, i.backend == wgpu::Backend::Vulkan)
            })
            .context("no hardware GPU adapter found (wgpu: Vulkan/DX12/Metal)")?;
        let info = adapter.get_info();
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("bmrl"),
            required_limits: adapter.limits(),
            ..Default::default()
        }))
        .with_context(|| format!("opening {}", info.name))?;

        let fault = Arc::new(Mutex::new(None::<String>));
        let f = fault.clone();
        device.set_device_lost_callback(move |reason, msg| {
            *f.lock().expect("fault lock") = Some(format!("device lost ({reason:?}): {msg}"));
        });
        let f = fault.clone();
        device.on_uncaptured_error(Arc::new(move |e: wgpu::Error| {
            *f.lock().expect("fault lock") = Some(format!("uncaptured GPU error: {e}"));
        }));

        let scope = device.push_error_scope(wgpu::ErrorFilter::Validation);
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("sha256d.wgsl"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let storage = |binding, read_only| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("sha256d"),
            entries: &[storage(0, true), storage(1, false), storage(2, false)],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("sha256d"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = |entry: &str| {
            device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(entry),
                layout: Some(&pipeline_layout),
                module: &module,
                entry_point: Some(entry),
                compilation_options: Default::default(),
                cache: None,
            })
        };
        let (search, dump) = (pipeline("search"), pipeline("dump_hashes"));
        if let Some(e) = pollster::block_on(scope.pop()) {
            bail!("WGSL shader or pipeline rejected: {e}");
        }

        let buf = |label, size: u64, usage| device.create_buffer(&wgpu::BufferDescriptor { label: Some(label), size, usage, mapped_at_creation: false });
        use wgpu::BufferUsages as U;
        let found_bytes = (1 + CAPACITY as u64) * 4;
        let dump_bytes = DUMP_MAX as u64 * 32;
        let params = buf("params", (PARAM_WORDS * 4) as u64, U::STORAGE | U::COPY_DST);
        let found = buf("found", found_bytes, U::STORAGE | U::COPY_SRC | U::COPY_DST);
        let found_read = buf("found-readback", found_bytes, U::MAP_READ | U::COPY_DST);
        let dump_buf = buf("dump", dump_bytes, U::STORAGE | U::COPY_SRC);
        let dump_read = buf("dump-readback", dump_bytes, U::MAP_READ | U::COPY_DST);
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("sha256d"),
            layout: &layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: params.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: found.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: dump_buf.as_entire_binding() },
            ],
        });
        let max_groups = device.limits().max_compute_workgroups_per_dimension;
        Ok(Self {
            device,
            queue,
            info,
            search,
            dump,
            max_groups,
            batch: AtomicU32::new(1 << 24),
            fault,
            buffers: Mutex::new(Buffers { params, found, found_read, dump: dump_buf, dump_read, bind_group }),
        })
    }

    pub fn adapter(&self) -> AdapterSummary {
        summarize(&self.info)
    }

    pub fn batch(&self) -> u32 {
        self.batch.load(Ordering::Relaxed)
    }

    fn check_fault(&self) -> Result<()> {
        match self.fault.lock().expect("fault lock").clone() {
            Some(msg) => bail!("{msg}"),
            None => Ok(()),
        }
    }

    fn params(work: &Work, start: u32, count: u32, per_invocation: u32, stride: u32) -> [u32; PARAM_WORDS] {
        let mut p = [0u32; PARAM_WORDS];
        p[0..8].copy_from_slice(&work.midstate.state);
        p[8..11].copy_from_slice(&work.midstate.tail);
        p[12..20].copy_from_slice(&work.target.words());
        p[20] = start;
        p[21] = count;
        p[22] = per_invocation;
        p[23] = stride;
        p[24] = CAPACITY;
        p
    }

    /// One dispatch plus readback of `bytes` from `src`.
    fn run(&self, b: &Buffers, pipeline: &wgpu::ComputePipeline, params: &[u32; PARAM_WORDS], groups: u32, src: &wgpu::Buffer, dst: &wgpu::Buffer, bytes: u64) -> Result<Vec<u32>> {
        self.check_fault()?;
        self.queue.write_buffer(&b.params, 0, bytemuck::cast_slice(params));
        self.queue.write_buffer(&b.found, 0, &0u32.to_le_bytes());
        let mut enc = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("sha256d") });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, &b.bind_group, &[]);
            pass.dispatch_workgroups(groups, 1, 1);
        }
        enc.copy_buffer_to_buffer(src, 0, dst, 0, bytes);
        let index = self.queue.submit([enc.finish()]);
        let (tx, rx) = mpsc::channel();
        dst.map_async(wgpu::MapMode::Read, 0..bytes, move |r| {
            let _ = tx.send(r);
        });
        self.device
            .poll(wgpu::PollType::Wait { submission_index: Some(index), timeout: Some(WAIT) })
            .map_err(|e| anyhow!("GPU wait failed: {e:?}"))?;
        self.check_fault()?;
        rx.recv_timeout(WAIT).context("readback timed out")?.map_err(|e| anyhow!("readback failed: {e:?}"))?;
        let words = {
            let view = dst.get_mapped_range(0..bytes).map_err(|e| anyhow!("mapping readback: {e:?}"))?;
            view.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
        };
        dst.unmap();
        Ok(words)
    }

    fn search_batch(&self, b: &Buffers, work: &Work, start: u32, count: u32, max_found: usize) -> Result<Vec<u32>> {
        let groups = count.div_ceil(WORKGROUP).min(self.max_groups);
        let stride = groups * WORKGROUP;
        let params = Self::params(work, start, count, count.div_ceil(stride), stride);
        let words = self.run(b, &self.search, &params, groups, &b.found, &b.found_read, (1 + CAPACITY as u64) * 4)?;
        let hits = words[0];
        if hits > CAPACITY && max_found > CAPACITY as usize {
            // Slots overflowed and the caller wants every hit: split and rerun.
            let half = count / 2;
            let mut out = self.search_batch(b, work, start, half, max_found)?;
            out.extend(self.search_batch(b, work, start.wrapping_add(half), count - half, max_found)?);
            return Ok(out);
        }
        Ok(words[1..1 + hits.min(CAPACITY) as usize].to_vec())
    }

    /// Full SHA-256d digests (H0..H7) for `count <= DUMP_MAX` nonces from `start`.
    pub fn hash_dump(&self, work: &Work, start: u32, count: u32) -> Result<Vec<[u32; 8]>> {
        ensure!(count <= DUMP_MAX && start as u64 + count as u64 <= 1 << 32, "dump range too large");
        let b = self.buffers.lock().expect("buffer lock");
        let groups = count.div_ceil(WORKGROUP);
        let params = Self::params(work, start, count, 1, groups * WORKGROUP);
        let words = self.run(&b, &self.dump, &params, groups, &b.dump, &b.dump_read, count as u64 * 32)?;
        Ok(words.chunks_exact(8).map(|c| c.try_into().expect("8 words")).collect())
    }

    /// Resize the batch so one dispatch takes about `target` (Windows resets
    /// GPU work running longer than ~2 s). Returns the measured rate in H/s.
    pub fn calibrate(&self, target: Duration) -> Result<f64> {
        let work = mining_engine::synthetic_work(0xca1b, 32);
        let mut rate = 0.0;
        for _ in 0..3 {
            let n = self.batch();
            let t = Instant::now();
            self.scan(&work, 0, n as u64, usize::MAX)?;
            let secs = t.elapsed().as_secs_f64();
            rate = n as f64 / secs;
            let next = (rate * target.as_secs_f64()).clamp((1u64 << 20) as f64, (1u64 << 30) as f64) as u32;
            self.batch.store(next / WORKGROUP * WORKGROUP, Ordering::Relaxed);
        }
        Ok(rate)
    }
}

impl Backend for GpuBackend {
    fn name(&self) -> String {
        format!("gpu-wgsl {} ({:?})", self.info.name, self.info.backend)
    }

    fn scan(&self, work: &Work, start: u32, count: u64, max_found: usize) -> Result<Scan> {
        ensure!(start as u64 + count <= 1 << 32, "nonce range exceeds 2^32");
        ensure!(work.midstate.rounds == 64, "GPU kernel is full-round only");
        let b = self.buffers.lock().expect("buffer lock");
        let batch = self.batch() as u64;
        let (mut found, mut hashes, mut s) = (Vec::new(), 0u64, start as u64);
        let end = start as u64 + count;
        while s < end && found.len() < max_found {
            let n = batch.min(end - s);
            found.extend(self.search_batch(&b, work, s as u32, n as u32, max_found)?);
            hashes += n;
            s += n;
        }
        found.sort_unstable();
        Ok(Scan { found, hashes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mining_engine::{ReferenceBackend, scan_verified, synthetic_work};

    fn gpu() -> Option<GpuBackend> {
        match GpuBackend::new(None) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("skipping GPU test: {e:#}");
                None
            }
        }
    }

    #[test]
    fn dump_matches_cpu_reference() {
        let Some(g) = gpu() else { return };
        let work = synthetic_work(9, 0);
        let start = u32::MAX - 40_000;
        let hashes = g.hash_dump(&work, start, 40_001).unwrap();
        for (i, h) in hashes.iter().enumerate() {
            let nonce = start.wrapping_add(i as u32);
            assert_eq!(*h, work.midstate.hash_words(nonce), "nonce {nonce:#x}");
        }
    }

    #[test]
    fn search_matches_reference_including_overflow_split() {
        let Some(g) = gpu() else { return };
        for (seed, bits) in [(1u32, 8u32), (2, 2)] {
            let work = synthetic_work(seed, bits);
            let reference = ReferenceBackend.scan(&work, 123, 50_000, usize::MAX).unwrap();
            assert_eq!(scan_verified(&g, &work, 123, 50_000).unwrap(), reference, "bits {bits}");
        }
    }
}
