//! Bitcoin Core regtest integration: node lifecycle, template-to-block
//! assembly, proof-of-work search, submission and acceptance checks.

use crate::rpc::Rpc;
use crate::{Backend, Work, find_nonce};
use anyhow::{Context, Result, bail, ensure};
use bitcoin_header::block::{Coinbase, serialize_block};
use bitcoin_header::{BlockHeader, Target, hex_decode, hex_encode, merkle_root, parse_display_hex};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const COIN: u64 = 100_000_000;
/// Regtest block subsidy below the first halving (height 150).
const REGTEST_SUBSIDY: u64 = 50 * COIN;
const COINBASE_MATURITY: u64 = 100;

/// Locate `bitcoind`: `BMR_BITCOIND`, then `<root>/tools/bitcoin-core/*/bin`, then `PATH`.
pub fn find_bitcoind(root: &Path) -> Option<PathBuf> {
    let exe = if cfg!(windows) { "bitcoind.exe" } else { "bitcoind" };
    if let Some(p) = std::env::var_os("BMR_BITCOIND") {
        return Some(PathBuf::from(p));
    }
    let tools = root.join("tools").join("bitcoin-core");
    if let Ok(entries) = std::fs::read_dir(&tools) {
        let mut found: Vec<PathBuf> = entries.flatten().map(|e| e.path().join("bin").join(exe)).filter(|p| p.is_file()).collect();
        found.sort();
        if let Some(p) = found.pop() {
            return Some(p);
        }
    }
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(exe)).find(|p| p.is_file()))
}

/// First line of `bitcoind -version`.
pub fn bitcoind_version(bitcoind: &Path) -> Option<String> {
    let out = Command::new(bitcoind).arg("-version").stderr(Stdio::null()).output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().next().map(str::to_string)
}

/// Fresh empty directory for a throwaway node.
pub fn temp_datadir(tag: &str) -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("bmrl-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Independent validation of the header engine against Bitcoin Core: let
/// the node mine `blocks` blocks itself (`generatetoaddress`), then parse
/// each raw header with our code and compare every field, the hash, the
/// decoded target and the proof-of-work check with the node's own view.
pub fn validate_core_headers(bitcoind: &Path, datadir: &Path, blocks: u32) -> Result<Value> {
    use bitcoin_header::{REGTEST_POW_LIMIT_BITS, check_proof_of_work, display_hex};
    let node = Node::start(bitcoind, datadir)?;
    let rpc = &node.rpc;
    rpc.call("createwallet", json!(["bmrl-verify"]))?;
    let address = rpc.call("getnewaddress", json!([]))?;
    rpc.call("generatetoaddress", json!([blocks, address]))?;
    let mut failures = Vec::new();
    for height in 0..=blocks {
        let hash = rpc.call("getblockhash", json!([height]))?;
        let hash = hash.as_str().context("hash")?;
        let raw = rpc.call("getblockheader", json!([hash, false]))?;
        let v = rpc.call("getblockheader", json!([hash, true]))?;
        let h = BlockHeader::from_hex(raw.as_str().context("raw header")?)?;
        let mut problems = Vec::new();
        let bits = u32::from_str_radix(v["bits"].as_str().unwrap_or(""), 16).ok();
        if h.block_hash_hex() != hash {
            problems.push("hash");
        }
        if Some(h.version as i64) != v["version"].as_i64() {
            problems.push("version");
        }
        if Some(h.time as u64) != v["time"].as_u64() || Some(h.nonce as u64) != v["nonce"].as_u64() || Some(h.bits) != bits {
            problems.push("time/nonce/bits");
        }
        if Some(display_hex(&h.merkle_root).as_str()) != v["merkleroot"].as_str() {
            problems.push("merkleroot");
        }
        if height > 0 && Some(display_hex(&h.prev_blockhash).as_str()) != v["previousblockhash"].as_str() {
            problems.push("previousblockhash");
        }
        if let Some(t) = v["target"].as_str() {
            if Target::from_hex(t)? != Target::from_compact(h.bits).target {
                problems.push("target");
            }
        }
        if check_proof_of_work(&h.hash(), h.bits, REGTEST_POW_LIMIT_BITS) != Ok(true) {
            problems.push("proof-of-work");
        }
        if !problems.is_empty() {
            failures.push(json!({ "height": height, "hash": hash, "mismatches": problems }));
        }
    }
    let version = rpc.call("getnetworkinfo", json!([]))?["subversion"].clone();
    node.stop()?;
    Ok(json!({ "node": version, "headers_checked": blocks + 1, "failures": failures, "passed": failures.is_empty() }))
}

/// A `bitcoind -regtest` child process with an authenticated RPC client.
pub struct Node {
    child: Child,
    pub datadir: PathBuf,
    pub rpc: Rpc,
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn debug_log_tail(datadir: &Path) -> String {
    let log = std::fs::read_to_string(datadir.join("regtest").join("debug.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

impl Node {
    pub fn start(bitcoind: &Path, datadir: &Path) -> Result<Self> {
        std::fs::create_dir_all(datadir)?;
        let (rpc_port, p2p_port) = (free_port()?, free_port()?);
        let mut child = Command::new(bitcoind)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .args(["-server=1", "-listen=0", "-fallbackfee=0.0002", "-printtoconsole=0"])
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting {}", bitcoind.display()))?;
        let url = format!("http://127.0.0.1:{rpc_port}/");
        let cookie = datadir.join("regtest").join(".cookie");
        let deadline = Instant::now() + Duration::from_secs(120);
        let rpc = loop {
            if let Some(status) = child.try_wait()? {
                bail!("bitcoind exited during startup ({status}):\n{}", debug_log_tail(datadir));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!("bitcoind RPC not ready after 120 s:\n{}", debug_log_tail(datadir));
            }
            // Until the node writes a fresh cookie and finishes warm-up, calls fail.
            if let Ok(rpc) = Rpc::from_cookie(&url, &cookie) {
                if rpc.call("getblockchaininfo", json!([])).is_ok() {
                    break rpc;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        Ok(Self { child, datadir: datadir.to_path_buf(), rpc })
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        let _ = self.rpc.call("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.child.kill()?;
        self.child.wait()?;
        bail!("bitcoind did not stop within 60 s and was killed")
    }

    pub fn stop(mut self) -> Result<()> {
        self.shutdown()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Clone, Debug)]
pub struct MinedBlock {
    pub height: i64,
    /// Display (RPC) hex.
    pub hash: String,
    pub header_hex: String,
    pub nonce: u32,
    pub extra_nonce: u64,
    pub hashes: u64,
    pub seconds: f64,
    pub transactions: usize,
    pub coinbase_value: u64,
    pub fees: u64,
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("template field {key} missing"))
}

/// A parsed `getblocktemplate` response.
pub struct Template {
    pub height: i64,
    pub value: u64,
    pub bits: u32,
    pub target: Target,
    commitment: Option<Vec<u8>>,
    txs: Vec<Vec<u8>>,
    txids: Vec<[u8; 32]>,
    pub fees: u64,
    prev_blockhash: [u8; 32],
    version: i32,
    time: u32,
}

impl Template {
    pub fn fetch(rpc: &Rpc) -> Result<Self> {
        let t = rpc.call("getblocktemplate", json!([{ "rules": ["segwit"] }]))?;
        let bits = u32::from_str_radix(str_field(&t, "bits")?, 16)?;
        let target = Target::from_hex(str_field(&t, "target")?)?;
        // Independent check of our compact decoder against the node.
        ensure!(Target::from_compact(bits).target == target, "template target {} disagrees with bits {bits:08x}", target.to_hex());
        let (mut txs, mut txids, mut fees) = (Vec::new(), Vec::new(), 0u64);
        for tx in t["transactions"].as_array().context("template transactions")? {
            txs.push(hex_decode(str_field(tx, "data")?)?);
            txids.push(parse_display_hex(str_field(tx, "txid")?)?);
            fees += tx["fee"].as_u64().unwrap_or(0);
        }
        Ok(Self {
            height: t["height"].as_i64().context("template height")?,
            value: t["coinbasevalue"].as_u64().context("template coinbasevalue")?,
            bits,
            target,
            commitment: t.get("default_witness_commitment").and_then(Value::as_str).map(hex_decode).transpose()?,
            txs,
            txids,
            fees,
            prev_blockhash: parse_display_hex(str_field(&t, "previousblockhash")?)?,
            version: t["version"].as_i64().context("template version")? as i32,
            time: t["curtime"].as_u64().context("template curtime")? as u32,
        })
    }

    pub fn transactions(&self) -> usize {
        self.txs.len() + 1
    }

    /// Coinbase and header (nonce 0) for `extra_nonce`: the merkle root changes with it.
    pub fn candidate(&self, payout_script: &[u8], extra_nonce: u64) -> (BlockHeader, Coinbase) {
        let coinbase = Coinbase {
            height: self.height,
            value: self.value,
            script_pubkey: payout_script.to_vec(),
            extra_nonce,
            tag: b"/BMRL/".to_vec(),
            witness_commitment: self.commitment.clone(),
        };
        let mut ids = vec![coinbase.txid()];
        ids.extend_from_slice(&self.txids);
        let header = BlockHeader { version: self.version, prev_blockhash: self.prev_blockhash, merkle_root: merkle_root(&ids), time: self.time, bits: self.bits, nonce: 0 };
        (header, coinbase)
    }

    /// Serialize and submit a block; `Err` unless the node accepts it.
    pub fn submit(&self, rpc: &Rpc, header: &BlockHeader, coinbase: &Coinbase) -> Result<()> {
        let mut all = vec![coinbase.serialize(true)];
        all.extend(self.txs.iter().cloned());
        let result = rpc.call("submitblock", json!([hex_encode(&serialize_block(header, &all))]))?;
        ensure!(result.is_null(), "submitblock rejected {}: {result}", header.block_hash_hex());
        Ok(())
    }
}

/// Payout address of a fresh wallet and its scriptPubKey.
pub fn wallet_script(rpc: &Rpc, wallet: &str) -> Result<Vec<u8>> {
    rpc.call("createwallet", json!([wallet]))?;
    let address = rpc.call("getnewaddress", json!(["", "bech32"]))?;
    let info = rpc.call("getaddressinfo", json!([address]))?;
    hex_decode(str_field(&info, "scriptPubKey")?).map_err(Into::into)
}

/// Fetch a block template, build the coinbase and header, search for proof
/// of work with `backend`, and submit the block.
pub fn mine_template(rpc: &Rpc, backend: &dyn Backend, payout_script: &[u8]) -> Result<MinedBlock> {
    let started = Instant::now();
    let t = Template::fetch(rpc)?;
    let mut hashes = 0;
    for extra_nonce in 0u64..1_000 {
        let (mut header, coinbase) = t.candidate(payout_script, extra_nonce);
        let (nonce, n) = find_nonce(backend, &Work::new(header, t.target), 1 << 20)?;
        hashes += n;
        let Some(nonce) = nonce else { continue };
        header.nonce = nonce;
        t.submit(rpc, &header, &coinbase)?;
        return Ok(MinedBlock {
            height: t.height,
            hash: header.block_hash_hex(),
            header_hex: header.to_hex(),
            nonce,
            extra_nonce,
            hashes,
            seconds: started.elapsed().as_secs_f64(),
            transactions: t.transactions(),
            coinbase_value: t.value,
            fees: t.fees,
        });
    }
    bail!("no valid nonce in 1000 extra-nonce rounds")
}

/// End-to-end header search on a live template: for `seconds`, roll the extra
/// nonce, rebuild coinbase and merkle root, scan the full nonce space with
/// `backend` against `share` (the real target comparison, harder than
/// regtest's so hits are countable), and verify every hit with `check`
/// (an independent SHA-256d of the serialized header). Then submit one hit
/// that also meets the template target and confirm the node accepted it.
pub fn search_and_submit(
    rpc: &Rpc,
    backend: &dyn Backend,
    payout_script: &[u8],
    share: Target,
    seconds: f64,
    check: &dyn Fn(&[u8; 80]) -> [u8; 32],
) -> Result<Value> {
    let started = Instant::now();
    let t = Template::fetch(rpc)?;
    let (mut hashes, mut hits, mut verified, mut extra_nonce) = (0u64, 0u64, 0u64, 0u64);
    let mut block: Option<(BlockHeader, Coinbase)> = None;
    const SLICE: u64 = 1 << 26;
    'search: loop {
        let (header, coinbase) = t.candidate(payout_script, extra_nonce);
        let work = Work::new(header, share);
        let mut start = 0u64;
        while start < 1 << 32 {
            if started.elapsed().as_secs_f64() >= seconds && block.is_some() {
                break 'search;
            }
            let count = SLICE.min((1 << 32) - start);
            let scan = backend.scan(&work, start as u32, count, usize::MAX)?;
            hashes += scan.hashes;
            for nonce in scan.found {
                hits += 1;
                let mut h = header;
                h.nonce = nonce;
                let independent = check(&h.serialize());
                ensure!(share.is_met_by(&independent), "backend {} reported nonce {nonce:#010x} that fails the independent check", backend.name());
                ensure!(independent == h.hash(), "independent hash differs from sha256-core for nonce {nonce:#010x}");
                verified += 1;
                if block.is_none() && t.target.is_met_by(&independent) {
                    block = Some((h, coinbase.clone()));
                }
            }
            start += count;
        }
        extra_nonce += 1;
    }
    let seconds_used = started.elapsed().as_secs_f64();
    let (header, coinbase) = block.context("no hit met the template target")?;
    t.submit(rpc, &header, &coinbase)?;
    let best = rpc.call("getbestblockhash", json!([]))?;
    ensure!(best.as_str() == Some(header.block_hash_hex().as_str()), "node tip {best} is not the submitted block");
    Ok(json!({
        "backend": backend.name(),
        "template_height": t.height,
        "seconds": seconds_used,
        "hashes": hashes,
        "extra_nonce_rolls": extra_nonce + 1,
        "hits": hits,
        "hits_verified_independently": verified,
        "end_to_end_hashes_per_second": hashes as f64 / seconds_used,
        "valid_headers_per_second": verified as f64 / seconds_used,
        "submitted_block": header.block_hash_hex(),
        "submitted_nonce": header.nonce,
        "accepted": true,
    }))
}

fn sats(v: &Value) -> Result<u64> {
    Ok((v.as_f64().context("amount")? * COIN as f64).round() as u64)
}

/// Confirm the node accepted `b` as its tip and stores exactly our header and coinbase.
pub fn verify_accepted(rpc: &Rpc, b: &MinedBlock, payout_script: &[u8]) -> Result<()> {
    let best = rpc.call("getbestblockhash", json!([]))?;
    ensure!(best.as_str() == Some(b.hash.as_str()), "tip is {best}, expected {}", b.hash);
    let raw = rpc.call("getblockheader", json!([b.hash, false]))?;
    let raw = raw.as_str().context("raw header")?;
    ensure!(raw == b.header_hex, "node header {raw} differs from ours {}", b.header_hex);
    ensure!(BlockHeader::from_hex(raw)?.block_hash_hex() == b.hash, "our hash of the node's header differs");
    let blk = rpc.call("getblock", json!([b.hash, 2]))?;
    ensure!(blk["height"].as_i64() == Some(b.height), "height {} != {}", blk["height"], b.height);
    ensure!(blk["tx"].as_array().map(Vec::len) == Some(b.transactions), "transaction count mismatch");
    let out = &blk["tx"][0]["vout"][0];
    ensure!(sats(&out["value"])? == b.coinbase_value, "coinbase pays {}, template said {}", out["value"], b.coinbase_value);
    ensure!(out["scriptPubKey"]["hex"].as_str() == Some(hex_encode(payout_script).as_str()), "coinbase pays a different script");
    Ok(())
}

fn balances(rpc: &Rpc) -> Result<(u64, u64)> {
    let b = rpc.call("getbalances", json!([]))?;
    Ok((sats(&b["mine"]["trusted"])?, sats(&b["mine"]["immature"])?))
}

fn check(checks: &mut Vec<Value>, name: &str, passed: bool, detail: String) -> Result<()> {
    checks.push(json!({ "name": name, "passed": passed, "detail": detail }));
    ensure!(passed, "{name}: {detail}");
    Ok(())
}

/// Full acceptance run on a fresh regtest chain:
/// 1. mine block 1 to a wallet address, verify reward is immature;
/// 2. mine to height 100 (still immature) and 101 (first coinbase matures);
/// 3. send a wallet transaction and mine a block that includes it.
///
/// Every block is built from `getblocktemplate`, searched with `backend`,
/// submitted with `submitblock` and checked with [`verify_accepted`].
pub fn run_session(bitcoind: &Path, backend: &dyn Backend, datadir: &Path) -> Result<Value> {
    let started = Instant::now();
    let empty = std::fs::read_dir(datadir).map_or(true, |mut d| d.next().is_none());
    ensure!(empty, "{} is not empty; the session needs a fresh regtest chain", datadir.display());
    let node = Node::start(bitcoind, datadir)?;
    let rpc = &node.rpc;
    let subversion = rpc.call("getnetworkinfo", json!([]))?["subversion"].clone();
    let script = wallet_script(rpc, "bmrl")?;

    let (mut checks, mut mined) = (Vec::new(), Vec::<MinedBlock>::new());
    let mut mine = |rpc: &Rpc| -> Result<MinedBlock> {
        let b = mine_template(rpc, backend, &script)?;
        verify_accepted(rpc, &b, &script).with_context(|| format!("block {} at height {}", b.hash, b.height))?;
        mined.push(b.clone());
        Ok(b)
    };

    let first = mine(rpc)?;
    check(&mut checks, "block 1 accepted", first.height == 1, format!("hash {}", first.hash))?;
    check(&mut checks, "subsidy", first.coinbase_value == REGTEST_SUBSIDY, format!("coinbase {} sat", first.coinbase_value))?;
    let (trusted, immature) = balances(rpc)?;
    check(&mut checks, "reward immature at depth 1", trusted == 0 && immature == REGTEST_SUBSIDY, format!("trusted {trusted}, immature {immature}"))?;

    while mine(rpc)?.height < COINBASE_MATURITY as i64 {}
    let (trusted, immature) = balances(rpc)?;
    check(
        &mut checks,
        "still immature at depth 100",
        trusted == 0 && immature == COINBASE_MATURITY * REGTEST_SUBSIDY,
        format!("height 100: trusted {trusted}, immature {immature}"),
    )?;

    mine(rpc)?;
    let (trusted, immature) = balances(rpc)?;
    check(
        &mut checks,
        "matures at depth 101",
        trusted == REGTEST_SUBSIDY && immature == COINBASE_MATURITY * REGTEST_SUBSIDY,
        format!("height 101: trusted {trusted}, immature {immature}"),
    )?;

    let to = rpc.call("getnewaddress", json!(["", "bech32"]))?;
    let txid = rpc.call("sendtoaddress", json!([to, 1.0]))?;
    let txid = txid.as_str().context("txid")?.to_string();
    let with_tx = mine(rpc)?;
    let wtx = rpc.call("gettransaction", json!([txid]))?;
    check(
        &mut checks,
        "template transaction mined",
        with_tx.transactions == 2
            && wtx["confirmations"].as_i64() == Some(1)
            && wtx["blockhash"].as_str() == Some(with_tx.hash.as_str())
            && with_tx.fees > 0
            && with_tx.coinbase_value == REGTEST_SUBSIDY + with_tx.fees,
        format!("tx {txid} in {}, fee {} sat collected by coinbase", with_tx.hash, with_tx.fees),
    )?;

    let chain = rpc.call("getblockchaininfo", json!([]))?;
    let height = chain["blocks"].as_u64().unwrap_or(0);
    check(&mut checks, "final height", height == mined.len() as u64, format!("{height} blocks, all mined by {}", backend.name()))?;
    node.stop()?;

    let hashes: u64 = mined.iter().map(|b| b.hashes).sum();
    let summary = |b: &MinedBlock| json!({ "height": b.height, "hash": b.hash, "nonce": b.nonce, "hashes": b.hashes, "transactions": b.transactions });
    Ok(json!({
        "node": subversion,
        "backend": backend.name(),
        "blocks_mined": mined.len(),
        "hashes": hashes,
        "seconds": started.elapsed().as_secs_f64(),
        "checks": checks,
        "first_block": summary(&mined[0]),
        "maturity_block": summary(&mined[COINBASE_MATURITY as usize]),
        "transaction_block": summary(mined.last().context("no blocks")?),
        "all_accepted": true,
    }))
}
