//! Minimal Bitcoin P2P client: version handshake and `getheaders`, enough to
//! download the main chain's block headers from public nodes (80 bytes per
//! block, about 75 MB for the whole chain). Nothing here trusts the peer:
//! the caller validates the chain (links, proof of work, retargets).

use anyhow::{Context, Result, bail, ensure};
use bitcoin_header::{BlockHeader, HEADER_LEN};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
pub const MAINNET_PORT: u16 = 8333;
/// Bitcoin Core's main-network DNS seeds.
pub const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
    "seed.mainnet.achownodes.xyz",
];
const PROTOCOL_VERSION: i32 = 70016;
const MAX_PAYLOAD: usize = 4 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256_core::sha256(&sha256_core::sha256(data))
}

fn read_varint(b: &[u8], pos: &mut usize) -> Result<u64> {
    let take = |pos: &mut usize, n: usize| -> Result<u64> {
        let s = b.get(*pos..*pos + n).context("truncated varint")?;
        *pos += n;
        Ok(s.iter().rev().fold(0u64, |acc, &x| (acc << 8) | x as u64))
    };
    Ok(match take(pos, 1)? {
        0xfd => take(pos, 2)?,
        0xfe => take(pos, 4)?,
        0xff => take(pos, 8)?,
        x => x,
    })
}

pub struct Peer {
    stream: TcpStream,
    pub addr: SocketAddr,
    /// The peer's `version` user agent and best height.
    pub user_agent: String,
    pub start_height: i32,
}

impl Peer {
    /// Connect and complete the version/verack handshake.
    pub fn connect(addr: SocketAddr) -> Result<Peer> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let mut peer = Peer { stream, addr, user_agent: String::new(), start_height: 0 };
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut v = Vec::new();
        v.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes()); // services: none
        v.extend_from_slice(&(now as i64).to_le_bytes());
        v.extend_from_slice(&[0u8; 26]); // addr_recv
        v.extend_from_slice(&[0u8; 26]); // addr_from
        v.extend_from_slice(&(now ^ 0x424d_524c_0000_0000).to_le_bytes()); // nonce
        let agent = b"/bmrl:0.1.0/";
        v.push(agent.len() as u8);
        v.extend_from_slice(agent);
        v.extend_from_slice(&0i32.to_le_bytes()); // start height
        v.push(0); // relay: no transactions
        peer.send("version", &v)?;
        let (mut got_version, mut got_verack) = (false, false);
        while !(got_version && got_verack) {
            let (cmd, payload) = peer.recv()?;
            match cmd.as_str() {
                "version" => {
                    ensure!(payload.len() >= 81, "short version message");
                    let mut pos = 80;
                    let len = read_varint(&payload, &mut pos)? as usize;
                    peer.user_agent = String::from_utf8_lossy(payload.get(pos..pos + len).context("truncated user agent")?).into_owned();
                    pos += len;
                    peer.start_height = i32::from_le_bytes(payload.get(pos..pos + 4).context("no start height")?.try_into()?);
                    peer.send("verack", &[])?;
                    got_version = true;
                }
                "verack" => got_verack = true,
                _ => {}
            }
        }
        Ok(peer)
    }

    fn send(&mut self, cmd: &str, payload: &[u8]) -> Result<()> {
        let mut msg = Vec::with_capacity(24 + payload.len());
        msg.extend_from_slice(&MAINNET_MAGIC);
        let mut name = [0u8; 12];
        name[..cmd.len()].copy_from_slice(cmd.as_bytes());
        msg.extend_from_slice(&name);
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&sha256d(payload)[..4]);
        msg.extend_from_slice(payload);
        self.stream.write_all(&msg)?;
        Ok(())
    }

    /// Next message; answers pings on the way.
    fn recv(&mut self) -> Result<(String, Vec<u8>)> {
        loop {
            let mut head = [0u8; 24];
            self.stream.read_exact(&mut head)?;
            ensure!(head[..4] == MAINNET_MAGIC, "wrong network magic from {}", self.addr);
            let cmd = String::from_utf8_lossy(&head[4..16]).trim_end_matches('\0').to_string();
            let len = u32::from_le_bytes(head[16..20].try_into()?) as usize;
            ensure!(len <= MAX_PAYLOAD, "oversized {cmd} message ({len} bytes)");
            let mut payload = vec![0u8; len];
            self.stream.read_exact(&mut payload)?;
            ensure!(sha256d(&payload)[..4] == head[20..24], "bad checksum on {cmd}");
            if cmd == "ping" {
                self.send("pong", &payload)?;
                continue;
            }
            return Ok((cmd, payload));
        }
    }

    /// Up to 2000 headers following the first locator hash the peer knows.
    pub fn get_headers(&mut self, locator: &[[u8; 32]]) -> Result<Vec<BlockHeader>> {
        let mut p = Vec::new();
        p.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
        bitcoin_header::block::write_varint(&mut p, locator.len() as u64);
        for h in locator {
            p.extend_from_slice(h);
        }
        p.extend_from_slice(&[0u8; 32]);
        self.send("getheaders", &p)?;
        loop {
            let (cmd, payload) = self.recv()?;
            if cmd != "headers" {
                continue;
            }
            let mut pos = 0;
            let n = read_varint(&payload, &mut pos)? as usize;
            ensure!(n <= 2000, "peer sent {n} headers");
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let raw: &[u8; HEADER_LEN] = payload.get(pos..pos + HEADER_LEN).context("truncated headers message")?.try_into()?;
                out.push(BlockHeader::deserialize(raw));
                pos += HEADER_LEN;
                read_varint(&payload, &mut pos)?; // transaction count, always 0
            }
            return Ok(out);
        }
    }
}

/// Addresses from the DNS seeds (IPv4 and IPv6), seed by seed.
pub fn seed_addresses() -> Vec<SocketAddr> {
    MAINNET_SEEDS.iter().flat_map(|s| (*s, MAINNET_PORT).to_socket_addrs().map(|a| a.take(8).collect::<Vec<_>>()).unwrap_or_default()).collect()
}

/// Locator for `chain`: the last 10 hashes, then exponentially sparser, then genesis.
pub fn locator(hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let mut i = hashes.len() as i64 - 1;
    let mut step = 1;
    while i > 0 {
        out.push(hashes[i as usize]);
        if out.len() >= 10 {
            step *= 2;
        }
        i -= step;
    }
    if let Some(g) = hashes.first() {
        out.push(*g);
    }
    out
}

/// Extend `chain` (starting at genesis) to the tip of one peer, trying seed
/// peers until one serves. Returns the peer used. Headers are linked to
/// their predecessor here; every other rule is the caller's to check.
pub fn sync_headers(chain: &mut Vec<BlockHeader>, progress: &mut dyn FnMut(usize)) -> Result<String> {
    ensure!(!chain.is_empty(), "start from at least the genesis header");
    let mut hashes: Vec<[u8; 32]> = chain.iter().map(BlockHeader::hash).collect();
    let mut errors = Vec::new();
    for addr in seed_addresses() {
        let mut peer = match Peer::connect(addr) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{addr}: {e:#}"));
                continue;
            }
        };
        loop {
            let batch = match peer.get_headers(&locator(&hashes)) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("{addr}: {e:#}"));
                    break;
                }
            };
            if batch.is_empty() {
                return Ok(format!("{} {} (height {})", peer.addr, peer.user_agent, peer.start_height));
            }
            // The peer answers from the fork point it found in the locator.
            let fork = hashes.iter().rposition(|h| *h == batch[0].prev_blockhash).context("peer's headers do not connect to our chain")?;
            chain.truncate(fork + 1);
            hashes.truncate(fork + 1);
            for h in batch {
                if h.prev_blockhash != *hashes.last().expect("non-empty") {
                    bail!("unlinked header from {addr}");
                }
                hashes.push(h.hash());
                chain.push(h);
            }
            progress(chain.len() - 1);
        }
    }
    bail!("no peer served headers: {}", errors.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_and_locator() {
        let mut v = Vec::new();
        for n in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, u32::MAX as u64 + 1] {
            v.clear();
            bitcoin_header::block::write_varint(&mut v, n);
            let mut pos = 0;
            assert_eq!(read_varint(&v, &mut pos).unwrap(), n);
            assert_eq!(pos, v.len());
        }
        let hashes: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
        let loc = locator(&hashes);
        assert_eq!(loc[0], [99; 32]);
        assert_eq!(*loc.last().unwrap(), [0; 32]);
        assert!(loc.len() < 20);
    }
}
