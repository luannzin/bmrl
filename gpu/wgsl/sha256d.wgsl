// SHA-256d nonce search over 80-byte Bitcoin block headers (midstate form).
//
// The host computes the midstate (compression of header bytes 0..64) and
// passes the remaining 12 header bytes as big-endian words. Each invocation
// evaluates nonces `nonce_base + j * stride + invocation` for j = 0, 1, ...
// while the offset stays below `count`.
//
// Results must be bit-identical to crates/cpu-backend. `dump_hashes` writes
// full digests so the host can check every lane, not just the hits.

struct Params {
    midstate: array<u32, 8>,
    // Big-endian words of header bytes 64..76 (merkle tail, time, bits); [3] unused.
    tail: array<u32, 4>,
    // 256-bit target as big-endian words, most significant first.
    target_be: array<u32, 8>,
    nonce_base: u32,
    count: u32,
    per_invocation: u32,
    stride: u32,
    capacity: u32,
    pad0: u32,
    pad1: u32,
    pad2: u32,
}

struct Found {
    count: atomic<u32>,
    nonces: array<u32>,
}

@group(0) @binding(0) var<storage, read> params: Params;
@group(0) @binding(1) var<storage, read_write> found: Found;
@group(0) @binding(2) var<storage, read_write> dump: array<u32>;

var<private> K: array<u32, 64> = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

const IV = array<u32, 8>(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
);

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn bsig0(x: u32) -> u32 { return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn bsig1(x: u32) -> u32 { return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn ssig0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u); }
fn ssig1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u); }
fn ch(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (~x & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }

fn bswap(x: u32) -> u32 {
    return (x << 24u) | ((x & 0xff00u) << 8u) | ((x >> 8u) & 0xff00u) | (x >> 24u);
}

// Full 64-round compression with feed-forward.
fn compress(state: array<u32, 8>, block: array<u32, 16>) -> array<u32, 8> {
    var m = block;
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i++) {
        w[i] = m[i];
    }
    for (var i = 16u; i < 64u; i++) {
        w[i] = ssig1(w[i - 2u]) + w[i - 7u] + ssig0(w[i - 15u]) + w[i - 16u];
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    var f = state[5];
    var g = state[6];
    var h = state[7];
    for (var i = 0u; i < 64u; i++) {
        let t1 = h + bsig1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    return array<u32, 8>(
        state[0] + a, state[1] + b, state[2] + c, state[3] + d,
        state[4] + e, state[5] + f, state[6] + g, state[7] + h,
    );
}

// SHA-256d of the header with `nonce`; returns H0..H7.
fn header_hash(nonce: u32) -> array<u32, 8> {
    var mid: array<u32, 8>;
    for (var i = 0u; i < 8u; i++) {
        mid[i] = params.midstate[i];
    }
    var blk: array<u32, 16>;
    blk[0] = params.tail[0];
    blk[1] = params.tail[1];
    blk[2] = params.tail[2];
    // The nonce is serialized little-endian; SHA-256 reads big-endian words.
    blk[3] = bswap(nonce);
    blk[4] = 0x80000000u;
    blk[15] = 640u;
    var inner = compress(mid, blk);
    var blk2: array<u32, 16>;
    for (var i = 0u; i < 8u; i++) {
        blk2[i] = inner[i];
    }
    blk2[8] = 0x80000000u;
    blk2[15] = 256u;
    return compress(IV, blk2);
}

// The hash is a little-endian 256-bit number: its most significant word is bswap(H7).
fn meets_target(hash: array<u32, 8>) -> bool {
    var h = hash;
    for (var i = 0u; i < 8u; i++) {
        let v = bswap(h[7u - i]);
        let t = params.target_be[i];
        if (v < t) {
            return true;
        }
        if (v > t) {
            return false;
        }
    }
    return true;
}

@compute @workgroup_size(256)
fn search(@builtin(global_invocation_id) gid: vec3<u32>) {
    for (var j = 0u; j < params.per_invocation; j++) {
        let offset = j * params.stride + gid.x;
        if (offset >= params.count) {
            break;
        }
        let nonce = params.nonce_base + offset;
        if (meets_target(header_hash(nonce))) {
            let slot = atomicAdd(&found.count, 1u);
            if (slot < params.capacity) {
                found.nonces[slot] = nonce;
            }
        }
    }
}

@compute @workgroup_size(256)
fn dump_hashes(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x >= params.count) {
        return;
    }
    var h = header_hash(params.nonce_base + gid.x);
    for (var k = 0u; k < 8u; k++) {
        dump[gid.x * 8u + k] = h[k];
    }
}
