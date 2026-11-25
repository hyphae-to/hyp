//! Zero-dependency compile-time SHA-256 pinning for official external Hyphae plugins.
//!
//! Instead of embedding external plugin JS sources inside the static `hyp` binary,
//! `build.rs` pins only the LF-normalized FIPS 180-4 SHA-256 digest of each of the
//! 6 official runtime files (~400 bytes total). `hyp plugin install` / `verify`
//! downloads `hyp-vX.Y.Z-plugins.tar.gz` (or reads `--archive` / `--from-dir`) and
//! verifies every file in constant time against these pinned digests before writing
//! a single byte to `<state_dir>/plugins/`.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const PLUGIN_FILES: &[(&str, &str)] = &[
    ("sdk", "sdk/client.mjs"),
    ("telegram", "telegram/index.mjs"),
    ("slack", "slack/index.mjs"),
    ("whatsapp", "whatsapp/index.mjs"),
    ("webhook", "webhook/index.mjs"),
    ("prometheus", "prometheus/index.mjs"),
];

const SHA256_H_INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

/// Self-contained FIPS 180-4 SHA-256 returning 64-char lowercase hex.
fn sha256_hex(input: &[u8]) -> String {
    let bit_len = (input.len() as u64)
        .checked_mul(8)
        .expect("input length bit overflow");

    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = SHA256_H_INIT;
    let mut w = [0u32; 64];

    for chunk in padded.chunks_exact(64) {
        for (slot, word) in w.iter_mut().zip(chunk.chunks_exact(4)) {
            *slot = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (&k, &wi) in SHA256_K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = String::with_capacity(64);
    for word in state {
        let _ = write!(&mut out, "{word:08x}");
    }
    out
}

/// Normalizes `\r\n` -> `\n` so Windows (`core.autocrlf=true`) and Unix produce identical digests.
fn normalize_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

fn main() {
    // Compile-time FIPS 180-4 self-check against official NIST vectors.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let plugins_root = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("plugins");

    let mut generated = String::from(
        "// Auto-generated by crates/hyp-cli/build.rs — DO NOT EDIT.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct PinnedPluginFile {\n\
             pub plugin: &'static str,\n\
             pub rel_path: &'static str,\n\
             pub sha256: &'static str,\n\
         }\n\n\
         pub const PINNED_PLUGIN_FILES: &[PinnedPluginFile] = &[\n",
    );

    for &(plugin, rel_path) in PLUGIN_FILES {
        println!("cargo:rerun-if-changed=../../plugins/{rel_path}");
        let full_path = plugins_root.join(rel_path);
        let raw = fs::read(&full_path).unwrap_or_else(|e| {
            panic!(
                "failed to read official plugin file {}: {e}",
                full_path.display()
            )
        });
        let normalized = normalize_crlf(&raw);
        let digest = sha256_hex(&normalized);
        let _ = writeln!(
            &mut generated,
            "    PinnedPluginFile {{\n        plugin: {plugin:?},\n        rel_path: {rel_path:?},\n        sha256: {digest:?},\n    }},"
        );
    }

    generated.push_str("];\n");

    let dest = Path::new(&out_dir).join("plugin_checksums.rs");
    fs::write(&dest, generated)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", dest.display()));
}
