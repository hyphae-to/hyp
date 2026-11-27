//! Zero-dependency compile-time SHA-256 & tree-digest pinning for ALL official
//! non-Rust Hyphae plugins and harness UI mods.
//!
//! Instead of embedding JS/TS/TSX/SVG/PNG plugin assets inside the static `hyp` binary,
//! `build.rs` pins ONLY the FIPS 180-4 SHA-256 digest of each official file (LF-normalized
//! for UTF-8 text files, raw bytes for binary assets like `.png`) plus a deterministic
//! per-plugin `tree_sha256` (SHA-256 over lexicographically sorted `"{rel_path}\0{sha256}\n"`
//! lines). `hyp plugin install/update/verify` and `hyp setup` verify every file in constant
//! time against these pinned digests before writing a single byte to disk.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy)]
enum SpecKind {
    Bridge,
    Harness,
}

impl SpecKind {
    const fn rust_variant(self) -> &'static str {
        match self {
            Self::Bridge => "PluginKind::Bridge",
            Self::Harness => "PluginKind::Harness",
        }
    }
}

struct BuildPluginSpec {
    id: &'static str,
    kind: SpecKind,
    /// `(rel_path_under_plugins_dir, is_binary)`
    files: &'static [(&'static str, bool)],
}

const PLUGIN_SPECS: &[BuildPluginSpec] = &[
    BuildPluginSpec {
        id: "sdk",
        kind: SpecKind::Bridge,
        files: &[
            ("sdk/client.mjs", false),
            ("sdk/client.py", false),
            ("sdk/google-oauth.mjs", false),
            ("sdk/source-kit.mjs", false),
        ],
    },
    BuildPluginSpec {
        id: "telegram",
        kind: SpecKind::Bridge,
        files: &[("telegram/index.mjs", false)],
    },
    BuildPluginSpec {
        id: "slack",
        kind: SpecKind::Bridge,
        files: &[("slack/index.mjs", false)],
    },
    BuildPluginSpec {
        id: "whatsapp",
        kind: SpecKind::Bridge,
        files: &[("whatsapp/index.mjs", false)],
    },
    BuildPluginSpec {
        id: "webhook",
        kind: SpecKind::Bridge,
        files: &[("webhook/index.mjs", false)],
    },
    BuildPluginSpec {
        id: "prometheus",
        kind: SpecKind::Bridge,
        files: &[("prometheus/index.mjs", false)],
    },
    BuildPluginSpec {
        id: "agentmail",
        kind: SpecKind::Bridge,
        files: &[
            ("agentmail/index.mjs", false),
            ("agentmail/onboarding.json", false),
        ],
    },
    BuildPluginSpec {
        id: "sentry",
        kind: SpecKind::Bridge,
        files: &[
            ("sentry/index.mjs", false),
            ("sentry/onboarding.json", false),
        ],
    },
    BuildPluginSpec {
        id: "gmail",
        kind: SpecKind::Bridge,
        files: &[("gmail/index.mjs", false), ("gmail/onboarding.json", false)],
    },
    BuildPluginSpec {
        id: "google-calendar",
        kind: SpecKind::Bridge,
        files: &[
            ("google-calendar/index.mjs", false),
            ("google-calendar/onboarding.json", false),
        ],
    },
    BuildPluginSpec {
        id: "vercel",
        kind: SpecKind::Bridge,
        files: &[
            ("vercel/index.mjs", false),
            ("vercel/onboarding.json", false),
        ],
    },
    BuildPluginSpec {
        id: "notion",
        kind: SpecKind::Bridge,
        files: &[
            ("notion/index.mjs", false),
            ("notion/onboarding.json", false),
        ],
    },
    BuildPluginSpec {
        id: "claude-panel",
        kind: SpecKind::Harness,
        files: &[
            ("claude-code/hooks/register.tsx", false),
            ("claude-code/hooks/state.ts", false),
            ("claude-code/hooks/kv-view.mjs", false),
        ],
    },
    BuildPluginSpec {
        id: "claude-code",
        kind: SpecKind::Harness,
        files: &[
            ("claude-code/.claude-plugin/plugin.json", false),
            ("claude-code/.claude-plugin/icon.png", true),
            ("claude-code/.mcp.json", false),
            ("claude-code/hooks/hooks.json", false),
            ("claude-code/hooks/register.tsx", false),
            ("claude-code/hooks/state.ts", false),
            ("claude-code/hooks/kv-view.mjs", false),
            ("claude-code/commands/hyp.md", false),
            ("claude-code/commands/hyp-focus.md", false),
            ("claude-code/commands/hyp-mute.md", false),
            ("claude-code/commands/hyp-subs.md", false),
            ("claude-code/skills/hyp-mesh/SKILL.md", false),
            ("claude-code/README.md", false),
        ],
    },
    BuildPluginSpec {
        id: "herdr-mod",
        kind: SpecKind::Harness,
        files: &[
            ("herdr-mod/mods/hyphae-pane/mod.json", false),
            ("herdr-mod/mods/hyphae-pane/main.js", false),
            ("herdr-mod/mods/hyphae-pane/pill.js", false),
            ("herdr-mod/mods/hyphae-pane/shared-client.js", false),
            ("herdr-mod/mods/hyphae-pane/kv-view.js", false),
            ("herdr-mod/mods/hyphae-pane/hyphae.svg", false),
            ("herdr-mod/mods/hyphae-panel/mod.json", false),
            ("herdr-mod/mods/hyphae-panel/main.js", false),
            ("herdr-mod/mods/hyphae-panel/shared-client.js", false),
            ("herdr-mod/mods/hyphae-panel/kv-view.js", false),
            ("herdr-mod/mods/hyphae-panel/hyphae.svg", false),
        ],
    },
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
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
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

/// Computes deterministic per-plugin `tree_sha256` over lexicographically sorted
/// `"{rel_path}\0{file_sha256}\n"` lines.
fn compute_tree_sha256(entries: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::new();
    for (rel_path, digest) in sorted {
        buf.extend_from_slice(rel_path.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(digest.as_bytes());
        buf.push(b'\n');
    }
    sha256_hex(&buf)
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
    println!("cargo:rerun-if-env-changed=HYPHAE_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=HYPHAE_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed=HYPHAE_RELEASE_TAG");

    let pkg_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");
    let build_version = env::var("HYPHAE_BUILD_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| pkg_version.clone());
    let explicit_tag = env::var("HYPHAE_RELEASE_TAG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let explicit_channel = env::var("HYPHAE_BUILD_CHANNEL")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let is_nightly_ver = build_version
        .split('+')
        .next()
        .unwrap_or(&build_version)
        .split_once('-')
        .is_some_and(|(_, pre)| {
            pre.split('.')
                .any(|ident| ident.eq_ignore_ascii_case("nightly"))
        });

    let build_channel = explicit_channel.unwrap_or_else(|| {
        if explicit_tag
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("nightly"))
            || is_nightly_ver
        {
            "nightly".to_string()
        } else {
            "stable".to_string()
        }
    });

    let release_tag = explicit_tag.unwrap_or_else(|| {
        if build_channel.eq_ignore_ascii_case("nightly") {
            "nightly".to_string()
        } else {
            format!("v{}", build_version.trim_start_matches('v'))
        }
    });

    for (name, val) in [
        ("HYPHAE_BUILD_VERSION", &build_version),
        ("HYPHAE_BUILD_CHANNEL", &build_channel),
        ("HYPHAE_RELEASE_TAG", &release_tag),
    ] {
        assert!(
            !val.chars().any(char::is_control),
            "{name} must not contain control characters"
        );
        println!("cargo:rustc-env={name}={val}");
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let plugins_root = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("plugins");

    // Hash every unique official plugin file once, keeping track of canonical owner & binary flag.
    let mut file_digests: BTreeMap<&'static str, (String, bool)> = BTreeMap::new();
    let mut unique_files_ordered: Vec<(&'static str, &'static str, bool)> = Vec::new();
    let mut seen_rel: BTreeSet<&'static str> = BTreeSet::new();

    for spec in PLUGIN_SPECS {
        for &(rel_path, is_binary) in spec.files {
            if let Some((_, prev_binary)) = file_digests.get(rel_path) {
                assert_eq!(
                    *prev_binary, is_binary,
                    "conflicting is_binary flag for {rel_path}"
                );
                continue;
            }
            println!("cargo:rerun-if-changed=../../plugins/{rel_path}");
            let full_path = plugins_root.join(rel_path);
            let raw = fs::read(&full_path).unwrap_or_else(|e| {
                panic!(
                    "failed to read official plugin file {}: {e}",
                    full_path.display()
                )
            });
            let digest = if is_binary {
                sha256_hex(&raw)
            } else {
                sha256_hex(&normalize_crlf(&raw))
            };
            file_digests.insert(rel_path, (digest, is_binary));
            if seen_rel.insert(rel_path) {
                unique_files_ordered.push((spec.id, rel_path, is_binary));
            }
        }
    }

    let mut generated = String::from(
        "// Auto-generated by crates/hyp-cli/build.rs — DO NOT EDIT.\n\
         #[allow(dead_code)]\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum PluginKind {\n\
             Bridge,\n\
             Harness,\n\
         }\n\n\
         #[allow(dead_code)]\n\
         impl PluginKind {\n\
             pub const fn as_str(self) -> &'static str {\n\
                 match self {\n\
                     Self::Bridge => \"bridge\",\n\
                     Self::Harness => \"harness\",\n\
                 }\n\
             }\n\
         }\n\n\
         #[allow(dead_code)]\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct PinnedPluginFile {\n\
             pub plugin: &'static str,\n\
             pub rel_path: &'static str,\n\
             pub sha256: &'static str,\n\
             pub is_binary: bool,\n\
         }\n\n\
         #[allow(dead_code)]\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct PinnedPluginSpec {\n\
             pub id: &'static str,\n\
             pub kind: PluginKind,\n\
             pub tree_sha256: &'static str,\n\
             pub files: &'static [PinnedPluginFile],\n\
         }\n\n\
         #[allow(dead_code)]\n\
         pub const PINNED_PLUGIN_FILES: &[PinnedPluginFile] = &[\n",
    );

    for (owner, rel_path, is_binary) in &unique_files_ordered {
        let (digest, _) = file_digests
            .get(rel_path)
            .expect("digest computed for unique file");
        let _ = writeln!(
            &mut generated,
            "    PinnedPluginFile {{\n\
             \x20       plugin: {owner:?},\n\
             \x20       rel_path: {rel_path:?},\n\
             \x20       sha256: {digest:?},\n\
             \x20       is_binary: {is_binary},\n\
             \x20   }},"
        );
    }
    generated.push_str("];\n\n");

    generated.push_str("#[allow(dead_code)]\npub const PINNED_PLUGINS: &[PinnedPluginSpec] = &[\n");
    for spec in PLUGIN_SPECS {
        let mut sorted_files: Vec<(&'static str, bool, &str)> = spec
            .files
            .iter()
            .map(|&(rel_path, is_binary)| {
                let (digest, _) = file_digests.get(rel_path).expect("digest exists");
                (rel_path, is_binary, digest.as_str())
            })
            .collect();
        sorted_files.sort_by(|a, b| a.0.cmp(b.0));

        let tree_pairs: Vec<(&str, &str)> = sorted_files
            .iter()
            .map(|&(rel_path, _, digest)| (rel_path, digest))
            .collect();
        let tree_sha256 = compute_tree_sha256(&tree_pairs);

        let _ = writeln!(
            &mut generated,
            "    PinnedPluginSpec {{\n\
             \x20       id: {:?},\n\
             \x20       kind: {},\n\
             \x20       tree_sha256: {:?},\n\
             \x20       files: &[",
            spec.id,
            spec.kind.rust_variant(),
            tree_sha256
        );
        for (rel_path, is_binary, digest) in sorted_files {
            let _ = writeln!(
                &mut generated,
                "            PinnedPluginFile {{\n\
                 \x20               plugin: {:?},\n\
                 \x20               rel_path: {:?},\n\
                 \x20               sha256: {:?},\n\
                 \x20               is_binary: {},\n\
                 \x20           }},",
                spec.id, rel_path, digest, is_binary
            );
        }
        generated.push_str("        ],\n    },\n");
    }
    generated.push_str("];\n");

    let dest = Path::new(&out_dir).join("plugin_checksums.rs");
    fs::write(&dest, generated)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", dest.display()));
}
