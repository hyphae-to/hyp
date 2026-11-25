//! End-to-end & differential verification tests for the Release-Artifact Verified
//! `hyp plugin` Manager (`build.rs` compile-time SHA-256 pinning, release workflow
//! packaging, RFC 8785 JCS manifest compatibility, `SKILL.md` / `docs/plugins.md` contracts).

use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::transfer::{TarPackOptions, TarUnpackOptions, pack_tar_gz, unpack_tar_gz, TarInputEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

include!(concat!(env!("OUT_DIR"), "/plugin_checksums.rs"));

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

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

fn sha256_lf_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(normalize_crlf(bytes)))
}

#[test]
fn build_rs_pinned_digests_match_sha2_crate_and_crlf_invariance() {
    let expected_files = [
        ("sdk", "sdk/client.mjs"),
        ("telegram", "telegram/index.mjs"),
        ("slack", "slack/index.mjs"),
        ("whatsapp", "whatsapp/index.mjs"),
        ("webhook", "webhook/index.mjs"),
        ("prometheus", "prometheus/index.mjs"),
    ];

    assert_eq!(PINNED_PLUGIN_FILES.len(), expected_files.len());
    let plugins_dir = repo_root().join("plugins");

    for (entry, (exp_plugin, exp_rel)) in PINNED_PLUGIN_FILES.iter().zip(expected_files.iter()) {
        assert_eq!(entry.plugin, *exp_plugin);
        assert_eq!(entry.rel_path, *exp_rel);
        assert_eq!(entry.sha256.len(), 64, "pinned digest must be 64 hex chars");
        assert!(
            entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "pinned digest must be lowercase hex"
        );

        let raw = fs::read(plugins_dir.join(entry.rel_path))
            .unwrap_or_else(|e| panic!("failed reading {}: {e}", entry.rel_path));
        let computed = sha256_lf_hex(&raw);
        assert_eq!(
            entry.sha256, computed,
            "zero-dep build.rs SHA-256 must match sha2::Sha256 for {}",
            entry.rel_path
        );

        // Windows core.autocrlf=true simulation: convert every LF to CRLF and verify identical hash.
        let lf = normalize_crlf(&raw);
        let mut crlf = Vec::with_capacity(lf.len() + 128);
        for &b in &lf {
            if b == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(b);
        }
        assert_eq!(
            sha256_lf_hex(&crlf),
            entry.sha256,
            "CRLF-converted {} must hash identically",
            entry.rel_path
        );

        if entry.plugin != "sdk" {
            let text = String::from_utf8(lf).expect("plugin .mjs must be UTF-8");
            assert!(
                text.contains("../sdk/client.mjs"),
                "official plugin {} must import ../sdk/client.mjs",
                entry.rel_path
            );
        }
    }
}

#[test]
fn packed_plugins_tarball_unpacks_and_matches_all_pinned_digests() {
    let plugins_dir = repo_root().join("plugins");
    let entries: Vec<TarInputEntry> = PINNED_PLUGIN_FILES
        .iter()
        .map(|p| TarInputEntry {
            archive_path: p.rel_path.to_string(),
            source_path: plugins_dir.join(p.rel_path),
        })
        .collect();

    let mut archive = Vec::new();
    pack_tar_gz(&entries, &mut archive, TarPackOptions::default())
        .expect("pack official plugins tarball");
    assert!(
        archive.len() < 4 * 1024 * 1024,
        "official plugins tarball must stay well below 4 MiB limit"
    );

    let tmp = TempDir::new().expect("temp dir");
    let unpacked = unpack_tar_gz(
        Cursor::new(&archive),
        tmp.path(),
        &TarUnpackOptions {
            max_files: 32,
            max_raw_bytes: 4 * 1024 * 1024,
            attachment_guard: None,
        },
    )
    .expect("unpack official plugins tarball");

    assert_eq!(unpacked.files.len(), PINNED_PLUGIN_FILES.len());
    for pinned in PINNED_PLUGIN_FILES {
        let extracted = unpacked
            .files
            .iter()
            .find(|f| f.archive_path == pinned.rel_path)
            .unwrap_or_else(|| panic!("missing {} in unpacked archive", pinned.rel_path));
        let bytes = fs::read(&extracted.disk_path).expect("read extracted file");
        assert_eq!(sha256_lf_hex(&bytes), pinned.sha256);
    }
}

#[test]
fn release_workflows_package_sign_and_checksum_plugins_tarball() {
    let root = repo_root();
    for wf_rel in [
        ".github/workflows/release-rust.yml",
        ".github/workflows/nightly-rust.yml",
    ] {
        let content = fs::read_to_string(root.join(wf_rel))
            .unwrap_or_else(|e| panic!("failed reading {wf_rel}: {e}"));

        assert!(
            content.contains("ref: ${{ needs.prepare.outputs.git_sha }}"),
            "{wf_rel} must check out the exact prepared git_sha in the release job"
        );
        assert!(
            content.contains("tar --format=ustar") && content.contains("dist/hyp-${TAG}-plugins.tar.gz"),
            "{wf_rel} must package dist/hyp-${{TAG}}-plugins.tar.gz using POSIX ustar format"
        );
        assert!(
            content.contains("\"hyp-${TAG}-plugins.tar.gz\""),
            "{wf_rel} must include hyp-${{TAG}}-plugins.tar.gz in SHA256SUMS.txt"
        );
        assert!(
            content.contains("[\"plugins\", \"tar.gz\"]"),
            "{wf_rel} must include artifacts[\"plugins\"] in release-manifest.json"
        );
        for pinned in PINNED_PLUGIN_FILES {
            assert!(
                content.contains(pinned.rel_path),
                "{wf_rel} must package official plugin file {}",
                pinned.rel_path
            );
        }
    }
}

#[test]
fn release_manifest_with_plugins_artifact_remains_jcs_compatible_with_update_rs() {
    // Mirror exact `ReleaseManifestPayload` & `ReleaseArtifact` structs from `crates/hyp-cli/src/update.rs`
    // to prove adding `artifacts["plugins"]` NEVER breaks `canonical != signed.payload`!
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ReleaseArtifact {
        url: String,
        sha256: String,
        size: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ReleaseManifestPayload {
        channel: String,
        version: String,
        git_sha: String,
        published_at: String,
        min_protocol: u32,
        artifacts: BTreeMap<String, ReleaseArtifact>,
        changelog_summary: String,
    }

    let mut artifacts = BTreeMap::new();
    for (triple, ext) in [
        ("aarch64-apple-darwin", "tar.gz"),
        ("aarch64-unknown-linux-gnu", "tar.gz"),
        ("plugins", "tar.gz"),
        ("x86_64-apple-darwin", "tar.gz"),
        ("x86_64-pc-windows-msvc", "zip"),
        ("x86_64-unknown-linux-gnu", "tar.gz"),
        ("x86_64-unknown-linux-musl", "tar.gz"),
    ] {
        artifacts.insert(
            triple.to_string(),
            ReleaseArtifact {
                url: format!(
                    "https://github.com/hyphae-to/hyp/releases/download/v0.6.1/hyp-v0.6.1-{triple}.{ext}"
                ),
                sha256: "a".repeat(64),
                size: 12345,
            },
        );
    }

    let payload = ReleaseManifestPayload {
        channel: "stable".to_string(),
        version: "0.6.1".to_string(),
        git_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        published_at: "2026-11-25T10:00:00Z".to_string(),
        min_protocol: 1,
        artifacts,
        changelog_summary: "Hyphae v0.6.1".to_string(),
    };

    let kp = Ed25519KeyPair::generate().expect("generate Ed25519 keypair");
    let signed = kp
        .sign_jcs("release", &payload)
        .expect("sign JCS release manifest");

    // Re-deserialize and re-canonicalize exactly as `update.rs::verify_release_manifest` does.
    let decoded: ReleaseManifestPayload =
        serde_json::from_str(&signed.payload).expect("deserialize manifest payload");
    let recanonical = to_canonical_json(&decoded).expect("re-canonicalize payload");
    assert_eq!(recanonical, signed.payload);
    assert!(decoded.artifacts.contains_key("plugins"));
    kp.public_key()
        .verify_domain_b64("release", signed.payload.as_bytes(), &signed.sig)
        .expect("Ed25519 signature over manifest with plugins artifact must verify");
}

#[test]
fn setup_skill_and_plugins_doc_enforce_verified_plugin_manager_contract() {
    let root = repo_root();

    let skill = fs::read_to_string(root.join("skills/hyphae-setup/SKILL.md"))
        .expect("read skills/hyphae-setup/SKILL.md");
    assert!(
        skill.contains("hyp plugin install"),
        "SKILL.md must instruct `hyp plugin install`"
    );
    assert!(
        skill.contains("data.nodePath") && skill.contains("data.plugins[0].scriptPath"),
        "SKILL.md must wire node.json from data.nodePath and data.plugins[0].scriptPath"
    );
    assert!(
        skill.contains("local git checkout"),
        "SKILL.md must forbid pointing node.json at a local git checkout"
    );

    let docs = fs::read_to_string(root.join("docs/plugins.md")).expect("read docs/plugins.md");
    for needle in [
        "hyp plugin list",
        "hyp plugin install",
        "hyp plugin verify",
        "hyp plugin remove",
        "hyp-vX.Y.Z-plugins.tar.gz",
    ] {
        assert!(
            docs.contains(needle),
            "docs/plugins.md must document `{needle}`"
        );
    }
}
