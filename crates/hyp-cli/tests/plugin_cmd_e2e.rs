//! End-to-end & differential verification tests for the Unified Non-Rust Plugin & Harness Mod
//! Manager (`build.rs` compile-time SHA-256 + `tree_sha256` pinning, `scripts/pack-plugins.mjs`
//! bit-exact parity & change detection, release workflow contracts, RFC 8785 JCS manifest
//! compatibility, three-way selective updates, offline `hyp setup` fallback, tarball cache,
//! `hyp doctor` drift checks, and `SKILL.md` / `docs/plugins.md` contracts).

#[path = "../../test-support/node_runtime.rs"]
mod node_runtime;

use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::transfer::{
    TarInputEntry, TarPackOptions, TarUnpackOptions, pack_tar_gz, unpack_tar_gz,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn sha256_file_hex(bytes: &[u8], is_binary: bool) -> String {
    if is_binary {
        hex::encode(Sha256::digest(bytes))
    } else {
        hex::encode(Sha256::digest(normalize_crlf(bytes)))
    }
}

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
    hex::encode(Sha256::digest(&buf))
}

#[test]
fn build_rs_pinned_digests_and_tree_hashes_match_sha2_crate_and_crlf_invariance() {
    let expected_plugins = [
        ("sdk", PluginKind::Bridge, 4usize),
        ("telegram", PluginKind::Bridge, 1),
        ("slack", PluginKind::Bridge, 1),
        ("whatsapp", PluginKind::Bridge, 1),
        ("webhook", PluginKind::Bridge, 1),
        ("prometheus", PluginKind::Bridge, 1),
        ("agentmail", PluginKind::Bridge, 2),
        ("sentry", PluginKind::Bridge, 2),
        ("gmail", PluginKind::Bridge, 2),
        ("google-calendar", PluginKind::Bridge, 2),
        ("vercel", PluginKind::Bridge, 2),
        ("notion", PluginKind::Bridge, 2),
        ("claude-panel", PluginKind::Harness, 3),
        ("claude-code", PluginKind::Harness, 13),
        ("herdr-mod", PluginKind::Harness, 11),
    ];

    assert_eq!(PINNED_PLUGINS.len(), expected_plugins.len());
    assert_eq!(PINNED_PLUGIN_FILES.len(), 45);
    let plugins_dir = repo_root().join("plugins");

    for (spec, (exp_id, exp_kind, exp_count)) in PINNED_PLUGINS.iter().zip(expected_plugins.iter())
    {
        assert_eq!(spec.id, *exp_id);
        assert_eq!(spec.kind, *exp_kind);
        assert_eq!(spec.files.len(), *exp_count);
        assert_eq!(spec.tree_sha256.len(), 64);

        let pairs: Vec<(&str, &str)> = spec.files.iter().map(|f| (f.rel_path, f.sha256)).collect();
        assert_eq!(
            spec.tree_sha256,
            compute_tree_sha256(&pairs),
            "tree_sha256 mismatch for {}",
            spec.id
        );
    }

    for entry in PINNED_PLUGIN_FILES {
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
        let computed = sha256_file_hex(&raw, entry.is_binary);
        assert_eq!(
            entry.sha256, computed,
            "zero-dep build.rs SHA-256 must match sha2::Sha256 for {}",
            entry.rel_path
        );

        if entry.is_binary {
            assert!(
                entry.rel_path.ends_with(".png"),
                "only binary assets should set is_binary=true: {}",
                entry.rel_path
            );
        } else {
            let lf = normalize_crlf(&raw);
            let mut crlf = Vec::with_capacity(lf.len() + 128);
            for &b in &lf {
                if b == b'\n' {
                    crlf.push(b'\r');
                }
                crlf.push(b);
            }
            assert_eq!(
                sha256_file_hex(&crlf, false),
                entry.sha256,
                "CRLF-converted {} must hash identically",
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
            max_files: 64,
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
        assert_eq!(sha256_file_hex(&bytes, pinned.is_binary), pinned.sha256);
    }
}

#[test]
fn pack_plugins_mjs_matches_build_rs_digests_and_detects_changes() {
    // Only skip if node is unavailable on a bare runner (never skipped on Linux/macOS CI).
    if !node_runtime::node_available() {
        return;
    }

    let root = repo_root();
    let tmp = TempDir::new().expect("temp dir");
    let out_dir = tmp.path().join("dist-head");
    let notes_path = out_dir.join("changed-plugins.md");
    let gh_out = out_dir.join("github_output.txt");

    // 1. Compare against HEAD -> EVERY plugin MUST report `changed: false` and `changed_claude_code=false`!
    let run_head = Command::new("node")
        .current_dir(&root)
        .args([
            "scripts/pack-plugins.mjs",
            "--tag",
            "v0.6.2-test",
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--prev-tag",
            "HEAD",
            "--notes-out",
            notes_path.to_str().unwrap(),
            "--github-output",
            gh_out.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run pack-plugins.mjs");
    assert!(
        run_head.status.success(),
        "pack-plugins.mjs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run_head.stdout),
        String::from_utf8_lossy(&run_head.stderr)
    );

    let manifest: Value =
        serde_json::from_slice(&run_head.stdout).expect("parse plugins-manifest.json stdout");
    assert_eq!(manifest["schemaVersion"], 1);
    assert_eq!(manifest["releaseTag"], "v0.6.2-test");
    assert_eq!(manifest["previousTag"], "HEAD");
    assert_eq!(manifest["changedPlugins"], json!([]));

    // Differential check: EVERY treeSha256 and per-file SHA-256 from Node MUST match build.rs bit-for-bit!
    for spec in PINNED_PLUGINS {
        let p = &manifest["plugins"][spec.id];
        assert_eq!(p["kind"], spec.kind.as_str());
        assert_eq!(
            p["treeSha256"].as_str(),
            Some(spec.tree_sha256),
            "pack-plugins.mjs treeSha256 diverged from build.rs for {}",
            spec.id
        );
        assert_eq!(p["previousTreeSha256"].as_str(), Some(spec.tree_sha256));
        assert_eq!(p["changed"], false);
        for f in spec.files {
            assert_eq!(
                p["files"][f.rel_path].as_str(),
                Some(f.sha256),
                "pack-plugins.mjs file sha256 diverged from build.rs for {}",
                f.rel_path
            );
        }
    }

    let gh_text = fs::read_to_string(&gh_out).expect("read github output");
    assert!(gh_text.contains("changed_count=0"));
    assert!(gh_text.contains("changed_claude_code=false"));

    // 2. Compare against `--prev-tag none` (baseline / no prior tag) -> EVERY plugin reports `changed: true`!
    let out_none = tmp.path().join("dist-none");
    let gh_none = out_none.join("github_output.txt");
    let run_none = Command::new("node")
        .current_dir(&root)
        .args([
            "scripts/pack-plugins.mjs",
            "--tag",
            "v0.6.2-baseline",
            "--out-dir",
            out_none.to_str().unwrap(),
            "--prev-tag",
            "none",
            "--github-output",
            gh_none.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run pack-plugins.mjs baseline");
    assert!(run_none.status.success());
    let none_manifest: Value = serde_json::from_slice(&run_none.stdout).unwrap();
    assert!(none_manifest["previousTag"].is_null());
    assert_eq!(
        none_manifest["changedPlugins"].as_array().map(Vec::len),
        Some(PINNED_PLUGINS.len())
    );
    let gh_none_text = fs::read_to_string(&gh_none).unwrap();
    assert!(gh_none_text.contains("changed_claude_code=true"));

    // 3. Real compiled `hyp plugin install all --archive <pack-plugins.mjs tarball>` MUST verify & succeed!
    let tarball_path = out_dir.join("hyp-v0.6.2-test-plugins.tar.gz");
    assert!(tarball_path.is_file());
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();

    let inst = Command::new(env!("CARGO_BIN_EXE_hyp"))
        .args([
            "plugin",
            "install",
            "all",
            "--archive",
            tarball_path.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home)
        .env_remove("HYPHAE_PLUGINS_DIR")
        .env_remove("HYPHAE_PLUGINS_ARCHIVE")
        .output()
        .expect("install from pack-plugins.mjs tarball");
    assert!(
        inst.status.success(),
        "hyp plugin install from pack-plugins.mjs tarball failed: stdout={} stderr={}",
        String::from_utf8_lossy(&inst.stdout),
        String::from_utf8_lossy(&inst.stderr)
    );

    let ver = Command::new(env!("CARGO_BIN_EXE_hyp"))
        .args([
            "plugin",
            "verify",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home)
        .output()
        .expect("verify installed plugins");
    assert!(
        ver.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&ver.stdout),
        String::from_utf8_lossy(&ver.stderr)
    );
}

#[test]
fn release_workflows_package_sign_and_checksum_plugins_tarball() {
    let root = repo_root();
    let pack_script = fs::read_to_string(root.join("scripts/pack-plugins.mjs"))
        .expect("read scripts/pack-plugins.mjs");
    assert!(
        pack_script.contains("--format=ustar"),
        "scripts/pack-plugins.mjs must pack archives using POSIX ustar format"
    );
    for pinned in PINNED_PLUGIN_FILES {
        assert!(
            pack_script.contains(pinned.rel_path),
            "scripts/pack-plugins.mjs must include official plugin file {}",
            pinned.rel_path
        );
    }

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
            content.contains("node scripts/pack-plugins.mjs"),
            "{wf_rel} must invoke scripts/pack-plugins.mjs"
        );
        assert!(
            content.contains("\"hyp-${TAG}-plugins.tar.gz\""),
            "{wf_rel} must include hyp-${{TAG}}-plugins.tar.gz in SHA256SUMS.txt"
        );
        assert!(
            content.contains("[\"plugins\", \"tar.gz\"]"),
            "{wf_rel} must include artifacts[\"plugins\"] in release-manifest.json"
        );
        assert!(
            content.contains("dist/plugins-manifest.json"),
            "{wf_rel} must upload dist/plugins-manifest.json"
        );
    }

    let release_wf = fs::read_to_string(root.join(".github/workflows/release-rust.yml")).unwrap();
    assert!(
        release_wf.contains("steps.plugins.outputs.changed_claude_code == 'true'"),
        "release-rust.yml must gate Claude Code plugin tagging on changed_claude_code == 'true'"
    );

    let nightly_wf = fs::read_to_string(root.join(".github/workflows/nightly-rust.yml")).unwrap();
    assert_eq!(
        nightly_wf
            .matches("HYPHAE_BUILD_VERSION: ${{ needs.prepare.outputs.version }}")
            .count(),
        2,
        "nightly-rust.yml must pass HYPHAE_BUILD_VERSION to both Unix and Windows build steps"
    );
    assert_eq!(
        nightly_wf.matches("HYPHAE_BUILD_CHANNEL: nightly").count(),
        2,
        "nightly-rust.yml must pass HYPHAE_BUILD_CHANNEL: nightly to both Unix and Windows build steps"
    );
    assert_eq!(
        nightly_wf
            .matches("HYPHAE_RELEASE_TAG: ${{ needs.prepare.outputs.tag }}")
            .count(),
        2,
        "nightly-rust.yml must pass HYPHAE_RELEASE_TAG to both Unix and Windows build steps"
    );
}

#[test]
fn release_manifest_with_plugins_artifact_remains_jcs_compatible_with_update_rs() {
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
                    "https://github.com/hyphae-to/hyp/releases/download/v0.6.2/hyp-v0.6.2-{triple}.{ext}"
                ),
                sha256: "a".repeat(64),
                size: 12345,
            },
        );
    }

    let payload = ReleaseManifestPayload {
        channel: "stable".to_string(),
        version: "0.6.2".to_string(),
        git_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        published_at: "2026-11-25T10:00:00Z".to_string(),
        min_protocol: 1,
        artifacts,
        changelog_summary: "Hyphae v0.6.2".to_string(),
    };

    let kp = Ed25519KeyPair::generate().expect("generate Ed25519 keypair");
    let signed = kp
        .sign_jcs("release", &payload)
        .expect("sign JCS release manifest");

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

    let skill = fs::read_to_string(root.join("skills/hyp-setup/SKILL.md"))
        .expect("read skills/hyp-setup/SKILL.md");
    assert!(
        skill.contains("hyp plugin install"),
        "SKILL.md must instruct `hyp plugin install`"
    );
    assert!(
        skill.contains("hyp plugin update --all"),
        "SKILL.md must document `hyp plugin update --all`"
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
        "hyp plugin update",
        "hyp plugin verify",
        "hyp plugin remove",
        "hyp-vX.Y.Z-plugins.tar.gz",
        "installed.json",
        "claude-panel",
        "herdr-mod",
        "--no-plugins",
    ] {
        assert!(
            docs.contains(needle),
            "docs/plugins.md must document `{needle}`"
        );
    }
}

#[test]
fn compiled_hyp_plugin_cli_unified_three_way_update_cache_offline_setup_and_doctor_e2e() {
    let bin = env!("CARGO_BIN_EXE_hyp");
    let root = repo_root();
    let plugins_dir = root.join("plugins");
    let tmp = TempDir::new().expect("create temp dir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();

    let run = |args: &[&str], extra_env: &[(&str, Option<&str>)]| {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("HYPHAE_PLUGINS_DIR")
            .env_remove("HYPHAE_PLUGINS_ARCHIVE")
            .env_remove("HYPHAE_PLUGINS_URL")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("HERDR_APP_HOME");
        for (k, v) in extra_env {
            match v {
                Some(val) => {
                    cmd.env(k, val);
                }
                None => {
                    cmd.env_remove(k);
                }
            }
        }
        cmd.output().expect("spawn hyp")
    };

    // 1. `hyp plugin list --json` lists all 9 official non-Rust plugins & harness mods.
    let list_out = run(
        &[
            "plugin",
            "list",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(list_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_out.stdout).expect("parse list json");
    assert_eq!(list_json["ok"], true);
    assert_eq!(
        list_json["data"]["plugins"].as_array().map(Vec::len),
        Some(15)
    );
    // Event-source plugins advertise their structured onboarding tree; bridges without one do not.
    let listed = list_json["data"]["plugins"].as_array().unwrap();
    let onboarding_of = |name: &str| {
        listed
            .iter()
            .find(|p| p["name"] == name)
            .map(|p| p["onboardingPath"].clone())
            .unwrap_or(Value::Null)
    };
    for name in [
        "agentmail",
        "sentry",
        "gmail",
        "google-calendar",
        "vercel",
        "notion",
    ] {
        let path = onboarding_of(name);
        let expected = state_dir.join("plugins").join(name).join("onboarding.json");
        assert_eq!(
            path.as_str().map(Path::new),
            Some(expected.as_path()),
            "{name} must report its onboardingPath"
        );
    }
    assert_eq!(onboarding_of("telegram"), Value::Null);

    // Seed the previous standalone panel and a file the user added.
    let legacy_panel = home.join(".claude/skills/hyphae-panel");
    fs::create_dir_all(legacy_panel.join("hooks")).unwrap();
    fs::create_dir_all(legacy_panel.join(".claude-plugin")).unwrap();
    fs::write(
        legacy_panel.join(".claude-plugin/plugin.json"),
        json!({
            "name": "hyphae-panel",
            "version": "0.7.0",
            "description": "Native Hyphae live mesh side-panel mod (/hyphae-panel) for Claude Code.",
            "author": {"name": "Hyphae"},
            "license": "MIT",
            "repository": "https://github.com/hyphae-to/hyp",
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        legacy_panel.join("hooks/hooks.json"),
        r#"{"modules":["./register.tsx"]}"#,
    )
    .unwrap();
    let legacy_files = [
        (
            "claude-code/hooks/register.tsx",
            "// legacy panel register fixture",
        ),
        (
            "claude-code/hooks/state.ts",
            "// legacy panel state fixture",
        ),
    ];
    let legacy_digests: Vec<_> = legacy_files
        .iter()
        .map(|(rel, text)| {
            fs::write(
                legacy_panel.join(rel.strip_prefix("claude-code/").unwrap()),
                text,
            )
            .unwrap();
            (*rel, sha256_file_hex(text.as_bytes(), false))
        })
        .collect();
    let legacy_pairs: Vec<_> = legacy_digests
        .iter()
        .map(|(rel, hash)| (*rel, hash.as_str()))
        .collect();
    let receipts_path = state_dir.join("plugins/installed.json");
    fs::create_dir_all(receipts_path.parent().unwrap()).unwrap();
    fs::write(
        &receipts_path,
        json!({
            "schemaVersion": 1,
            "installed": {
                "claude-panel": {
                    "kind": "harness",
                    "treeSha256": compute_tree_sha256(&legacy_pairs),
                    "installedAt": 1,
                    "targetPaths": [legacy_panel],
                },
            },
        })
        .to_string(),
    )
    .unwrap();
    fs::write(legacy_panel.join("notes.txt"), "my notes").unwrap();

    // 2. Install telegram, claude-panel, and herdr-mod via --from-dir.
    for name in ["telegram", "claude-panel", "herdr-mod"] {
        let inst = run(
            &[
                "plugin",
                "install",
                name,
                "--from-dir",
                plugins_dir.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--json",
            ],
            &[],
        );
        assert!(
            inst.status.success(),
            "install {name} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&inst.stdout),
            String::from_utf8_lossy(&inst.stderr)
        );
    }
    assert!(!legacy_panel.join("hooks/register.tsx").exists());
    assert!(!legacy_panel.join(".claude-plugin/plugin.json").exists());
    assert_eq!(
        fs::read_to_string(legacy_panel.join("notes.txt")).unwrap(),
        "my notes"
    );
    assert!(state_dir.join("plugins/installed.json").is_file());
    assert!(state_dir.join("plugins/telegram/index.mjs").is_file());
    assert!(state_dir.join("plugins/sdk/client.mjs").is_file());
    assert!(
        home.join(".claude/skills/hyp-panel/hooks/register.tsx")
            .is_file()
    );
    assert!(
        home.join(".config/herdr-app/mods/hyphae-pane/pill.js")
            .is_file()
    );
    assert!(
        home.join(".config/herdr-app/mods/hyphae-panel/main.js")
            .is_file()
    );

    // 3. `hyp plugin verify` & `hyp doctor` pass cleanly when all are up_to_date.
    let ver_ok = run(
        &[
            "plugin",
            "verify",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(ver_ok.status.success());

    let doc_ok = run(
        &[
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(doc_ok.status.success());
    let doc_json: Value = serde_json::from_slice(&doc_ok.stdout).unwrap();
    assert_eq!(doc_json["data"]["plugins"]["installedCount"], 4);
    assert_eq!(doc_json["data"]["plugins"]["upToDateCount"], 4);

    // 4. Simulate OUTDATED `telegram` (`disk == receipt && disk != pinned`):
    //    - `hyp doctor` warns with `hyp plugin update --all`
    //    - `hyp plugin update --all --dry-run` plans update without writing
    //    - `hyp plugin update --all --from-dir` updates ONLY `telegram`!
    let tg_path = state_dir.join("plugins/telegram/index.mjs");
    let old_tg = b"// simulated v0.6.1 telegram\n";
    fs::write(&tg_path, old_tg).unwrap();
    let old_sha = sha256_file_hex(old_tg, false);
    let old_tree = compute_tree_sha256(&[("telegram/index.mjs", &old_sha)]);
    let mut receipts_doc: Value =
        serde_json::from_str(&fs::read_to_string(&receipts_path).unwrap()).unwrap();
    receipts_doc["installed"]["telegram"]["treeSha256"] = Value::String(old_tree);
    fs::write(
        &receipts_path,
        serde_json::to_string_pretty(&receipts_doc).unwrap(),
    )
    .unwrap();

    let doc_outdated = run(
        &[
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    let doc_outdated_json: Value = serde_json::from_slice(&doc_outdated.stdout).unwrap();
    assert_eq!(doc_outdated_json["data"]["plugins"]["outdatedCount"], 1);
    let tg_check = doc_outdated_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "plugin:telegram")
        .expect("plugin:telegram doctor check");
    assert_eq!(tg_check["status"], "warn");
    assert_eq!(tg_check["fix"], "hyp plugin update --all");

    let dry_upd = run(
        &[
            "plugin",
            "update",
            "--all",
            "--dry-run",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(dry_upd.status.success());
    let dry_json: Value = serde_json::from_slice(&dry_upd.stdout).unwrap();
    assert_eq!(dry_json["data"]["planned"], json!(["telegram"]));
    assert_eq!(fs::read(&tg_path).unwrap(), old_tg);

    let real_upd = run(
        &[
            "plugin",
            "update",
            "--all",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(real_upd.status.success());
    let real_upd_json: Value = serde_json::from_slice(&real_upd.stdout).unwrap();
    assert_eq!(real_upd_json["data"]["updated"], json!(["telegram"]));

    // 5. Local edit on `claude-panel` (`modified`) -> refuses without `--force`, succeeds with `--force`!
    let panel_reg = home.join(".claude/skills/hyp-panel/hooks/register.tsx");
    let user_edit = b"// user custom edit\n";
    fs::write(&panel_reg, user_edit).unwrap();

    let refuse_single = run(
        &[
            "plugin",
            "update",
            "claude-panel",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert_eq!(refuse_single.status.code(), Some(1));
    let refuse_json: Value = serde_json::from_slice(&refuse_single.stdout).unwrap();
    assert_eq!(refuse_json["error"]["code"], "PLUGIN_MODIFIED");
    assert_eq!(fs::read(&panel_reg).unwrap(), user_edit);

    let force_single = run(
        &[
            "plugin",
            "update",
            "claude-panel",
            "--force",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert!(force_single.status.success());
    assert_ne!(fs::read(&panel_reg).unwrap(), user_edit);

    // 6. Graceful offline `hyp setup`: when network download fails and no cache/dir/archive exists,
    //    pure-Rust Claude + Herdr setup STILL succeeds (exit 0) with clear warning & `next` hints!
    let offline_home = tmp.path().join("offline-home");
    let offline_state = tmp.path().join("offline-state");
    fs::create_dir_all(offline_home.join(".claude")).unwrap();
    fs::create_dir_all(offline_home.join(".config/herdr-app")).unwrap();

    let offline_setup = run(
        &[
            "setup",
            "--harness",
            "claude,herdr",
            "--mod",
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            offline_home.to_str().unwrap(),
            "--state-dir",
            offline_state.to_str().unwrap(),
            "--json",
        ],
        &[(
            "HYPHAE_PLUGINS_URL",
            Some("http://127.0.0.1:1/unreachable.tar.gz"),
        )],
    );
    assert_eq!(
        offline_setup.status.code(),
        Some(0),
        "offline setup must succeed on pure-Rust config: stdout={} stderr={}",
        String::from_utf8_lossy(&offline_setup.stdout),
        String::from_utf8_lossy(&offline_setup.stderr)
    );
    let offline_json: Value = serde_json::from_slice(&offline_setup.stdout).unwrap();
    assert_eq!(offline_json["ok"], true);
    // Pure-Rust configs MUST exist!
    assert!(offline_home.join(".claude.json").is_file());
    assert!(offline_home.join(".claude/settings.json").is_file());
    assert!(offline_home.join(".claude/commands/hyp.md").is_file());
    assert!(!offline_home.join(".config/herdr/hyphae.json").exists());
    assert!(
        offline_home
            .join(".config/herdr/skills/hyp-mesh/SKILL.md")
            .is_file()
    );
    // Non-Rust UI mods were skipped gracefully with actionable next commands!
    let next_steps: Vec<String> = offline_json["next"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    assert!(
        next_steps
            .iter()
            .any(|s| s.contains("hyp plugin install claude-panel")),
        "expected `hyp plugin install claude-panel` in next: {next_steps:?}"
    );
    assert!(
        next_steps
            .iter()
            .any(|s| s.contains("hyp plugin install herdr-mod")),
        "expected `hyp plugin install herdr-mod` in next: {next_steps:?}"
    );

    // 7. Verified local tarball cache (`plugins-cache/hyp-v<ver>-plugins.tar.gz`) serves
    //    `hyp setup` 100% offline with ZERO network calls!
    let cache_path = offline_state
        .join("plugins-cache")
        .join(format!("hyp-v{}-plugins.tar.gz", env!("CARGO_PKG_VERSION")));
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    let entries: Vec<TarInputEntry> = PINNED_PLUGIN_FILES
        .iter()
        .map(|p| TarInputEntry {
            archive_path: p.rel_path.to_string(),
            source_path: plugins_dir.join(p.rel_path),
        })
        .collect();
    pack_tar_gz(
        &entries,
        fs::File::create(&cache_path).unwrap(),
        TarPackOptions::default(),
    )
    .unwrap();

    let cached_setup = run(
        &[
            "setup",
            "--harness",
            "claude,herdr",
            "--mod",
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            offline_home.to_str().unwrap(),
            "--state-dir",
            offline_state.to_str().unwrap(),
            "--json",
        ],
        &[(
            "HYPHAE_PLUGINS_URL",
            Some("http://127.0.0.1:1/unreachable.tar.gz"),
        )],
    );
    assert_eq!(
        cached_setup.status.code(),
        Some(0),
        "cached offline setup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cached_setup.stdout),
        String::from_utf8_lossy(&cached_setup.stderr)
    );
    assert!(
        offline_home
            .join(".claude/skills/hyp-panel/hooks/register.tsx")
            .is_file()
    );
    assert!(
        offline_home
            .join(".config/herdr-app/mods/hyphae-pane/pill.js")
            .is_file()
    );

    // 8. Tampered --plugins-dir during `hyp setup` MUST FAIL CLOSED (never ignored as offline)!
    let tampered_dir = tmp.path().join("tampered-plugins");
    for entry in PINNED_PLUGIN_FILES {
        let dst = tampered_dir.join(entry.rel_path);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        let mut bytes = fs::read(plugins_dir.join(entry.rel_path)).unwrap();
        if entry.rel_path == "claude-code/hooks/register.tsx" {
            bytes[0] ^= 0x01;
        }
        fs::write(&dst, &bytes).unwrap();
    }
    let tamper_home = tmp.path().join("tamper-home");
    let tamper_state = tmp.path().join("tamper-state");
    fs::create_dir_all(tamper_home.join(".claude")).unwrap();
    let tamper_setup = run(
        &[
            "setup",
            "--harness",
            "claude",
            "--plugins-dir",
            tampered_dir.to_str().unwrap(),
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            tamper_home.to_str().unwrap(),
            "--state-dir",
            tamper_state.to_str().unwrap(),
            "--json",
        ],
        &[],
    );
    assert_eq!(tamper_setup.status.code(), Some(1));
    assert!(!tamper_home.join(".claude/skills/hyp-panel").exists());
}

#[test]
fn compiled_hyp_plugin_install_telegram_resolves_bot_username_via_getme_and_falls_back_safely() {
    use hyp_crypto::keystore::{SecretBackend, SecretStore};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let bin = env!("CARGO_BIN_EXE_hyp");
    let root = repo_root();
    let plugins_dir = root.join("plugins");

    let ok_tok = "30001:CLI_E2E_OK_TOKEN_NEVER_LEAK";
    let fail_tok = "30002:CLI_E2E_500_TOKEN_NEVER_LEAK";

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            if path == format!("/bot{ok_tok}/getMe") {
                let body =
                    r#"{"ok":true,"result":{"id":7,"is_bot":true,"username":"Moneypenny0_Bot"}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            } else {
                let body = r#"{"ok":false,"description":"service unavailable"}"#;
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        }
    });

    let api_base = format!("http://{addr}");

    // 1. Happy path: stored telegram-bot-token + mock getMe -> defaultTarget == "moneypenny0_bot"
    let tmp_ok = TempDir::new().expect("tempdir ok");
    let home_ok = tmp_ok.path().join("home");
    let state_ok = tmp_ok.path().join("state");
    fs::create_dir_all(&home_ok).unwrap();
    fs::create_dir_all(&state_ok).unwrap();
    SecretStore::new(&state_ok, SecretBackend::File)
        .set("telegram-bot-token", ok_tok)
        .unwrap();

    let out_ok = Command::new(bin)
        .args([
            "plugin",
            "install",
            "telegram",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home_ok.to_str().unwrap(),
            "--state-dir",
            state_ok.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home_ok)
        .env("TELEGRAM_API_BASE", &api_base)
        .output()
        .expect("run hyp plugin install telegram");
    assert!(
        out_ok.status.success(),
        "install telegram failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_ok.stdout),
        String::from_utf8_lossy(&out_ok.stderr)
    );
    let stdout_ok = String::from_utf8_lossy(&out_ok.stdout);
    let stderr_ok = String::from_utf8_lossy(&out_ok.stderr);
    assert!(!stdout_ok.contains(ok_tok) && !stderr_ok.contains(ok_tok));
    let json_ok: Value = serde_json::from_str(&stdout_ok).expect("parse json");
    assert_eq!(json_ok["ok"], true);
    assert_eq!(
        json_ok["data"]["plugins"][0]["defaultTarget"],
        "moneypenny0_bot"
    );
    assert_eq!(
        json_ok["data"]["plugins"][0]["defaultTargetSource"],
        "getMe"
    );
    assert!(
        json_ok["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains("moneypenny0_bot"))),
        "next hints should suggest resolved target: {}",
        json_ok["next"]
    );

    // 2. Fallback path: HTTP 500 -> install still succeeds (exit 0), defaultTarget == "personal", zero token leak!
    let tmp_fail = TempDir::new().expect("tempdir fail");
    let home_fail = tmp_fail.path().join("home");
    let state_fail = tmp_fail.path().join("state");
    fs::create_dir_all(&home_fail).unwrap();
    fs::create_dir_all(&state_fail).unwrap();
    SecretStore::new(&state_fail, SecretBackend::File)
        .set("telegram-bot-token", fail_tok)
        .unwrap();

    let out_fail = Command::new(bin)
        .args([
            "plugin",
            "install",
            "telegram",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home_fail.to_str().unwrap(),
            "--state-dir",
            state_fail.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home_fail)
        .env("TELEGRAM_API_BASE", &api_base)
        .output()
        .expect("run hyp plugin install telegram (500 fallback)");
    assert!(
        out_fail.status.success(),
        "install telegram must never block on getMe error: stdout={} stderr={}",
        String::from_utf8_lossy(&out_fail.stdout),
        String::from_utf8_lossy(&out_fail.stderr)
    );
    let stdout_fail = String::from_utf8_lossy(&out_fail.stdout);
    let stderr_fail = String::from_utf8_lossy(&out_fail.stderr);
    assert!(
        !stdout_fail.contains(fail_tok) && !stderr_fail.contains(fail_tok),
        "token leaked on fallback!"
    );
    let json_fail: Value = serde_json::from_str(&stdout_fail).expect("parse json");
    assert_eq!(json_fail["ok"], true);
    assert_eq!(json_fail["data"]["plugins"][0]["defaultTarget"], "personal");
    assert_eq!(
        json_fail["data"]["plugins"][0]["defaultTargetSource"],
        "fallback"
    );
    assert!(
        json_fail["warnings"]
            .as_array()
            .is_some_and(|w| !w.is_empty()),
        "expected non-fatal fallback warning"
    );

    let _ = server.join();
}

#[test]
fn compiled_hyp_plugin_update_respects_env_url_and_local_dir_precedence() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let bin = env!("CARGO_BIN_EXE_hyp");
    let root = repo_root();
    let plugins_dir = root.join("plugins");
    let tmp = TempDir::new().expect("create temp dir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();

    // Build an in-memory tarball identical to the nightly release asset (`hyp-nightly-plugins.tar.gz`).
    let mut tarball_bytes = Vec::new();
    let entries: Vec<TarInputEntry> = PINNED_PLUGIN_FILES
        .iter()
        .map(|p| TarInputEntry {
            archive_path: p.rel_path.to_string(),
            source_path: plugins_dir.join(p.rel_path),
        })
        .collect();
    pack_tar_gz(&entries, &mut tarball_bytes, TarPackOptions::default()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock plugins server");
    let addr = listener.local_addr().unwrap();
    let server_body = tarball_bytes.clone();
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");
            if first.starts_with("GET /releases/download/nightly/hyp-nightly-plugins.tar.gz ") {
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    server_body.len()
                );
                let _ = stream.write_all(hdr.as_bytes());
                let _ = stream.write_all(&server_body);
            } else {
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    });

    // 1. Install `telegram` from local dir, then simulate an outdated install (`disk == receipt != pinned`).
    let install_out = Command::new(bin)
        .args([
            "plugin",
            "install",
            "telegram",
            "--from-dir",
            plugins_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home)
        .env_remove("HYPHAE_PLUGINS_DIR")
        .env_remove("HYPHAE_PLUGINS_ARCHIVE")
        .env_remove("HYPHAE_PLUGINS_URL")
        .output()
        .expect("install telegram");
    assert!(install_out.status.success());

    let mark_telegram_outdated = |state: &Path| {
        let tg_path = state.join("plugins/telegram/index.mjs");
        let old_tg = b"// simulated outdated telegram script\n";
        fs::write(&tg_path, old_tg).unwrap();
        let old_sha = sha256_file_hex(old_tg, false);
        let old_tree = compute_tree_sha256(&[("telegram/index.mjs", &old_sha)]);
        let receipts_path = state.join("plugins/installed.json");
        let mut doc: Value =
            serde_json::from_str(&fs::read_to_string(&receipts_path).unwrap()).unwrap();
        doc["installed"]["telegram"]["treeSha256"] = Value::String(old_tree);
        fs::write(&receipts_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    };

    // 2. `HYPHAE_PLUGINS_URL` override resolves & verifies the nightly archive cleanly!
    mark_telegram_outdated(&state_dir);
    let env_url = format!("http://{addr}/releases/download/nightly/hyp-nightly-plugins.tar.gz");
    let upd_env_url = Command::new(bin)
        .args([
            "plugin",
            "update",
            "--all",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home)
        .env("HYPHAE_PLUGINS_URL", &env_url)
        .env_remove("HYPHAE_PLUGINS_DIR")
        .env_remove("HYPHAE_PLUGINS_ARCHIVE")
        .output()
        .expect("plugin update via HYPHAE_PLUGINS_URL");
    assert!(
        upd_env_url.status.success(),
        "plugin update via HYPHAE_PLUGINS_URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&upd_env_url.stdout),
        String::from_utf8_lossy(&upd_env_url.stderr)
    );
    let upd_json: Value = serde_json::from_slice(&upd_env_url.stdout).unwrap();
    assert_eq!(upd_json["data"]["updated"], json!(["telegram"]));
    assert_eq!(upd_json["data"]["source"], "release");
    assert_eq!(upd_json["data"]["sourceLocation"], env_url);

    // 3. `HYPHAE_PLUGINS_DIR` takes precedence over an unreachable `HYPHAE_PLUGINS_URL`!
    mark_telegram_outdated(&state_dir);
    let _ = fs::remove_dir_all(state_dir.join("plugins-cache"));
    let upd_env_dir = Command::new(bin)
        .args([
            "plugin",
            "update",
            "--all",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &home)
        .env("HYPHAE_PLUGINS_DIR", &plugins_dir)
        .env(
            "HYPHAE_PLUGINS_URL",
            "http://127.0.0.1:1/unreachable.tar.gz",
        )
        .env_remove("HYPHAE_PLUGINS_ARCHIVE")
        .output()
        .expect("plugin update via HYPHAE_PLUGINS_DIR");
    assert!(
        upd_env_dir.status.success(),
        "HYPHAE_PLUGINS_DIR must beat unreachable HYPHAE_PLUGINS_URL: stdout={} stderr={}",
        String::from_utf8_lossy(&upd_env_dir.stdout),
        String::from_utf8_lossy(&upd_env_dir.stderr)
    );
    let upd_dir_json: Value = serde_json::from_slice(&upd_env_dir.stdout).unwrap();
    assert_eq!(upd_dir_json["data"]["updated"], json!(["telegram"]));
    assert_eq!(upd_dir_json["data"]["source"], "dir");

    let _ = server.join();
}
