//! Comprehensive differential, security, and end-to-end tests for `hyp exec`
//! (`crates/hyp-cli/src/exec_cmd.rs`, GitHub Issue #1).
//!
//! Includes McKeeman differential testing of `StreamScrubber` across chunk sizes
//! `[1, 2, 3, 7, 16, 64, 4096]` + pseudo-random irregular boundaries against an
//! independent whole-buffer reference oracle, fail-closed validation/denylist checks,
//! clap CLI `debug_assert()`, and real child subprocess execution & signal propagation.

#[allow(dead_code)]
#[path = "../src/config_file.rs"]
mod config_file;
#[path = "../src/exec_cmd.rs"]
mod exec_cmd;
#[allow(dead_code)]
#[path = "../src/ui.rs"]
mod ui;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use clap::{CommandFactory, Parser, Subcommand};
use exec_cmd::{
    ExecArgs, RedactionRuleSet, StreamScrubber, build_redaction_patterns,
    collect_node_config_secret_names, parse_env_binding, run_exec, run_exec_with_writers,
    scrub_stream, validate_env_var_name, validate_exec_secret_name,
};
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_node::engine::http_util::percent_encode;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

// ============================================================================
// Helpers: In-memory capture writer & independent whole-buffer reference oracle
// ============================================================================

#[derive(Clone, Default)]
struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    fn new() -> Self {
        Self::default()
    }

    fn take_bytes(&self) -> Vec<u8> {
        self.buf.lock().expect("capture lock").clone()
    }

    fn take_string(&self) -> String {
        String::from_utf8_lossy(&self.take_bytes()).into_owned()
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf
            .lock()
            .expect("capture lock")
            .extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Pure, independent whole-buffer reference specification oracle for differential testing.
/// Computes the exact greedy left-to-right longest-match-first redaction over the complete buffer.
fn reference_scrub_whole_buffer(input: &[u8], patterns: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    // Deduplicate needles (first wins) and sort longest-first stably.
    let mut compiled: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (needle, repl) in patterns {
        if needle.is_empty() {
            continue;
        }
        if compiled.iter().any(|(existing, _)| existing == needle) {
            continue;
        }
        compiled.push((needle.clone(), repl.clone()));
    }
    compiled.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    while pos < input.len() {
        let mut matched = false;
        for (needle, repl) in &compiled {
            if input[pos..].starts_with(needle) {
                out.extend_from_slice(repl);
                pos += needle.len();
                matched = true;
                break;
            }
        }
        if !matched {
            out.push(input[pos]);
            pos += 1;
        }
    }
    out
}

fn expand_reference_patterns(secrets: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let add_enc = |out: &mut Vec<(Vec<u8>, Vec<u8>)>, s: &str, repl: &[u8]| {
        if s.len() < 6 {
            return;
        }
        out.push((STANDARD.encode(s.as_bytes()).into_bytes(), repl.to_vec()));
        out.push((
            STANDARD_NO_PAD.encode(s.as_bytes()).into_bytes(),
            repl.to_vec(),
        ));
        out.push((URL_SAFE.encode(s.as_bytes()).into_bytes(), repl.to_vec()));
        out.push((
            URL_SAFE_NO_PAD.encode(s.as_bytes()).into_bytes(),
            repl.to_vec(),
        ));
        let pct_u = percent_encode(s);
        if pct_u != s {
            out.push((pct_u.into_bytes(), repl.to_vec()));
        }
        let pct_l: String = s
            .as_bytes()
            .iter()
            .map(|&b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02x}")
                }
            })
            .collect();
        if pct_l != s {
            out.push((pct_l.into_bytes(), repl.to_vec()));
        }
        if s.contains(' ') {
            let form_u: String = s
                .as_bytes()
                .iter()
                .map(|&b| {
                    if b == b' ' {
                        "+".to_string()
                    } else if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            out.push((form_u.into_bytes(), repl.to_vec()));
            let form_l: String = s
                .as_bytes()
                .iter()
                .map(|&b| {
                    if b == b' ' {
                        "+".to_string()
                    } else if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02x}")
                    }
                })
                .collect();
            out.push((form_l.into_bytes(), repl.to_vec()));
        }
    };

    for &(name, raw) in secrets {
        if raw.is_empty() {
            continue;
        }
        let repl = format!("[REDACTED:{name}]").into_bytes();
        if raw.len() >= 4 {
            out.push((raw.as_bytes().to_vec(), repl.clone()));
            add_enc(&mut out, raw, &repl);
        }
        let trimmed = raw.trim();
        if trimmed != raw && trimmed.len() >= 4 {
            out.push((trimmed.as_bytes().to_vec(), repl.clone()));
            add_enc(&mut out, trimmed, &repl);
        }
    }
    out
}

fn run_streaming_chunks(input: &[u8], rules: Arc<RedactionRuleSet>, chunk_size: usize) -> Vec<u8> {
    let mut scrubber = StreamScrubber::new(rules);
    let mut out = Vec::new();
    for chunk in input.chunks(chunk_size) {
        scrubber.process_chunk(chunk, &mut out).unwrap();
    }
    scrubber.finish(&mut out).unwrap();
    out
}

// ============================================================================
// 1. McKeeman Differential Testing: StreamScrubber vs Whole-Buffer Oracle
// ============================================================================

#[test]
fn differential_scrubber_matches_reference_across_all_chunk_sizes_and_random_splits() {
    let secrets: Vec<(&str, &str)> = vec![
        ("short-key", "secret1234"),
        ("long-key", "secret12345678"),
        ("overlap-left", "abcdef12"),
        ("overlap-right", "ef12ghij"),
        ("special-key", "aws/key+with=pad & space?x=1"),
        ("padded-secret", "  trimmed_secret_98765  "),
        ("regex-meta", "r3g3x.*+?^$()[]{}|\\meta"),
        ("four-char", "z9q8"),
        ("too-short", "xyz"),
        ("empty", ""),
    ];

    let rules = Arc::new(build_redaction_patterns(&secrets));
    let ref_patterns = expand_reference_patterns(&secrets);

    // Construct a rich corpus exercising:
    // - Split secrets right across 4096-byte boundaries
    // - Overlapping prefix/suffix secrets (`secret1234` vs `secret12345678`, `abcdef12` vs `ef12ghij`)
    // - Adjacent zero-gap secrets
    // - Base64, Base64url, uppercase/lowercase URL-encoded, form-encoded forms
    // - False partial prefixes right before EOF and before non-matching bytes
    // - Raw binary / invalid UTF-8 / NUL bytes surrounding embedded secrets
    let mut corpus: Vec<u8> = Vec::new();
    corpus.extend_from_slice(b"header ");
    corpus.extend_from_slice(&vec![b'A'; 4090]); // lands right across 4096 boundary!
    corpus.extend_from_slice(b"secret12345678");
    corpus.extend_from_slice(b"|secret1234|secret1234567|secret12345678secret1234|");
    corpus.extend_from_slice(b"abcdef12ghij|abcdef12ef12ghij|");
    corpus.extend_from_slice(b"aws/key+with=pad & space?x=1|");
    corpus.extend_from_slice(STANDARD.encode(b"aws/key+with=pad & space?x=1").as_bytes());
    corpus.push(b'|');
    corpus.extend_from_slice(
        STANDARD_NO_PAD
            .encode(b"aws/key+with=pad & space?x=1")
            .as_bytes(),
    );
    corpus.push(b'|');
    corpus.extend_from_slice(
        URL_SAFE_NO_PAD
            .encode(b"aws/key+with=pad & space?x=1")
            .as_bytes(),
    );
    corpus.push(b'|');
    corpus.extend_from_slice(percent_encode("aws/key+with=pad & space?x=1").as_bytes());
    corpus.push(b'|');
    corpus.extend_from_slice(b"aws%2fkey%2bwith%3dpad%20%26%20space%3fx%3d1|");
    corpus.extend_from_slice(b"aws%2Fkey%2Bwith%3Dpad+%26+space%3Fx%3D1|");
    corpus.extend_from_slice(b"trimmed_secret_98765|");
    corpus.extend_from_slice(STANDARD.encode(b"trimmed_secret_98765").as_bytes());
    corpus.push(b'|');
    corpus.extend_from_slice(b"r3g3x.*+?^$()[]{}|\\meta|z9q8|xyz|");
    // Binary & invalid UTF-8 around secret
    corpus.extend_from_slice(&[0x00, 0xff, 0xfe, 0x80]);
    corpus.extend_from_slice(b"secret12345678");
    corpus.extend_from_slice(&[0x00, 0x01, 0xff]);
    // Partial prefix right at EOF (must flush verbatim without corruption!)
    corpus.extend_from_slice(b"secret123");

    let expected = reference_scrub_whole_buffer(&corpus, &ref_patterns);

    // Ensure ZERO raw/encoded secrets remain in expected output.
    let expected_lossy = String::from_utf8_lossy(&expected);
    for forbidden in [
        "secret1234",
        "secret12345678",
        "abcdef12",
        "ef12ghij",
        "aws/key+with=pad",
        "trimmed_secret_98765",
        "r3g3x.*+?^$",
        "z9q8",
    ] {
        assert!(
            !expected_lossy.contains(forbidden),
            "reference output still leaked '{forbidden}': {expected_lossy}"
        );
    }
    assert!(expected_lossy.contains("[REDACTED:long-key]"));
    assert!(expected_lossy.contains("[REDACTED:short-key]"));
    assert!(expected_lossy.contains("[REDACTED:special-key]"));
    assert!(expected_lossy.contains("[REDACTED:padded-secret]"));
    assert!(expected_lossy.contains("[REDACTED:regex-meta]"));
    assert!(expected_lossy.contains("[REDACTED:four-char]"));
    assert!(expected_lossy.ends_with("secret123"));

    // Differential check across fixed chunk sizes 1, 2, 3, 7, 16, 64, 4096 (+ whole buffer).
    for chunk_size in [1, 2, 3, 7, 16, 64, 4096, corpus.len()] {
        let actual = run_streaming_chunks(&corpus, Arc::clone(&rules), chunk_size);
        assert_eq!(
            actual, expected,
            "StreamScrubber diverged from whole-buffer oracle at chunk_size={chunk_size}"
        );
    }

    // Differential check across deterministic pseudo-random irregular chunk sizes (including 0-byte chunks).
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for trial in 0..25 {
        let mut scrubber = StreamScrubber::new(Arc::clone(&rules));
        let mut actual = Vec::new();
        let mut offset = 0;
        while offset < corpus.len() {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let step = ((seed >> 33) % 23) as usize; // includes 0-byte empty chunks!
            let end = (offset + step).min(corpus.len());
            scrubber
                .process_chunk(&corpus[offset..end], &mut actual)
                .unwrap();
            offset = end;
        }
        scrubber.finish(&mut actual).unwrap();
        assert_eq!(
            actual, expected,
            "StreamScrubber diverged from reference oracle on random split trial={trial}"
        );
    }

    // Also test `scrub_stream` over `Cursor` (4096-byte reader loop).
    let streamed = scrub_stream(Cursor::new(corpus.clone()), Vec::new(), rules).unwrap();
    assert_eq!(streamed, expected);
}

#[test]
fn scrubber_exact_4096_boundary_every_offset_redacts_secret() {
    let secret = "hyphae-boundary-secret-token-0123456789";
    let rules = Arc::new(build_redaction_patterns(&[("boundary-tok", secret)]));

    // Place the secret starting at every single offset across the 4096-byte read boundary!
    for offset in (4096 - secret.len())..=4096 {
        let mut buf = vec![b'x'; offset];
        buf.extend_from_slice(secret.as_bytes());
        buf.extend_from_slice(b"-end");

        let out = scrub_stream(Cursor::new(buf), Vec::new(), Arc::clone(&rules)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains(secret),
            "secret leaked at boundary offset={offset}"
        );
        let mut expected = "x".repeat(offset);
        expected.push_str("[REDACTED:boundary-tok]-end");
        assert_eq!(text, expected, "mismatch at boundary offset={offset}");
    }
}

#[test]
fn scrubber_interactive_zero_latency_for_non_matching_chunks() {
    let rules = Arc::new(build_redaction_patterns(&[(
        "api-key",
        "sk-super-secret-value-999999",
    )]));
    let mut scrubber = StreamScrubber::new(rules);
    let mut out = Vec::new();

    // Non-matching prompt must flush immediately without waiting for max_pattern_len bytes.
    scrubber.process_chunk(b"Ready> ", &mut out).unwrap();
    assert_eq!(out, b"Ready> ");

    // Partial prefix of the secret MUST be held back (zero unbuffered leak!).
    out.clear();
    scrubber.process_chunk(b"tok=sk-super", &mut out).unwrap();
    assert_eq!(out, b"tok=");

    // Completing the secret emits only the redaction marker.
    out.clear();
    scrubber
        .process_chunk(b"-secret-value-999999\n", &mut out)
        .unwrap();
    assert_eq!(out, b"[REDACTED:api-key]\n");

    out.clear();
    scrubber.finish(&mut out).unwrap();
    assert!(out.is_empty());
}

// ============================================================================
// 2. Clap CLI Contract & Fail-Closed Validation Security Tests
// ============================================================================

#[derive(Parser)]
#[command(name = "hyp")]
struct SimCli {
    #[command(subcommand)]
    command: SimCommands,
}

#[derive(Subcommand)]
enum SimCommands {
    Exec(ExecArgs),
}

#[test]
fn simulated_main_cli_debug_assert_and_parsing_edge_cases() {
    SimCli::command().debug_assert();

    // Multiple --env, --config, --state-dir, hyphenated command args after `--`
    let cli = SimCli::try_parse_from([
        "hyp",
        "exec",
        "-e",
        "TOKEN_A=sec-a",
        "--env",
        "TOKEN_B=sec-b",
        "--config",
        "/tmp/node.json",
        "--state-dir",
        "/tmp/state",
        "--",
        "my-cli",
        "--env",
        "literal",
        "-e",
        "--help",
        "--state-dir",
        "/other",
    ])
    .expect("parse exec");

    let SimCommands::Exec(args) = cli.command;
    assert_eq!(args.env, vec!["TOKEN_A=sec-a", "TOKEN_B=sec-b"]);
    assert_eq!(args.config, Some(PathBuf::from("/tmp/node.json")));
    assert_eq!(args.state_dir, Some(PathBuf::from("/tmp/state")));
    assert_eq!(
        args.command,
        vec![
            "my-cli",
            "--env",
            "literal",
            "-e",
            "--help",
            "--state-dir",
            "/other"
        ]
    );

    // Without `--`, trailing_var_arg still captures hyphenated child args after command name
    let no_sep =
        SimCli::try_parse_from(["hyp", "exec", "--env", "K=sec-a", "echo", "-n", "--flag"])
            .expect("parse without --");
    let SimCommands::Exec(args2) = no_sep.command;
    assert_eq!(args2.command, vec!["echo", "-n", "--flag"]);
}

#[test]
fn fail_closed_validation_blocks_all_dangerous_env_vars_and_bad_syntax() {
    let invalid_syntax = [
        "",
        "1ABC",
        "API-KEY",
        "API.KEY",
        "API KEY",
        "A=B",
        "KEY\0VAL",
        &"A".repeat(129),
    ];
    for bad in invalid_syntax {
        let err = validate_env_var_name(bad).unwrap_err();
        assert_eq!(
            err.0, "INVALID_ENV_VAR",
            "expected INVALID_ENV_VAR for {bad:?}"
        );
    }
    // Boundary: exactly 128 chars is valid.
    assert!(validate_env_var_name(&"A".repeat(128)).is_ok());

    // Missing `=` in binding fails closed.
    assert_eq!(
        parse_env_binding("API_KEY").unwrap_err().0,
        "INVALID_ENV_SPEC"
    );

    // Accidentally pasted raw secret value (uppercase/symbols) MUST NOT be echoed back in stderr!
    let accidental_secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456";
    let err = validate_exec_secret_name(accidental_secret).unwrap_err();
    assert_eq!(err.0, "INVALID_SECRET_NAME");
    assert!(
        !err.1.contains(accidental_secret),
        "error message leaked rejected raw secret value: {}",
        err.1
    );

    // Path traversal blocked.
    for bad_name in ["../etc/passwd", "foo/bar", "a..b", ".hidden", "-dash"] {
        assert!(
            validate_exec_secret_name(bad_name).is_err(),
            "expected '{bad_name}' to fail validation"
        );
    }
}

#[test]
fn run_exec_fails_closed_on_missing_secret_reserved_secret_dangerous_env_and_duplicates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let store = SecretStore::new(&state_dir, SecretBackend::File);

    // Even if a reserved system secret ACTUALLY exists in SecretStore, `hyp exec` MUST block it!
    store
        .set("node-ed25519-key", "super-private-node-ed25519-seed")
        .unwrap();
    store
        .set("gate-policy-hmac-key", "super-private-gate-hmac-key")
        .unwrap();
    store
        .set("staged-join-token", "am2_super_secret_join_token")
        .unwrap();
    store
        .set("human-admin-1234", "super-private-human-admin-key")
        .unwrap();
    store
        .set("valid-app-secret", "app-secret-value-12345")
        .unwrap();

    // 1. Reserved secrets blocked with EXIT_USAGE (2) and zero secret leak.
    for reserved in [
        "node-ed25519-key",
        "gate-policy-hmac-key",
        "gate-policy-hmac",
        "gate_policy_hmac",
        "staged-join-token",
        "human-admin-1234",
        "node-sign-deadbeef1234",
        "node-x25519-key",
        "openclaw-hooks-token",
        "hyphae-admin-pubkey",
        "daemon-session-token-key",
        "pair-custom-node",
        "p2p-offer-abcdef",
    ] {
        let out = CaptureWriter::new();
        let err = CaptureWriter::new();
        let code = run_exec_with_writers(
            ExecArgs {
                env: vec![format!("LEAK_ME={reserved}")],
                state_dir: Some(state_dir.clone()),
                config: None,
                command: vec!["echo".to_string(), "never-runs".to_string()],
            },
            out.clone(),
            err.clone(),
        );
        assert_eq!(code, ExitCode::from(ui::EXIT_USAGE), "reserved={reserved}");
        assert!(out.take_bytes().is_empty());
        let err_text = err.take_string();
        assert!(err_text.contains("RESERVED_SECRET_NAME"), "err={err_text}");
        assert!(!err_text.contains("super-private"));
        assert!(!err_text.contains("am2_super_secret"));
    }

    // 2. Dangerous env var blocked with EXIT_USAGE (2).
    for danger in [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PATH",
        "HYPHAE_SOCKET",
    ] {
        let out = CaptureWriter::new();
        let err = CaptureWriter::new();
        let code = run_exec_with_writers(
            ExecArgs {
                env: vec![format!("{danger}=valid-app-secret")],
                state_dir: Some(state_dir.clone()),
                config: None,
                command: vec!["echo".to_string(), "never-runs".to_string()],
            },
            out.clone(),
            err.clone(),
        );
        assert_eq!(code, ExitCode::from(ui::EXIT_USAGE), "danger={danger}");
        assert!(err.take_string().contains("DANGEROUS_ENV_VAR"));
    }

    // 3. Duplicate env var (exact & case-insensitive) blocked with EXIT_USAGE (2).
    for dup_pair in [
        vec![
            "API_KEY=valid-app-secret".to_string(),
            "API_KEY=valid-app-secret".to_string(),
        ],
        vec![
            "api_key=valid-app-secret".to_string(),
            "API_KEY=valid-app-secret".to_string(),
        ],
    ] {
        let out = CaptureWriter::new();
        let err = CaptureWriter::new();
        let code = run_exec_with_writers(
            ExecArgs {
                env: dup_pair,
                state_dir: Some(state_dir.clone()),
                config: None,
                command: vec!["echo".to_string(), "never-runs".to_string()],
            },
            out.clone(),
            err.clone(),
        );
        assert_eq!(code, ExitCode::from(ui::EXIT_USAGE));
        assert!(err.take_string().contains("DUPLICATE_ENV_VAR"));
    }

    // 4. Missing secret fails closed with EXIT_ERROR (1), actionable hints, ZERO paths/values!
    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec!["MISSING_KEY=not-configured-yet".to_string()],
            state_dir: Some(state_dir.clone()),
            config: None,
            command: vec!["echo".to_string(), "never-runs".to_string()],
        },
        out.clone(),
        err.clone(),
    );
    assert_eq!(code, ExitCode::from(ui::EXIT_ERROR));
    assert!(out.take_bytes().is_empty());
    let err_text = err.take_string();
    assert!(err_text.contains("SECRET_NOT_FOUND"), "err={err_text}");
    assert!(
        err_text.contains("hyp secret set not-configured-yet --web"),
        "missing web hint: {err_text}"
    );
    assert!(
        err_text.contains("hyp drop create --kind secret --secret-name not-configured-yet"),
        "missing drop hint: {err_text}"
    );
    assert!(
        !err_text.contains(&state_dir.display().to_string()),
        "error message leaked state_dir path: {err_text}"
    );
}

#[test]
fn wave4c_exec_blocks_hyphae_infrastructure_secrets_referenced_in_node_json() {
    use hyp_crypto::human::is_reserved_secret_name;

    // Verify new reserved names/prefixes in hyp-crypto::human::is_reserved_secret_name
    for reserved in [
        "openclaw-hooks-token",
        "hyphae-admin-pubkey",
        "daemon-session-token-key",
        "gate-policy-hmac",
        "gate_policy_hmac",
        "pair-alice-laptop",
        "p2p-offer-12345678",
    ] {
        assert!(
            is_reserved_secret_name(reserved),
            "expected '{reserved}' to be reserved in hyp_crypto::human"
        );
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let cfg_path = state_dir.join("node.json");

    let node_cfg = serde_json::json!({
        "v": 2,
        "nodeId": "exec-iso@box",
        "plugins": [
            {
                "id": "telegram",
                "command": "node",
                "args": ["/tmp/tg.mjs"],
                "targets": ["personal"],
                "env": {
                    "TELEGRAM_BOT_TOKEN": { "secret": "tg-bot-token" }
                }
            }
        ],
        "sources": [
            {
                "id": "gh-webhooks",
                "kind": "github-webhook",
                "webhookSecret": { "secret": "gh-webhook-hmac" },
                "repoTokens": {
                    "acme/*": { "secret": "gh-repo-pat" }
                }
            }
        ],
        "gate": {
            "stage2": {
                "enabled": false,
                "api_key_secret": "stage2-llm-key"
            },
            "filters": [
                {
                    "id": "ant-guard",
                    "enabled": true,
                    "adapter": {
                        "type": "anthropic",
                        "model": "claude-haiku-4-5",
                        "api_key_secret": "classifier-anthropic-cred"
                    }
                }
            ]
        },
        "pairing": {
            "adminKey": { "secret": "org-pairing-admin" }
        },
        "t3": {
            "url": "http://127.0.0.1:3773",
            "tokenSecret": "custom-t3-secret"
        },
        "openclaw": {
            "url": "http://127.0.0.1:18789",
            "tokenSecret": "custom-openclaw-secret"
        }
    });
    fs::write(&cfg_path, serde_json::to_string_pretty(&node_cfg).unwrap()).unwrap();

    let collected = collect_node_config_secret_names(&node_cfg);
    let blocked_infra = [
        "tg-bot-token",
        "gh-webhook-hmac",
        "gh-repo-pat",
        "stage2-llm-key",
        "classifier-anthropic-cred",
        "org-pairing-admin",
        "custom-t3-secret",
        "custom-openclaw-secret",
    ];
    for name in blocked_infra {
        assert!(
            collected.contains(name),
            "expected '{name}' collected from node.json: {collected:?}"
        );
    }

    let store = SecretStore::new(&state_dir, SecretBackend::File);
    for name in blocked_infra {
        store
            .set(name, &format!("infra-secret-val-{name}"))
            .unwrap();
    }
    store
        .set("user-app-stripe-key", "sk-user-app-only-99999")
        .unwrap();

    // Every secret referenced by node.json infrastructure MUST be refused with RESERVED_CONFIG_SECRET!
    for name in blocked_infra {
        let out = CaptureWriter::new();
        let err = CaptureWriter::new();
        let code = run_exec_with_writers(
            ExecArgs {
                env: vec![format!("STEAL={name}")],
                state_dir: Some(state_dir.clone()),
                config: None,
                command: vec!["echo".to_string(), "should-never-run".to_string()],
            },
            out.clone(),
            err.clone(),
        );
        assert_eq!(
            code,
            ExitCode::from(ui::EXIT_USAGE),
            "node.json infra secret '{name}' must fail closed with EXIT_USAGE"
        );
        assert!(out.take_bytes().is_empty());
        let err_text = err.take_string();
        assert!(
            err_text.contains("RESERVED_CONFIG_SECRET"),
            "expected RESERVED_CONFIG_SECRET for '{name}', got: {err_text}"
        );
        assert!(
            !err_text.contains("infra-secret-val-"),
            "secret value must never leak: {err_text}"
        );
    }

    // Unrelated user application secret NOT referenced by node.json still works normally!
    #[cfg(unix)]
    {
        let out = CaptureWriter::new();
        let err = CaptureWriter::new();
        let code = run_exec_with_writers(
            ExecArgs {
                env: vec!["APP_KEY=user-app-stripe-key".to_string()],
                state_dir: Some(state_dir),
                config: None,
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf 'ok=%s' \"$APP_KEY\"".to_string(),
                ],
            },
            out.clone(),
            err.clone(),
        );
        assert_eq!(code, ExitCode::from(0), "stderr={}", err.take_string());
        assert_eq!(out.take_string(), "ok=[REDACTED:user-app-stripe-key]");
    }
}

// ============================================================================
// 3. Real Subprocess E2E Tests (Secret Injection, Dual-Pipe Scrubbing, Exit Codes)
// ============================================================================

#[cfg(unix)]
#[test]
fn e2e_subprocess_injects_secrets_and_scrubs_stdout_stderr_encodings_and_chunk_boundaries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let store = SecretStore::new(&state_dir, SecretBackend::File);

    let secret_a = "sk-live/alpha+beta=gamma&delta";
    let secret_b = "ghp_MultiSecretBetaToken_9876543210";
    store.set("api-alpha", secret_a).unwrap();
    store.set("gh-beta", secret_b).unwrap();

    // Child proves it REALLY received the exact secret values (via length check + hash/transform),
    // then intentionally tries to exfiltrate raw, split-across-4096-bytes, base64, base64url,
    // and URL-encoded forms to BOTH stdout and stderr!
    let b64_a = STANDARD.encode(secret_a.as_bytes());
    let b64url_a = URL_SAFE_NO_PAD.encode(secret_a.as_bytes());
    let pct_a = percent_encode(secret_a);

    let script = format!(
        r#"
set -eu
# Confirm exact secret injection inside child without leaking
test "${{#ALPHA_KEY}}" -eq {len_a}
test "${{#BETA_KEY}}" -eq {len_b}
printf 'received_ok lenA=%d lenB=%d\n' "${{#ALPHA_KEY}}" "${{#BETA_KEY}}"
# Attempt to leak raw & encoded secrets to stdout
printf 'stdout_raw=%s\n' "$ALPHA_KEY"
printf 'stdout_b64=%s\n' '{b64_a}'
printf 'stdout_b64url=%s\n' '{b64url_a}'
printf 'stdout_pct=%s\n' '{pct_a}'
# Split secret_b right across a 4096-byte pipe boundary
head -c 4090 /dev/zero | tr '\0' 'Z'
printf '%s_after_boundary\n' "$BETA_KEY"
# Attempt to leak both secrets to stderr simultaneously
printf 'stderr_both=%s::%s\n' "$ALPHA_KEY" "$BETA_KEY" >&2
"#,
        len_a = secret_a.len(),
        len_b = secret_b.len(),
    );

    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec![
                "ALPHA_KEY=api-alpha".to_string(),
                "BETA_KEY=gh-beta".to_string(),
            ],
            state_dir: Some(state_dir),
            config: None,
            command: vec!["/bin/sh".to_string(), "-c".to_string(), script],
        },
        out.clone(),
        err.clone(),
    );

    assert_eq!(code, ExitCode::from(0));
    let stdout = out.take_string();
    let stderr = err.take_string();

    // Verify child actually saw full unredacted secrets!
    assert!(
        stdout.contains(&format!(
            "received_ok lenA={} lenB={}",
            secret_a.len(),
            secret_b.len()
        )),
        "stdout={stdout}"
    );

    // Verify ZERO secret material (raw or encoded) leaked on stdout or stderr!
    for leaked in [secret_a, secret_b, &b64_a, &b64url_a, &pct_a] {
        assert!(!stdout.contains(leaked), "stdout leaked '{leaked}'!");
        assert!(!stderr.contains(leaked), "stderr leaked '{leaked}'!");
    }

    assert!(stdout.contains("stdout_raw=[REDACTED:api-alpha]"));
    assert!(stdout.contains("stdout_b64=[REDACTED:api-alpha]"));
    assert!(stdout.contains("stdout_b64url=[REDACTED:api-alpha]"));
    assert!(stdout.contains("stdout_pct=[REDACTED:api-alpha]"));
    assert!(stdout.contains("[REDACTED:gh-beta]_after_boundary"));
    assert_eq!(
        stderr,
        "stderr_both=[REDACTED:api-alpha]::[REDACTED:gh-beta]\n"
    );
}

#[cfg(unix)]
#[test]
fn e2e_subprocess_concurrent_large_stdout_and_stderr_never_deadlocks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    let secret = "deadlock-free-secret-token-777";
    store.set("stream-key", secret).unwrap();

    // Emit > 128 KiB on BOTH stdout and stderr (> typical 64 KiB OS pipe buffer) so a
    // sequential single-threaded reader would deadlock permanently.
    let script = r#"
i=0
while [ "$i" -lt 1500 ]; do
  printf 'OUT:%04d:%s:padding-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' "$i" "$TOK"
  printf 'ERR:%04d:%s:padding-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n' "$i" "$TOK" >&2
  i=$((i + 1))
done
"#;

    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec!["TOK=stream-key".to_string()],
            state_dir: Some(state_dir),
            config: None,
            command: vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        },
        out.clone(),
        err.clone(),
    );

    assert_eq!(code, ExitCode::from(0));
    let stdout = out.take_string();
    let stderr = err.take_string();
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
    assert_eq!(stdout.matches("[REDACTED:stream-key]").count(), 1500);
    assert_eq!(stderr.matches("[REDACTED:stream-key]").count(), 1500);
}

#[cfg(unix)]
#[test]
fn e2e_subprocess_propagates_exact_exit_code_and_unix_signal_and_config_state_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("cfg");
    let custom_state = tmp.path().join("custom-state");
    fs::create_dir_all(&cfg_dir).unwrap();
    let cfg_path = cfg_dir.join("node.json");
    fs::write(
        &cfg_path,
        format!(
            "{{\"v\":2,\"nodeId\":\"exec@test\",\"stateDir\":\"{}\"}}\n",
            custom_state.display()
        ),
    )
    .unwrap();

    let store = SecretStore::new(&custom_state, SecretBackend::File);
    store.set("exit-secret", "exit-code-secret-9999").unwrap();

    // 1. Exact non-zero exit code (42) resolved via `--config` (without `--state-dir`).
    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec!["K=exit-secret".to_string()],
            state_dir: None,
            config: Some(cfg_path.clone()),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'bye %s' \"$K\"; exit 42".to_string(),
            ],
        },
        out.clone(),
        err.clone(),
    );
    assert_eq!(code, ExitCode::from(42));
    assert_eq!(out.take_string(), "bye [REDACTED:exit-secret]");
    assert!(err.take_bytes().is_empty());

    // 2. Unix signal termination -> 128 + SIGTERM (15) = 143.
    let out2 = CaptureWriter::new();
    let err2 = CaptureWriter::new();
    let sig_code = run_exec_with_writers(
        ExecArgs {
            env: vec!["K=exit-secret".to_string()],
            state_dir: None,
            config: Some(cfg_path),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "kill -TERM $$".to_string(),
            ],
        },
        out2,
        err2,
    );
    assert_eq!(sig_code, ExitCode::from(128 + 15));

    // 3. No shell interpolation: metacharacters in args are passed verbatim, never executed!
    let out3 = CaptureWriter::new();
    let err3 = CaptureWriter::new();
    let safe_code = run_exec_with_writers(
        ExecArgs {
            env: vec!["K=exit-secret".to_string()],
            state_dir: Some(custom_state),
            config: None,
            command: vec!["/bin/echo".to_string(), "$(id);$K".to_string()],
        },
        out3.clone(),
        err3.clone(),
    );
    assert_eq!(safe_code, ExitCode::from(0));
    assert_eq!(out3.take_string(), "$(id);$K\n");
    assert!(err3.take_bytes().is_empty());
}

#[test]
fn e2e_command_not_found_fails_closed_without_leaking_secrets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    let secret = "never-leak-on-spawn-failure-secret";
    store.set("spawn-sec", secret).unwrap();

    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec!["S=spawn-sec".to_string()],
            state_dir: Some(state_dir),
            config: None,
            command: vec!["definitely-nonexistent-hyphae-exec-binary-xyz".to_string()],
        },
        out.clone(),
        err.clone(),
    );
    assert_eq!(code, ExitCode::from(ui::EXIT_ERROR));
    assert!(out.take_bytes().is_empty());
    let err_text = err.take_string();
    assert!(err_text.contains("COMMAND_NOT_FOUND"), "err={err_text}");
    assert!(!err_text.contains(secret));
}

#[test]
fn e2e_run_exec_entrypoint_and_config_errors_and_broken_pipe() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    store
        .set("direct-key", "direct-entry-secret-12345")
        .unwrap();

    // 1. Direct `run_exec` entrypoint with silent child verifying secret injection & exit code.
    #[cfg(unix)]
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "test \"${#DIRECT_KEY}\" -eq 25".to_string(),
    ];
    #[cfg(not(unix))]
    let cmd = vec!["cmd".to_string(), "/C".to_string(), "exit /B 0".to_string()];

    let exit = run_exec(ExecArgs {
        env: vec!["DIRECT_KEY=direct-key".to_string()],
        state_dir: Some(state_dir.clone()),
        config: None,
        command: cmd,
    });
    assert_eq!(exit, ExitCode::from(0));

    // 2. Non-existent or corrupt `--config` fails closed with CONFIG_ERROR.
    let missing_cfg = tmp.path().join("does-not-exist.json");
    let out = CaptureWriter::new();
    let err = CaptureWriter::new();
    let code = run_exec_with_writers(
        ExecArgs {
            env: vec!["DIRECT_KEY=direct-key".to_string()],
            state_dir: None,
            config: Some(missing_cfg),
            command: vec!["echo".to_string(), "never".to_string()],
        },
        out,
        err.clone(),
    );
    assert_eq!(code, ExitCode::from(ui::EXIT_ERROR));
    assert!(err.take_string().contains("CONFIG_ERROR"));

    let bad_cfg = tmp.path().join("corrupt.json");
    fs::write(&bad_cfg, "{not valid json").unwrap();
    let out2 = CaptureWriter::new();
    let err2 = CaptureWriter::new();
    let code2 = run_exec_with_writers(
        ExecArgs {
            env: vec!["DIRECT_KEY=direct-key".to_string()],
            state_dir: None,
            config: Some(bad_cfg),
            command: vec!["echo".to_string(), "never".to_string()],
        },
        out2,
        err2.clone(),
    );
    assert_eq!(code2, ExitCode::from(ui::EXIT_ERROR));
    assert!(err2.take_string().contains("CONFIG_ERROR"));

    // 3. Downstream BrokenPipe during `scrub_stream` returns cleanly without panicking.
    struct BrokenPipeWriter;
    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
    }
    let rules = Arc::new(build_redaction_patterns(&[(
        "direct-key",
        "direct-entry-secret-12345",
    )]));
    let _ = scrub_stream(
        Cursor::new(b"prefix direct-entry-secret-12345 suffix".to_vec()),
        BrokenPipeWriter,
        rules,
    )
    .expect("BrokenPipe should terminate stream cleanly");
}
