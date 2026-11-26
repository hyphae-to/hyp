//! Unit & real-subprocess E2E tests for the native Codex Queue push transport
//! (`crates/hyp-harness/src/transport/codex.rs`).
//!
//! Pure unit tests and missing-binary/validation tests run on all operating systems
//! (including Windows). Real `#!/bin/sh` subprocess E2E tests are `#[cfg(unix)]`-gated
//! so Windows builds cleanly with zero warnings.

use std::time::Duration;

use hyp_harness::transport::codex::{
    CodexQueueTarget, CodexQueueTransport, DEFAULT_CODEX_QUEUE_TIMEOUT, MAX_THREAD_ID_LEN,
    REASON_BINARY_MISSING, REASON_INVALID_REMOTE, REASON_INVALID_THREAD_ID,
    REASON_QUEUE_OUTCOME_UNKNOWN, REASON_QUEUE_UNAVAILABLE, build_codex_queue_args,
    classify_codex_queue_failure,
};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport};

#[test]
fn unit_arg_construction_and_flag_injection_guard() {
    let thread_id = "1c192b8d-aceb-4b35-a5d8-0baf687f1e7e";
    let payload = "hello\n$(echo pwned) `id` \"quotes\" 'single' --not-a-flag";

    let minimal = CodexQueueTarget::new(thread_id);
    assert_eq!(
        build_codex_queue_args(&minimal, payload).expect("minimal args"),
        vec!["queue", "--thread", thread_id, "--message", payload]
    );

    let resume_only = minimal.clone().with_resume(true);
    assert_eq!(
        build_codex_queue_args(&resume_only, payload).expect("resume args"),
        vec![
            "queue",
            "--thread",
            thread_id,
            "--message",
            payload,
            "--resume"
        ]
    );

    let remote_only = minimal
        .clone()
        .with_remote("https://codex.internal.test:8443/v1");
    assert_eq!(
        build_codex_queue_args(&remote_only, payload).expect("remote args"),
        vec![
            "queue",
            "--thread",
            thread_id,
            "--message",
            payload,
            "--remote",
            "https://codex.internal.test:8443/v1"
        ]
    );

    let full = minimal
        .clone()
        .with_resume(true)
        .with_remote("wss://codex.example.test/queue");
    assert_eq!(
        build_codex_queue_args(&full, payload).expect("full args"),
        vec![
            "queue",
            "--thread",
            thread_id,
            "--message",
            payload,
            "--resume",
            "--remote",
            "wss://codex.example.test/queue"
        ]
    );

    // Flag-injection & malformed thread_id checks (fail-closed)
    let over_max = "x".repeat(MAX_THREAD_ID_LEN + 1);
    for bad_thread in [
        "",
        "   ",
        "-",
        "-x",
        "--evil",
        "--remote=http://evil",
        " --evil",
        "thr\0bad",
        "thr\nbad",
        "thr\rbad",
        "thr\x1bbad",
        over_max.as_str(),
    ] {
        assert_eq!(
            build_codex_queue_args(&CodexQueueTarget::new(bad_thread), "msg"),
            Err(PushOutcome::reject(REASON_INVALID_THREAD_ID)),
            "thread_id {bad_thread:?} must be rejected"
        );
    }

    // Exact boundary length (256 chars) is accepted
    let exact_max = "t".repeat(MAX_THREAD_ID_LEN);
    assert!(build_codex_queue_args(&CodexQueueTarget::new(exact_max), "msg").is_ok());

    // Flag-injection & malformed remote checks (fail-closed)
    for bad_remote in [
        "",
        "   ",
        "-",
        "--evil",
        " --evil",
        "https://host\0/path",
        "https://host\n--evil",
    ] {
        let target = CodexQueueTarget::new(thread_id).with_remote(bad_remote);
        assert_eq!(
            build_codex_queue_args(&target, "msg"),
            Err(PushOutcome::reject(REASON_INVALID_REMOTE)),
            "remote {bad_remote:?} must be rejected"
        );
    }
}

#[test]
fn unit_stderr_classification_covers_all_six_keywords_and_unknown_errors() {
    let offline_samples = [
        ("not found", "Error: thread not found"),
        ("NOT FOUND", "SESSION NOT FOUND"),
        ("offline", "target daemon offline"),
        ("Offline", "Target is Offline"),
        ("connect", "failed to connect to codex ipc"),
        ("CONNECT", "UNABLE TO CONNECT"),
        ("socket", "socket error: enoent"),
        ("Socket", "Unix Socket closed"),
        ("refused", "connection refused"),
        ("REFUSED", "ECONNREFUSED"),
        ("daemon", "codex daemon is not running"),
        ("Daemon", "Daemon unreachable"),
    ];

    for (label, stderr) in offline_samples {
        assert_eq!(
            classify_codex_queue_failure(stderr),
            PushOutcome::Hold {
                reason: REASON_QUEUE_UNAVAILABLE.to_string(),
                interrupted: false,
            },
            "keyword case {label} ({stderr:?}) must classify as hold(codex_queue_unavailable)"
        );
    }

    let unknown_samples = [
        "",
        "\n\r\t",
        "not  found",
        "exit status 1: unexpected error",
        "permission denied",
        "invalid UTF-8 or malformed json",
        "rate limit exceeded: retry later",
        "timeout waiting for model",
    ];

    for stderr in unknown_samples {
        assert_eq!(
            classify_codex_queue_failure(stderr),
            PushOutcome::Reject {
                reason: REASON_QUEUE_OUTCOME_UNKNOWN.to_string(),
                interrupted: false,
            },
            "unknown stderr {stderr:?} must classify as reject(codex_queue_outcome_unknown)"
        );
    }
}

#[tokio::test]
async fn deliver_fails_closed_on_invalid_config_before_spawning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_bin = dir
        .path()
        .join("missing-codex-bin")
        .to_string_lossy()
        .into_owned();

    // Even when binary does not exist, invalid thread_id must fail closed with
    // codex_invalid_thread_id rather than spawning and returning codex_binary_missing.
    let bad_thread = CodexQueueTransport::new(
        CodexQueueTarget::new("--evil-flag").with_bin(missing_bin.clone()),
    );
    assert_eq!(bad_thread.kind(), "codex_queue");
    assert!(!bad_thread.supports_interrupt());
    assert_eq!(bad_thread.timeout(), DEFAULT_CODEX_QUEUE_TIMEOUT);
    assert_eq!(
        bad_thread.deliver("hello", PushMode::Queue).await,
        PushOutcome::Reject {
            reason: REASON_INVALID_THREAD_ID.to_string(),
            interrupted: false,
        }
    );

    let bad_remote = CodexQueueTransport::new(
        CodexQueueTarget::new("valid-thread-1")
            .with_bin(missing_bin)
            .with_remote("--inject"),
    );
    assert_eq!(
        bad_remote.deliver("hello", PushMode::Queue).await,
        PushOutcome::Reject {
            reason: REASON_INVALID_REMOTE.to_string(),
            interrupted: false,
        }
    );
}

#[tokio::test]
async fn deliver_missing_binary_returns_hold_codex_binary_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir
        .path()
        .join("nonexistent-codex-executable-xyz")
        .to_string_lossy()
        .into_owned();

    let transport = CodexQueueTransport::new(
        CodexQueueTarget::new("1c192b8d-aceb-4b35-a5d8-0baf687f1e7e").with_bin(missing),
    )
    .with_timeout(Duration::from_secs(5));

    let boxed: Box<dyn PushTransport> = Box::new(transport);
    let outcome = boxed.deliver("wake up", PushMode::Queue).await;
    assert_eq!(
        outcome,
        PushOutcome::Hold {
            reason: REASON_BINARY_MISSING.to_string(),
            interrupted: false,
        }
    );

    // Blank binary string also resolves deterministically to codex_binary_missing across all OSes.
    let empty_bin = CodexQueueTransport::new(CodexQueueTarget::new("thr-empty-bin").with_bin(""));
    assert_eq!(
        empty_bin.deliver("wake up", PushMode::Queue).await,
        PushOutcome::Hold {
            reason: REASON_BINARY_MISSING.to_string(),
            interrupted: false,
        }
    );
}

#[cfg(unix)]
mod unix_subprocess_e2e {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command as StdCommand;
    use std::time::Instant;

    use hyp_harness::transport::codex::REASON_QUEUE_TIMEOUT;

    use super::*;

    fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("write shim script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("chmod +x shim script");
        path
    }

    fn write_recording_shim(dir: &Path, record_dir: &Path) -> PathBuf {
        let script = format!(
            "#!/bin/sh\n\
             OUT='{out}'\n\
             printf '%s' \"$#\" > \"$OUT/argc.txt\"\n\
             if [ \"${{CODEX_HOME+set}}\" = \"set\" ]; then\n\
               printf '%s' \"$CODEX_HOME\" > \"$OUT/codex_home.txt\"\n\
             else\n\
               printf '__UNSET__' > \"$OUT/codex_home.txt\"\n\
             fi\n\
             i=0\n\
             for arg in \"$@\"; do\n\
               printf '%s' \"$arg\" > \"$OUT/arg_$i.txt\"\n\
               i=$((i + 1))\n\
             done\n\
             exit 0\n",
            out = record_dir.display()
        );
        write_executable_script(dir, "codex-record.sh", &script)
    }

    fn read_recorded_argv(record_dir: &Path) -> Vec<String> {
        let argc: usize = fs::read_to_string(record_dir.join("argc.txt"))
            .expect("read argc.txt")
            .parse()
            .expect("parse argc");
        (0..argc)
            .map(|i| {
                fs::read_to_string(record_dir.join(format!("arg_{i}.txt")))
                    .unwrap_or_else(|e| panic!("read arg_{i}.txt: {e}"))
            })
            .collect()
    }

    #[tokio::test]
    async fn e2e_happy_path_exact_argv_and_zero_shell_interpolation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let record_dir = tmp.path().join("recorded");
        fs::create_dir(&record_dir).expect("mkdir recorded");
        let shim = write_recording_shim(tmp.path(), &record_dir);

        let pwn_marker = tmp.path().join("pwned-marker");
        let thread_id = "1c192b8d-aceb-4b35-a5d8-0baf687f1e7e";
        let special_message = format!(
            "line one\n\
             $(touch {m})\n\
             `touch {m}`\n\
             $HOME 'single quotes' \"double quotes\" \\backslash\\; touch {m}\n\
             --leading-flag-line\n",
            m = pwn_marker.display()
        );

        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new(thread_id).with_bin(shim.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_secs(5));

        let outcome = transport.deliver(&special_message, PushMode::Queue).await;
        assert_eq!(outcome, PushOutcome::Delivered);

        let argv = read_recorded_argv(&record_dir);
        assert_eq!(
            argv,
            vec![
                "queue".to_string(),
                "--thread".to_string(),
                thread_id.to_string(),
                "--message".to_string(),
                special_message,
            ]
        );
        assert!(
            !pwn_marker.exists(),
            "shell metacharacters in message must never be executed"
        );
    }

    #[tokio::test]
    async fn e2e_resume_remote_and_codex_home_forwarding() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let record_dir = tmp.path().join("recorded");
        fs::create_dir(&record_dir).expect("mkdir recorded");
        let shim = write_recording_shim(tmp.path(), &record_dir);

        let custom_home = tmp.path().join("isolated-codex-home");
        fs::create_dir(&custom_home).expect("mkdir codex home");
        let thread_id = "thr_resume_remote_42";
        let remote_url = "https://codex.acme.internal:8443/queue";
        let message = "hello from hyphae mesh";

        let target = CodexQueueTarget {
            thread_id: thread_id.to_string(),
            codex_home: Some(custom_home.clone()),
            bin: shim.to_string_lossy().into_owned(),
            resume: true,
            remote: Some(remote_url.to_string()),
        };

        let transport = CodexQueueTransport::new(target).with_timeout(Duration::from_secs(5));
        let outcome = transport.deliver(message, PushMode::Queue).await;
        assert_eq!(outcome, PushOutcome::Delivered);

        let argv = read_recorded_argv(&record_dir);
        assert_eq!(
            argv,
            vec![
                "queue",
                "--thread",
                thread_id,
                "--message",
                message,
                "--resume",
                "--remote",
                remote_url,
            ]
        );

        let observed_home =
            fs::read_to_string(record_dir.join("codex_home.txt")).expect("read codex_home.txt");
        assert_eq!(observed_home, custom_home.to_string_lossy());
    }

    #[tokio::test]
    async fn e2e_offline_and_daemon_unavailable_stderr_variants_return_hold() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cases = [
            ("not_found", 1, "Error: thread not found\\n"),
            (
                "refused",
                1,
                "dial unix /tmp/codex.sock: connection refused\\n",
            ),
            ("offline", 2, "Codex daemon offline\\n"),
            ("socket", 1, "socket error: broken pipe\\n"),
            ("connect", 125, "Unable to CONNECT to codex server\\n"),
            ("daemon", 1, "Local DAEMON is stopped\\n"),
        ];

        for (idx, (name, exit_code, stderr_escaped)) in cases.iter().enumerate() {
            let script = format!("#!/bin/sh\nprintf '{stderr_escaped}' >&2\nexit {exit_code}\n");
            let shim = write_executable_script(
                tmp.path(),
                &format!("codex-fail-{idx}-{name}.sh"),
                &script,
            );
            let transport = CodexQueueTransport::new(
                CodexQueueTarget::new("thr-offline-test")
                    .with_bin(shim.to_string_lossy().into_owned()),
            )
            .with_timeout(Duration::from_secs(5));

            let outcome = transport.deliver("ping", PushMode::Queue).await;
            assert_eq!(
                outcome,
                PushOutcome::Hold {
                    reason: REASON_QUEUE_UNAVAILABLE.to_string(),
                    interrupted: false,
                },
                "case {name} (exit {exit_code}) must return Hold(codex_queue_unavailable)"
            );
        }

        // Invalid UTF-8 bytes combined with an offline keyword still classify safely without panic.
        let non_utf8_shim = write_executable_script(
            tmp.path(),
            "codex-non-utf8.sh",
            "#!/bin/sh\nprintf '\\377\\376 connection refused\\n' >&2\nexit 1\n",
        );
        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new("thr-non-utf8")
                .with_bin(non_utf8_shim.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_secs(5));
        assert_eq!(
            transport.deliver("ping", PushMode::Queue).await,
            PushOutcome::Hold {
                reason: REASON_QUEUE_UNAVAILABLE.to_string(),
                interrupted: false,
            }
        );
    }

    #[tokio::test]
    async fn e2e_unknown_stderr_failure_and_empty_stderr_return_reject() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cases = [
            (
                "unknown_msg",
                1,
                "fatal: unexpected serialization failure\\n",
            ),
            ("empty_stderr", 1, ""),
            (
                "permission_denied",
                126,
                "permission denied on workspace\\n",
            ),
        ];

        for (idx, (name, exit_code, stderr_escaped)) in cases.iter().enumerate() {
            let script = format!("#!/bin/sh\nprintf '{stderr_escaped}' >&2\nexit {exit_code}\n");
            let shim = write_executable_script(
                tmp.path(),
                &format!("codex-unknown-{idx}-{name}.sh"),
                &script,
            );
            let transport = CodexQueueTransport::new(
                CodexQueueTarget::new("thr-unknown-test")
                    .with_bin(shim.to_string_lossy().into_owned()),
            )
            .with_timeout(Duration::from_secs(5));

            let outcome = transport.deliver("ping", PushMode::Queue).await;
            assert_eq!(
                outcome,
                PushOutcome::Reject {
                    reason: REASON_QUEUE_OUTCOME_UNKNOWN.to_string(),
                    interrupted: false,
                },
                "case {name} must return Reject(codex_queue_outcome_unknown)"
            );
        }

        // Non-executable target file (PermissionDenied, not NotFound) fails closed as unknown.
        let non_exec = tmp.path().join("not-executable-codex");
        fs::write(&non_exec, "#!/bin/sh\nexit 0\n").expect("write non-exec");
        fs::set_permissions(&non_exec, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new("thr-non-exec").with_bin(non_exec.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_secs(5));
        assert_eq!(
            transport.deliver("ping", PushMode::Queue).await,
            PushOutcome::Reject {
                reason: REASON_QUEUE_OUTCOME_UNKNOWN.to_string(),
                interrupted: false,
            }
        );
    }

    #[tokio::test]
    async fn e2e_slow_hung_binary_exceeding_timeout_is_killed_cleanly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pid_file = tmp.path().join("hung.pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{pid}'\nexec sleep 30\n",
            pid = pid_file.display()
        );
        let shim = write_executable_script(tmp.path(), "codex-hung.sh", &script);

        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new("thr-hung-timeout").with_bin(shim.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_millis(150));

        let started = Instant::now();
        let outcome = transport.deliver("ping", PushMode::Queue).await;
        let elapsed = started.elapsed();

        assert_eq!(
            outcome,
            PushOutcome::Reject {
                reason: REASON_QUEUE_TIMEOUT.to_string(),
                interrupted: false,
            }
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "hung subprocess should time out quickly, took {elapsed:?}"
        );

        // If the shim wrote its PID before timeout, verify the process was actually killed.
        if let Ok(pid_raw) = fs::read_to_string(&pid_file) {
            let pid_trimmed = pid_raw.trim();
            if !pid_trimmed.is_empty() && pid_trimmed.chars().all(|c| c.is_ascii_digit()) {
                let mut dead = false;
                for _ in 0..20 {
                    let status = StdCommand::new("kill")
                        .args(["-0", pid_trimmed])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .expect("invoke kill -0");
                    if !status.success() {
                        dead = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                assert!(
                    dead,
                    "timed-out codex subprocess (pid {pid_trimmed}) must be terminated"
                );
            }
        }
    }

    #[tokio::test]
    async fn e2e_large_stdout_and_stderr_do_not_deadlock_or_oom() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Emit >300 KiB to stdout (redirected to /dev/null) and >300 KiB to stderr (bounded drain)
        // with an offline keyword at the beginning, then exit 1.
        let script = "#!/bin/sh\n\
            printf 'daemon offline: ' >&2\n\
            dd if=/dev/zero bs=1024 count=320 2>/dev/null | tr '\\000' 'X'\n\
            dd if=/dev/zero bs=1024 count=320 2>/dev/null | tr '\\000' 'Y' >&2\n\
            exit 1\n";
        let shim = write_executable_script(tmp.path(), "codex-noisy.sh", script);

        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new("thr-noisy").with_bin(shim.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_secs(5));

        let outcome = transport.deliver("ping", PushMode::Queue).await;
        assert_eq!(
            outcome,
            PushOutcome::Hold {
                reason: REASON_QUEUE_UNAVAILABLE.to_string(),
                interrupted: false,
            }
        );
    }

    #[tokio::test]
    async fn e2e_nul_byte_in_message_fails_closed_without_spawning() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ran_marker = tmp.path().join("should-not-run");
        let script = format!("#!/bin/sh\ntouch '{}'\nexit 0\n", ran_marker.display());
        let shim = write_executable_script(tmp.path(), "codex-nul.sh", &script);

        let transport = CodexQueueTransport::new(
            CodexQueueTarget::new("thr-nul-check").with_bin(shim.to_string_lossy().into_owned()),
        )
        .with_timeout(Duration::from_secs(5));

        let outcome = transport
            .deliver("prefix\0truncated", PushMode::Queue)
            .await;
        assert_eq!(
            outcome,
            PushOutcome::Reject {
                reason: REASON_QUEUE_OUTCOME_UNKNOWN.to_string(),
                interrupted: false,
            }
        );
        assert!(
            !ran_marker.exists(),
            "subprocess must not spawn when argv contains an interior NUL byte"
        );
    }
}
