//! Agent-first CLI output contract shared across `hyp-rs` subcommands (`AGENTS.md`, `src/cli-ui.ts`).
//!
//! Every subcommand supports `--json` returning the uniform envelope:
//! `{ ok, command, summary?, data?, warnings?, next?, error? }`
//! with deterministic exit codes: `0` (ok), `1` (operational/check failure), `2` (usage error).

use serde::Serialize;
use serde_json::Value;
use std::process::ExitCode;

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    pub const fn tag(self) -> &'static str {
        match self {
            CheckStatus::Ok => "OK",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl CliCheck {
    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    pub fn warn(
        name: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<Option<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            fix: fix.into(),
        }
    }

    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<Option<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            fix: fix.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonEnvelope<T: Serialize> {
    pub ok: bool,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliError>,
}

pub fn print_json<T: Serialize>(envelope: &JsonEnvelope<T>) {
    match serde_json::to_string_pretty(envelope) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("error: failed to serialize JSON output: {e}");
        }
    }
}

pub fn emit_error(
    command: &str,
    as_json: bool,
    exit_code: u8,
    code: &str,
    message: impl Into<String>,
    fix: Option<String>,
) -> ExitCode {
    let message = message.into();
    if as_json {
        let envelope: JsonEnvelope<Value> = JsonEnvelope {
            ok: false,
            command: command.to_string(),
            summary: Some(message.clone()),
            data: None,
            warnings: Vec::new(),
            next: fix.iter().cloned().collect(),
            error: Some(CliError {
                code: code.to_string(),
                message,
                fix,
            }),
        };
        print_json(&envelope);
    } else {
        eprintln!("FAIL [{code}] {message}");
        if let Some(f) = fix {
            eprintln!("Fix:  {f}");
        }
    }
    ExitCode::from(exit_code)
}

pub fn print_checks(checks: &[CliCheck]) {
    let name_width = checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(12)
        .max(12);
    for check in checks {
        println!(
            "{:<4}  {:<width$}  {}",
            check.status.tag(),
            check.name,
            check.detail,
            width = name_width
        );
        if let Some(fix) = &check.fix {
            println!("      {:<width$}  fix: {}", "", fix, width = name_width);
        }
    }
}

pub fn print_next_steps(next: &[String]) {
    if next.is_empty() {
        return;
    }
    println!();
    println!("Next steps:");
    for (idx, step) in next.iter().enumerate() {
        println!("  {}. {step}", idx + 1);
    }
}

pub fn print_warnings(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    println!();
    println!("Warnings:");
    for w in warnings {
        println!("  WARN  {w}");
    }
}
