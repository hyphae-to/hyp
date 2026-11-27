//! Agent-first CLI output contract shared across `hyp` subcommands (`AGENTS.md`, `src/cli-ui.ts`).
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
    #[serde(skip)]
    pub exit: u8,
    #[serde(skip)]
    command: Option<&'static str>,
    #[serde(skip)]
    data: Option<Box<Value>>,
    #[serde(skip)]
    plain: bool,
}

impl CliError {
    pub fn new(exit: u8, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            fix: None,
            exit,
            command: None,
            data: None,
            plain: false,
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(EXIT_ERROR, code, message)
    }

    pub fn usage(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(EXIT_USAGE, code, message)
    }

    pub fn with_command(mut self, command: &'static str) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(Box::new(data));
        self
    }

    pub fn plain(mut self) -> Self {
        self.plain = true;
        self
    }

    pub fn with_fix(self, fix: impl Into<String>) -> Self {
        self.with_optional_fix(Some(fix.into()))
    }

    pub fn with_optional_fix(mut self, fix: Option<String>) -> Self {
        self.fix = fix;
        self
    }
}

pub struct CommandResult {
    pub command: &'static str,
    pub as_json: bool,
    pub result: Result<ExitCode, CliError>,
}

impl CommandResult {
    pub fn new(command: &'static str, as_json: bool, result: Result<ExitCode, CliError>) -> Self {
        Self {
            command,
            as_json,
            result,
        }
    }
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

impl<T: Serialize> JsonEnvelope<T> {
    pub fn ok(command: impl Into<String>, summary: impl Into<String>, data: T) -> Self {
        Self {
            ok: true,
            command: command.into(),
            summary: Some(summary.into()),
            data: Some(data),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        }
    }

    pub fn warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    pub fn next(mut self, next: Vec<String>) -> Self {
        self.next = next;
        self
    }
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
    print_command_error(
        command,
        as_json,
        CliError::new(exit_code, code, message).with_optional_fix(fix),
    )
}

pub fn print_command_error(command: &str, as_json: bool, mut error: CliError) -> ExitCode {
    let exit = error.exit;
    if as_json {
        let envelope: JsonEnvelope<Value> = JsonEnvelope {
            ok: false,
            command: error.command.unwrap_or(command).to_string(),
            summary: Some(error.message.clone()),
            data: error.data.take().map(|value| *value),
            warnings: Vec::new(),
            next: error.fix.iter().cloned().collect(),
            error: Some(error),
        };
        print_json(&envelope);
    } else if error.plain {
        eprintln!("error: {}", error.message);
    } else {
        eprintln!("FAIL [{}] {}", error.code, error.message);
        if let Some(fix) = error.fix {
            eprintln!("Fix:  {fix}");
        }
    }
    ExitCode::from(exit)
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
