//! Host-verified per-call caller session registry (`CallRegistry`), matching `src/caller.ts`
//! fail-closed semantics.
//!
//! PreToolUse hooks register the host-verified `(session_id, harness, tool, call_id)` before
//! MCP tool execution and receive a single-use cryptographic `call_token`. Every MCP `tool.call`
//! must present a matching in-flight `call_id` (from `_meta`) or `call_token`, verified against
//! the exact canonical tool name and consumed atomically on first use.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyp_store::{now_ms, sha256_hex, uuid_v4};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::protocol::{HarnessKind, normalize_mesh_tool_name};

/// Default TTL (60s) for an in-flight PreToolUse call registration.
pub const DEFAULT_CALL_TTL_MS: i64 = 60_000;
/// Default wait window (1500ms) when MCP `tools/call` arrives slightly ahead of `call.start`.
pub const DEFAULT_RESOLVE_WAIT: Duration = Duration::from_millis(1_500);
/// Hard cap on simultaneous pending in-flight call registrations.
pub const MAX_PENDING_CALLS: usize = 512;

/// Registered host session metadata cached in [`CallRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredSession {
    pub session_id: String,
    pub harness: String,
    pub backend_json: String,
    pub registered_at_ms: i64,
}

/// Input for [`CallRegistry::start_call`].
#[derive(Debug, Clone)]
pub struct StartCallInput {
    pub harness: HarnessKind,
    pub session_id: String,
    pub tool: String,
    pub call_id: Option<String>,
    pub backend_json: Option<String>,
    pub ttl_ms: Option<i64>,
}

/// An active, single-use in-flight tool call registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCall {
    pub session_id: String,
    pub harness: HarnessKind,
    pub tool: String,
    pub call_id: Option<String>,
    pub token: String,
    pub expires_at_ms: i64,
}

/// How the caller session was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationMethod {
    CallId,
    Token,
}

/// Fail-closed caller verification error codes (matching `src/caller.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerErrorCode {
    CallerUnverifiable,
    CallerNotFound,
    CallerAmbiguous,
}

impl CallerErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerUnverifiable => "caller_unverifiable",
            Self::CallerNotFound => "caller_not_found",
            Self::CallerAmbiguous => "caller_ambiguous",
        }
    }
}

/// Outcome of [`CallRegistry::resolve_call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerResolution {
    Verified {
        session_id: String,
        harness: HarnessKind,
        verified_by: VerificationMethod,
    },
    Failed {
        code: CallerErrorCode,
        message: String,
    },
}

impl CallerResolution {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    sessions: HashMap<String, RegisteredSession>,
    by_token: HashMap<String, RegisteredCall>,
    by_call_id: HashMap<String, Vec<RegisteredCall>>,
}

impl RegistryState {
    fn prune(&mut self, now: i64) -> usize {
        let expired: Vec<RegisteredCall> = self
            .by_token
            .values()
            .filter(|e| e.expires_at_ms <= now)
            .cloned()
            .collect();
        let count = expired.len();
        for entry in expired {
            self.remove(&entry);
        }
        count
    }

    fn remove(&mut self, entry: &RegisteredCall) {
        self.by_token.remove(&entry.token);
        if let Some(ref cid) = entry.call_id {
            if let Some(list) = self.by_call_id.get_mut(cid) {
                list.retain(|item| item.token != entry.token);
                if list.is_empty() {
                    self.by_call_id.remove(cid);
                }
            }
        }
    }

    fn try_resolve(
        &mut self,
        tool: &str,
        call_id: Option<&str>,
        call_token: Option<&str>,
        now: i64,
    ) -> Option<CallerResolution> {
        self.prune(now);
        let Some(normalized_tool) = normalize_mesh_tool_name(tool) else {
            return Some(CallerResolution::Failed {
                code: CallerErrorCode::CallerUnverifiable,
                message: format!("Unknown mesh tool {tool}"),
            });
        };

        if let Some(tok) = call_token.filter(|s| !s.is_empty()) {
            if let Some(entry) = self.by_token.get(tok).cloned() {
                if entry.tool == normalized_tool {
                    self.remove(&entry);
                    return Some(CallerResolution::Verified {
                        session_id: entry.session_id,
                        harness: entry.harness,
                        verified_by: VerificationMethod::Token,
                    });
                }
            }
            if call_id.is_none_or(str::is_empty) {
                return None;
            }
        }

        if let Some(cid) = call_id.filter(|s| !s.is_empty()) {
            let matches: Vec<RegisteredCall> = self
                .by_call_id
                .get(cid)
                .map(|list| {
                    list.iter()
                        .filter(|entry| entry.tool == normalized_tool)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            if matches.len() == 1 {
                let entry = matches.into_iter().next().expect("len == 1");
                self.remove(&entry);
                return Some(CallerResolution::Verified {
                    session_id: entry.session_id,
                    harness: entry.harness,
                    verified_by: VerificationMethod::CallId,
                });
            }
            if matches.len() > 1 {
                let distinct_sessions: HashSet<&str> =
                    matches.iter().map(|m| m.session_id.as_str()).collect();
                if distinct_sessions.len() > 1 {
                    return Some(CallerResolution::Failed {
                        code: CallerErrorCode::CallerAmbiguous,
                        message: format!(
                            "Tool call {cid} matched {} distinct sessions",
                            distinct_sessions.len()
                        ),
                    });
                }
                let last = matches.last().cloned().expect("len > 1");
                for item in &matches {
                    self.remove(item);
                }
                return Some(CallerResolution::Verified {
                    session_id: last.session_id,
                    harness: last.harness,
                    verified_by: VerificationMethod::CallId,
                });
            }
            return None;
        }

        Some(CallerResolution::Failed {
            code: CallerErrorCode::CallerUnverifiable,
            message: "No verified tool-call ID or hook token present. Run 'hyp setup <harness>' to install hooks.".to_string(),
        })
    }
}

/// Thread-safe, zero-polling host-verified caller session & in-flight call registry.
#[derive(Debug, Clone, Default)]
pub struct CallRegistry {
    state: Arc<Mutex<RegistryState>>,
    notify: Arc<Notify>,
}

impl CallRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or refreshes a host session record.
    pub fn register_session(
        &self,
        session_id: &str,
        harness: HarnessKind,
        backend_json: impl Into<String>,
        now: i64,
    ) -> Result<RegisteredSession, String> {
        if !is_valid_session_id(session_id) {
            return Err(format!("Invalid session ID: {session_id}"));
        }
        let rec = RegisteredSession {
            session_id: session_id.to_string(),
            harness: harness.as_str().to_string(),
            backend_json: backend_json.into(),
            registered_at_ms: now,
        };
        let mut st = self.state.lock().expect("CallRegistry lock poisoned");
        st.sessions.insert(session_id.to_string(), rec.clone());
        Ok(rec)
    }

    /// Looks up a previously registered host session.
    pub fn get_session(&self, session_id: &str) -> Option<RegisteredSession> {
        let st = self.state.lock().expect("CallRegistry lock poisoned");
        st.sessions.get(session_id).cloned()
    }

    /// Registers an in-flight host-verified tool call from a `PreToolUse` hook (`call.start`)
    /// and mints a single-use cryptographic `callToken`.
    pub fn start_call(&self, input: StartCallInput, now: i64) -> Result<RegisteredCall, String> {
        let Some(normalized_tool) = normalize_mesh_tool_name(&input.tool) else {
            return Err(format!("Not a mesh tool: {}", input.tool));
        };
        if !is_valid_session_id(&input.session_id) {
            return Err(format!("Invalid session ID: {}", input.session_id));
        }

        let mut st = self.state.lock().expect("CallRegistry lock poisoned");
        st.prune(now);
        if st.by_token.len() >= MAX_PENDING_CALLS {
            return Err("Too many in-flight tool calls registered".to_string());
        }

        let backend_json = input
            .backend_json
            .unwrap_or_else(|| format!("{{\"kind\":\"{}\"}}", input.harness.as_str()));
        st.sessions.insert(
            input.session_id.clone(),
            RegisteredSession {
                session_id: input.session_id.clone(),
                harness: input.harness.as_str().to_string(),
                backend_json,
                registered_at_ms: now,
            },
        );

        let token = generate_call_token();
        let ttl_ms = input.ttl_ms.unwrap_or(DEFAULT_CALL_TTL_MS).max(1);
        let call_id = input.call_id.filter(|s| !s.is_empty());
        let entry = RegisteredCall {
            session_id: input.session_id,
            harness: input.harness,
            tool: normalized_tool.to_string(),
            call_id: call_id.clone(),
            token: token.clone(),
            expires_at_ms: now.saturating_add(ttl_ms),
        };
        st.by_token.insert(token, entry.clone());
        if let Some(cid) = call_id {
            st.by_call_id.entry(cid).or_default().push(entry.clone());
        }
        drop(st);
        self.notify.notify_waiters();
        Ok(entry)
    }

    /// Releases any unconsumed registration for a completed call (`call.end`).
    pub fn finish_call(&self, call_id: Option<&str>, call_token: Option<&str>) {
        let mut st = self.state.lock().expect("CallRegistry lock poisoned");
        if let Some(tok) = call_token.filter(|s| !s.is_empty()) {
            if let Some(entry) = st.by_token.get(tok).cloned() {
                st.remove(&entry);
            }
        }
        if let Some(cid) = call_id.filter(|s| !s.is_empty()) {
            if let Some(list) = st.by_call_id.get(cid).cloned() {
                for entry in list {
                    st.remove(&entry);
                }
            }
        }
    }

    /// Prunes expired call registrations and returns the number removed.
    pub fn prune(&self, now: i64) -> usize {
        let mut st = self.state.lock().expect("CallRegistry lock poisoned");
        st.prune(now)
    }

    /// Returns the number of currently active in-flight call tokens (for diagnostics/tests).
    pub fn pending_count(&self) -> usize {
        let st = self.state.lock().expect("CallRegistry lock poisoned");
        st.by_token.len()
    }

    /// Synchronous single-shot resolution (no waiting; useful in unit tests).
    pub fn resolve_call_immediate(
        &self,
        tool: &str,
        call_id: Option<&str>,
        call_token: Option<&str>,
        now: i64,
    ) -> CallerResolution {
        if call_id.is_none_or(str::is_empty) && call_token.is_none_or(str::is_empty) {
            return CallerResolution::Failed {
                code: CallerErrorCode::CallerUnverifiable,
                message: "No verified tool-call ID or hook token present. Run 'hyp setup <harness>' to install hooks.".to_string(),
            };
        }
        let mut st = self.state.lock().expect("CallRegistry lock poisoned");
        st.try_resolve(tool, call_id, call_token, now)
            .unwrap_or_else(|| CallerResolution::Failed {
                code: CallerErrorCode::CallerNotFound,
                message: format!(
                    "No verified PreToolUse hook registration found for {tool}. Ensure hooks are installed ('hyp setup <harness>')."
                ),
            })
    }

    /// Async fail-closed caller verification with zero-polling wakeup when `call.start` races
    /// briefly behind MCP `tools/call`.
    pub async fn resolve_call(
        &self,
        tool: &str,
        call_id: Option<&str>,
        call_token: Option<&str>,
        wait: Duration,
    ) -> CallerResolution {
        if call_id.is_none_or(str::is_empty) && call_token.is_none_or(str::is_empty) {
            return CallerResolution::Failed {
                code: CallerErrorCode::CallerUnverifiable,
                message: "No verified tool-call ID or hook token present. Run 'hyp setup <harness>' to install hooks.".to_string(),
            };
        }

        let deadline = Instant::now() + wait;
        loop {
            // Register notification listener BEFORE checking state so we never miss a wakeup.
            let notified = self.notify.notified();
            {
                let mut st = self.state.lock().expect("CallRegistry lock poisoned");
                if let Some(res) = st.try_resolve(tool, call_id, call_token, now_ms()) {
                    return res;
                }
            }
            let now_inst = Instant::now();
            if now_inst >= deadline {
                return CallerResolution::Failed {
                    code: CallerErrorCode::CallerNotFound,
                    message: format!(
                        "No verified PreToolUse hook registration found for {tool}. Ensure hooks are installed ('hyp setup <harness>')."
                    ),
                };
            }
            let remaining = deadline - now_inst;
            let _ = tokio::time::timeout(remaining, notified).await;
        }
    }
}

/// Validates a session ID matching `src/protocol.ts:sessionIdPattern` (`^[a-z0-9][a-z0-9._:-]{1,255}$`).
pub fn is_valid_session_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 256 {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn generate_call_token() -> String {
    // 256 bits of entropy via OS-backed `rand::thread_rng` inside `hyp_store::uuid_v4`, hashed to 48 hex chars.
    let raw = format!("{}:{}", uuid_v4(), uuid_v4());
    let digest = sha256_hex(raw.as_bytes());
    format!("ct_{}", &digest[..40])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verifies_single_use_token_and_call_id_and_rejects_unverified_or_ambiguous() {
        let reg = CallRegistry::new();
        let t0 = 1_700_000_000_000;

        // 1. Missing both callId & token -> fail closed caller_unverifiable
        let unverified = reg
            .resolve_call("hyp_send", None, None, Duration::from_millis(10))
            .await;
        assert!(matches!(
            unverified,
            CallerResolution::Failed {
                code: CallerErrorCode::CallerUnverifiable,
                ..
            }
        ));

        // 2. Token verification succeeds once, then replay fails closed
        let started = reg
            .start_call(
                StartCallInput {
                    harness: HarnessKind::Antigravity,
                    session_id: "antigravity:conv-1".into(),
                    tool: "hyp_send".into(),
                    call_id: Some("tc-1".into()),
                    backend_json: None,
                    ttl_ms: Some(10_000),
                },
                t0,
            )
            .unwrap();
        let ok = reg.resolve_call_immediate("hyp_send", None, Some(&started.token), t0 + 100);
        assert_eq!(
            ok,
            CallerResolution::Verified {
                session_id: "antigravity:conv-1".into(),
                harness: HarnessKind::Antigravity,
                verified_by: VerificationMethod::Token,
            }
        );
        let replay = reg.resolve_call_immediate("hyp_send", None, Some(&started.token), t0 + 101);
        assert!(matches!(
            replay,
            CallerResolution::Failed {
                code: CallerErrorCode::CallerNotFound,
                ..
            }
        ));

        // 3. Ambiguous callId across two sessions fails closed
        reg.start_call(
            StartCallInput {
                harness: HarnessKind::Claude,
                session_id: "claude:s1".into(),
                tool: "hyp_inbox".into(),
                call_id: Some("dup-id".into()),
                backend_json: None,
                ttl_ms: Some(10_000),
            },
            t0,
        )
        .unwrap();
        reg.start_call(
            StartCallInput {
                harness: HarnessKind::Claude,
                session_id: "claude:s2".into(),
                tool: "hyp_inbox".into(),
                call_id: Some("dup-id".into()),
                backend_json: None,
                ttl_ms: Some(10_000),
            },
            t0,
        )
        .unwrap();
        let amb = reg.resolve_call_immediate("hyp_inbox", Some("dup-id"), None, t0 + 50);
        assert!(matches!(
            amb,
            CallerResolution::Failed {
                code: CallerErrorCode::CallerAmbiguous,
                ..
            }
        ));

        // 4. TTL expiry prunes stale registrations
        assert_eq!(reg.prune(t0 + 20_000), 2);
        assert_eq!(reg.pending_count(), 0);
    }
}
