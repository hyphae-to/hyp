//! CloudEvents Subscriptions API v1.0 Filter AST, evaluator, upstream pushdown compiler,
//! and static reachability diagnostics (`src/core/router/filter.ts`, `src/core/router/events.ts`, §2.2).

use crate::cloudevent::CloudEvent;
use crate::jcs::{format_ecma_number, sha256_hex, to_jcs_string};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use thiserror::Error;

pub const MAX_FILTERS_BYTES: usize = 4 * 1024;
pub const MAX_FILTER_DEPTH: usize = 8;
pub const MAX_PUSHDOWN_SHARDS: usize = 8;

/// CloudEvents Subscriptions API v1.0 Filter AST node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Filter {
    Exact(BTreeMap<String, String>),
    Prefix(BTreeMap<String, String>),
    Suffix(BTreeMap<String, String>),
    All(Vec<Filter>),
    Any(Vec<Filter>),
    Not(Box<Filter>),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{path}: {message}")]
pub struct FilterError {
    pub path: String,
    pub message: String,
}

impl FilterError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

const DIALECTS: &[&str] = &["exact", "prefix", "suffix", "all", "any", "not"];

/// Validates a CloudEvents filter key: attribute name (`/^[a-z0-9]{1,20}$/`)
/// or `data.<field>` (`/^data\.[^\s]{1,128}$/`).
pub fn is_valid_filter_key(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("data.") {
        // Match JS `[^\s]{1,128}`: length in UTF-16 code units 1..=128, no Unicode whitespace or BOM.
        let utf16_len = rest.encode_utf16().count();
        if utf16_len == 0 || utf16_len > 128 {
            return false;
        }
        return !rest.chars().any(|c| c.is_whitespace() || c == '\u{FEFF}');
    }
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 20
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Validates a subscription's `filters` JSON array matching `checkFilters` in
/// `src/core/router/filter.ts` 100%, returning precise error paths on failure.
pub fn validate_filters(value: &Value) -> Result<Vec<Filter>, FilterError> {
    let Value::Array(items) = value else {
        return Err(FilterError::new("filters", "filters must be an array"));
    };
    let serialized_len = serde_json::to_string(value)
        .map(|s| s.len())
        .unwrap_or(usize::MAX);
    if serialized_len > MAX_FILTERS_BYTES {
        return Err(FilterError::new(
            "filters",
            format!("filters exceed {MAX_FILTERS_BYTES} bytes"),
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        out.push(check_filter(item, &format!("filters[{idx}]"), 1)?);
    }
    Ok(out)
}

fn check_filter(value: &Value, path: &str, depth: usize) -> Result<Filter, FilterError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(FilterError::new(
            path,
            format!("filters nest deeper than {MAX_FILTER_DEPTH}"),
        ));
    }
    let Value::Object(map) = value else {
        return Err(FilterError::new(
            path,
            "a filter must be an object with one dialect key",
        ));
    };
    if map.len() != 1 {
        return Err(FilterError::new(
            path,
            format!(
                "a filter must have exactly one key of {}",
                DIALECTS.join(", ")
            ),
        ));
    }
    let (dialect, body) = map.iter().next().expect("map.len() == 1");
    if !DIALECTS.contains(&dialect.as_str()) {
        return Err(FilterError::new(
            path,
            format!(
                "a filter must have exactly one key of {}",
                DIALECTS.join(", ")
            ),
        ));
    }
    let at = format!("{path}.{dialect}");
    match dialect.as_str() {
        "exact" | "prefix" | "suffix" => {
            let Value::Object(pairs) = body else {
                return Err(FilterError::new(
                    at,
                    "expected an object of attribute: string, with at least one key",
                ));
            };
            if pairs.is_empty() {
                return Err(FilterError::new(
                    at,
                    "expected an object of attribute: string, with at least one key",
                ));
            }
            let mut out = BTreeMap::new();
            for (key, expected) in pairs {
                let key_json = serde_json::to_string(key).unwrap_or_else(|_| format!("{key:?}"));
                if !is_valid_filter_key(key) {
                    return Err(FilterError::new(
                        format!("{at}[{key_json}]"),
                        "keys are attribute names or data.<field>",
                    ));
                }
                let Some(expected_str) = expected.as_str() else {
                    return Err(FilterError::new(
                        format!("{at}[{key_json}]"),
                        "values must be strings",
                    ));
                };
                out.insert(key.clone(), expected_str.to_string());
            }
            Ok(match dialect.as_str() {
                "exact" => Filter::Exact(out),
                "prefix" => Filter::Prefix(out),
                _ => Filter::Suffix(out),
            })
        }
        "all" | "any" => {
            let Value::Array(children) = body else {
                return Err(FilterError::new(
                    at,
                    "expected a non-empty array of filters",
                ));
            };
            if children.is_empty() {
                return Err(FilterError::new(
                    at,
                    "expected a non-empty array of filters",
                ));
            }
            let mut parsed = Vec::with_capacity(children.len());
            for (idx, child) in children.iter().enumerate() {
                parsed.push(check_filter(child, &format!("{at}[{idx}]"), depth + 1)?);
            }
            Ok(if dialect == "all" {
                Filter::All(parsed)
            } else {
                Filter::Any(parsed)
            })
        }
        "not" => {
            let inner = check_filter(body, &at, depth + 1)?;
            Ok(Filter::Not(Box::new(inner)))
        }
        _ => unreachable!(),
    }
}

/// Computes the maximum nesting depth of a single filter node (leaf = 1).
pub fn filter_depth(filter: &Filter) -> usize {
    match filter {
        Filter::Exact(_) | Filter::Prefix(_) | Filter::Suffix(_) => 1,
        Filter::All(children) | Filter::Any(children) => {
            1 + children.iter().map(filter_depth).max().unwrap_or(0)
        }
        Filter::Not(inner) => 1 + filter_depth(inner),
    }
}

/// Pre-validated filter list ready for repeated evaluation against CloudEvents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFilters {
    filters: Vec<Filter>,
}

impl CompiledFilters {
    pub fn filters(&self) -> &[Filter] {
        &self.filters
    }

    /// Evaluates the compiled filter list against a `CloudEvent` (top-level AND; empty matches all).
    pub fn matches_event(&self, event: &CloudEvent) -> bool {
        matches_filters(&self.filters, event)
    }

    /// Evaluates the compiled filter list against a raw JSON CloudEvent `Value`.
    pub fn matches_value(&self, event: &Value) -> bool {
        self.filters.iter().all(|f| matches_filter_value(f, event))
    }
}

/// Validates and compiles a `Vec<Filter>` into `CompiledFilters`.
pub fn compile_filters(filters: Vec<Filter>) -> Result<CompiledFilters, FilterError> {
    let as_value =
        serde_json::to_value(&filters).map_err(|e| FilterError::new("filters", e.to_string()))?;
    let validated = validate_filters(&as_value)?;
    Ok(CompiledFilters { filters: validated })
}

/// Extracts comparable texts matching `src/core/router/filter.ts:texts`:
/// strings as-is, numbers via ECMA-262 JSON, booleans as `"true"`/`"false"`,
/// flat 1-level arrays element-wise (nested arrays yield none), null/objects yield none.
fn value_texts(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Bool(true) => vec!["true".to_string()],
        Value::Bool(false) => vec!["false".to_string()],
        Value::Number(n) => n
            .as_f64()
            .and_then(|f| format_ecma_number(f).ok())
            .into_iter()
            .collect(),
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                // Match v1 TS: nested arrays are NOT recursively flattened.
                if !item.is_array() {
                    out.extend(value_texts(item));
                }
            }
            out
        }
        Value::Null | Value::Object(_) => Vec::new(),
    }
}

/// Looks up a filter key on a JSON `data` object: checks exact literal key first (v1 compat),
/// then falls back to dotted path traversal (`data.a.b.c`) into nested JSON objects (v2).
fn lookup_in_data(data: &Value, field: &str) -> Vec<String> {
    let Value::Object(map) = data else {
        return Vec::new();
    };
    if let Some(direct) = map.get(field) {
        return value_texts(direct);
    }
    if field.contains('.') {
        let mut cursor = data;
        for part in field.split('.') {
            if part.is_empty() {
                return Vec::new();
            }
            match cursor {
                Value::Object(obj) => match obj.get(part) {
                    Some(next) => cursor = next,
                    None => return Vec::new(),
                },
                _ => return Vec::new(),
            }
        }
        return value_texts(cursor);
    }
    Vec::new()
}

fn lookup_event(event: &CloudEvent, key: &str) -> Vec<String> {
    if let Some(field) = key.strip_prefix("data.") {
        return match &event.data {
            Some(data) => lookup_in_data(data, field),
            None => Vec::new(),
        };
    }
    if key == "data" {
        return Vec::new();
    }
    match event.get_attribute(key) {
        Some(v) => value_texts(&v),
        None => Vec::new(),
    }
}

fn lookup_value(event: &Value, key: &str) -> Vec<String> {
    let Value::Object(map) = event else {
        return Vec::new();
    };
    if let Some(field) = key.strip_prefix("data.") {
        return match map.get("data") {
            Some(data) => lookup_in_data(data, field),
            None => Vec::new(),
        };
    }
    if key == "data" {
        return Vec::new();
    }
    match map.get(key) {
        Some(v) => value_texts(v),
        None => Vec::new(),
    }
}

/// Matches a single `Filter` against a `CloudEvent`.
pub fn matches_filter(filter: &Filter, event: &CloudEvent) -> bool {
    match filter {
        Filter::Exact(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_event(event, k)
                .iter()
                .any(|actual| actual == expected)
        }),
        Filter::Prefix(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_event(event, k)
                .iter()
                .any(|actual| actual.starts_with(expected.as_str()))
        }),
        Filter::Suffix(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_event(event, k)
                .iter()
                .any(|actual| actual.ends_with(expected.as_str()))
        }),
        Filter::All(inner) => inner.iter().all(|f| matches_filter(f, event)),
        Filter::Any(inner) => inner.iter().any(|f| matches_filter(f, event)),
        Filter::Not(inner) => !matches_filter(inner, event),
    }
}

/// Matches a top-level AND-list of filters against a `CloudEvent` (empty matches all).
pub fn matches_filters(filters: &[Filter], event: &CloudEvent) -> bool {
    filters.iter().all(|f| matches_filter(f, event))
}

fn matches_filter_value(filter: &Filter, event: &Value) -> bool {
    match filter {
        Filter::Exact(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_value(event, k)
                .iter()
                .any(|actual| actual == expected)
        }),
        Filter::Prefix(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_value(event, k)
                .iter()
                .any(|actual| actual.starts_with(expected.as_str()))
        }),
        Filter::Suffix(pairs) => pairs.iter().all(|(k, expected)| {
            lookup_value(event, k)
                .iter()
                .any(|actual| actual.ends_with(expected.as_str()))
        }),
        Filter::All(inner) => inner.iter().all(|f| matches_filter_value(f, event)),
        Filter::Any(inner) => inner.iter().any(|f| matches_filter_value(f, event)),
        Filter::Not(inner) => !matches_filter_value(inner, event),
    }
}

// ---- Upstream Subscription Pushdown Compiler (§2.2) ----

/// A single local subscription feeding into upstream pushdown compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSubscription {
    pub filters: Vec<Filter>,
    pub coalesce_seconds: u32,
}

/// One compiled upstream subscription shard (`pd:<sha256(topic)>:<index>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushdownShard {
    pub id: String,
    pub filters: Vec<Filter>,
    pub coalesce_seconds: u32,
}

/// Compiled upstream pushdown plan for a `(peer, topic)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushdownPlan {
    pub shards: Vec<PushdownShard>,
    pub coalesce_seconds: Option<u32>,
    /// True if coarsening fallback was needed to respect `MAX_PUSHDOWN_SHARDS` / `MAX_FILTERS_BYTES` / `MAX_FILTER_DEPTH`.
    pub coarsened: bool,
}

/// Compiles local subscriptions on `topic` into deterministic upstream pushdown shards (§2.2):
/// - Wraps each local AND-list into a single `Filter` (`[]` -> match-all, `[f]` -> `f`, `[f1, f2]` -> `{ all: [f1, f2] }`)
/// - Deduplicates via RFC 8785 JCS in deterministic sorted order
/// - Merges into `[{ any: [...] }]`
/// - Deterministically shards into `pd:<sha256(topic)>:0..N` (up to 8 shards) when exceeding 4 KiB or depth 8
/// - Falls back to conservative superset coarsening (dropping `data.*` predicates while retaining `repo`/`source`/`type`,
///   and ultimately match-all if still > 8 shards) — NEVER drops an event that matches any local subscription
/// - Sets `coalesce_seconds = min(local_subs.coalesce_seconds)`.
pub fn compile_upstream_pushdown(topic: &str, local_subs: &[LocalSubscription]) -> PushdownPlan {
    if local_subs.is_empty() {
        return PushdownPlan {
            shards: Vec::new(),
            coalesce_seconds: None,
            coarsened: false,
        };
    }

    let topic_hash = sha256_hex(topic.as_bytes());
    let min_coalesce = local_subs
        .iter()
        .map(|s| s.coalesce_seconds)
        .min()
        .unwrap_or(0);

    let make_id = |idx: usize| format!("pd:{topic_hash}:{idx}");

    // If any local subscription is match-all (`filters: []`), the union is match-all.
    if local_subs.iter().any(|s| s.filters.is_empty()) {
        return PushdownPlan {
            shards: vec![PushdownShard {
                id: make_id(0),
                filters: Vec::new(),
                coalesce_seconds: min_coalesce,
            }],
            coalesce_seconds: Some(min_coalesce),
            coarsened: false,
        };
    }

    // Represent each local sub as either a wrappable single Filter (depth <= 7 so `any` wrapper stays <= 8)
    // or a standalone top-level filter list (when wrapping in `all`/`any` would exceed depth 8).
    let (wrappable, standalone) = collect_deduped_branches(local_subs);

    if let Some(packed) = try_pack_shards(&wrappable, &standalone, &make_id, min_coalesce) {
        return PushdownPlan {
            shards: packed,
            coalesce_seconds: Some(min_coalesce),
            coarsened: false,
        };
    }

    // Coarsening Pass 1: drop `data.*` predicates conservatively (preserving superset invariant).
    let pass1 = coarsen_subs(local_subs, CoarsenLevel::DropData);
    if pass1.iter().any(|s| s.filters.is_empty()) {
        return PushdownPlan {
            shards: vec![PushdownShard {
                id: make_id(0),
                filters: Vec::new(),
                coalesce_seconds: min_coalesce,
            }],
            coalesce_seconds: Some(min_coalesce),
            coarsened: true,
        };
    }
    let (w1, s1) = collect_deduped_branches(&pass1);
    if let Some(packed) = try_pack_shards(&w1, &s1, &make_id, min_coalesce) {
        return PushdownPlan {
            shards: packed,
            coalesce_seconds: Some(min_coalesce),
            coarsened: true,
        };
    }

    // Coarsening Pass 2: retain only `repo`/`source`/`type` exact/prefix predicates.
    let pass2 = coarsen_subs(local_subs, CoarsenLevel::CoreRoutingOnly);
    if pass2.iter().any(|s| s.filters.is_empty()) {
        return PushdownPlan {
            shards: vec![PushdownShard {
                id: make_id(0),
                filters: Vec::new(),
                coalesce_seconds: min_coalesce,
            }],
            coalesce_seconds: Some(min_coalesce),
            coarsened: true,
        };
    }
    let (w2, s2) = collect_deduped_branches(&pass2);
    if let Some(packed) = try_pack_shards(&w2, &s2, &make_id, min_coalesce) {
        return PushdownPlan {
            shards: packed,
            coalesce_seconds: Some(min_coalesce),
            coarsened: true,
        };
    }

    // Final conservative fallback: single match-all shard (never misses an event, never violates wire caps).
    PushdownPlan {
        shards: vec![PushdownShard {
            id: make_id(0),
            filters: Vec::new(),
            coalesce_seconds: min_coalesce,
        }],
        coalesce_seconds: Some(min_coalesce),
        coarsened: true,
    }
}

fn collect_deduped_branches(local_subs: &[LocalSubscription]) -> (Vec<Filter>, Vec<Vec<Filter>>) {
    let mut wrappable_by_jcs: BTreeMap<String, Filter> = BTreeMap::new();
    let mut standalone_by_jcs: BTreeMap<String, Vec<Filter>> = BTreeMap::new();

    for sub in local_subs {
        let single_candidate = match sub.filters.len() {
            0 => continue,
            1 => sub.filters[0].clone(),
            _ => Filter::All(sub.filters.clone()),
        };

        // Can this filter fit inside `[{ any: [...] }]` within MAX_FILTER_DEPTH and MAX_FILTERS_BYTES?
        let wrapped_test = vec![Filter::Any(vec![single_candidate.clone()])];
        let wrapped_ok = filter_depth(&single_candidate) < MAX_FILTER_DEPTH
            && serialized_filter_len(&wrapped_test) <= MAX_FILTERS_BYTES;

        if wrapped_ok {
            let key = jcs_key_for_filter(&single_candidate);
            wrappable_by_jcs.entry(key).or_insert(single_candidate);
        } else {
            // Keep as its own top-level AND list (valid as long as the local sub itself was valid).
            let key = jcs_key_for_list(&sub.filters);
            standalone_by_jcs
                .entry(key)
                .or_insert_with(|| sub.filters.clone());
        }
    }

    (
        wrappable_by_jcs.into_values().collect(),
        standalone_by_jcs.into_values().collect(),
    )
}

fn try_pack_shards(
    wrappable: &[Filter],
    standalone: &[Vec<Filter>],
    make_id: &impl Fn(usize) -> String,
    coalesce_seconds: u32,
) -> Option<Vec<PushdownShard>> {
    let mut shard_filter_lists: Vec<Vec<Filter>> = Vec::new();

    // Greedy deterministic bin-packing of wrappable filters into `[{ any: [...] }]` shards.
    if !wrappable.is_empty() {
        let mut current_group: Vec<Filter> = Vec::new();
        for branch in wrappable {
            current_group.push(branch.clone());
            let candidate = vec![Filter::Any(current_group.clone())];
            if serialized_filter_len(&candidate) > MAX_FILTERS_BYTES {
                let overflowed = current_group.pop().expect("just pushed");
                if current_group.is_empty() {
                    // Single branch couldn't fit inside `any` wrapper (should have been standalone).
                    return None;
                }
                shard_filter_lists.push(vec![Filter::Any(current_group)]);
                current_group = vec![overflowed];
                if serialized_filter_len(&[Filter::Any(current_group.clone())]) > MAX_FILTERS_BYTES
                {
                    return None;
                }
            }
        }
        if !current_group.is_empty() {
            shard_filter_lists.push(vec![Filter::Any(current_group)]);
        }
    }

    for list in standalone {
        if serialized_filter_len(list) > MAX_FILTERS_BYTES
            || list.iter().any(|f| filter_depth(f) > MAX_FILTER_DEPTH)
        {
            return None;
        }
        shard_filter_lists.push(list.clone());
    }

    if shard_filter_lists.len() > MAX_PUSHDOWN_SHARDS {
        return None;
    }

    let shards = shard_filter_lists
        .into_iter()
        .enumerate()
        .map(|(idx, filters)| PushdownShard {
            id: make_id(idx),
            filters,
            coalesce_seconds,
        })
        .collect();
    Some(shards)
}

#[derive(Clone, Copy)]
enum CoarsenLevel {
    DropData,
    CoreRoutingOnly,
}

fn coarsen_subs(local_subs: &[LocalSubscription], level: CoarsenLevel) -> Vec<LocalSubscription> {
    local_subs
        .iter()
        .map(|sub| {
            let mut kept = Vec::new();
            for f in &sub.filters {
                if let Some(c) = coarsen_filter(f, level) {
                    kept.push(c);
                }
            }
            LocalSubscription {
                filters: kept,
                coalesce_seconds: sub.coalesce_seconds,
            }
        })
        .collect()
}

/// Conservatively coarsens a filter into a logical superset (`None` = match-all).
fn coarsen_filter(filter: &Filter, level: CoarsenLevel) -> Option<Filter> {
    let keep_key = |dialect: &str, key: &str| -> bool {
        match level {
            CoarsenLevel::DropData => !key.starts_with("data."),
            CoarsenLevel::CoreRoutingOnly => {
                matches!(dialect, "exact" | "prefix") && matches!(key, "repo" | "source" | "type")
            }
        }
    };

    match filter {
        Filter::Exact(pairs) => {
            let kept: BTreeMap<String, String> = pairs
                .iter()
                .filter(|(k, _)| keep_key("exact", k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if kept.is_empty() {
                None
            } else {
                Some(Filter::Exact(kept))
            }
        }
        Filter::Prefix(pairs) => {
            let kept: BTreeMap<String, String> = pairs
                .iter()
                .filter(|(k, _)| keep_key("prefix", k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if kept.is_empty() {
                None
            } else {
                Some(Filter::Prefix(kept))
            }
        }
        Filter::Suffix(pairs) => {
            let kept: BTreeMap<String, String> = pairs
                .iter()
                .filter(|(k, _)| keep_key("suffix", k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if kept.is_empty() {
                None
            } else {
                Some(Filter::Suffix(kept))
            }
        }
        Filter::All(children) => {
            let mut kept = Vec::new();
            for child in children {
                if let Some(c) = coarsen_filter(child, level) {
                    kept.push(c);
                }
            }
            match kept.len() {
                0 => None,
                1 => Some(kept.remove(0)),
                _ => Some(Filter::All(kept)),
            }
        }
        Filter::Any(children) => {
            let mut kept = Vec::new();
            for child in children {
                match coarsen_filter(child, level) {
                    // If any branch widens to match-all, the entire OR is match-all.
                    None => return None,
                    Some(c) => kept.push(c),
                }
            }
            match kept.len() {
                0 => None,
                1 => Some(kept.remove(0)),
                _ => Some(Filter::Any(kept)),
            }
        }
        // Coarsening inside `not` would narrow rather than widen, so drop `not` cleanly to match-all.
        Filter::Not(_) => None,
    }
}

fn serialized_filter_len(filters: &[Filter]) -> usize {
    serde_json::to_string(filters)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
}

fn jcs_key_for_filter(filter: &Filter) -> String {
    let val = serde_json::to_value(filter).expect("Filter serialization infallible");
    to_jcs_string(&val).expect("Filter has only strings")
}

fn jcs_key_for_list(filters: &[Filter]) -> String {
    let val = serde_json::to_value(filters).expect("Filter list serialization infallible");
    to_jcs_string(&val).expect("Filter list has only strings")
}

// ---- Static Reachability Diagnostics (`diagnose_subscription`, matching `src/core/router/events.ts`) ----

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicScope {
    #[serde(default)]
    pub repos: Vec<String>,
    #[serde(default)]
    pub orgs: Vec<String>,
    #[serde(default)]
    pub subjects: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicSchema {
    #[serde(default)]
    pub attributes: Vec<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(default)]
    pub filter_examples: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<TopicScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<TopicSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_guide: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedTopicStats {
    pub event_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub repos: Vec<String>,
}

/// Snapshot of a single configured topic passed into `diagnose_subscription`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicCatalogEntry {
    pub topic: String,
    pub has_provisioned_publisher: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TopicMetadata>,
    #[serde(default)]
    pub observed: ObservedTopicStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    UnprovisionedTopic,
    UnprovisionedPublisher,
    InvalidGithubSubjectFilter,
    InvalidGithubRepoFormat,
    InvalidGithubSourceFormat,
    UnknownFilterAttribute,
    UnmonitoredRepo,
    UnobservedRepo,
    TopicNoEventsYet,
    RepoNotFoundOrPrivate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: DiagnosticCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_filter: Option<Value>,
}

const STANDARD_CE_ATTRIBUTES: &[&str] = &[
    "specversion",
    "id",
    "source",
    "type",
    "subject",
    "time",
    "datacontenttype",
    "dataschema",
];

const GITHUB_SUBJECT_PREFIXES: &[&str] = &["pull/", "issues/", "actions/", "refs/"];

struct FlatPredicate<'a> {
    dialect: &'static str,
    key: &'a str,
    value: &'a str,
}

fn collect_positive_predicates<'a>(filters: &'a [Filter], out: &mut Vec<FlatPredicate<'a>>) {
    for filter in filters {
        match filter {
            Filter::Exact(map) => {
                for (k, v) in map {
                    out.push(FlatPredicate {
                        dialect: "exact",
                        key: k,
                        value: v,
                    });
                }
            }
            Filter::Prefix(map) => {
                for (k, v) in map {
                    out.push(FlatPredicate {
                        dialect: "prefix",
                        key: k,
                        value: v,
                    });
                }
            }
            Filter::Suffix(map) => {
                for (k, v) in map {
                    out.push(FlatPredicate {
                        dialect: "suffix",
                        key: k,
                        value: v,
                    });
                }
            }
            Filter::All(inner) | Filter::Any(inner) => collect_positive_predicates(inner, out),
            // Intentionally skip `not` branches: excluding a repo/source is not subscribing to it.
            Filter::Not(_) => {}
        }
    }
}

fn normalize_repo_ref(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    let stripped = if lower.starts_with("https://github.com/") {
        &trimmed["https://github.com/".len()..]
    } else if lower.starts_with("http://github.com/") {
        &trimmed["http://github.com/".len()..]
    } else if lower.starts_with("github.com/") {
        &trimmed["github.com/".len()..]
    } else {
        trimmed
    };
    stripped.trim_end_matches('/').to_string()
}

fn is_owner_repo_like(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/.*)?$").expect("valid regex")
    });
    re.is_match(value)
}

fn has_github_url_prefix(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("https://github.com/")
        || lower.starts_with("http://github.com/")
        || lower.starts_with("github.com/")
}

/// Static reachability lint for a subscription against the topic catalog (`src/core/router/events.ts:437`).
///
/// Catches dead subscriptions before activation: `unprovisioned_topic`, `unprovisioned_publisher`,
/// `invalid_github_subject_filter`, `invalid_github_repo_format`, `invalid_github_source_format`,
/// `unknown_filter_attribute`, `unmonitored_repo`, `unobserved_repo`, and `topic_no_events_yet`.
pub fn diagnose_subscription(
    topic: &str,
    filters: &[Filter],
    catalog: &[TopicCatalogEntry],
) -> Vec<SubscriptionDiagnostic> {
    let bare_topic = topic.strip_prefix("local.").unwrap_or(topic);
    let Some(info) = catalog
        .iter()
        .find(|entry| entry.topic == topic)
        .or_else(|| {
            catalog.iter().find(|entry| {
                entry.topic.strip_prefix("local.").unwrap_or(&entry.topic) == bare_topic
            })
        })
    else {
        let mut available: Vec<&str> = catalog.iter().map(|e| e.topic.as_str()).collect();
        available.sort_unstable();
        let avail_str = if available.is_empty() {
            "none".to_string()
        } else {
            available.join(", ")
        };
        return vec![SubscriptionDiagnostic {
            severity: DiagnosticSeverity::Error,
            code: DiagnosticCode::UnprovisionedTopic,
            message: format!(
                "Topic '{topic}' is not configured/provisioned on this node (available: {avail_str})."
            ),
            remediation: Some(
                "Call hyp_topics to inspect available topics, or add the stream via `hyp connect add`."
                    .to_string(),
            ),
            suggested_filter: None,
        }];
    };

    let mut diagnostics = Vec::new();
    if !info.has_provisioned_publisher {
        diagnostics.push(SubscriptionDiagnostic {
            severity: DiagnosticSeverity::Warn,
            code: DiagnosticCode::UnprovisionedPublisher,
            message: format!("Topic '{topic}' has no active provisioned publisher on this node."),
            remediation: Some(format!(
                "Provision a publisher (`hyp node add-publisher <id> --topic {topic}`) or verify the stream started cleanly."
            )),
            suggested_filter: None,
        });
    }

    let mut predicates = Vec::new();
    collect_positive_predicates(filters, &mut predicates);

    let is_github = topic == "github"
        || matches!(
            info.metadata.as_ref().and_then(|m| m.kind.as_deref()),
            Some("github-webhook" | "github-public")
        );

    let allowed_attrs: Option<BTreeSet<String>> = info
        .metadata
        .as_ref()
        .and_then(|m| m.schema.as_ref())
        .filter(|s| !s.attributes.is_empty())
        .map(|s| {
            let mut set: BTreeSet<String> = STANDARD_CE_ATTRIBUTES
                .iter()
                .map(|&a| a.to_string())
                .collect();
            for attr in &s.attributes {
                set.insert(attr.clone());
            }
            set
        });

    let mut referenced_repos: BTreeSet<String> = BTreeSet::new();

    for pred in &predicates {
        if let Some(allowed) = &allowed_attrs {
            if !pred.key.starts_with("data.") && !allowed.contains(pred.key) {
                let allowed_list: Vec<&str> = allowed.iter().map(String::as_str).collect();
                let remediation = info
                    .metadata
                    .as_ref()
                    .and_then(|m| m.schema.as_ref())
                    .and_then(|s| s.filter_examples.first())
                    .map(|ex| format!("Example valid filter: {ex}"));
                diagnostics.push(SubscriptionDiagnostic {
                    severity: DiagnosticSeverity::Warn,
                    code: DiagnosticCode::UnknownFilterAttribute,
                    message: format!(
                        "Filter references attribute '{}', which is not in '{topic}' schema attributes ({}).",
                        pred.key,
                        allowed_list.join(", ")
                    ),
                    remediation,
                    suggested_filter: None,
                });
            }
        }

        if !is_github {
            continue;
        }

        if pred.key == "subject"
            && pred.dialect != "suffix"
            && is_owner_repo_like(pred.value)
            && !GITHUB_SUBJECT_PREFIXES
                .iter()
                .any(|p| pred.value.starts_with(p))
        {
            let norm = normalize_repo_ref(pred.value);
            let clean_repo = norm.split('/').take(2).collect::<Vec<_>>().join("/");
            referenced_repos.insert(clean_repo.clone());
            diagnostics.push(SubscriptionDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: DiagnosticCode::InvalidGithubSubjectFilter,
                message: format!(
                    "Filter '{}.subject = {:?}' will NEVER match GitHub CloudEvents. \
                     GitHub events put the repository in 'repo' (\"owner/repo\") and 'source' (\"github.com/owner/repo\"); \
                     'subject' holds \"pull/<n>\", \"issues/<n>\", \"actions/runs/<id>\", or \"refs/heads/<branch>\".",
                    pred.dialect, pred.value
                ),
                remediation: Some(format!(
                    "Replace the filter with {{ exact: {{ repo: {clean_repo:?} }} }} (or {{ prefix: {{ repo: \"owner/\" }} }} for an org)."
                )),
                suggested_filter: Some(json!({ "exact": { "repo": clean_repo } })),
            });
        } else if pred.key == "repo" {
            if has_github_url_prefix(pred.value) {
                let clean_repo = normalize_repo_ref(pred.value);
                referenced_repos.insert(clean_repo.clone());
                diagnostics.push(SubscriptionDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: DiagnosticCode::InvalidGithubRepoFormat,
                    message: format!(
                        "Filter '{}.repo = {:?}' includes a URL/host prefix and will NEVER match. \
                         GitHub 'repo' is formatted as \"owner/repo\".",
                        pred.dialect, pred.value
                    ),
                    remediation: Some(format!(
                        "Use {{ {}: {{ repo: {clean_repo:?} }} }}.",
                        pred.dialect
                    )),
                    suggested_filter: Some(json!({ pred.dialect: { "repo": clean_repo } })),
                });
            } else if pred.dialect != "suffix" && !pred.value.trim().is_empty() {
                referenced_repos.insert(normalize_repo_ref(pred.value));
            }
        } else if pred.key == "source" && pred.dialect != "suffix" {
            if pred.value.to_ascii_lowercase().starts_with("github.com/") {
                let rest = normalize_repo_ref(pred.value);
                if !rest.is_empty() {
                    referenced_repos.insert(rest);
                }
            } else if is_owner_repo_like(pred.value) {
                let clean_repo = normalize_repo_ref(pred.value);
                referenced_repos.insert(clean_repo.clone());
                diagnostics.push(SubscriptionDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: DiagnosticCode::InvalidGithubSourceFormat,
                    message: format!(
                        "Filter '{}.source = {:?}' omits the \"github.com/\" prefix and will NEVER match.",
                        pred.dialect, pred.value
                    ),
                    remediation: Some(format!(
                        "Use {{ {}: {{ source: {:?} }} }} or {{ {}: {{ repo: {clean_repo:?} }} }}.",
                        pred.dialect,
                        format!("github.com/{clean_repo}"),
                        pred.dialect
                    )),
                    suggested_filter: Some(json!({ pred.dialect: { "repo": clean_repo } })),
                });
            }
        }
    }

    let scope_repos: Vec<String> = info
        .metadata
        .as_ref()
        .and_then(|m| m.scope.as_ref())
        .map(|s| {
            s.repos
                .iter()
                .map(|r| normalize_repo_ref(r).to_ascii_lowercase())
                .filter(|r| !r.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let scope_orgs: Vec<String> = info
        .metadata
        .as_ref()
        .and_then(|m| m.scope.as_ref())
        .map(|s| {
            s.orgs
                .iter()
                .map(|o| o.trim().to_ascii_lowercase())
                .filter(|o| !o.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let has_declared_scope = !scope_repos.is_empty() || !scope_orgs.is_empty();

    let is_covered = |target_ref: &str| -> bool {
        let target = target_ref.to_ascii_lowercase();
        let target_slash = format!("{target}/");
        if scope_repos
            .iter()
            .any(|r| r == &target || r.starts_with(&target_slash))
        {
            return true;
        }
        if scope_orgs
            .iter()
            .any(|o| target == *o || target.starts_with(&format!("{o}/")))
        {
            return true;
        }
        false
    };

    for repo_ref in &referenced_repos {
        if has_declared_scope && !is_covered(repo_ref) {
            let mut summary_parts = Vec::new();
            if !scope_repos.is_empty() {
                summary_parts.push(format!("repos: [{}]", scope_repos.join(", ")));
            }
            if !scope_orgs.is_empty() {
                summary_parts.push(format!("orgs: [{}]", scope_orgs.join(", ")));
            }
            let covered_summary = summary_parts.join(", ");
            diagnostics.push(SubscriptionDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: DiagnosticCode::UnmonitoredRepo,
                message: format!(
                    "Repository/org '{repo_ref}' is NOT in the configured '{topic}' stream scope ({covered_summary}). \
                     This subscription will NEVER receive notifications until a repository webhook is configured for '{repo_ref}'."
                ),
                remediation: Some(
                    info.metadata
                        .as_ref()
                        .and_then(|m| m.setup_guide.clone())
                        .unwrap_or_else(|| {
                            format!(
                                "Configure a repository webhook for '{repo_ref}' and add '{repo_ref}' to GITHUB_REPOS / GITHUB_ORGS."
                            )
                        }),
                ),
                suggested_filter: None,
            });
        } else if info.observed.event_count > 0
            && !info.observed.repos.iter().any(|obs| {
                let low = obs.to_ascii_lowercase();
                let target = repo_ref.to_ascii_lowercase();
                low == target || low.starts_with(&format!("{target}/"))
            })
        {
            let obs_str = if info.observed.repos.is_empty() {
                "none".to_string()
            } else {
                info.observed.repos.join(", ")
            };
            diagnostics.push(SubscriptionDiagnostic {
                severity: DiagnosticSeverity::Warn,
                code: DiagnosticCode::UnobservedRepo,
                message: format!(
                    "No webhook deliveries from '{repo_ref}' have been observed on topic '{topic}' yet (observed repos: {obs_str})."
                ),
                remediation: Some(format!(
                    "Confirm a repository webhook is configured for '{repo_ref}' and send a ping delivery."
                )),
                suggested_filter: None,
            });
        }
    }

    if info.observed.event_count == 0 {
        diagnostics.push(SubscriptionDiagnostic {
            severity: DiagnosticSeverity::Info,
            code: DiagnosticCode::TopicNoEventsYet,
            message: format!("Topic '{topic}' has received 0 events so far on this node."),
            remediation: info.metadata.as_ref().and_then(|m| m.setup_guide.clone()),
            suggested_filter: None,
        });
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(k: &str, v: &str) -> Filter {
        Filter::Exact(BTreeMap::from([(k.to_string(), v.to_string())]))
    }

    fn prefix(k: &str, v: &str) -> Filter {
        Filter::Prefix(BTreeMap::from([(k.to_string(), v.to_string())]))
    }

    #[test]
    fn dotted_data_path_traversal_works() {
        let ev = CloudEvent::new(
            "1",
            "github.com/acme/web",
            "com.github.pull_request.opened",
            json!({
                "pull_request": { "draft": false, "labels": ["urgent", "backend"] },
                "literal.key": "direct"
            }),
        );
        let f1 = compile_filters(vec![exact("data.pull_request.draft", "false")]).unwrap();
        assert!(f1.matches_event(&ev));

        let f2 = compile_filters(vec![exact("data.pull_request.labels", "urgent")]).unwrap();
        assert!(f2.matches_event(&ev));

        let f3 = compile_filters(vec![exact("data.literal.key", "direct")]).unwrap();
        assert!(f3.matches_event(&ev));

        let f4 = compile_filters(vec![exact("data.pull_request.missing", "x")]).unwrap();
        assert!(!f4.matches_event(&ev));
    }

    #[test]
    fn pushdown_merges_deduplicates_and_uses_min_coalesce() {
        let sub_a = LocalSubscription {
            filters: vec![exact("repo", "acme/checkout")],
            coalesce_seconds: 15,
        };
        let sub_b = LocalSubscription {
            filters: vec![
                exact("repo", "acme/payments"),
                prefix("type", "com.github.pull_request."),
            ],
            coalesce_seconds: 60,
        };
        // Duplicate of sub_a with different coalesce window.
        let sub_a_dup = LocalSubscription {
            filters: vec![exact("repo", "acme/checkout")],
            coalesce_seconds: 30,
        };

        let plan = compile_upstream_pushdown("github", &[sub_a, sub_b, sub_a_dup]);
        assert!(!plan.coarsened);
        assert_eq!(plan.coalesce_seconds, Some(15));
        assert_eq!(plan.shards.len(), 1);
        assert!(plan.shards[0].id.starts_with("pd:"));
        assert!(plan.shards[0].id.ends_with(":0"));
        assert_eq!(plan.shards[0].coalesce_seconds, 15);

        // Must be `[{ any: [branch1, branch2] }]` with deduped 2 branches.
        match &plan.shards[0].filters[0] {
            Filter::Any(branches) => assert_eq!(branches.len(), 2),
            other => panic!("expected Filter::Any, got {other:?}"),
        }

        // Order-independent determinism.
        let plan_rev = compile_upstream_pushdown(
            "github",
            &[
                LocalSubscription {
                    filters: vec![
                        exact("repo", "acme/payments"),
                        prefix("type", "com.github.pull_request."),
                    ],
                    coalesce_seconds: 60,
                },
                LocalSubscription {
                    filters: vec![exact("repo", "acme/checkout")],
                    coalesce_seconds: 15,
                },
            ],
        );
        assert_eq!(plan, plan_rev);
    }

    #[test]
    fn pushdown_shards_and_coarsens_while_preserving_superset_invariant() {
        // Create 120 distinct subscriptions with long `data.extra` predicates so they exceed 4 KiB
        // and require sharding (and then coarsening if > 8 shards).
        let mut subs = Vec::new();
        for i in 0..120 {
            subs.push(LocalSubscription {
                filters: vec![
                    exact("repo", &format!("acme/service-{i:03}")),
                    exact("data.payload_note", &"x".repeat(40)),
                ],
                coalesce_seconds: 10 + (i % 5),
            });
        }
        let plan = compile_upstream_pushdown("github", &subs);
        assert!(!plan.shards.is_empty());
        assert!(plan.shards.len() <= MAX_PUSHDOWN_SHARDS);
        assert_eq!(plan.coalesce_seconds, Some(10));
        for (idx, shard) in plan.shards.iter().enumerate() {
            assert!(shard.id.ends_with(&format!(":{idx}")));
            let val = serde_json::to_value(&shard.filters).unwrap();
            assert!(
                validate_filters(&val).is_ok(),
                "shard {idx} failed validation"
            );
        }

        // Superset soundness invariant: every event matching ANY local sub must match >= 1 shard!
        for i in 0..120 {
            let mut ev = CloudEvent::new(
                format!("e-{i}"),
                format!("github.com/acme/service-{i:03}"),
                "com.github.push",
                json!({ "payload_note": "x".repeat(40) }),
            );
            ev.set_extension("repo", format!("acme/service-{i:03}"));
            assert!(
                plan.shards
                    .iter()
                    .any(|shard| matches_filters(&shard.filters, &ev)),
                "pushdown missed matching event for service-{i:03}"
            );
        }
    }

    #[test]
    fn diagnose_subscription_catches_dead_subscriptions() {
        let catalog = vec![TopicCatalogEntry {
            topic: "github".to_string(),
            has_provisioned_publisher: true,
            metadata: Some(TopicMetadata {
                kind: Some("github-webhook".to_string()),
                description: None,
                scope: Some(TopicScope {
                    repos: vec!["acme/checkout".to_string()],
                    orgs: vec![],
                    subjects: vec![],
                }),
                schema: Some(TopicSchema {
                    attributes: vec!["repo".to_string(), "action".to_string()],
                    event_types: vec![],
                    filter_examples: vec![],
                }),
                setup_guide: None,
            }),
            observed: ObservedTopicStats {
                event_count: 3,
                last_event_at: None,
                sources: vec!["github.com/acme/checkout".to_string()],
                repos: vec!["acme/checkout".to_string()],
            },
        }];

        // Unprovisioned topic.
        let d_unknown = diagnose_subscription("linear", &[], &catalog);
        assert!(
            d_unknown
                .iter()
                .any(|d| d.code == DiagnosticCode::UnprovisionedTopic
                    && d.severity == DiagnosticSeverity::Error)
        );

        // Invalid github subject filter.
        let d_subj =
            diagnose_subscription("github", &[exact("subject", "acme/checkout")], &catalog);
        assert!(
            d_subj
                .iter()
                .any(|d| d.code == DiagnosticCode::InvalidGithubSubjectFilter
                    && d.severity == DiagnosticSeverity::Error)
        );

        // Unmonitored repo.
        let d_unmon = diagnose_subscription("github", &[exact("repo", "other/repo")], &catalog);
        assert!(
            d_unmon
                .iter()
                .any(|d| d.code == DiagnosticCode::UnmonitoredRepo
                    && d.severity == DiagnosticSeverity::Error)
        );

        // Valid filter + negated unmonitored repo produces zero errors.
        let d_ok = diagnose_subscription(
            "github",
            &[
                exact("repo", "acme/checkout"),
                Filter::Not(Box::new(exact("repo", "other/repo"))),
            ],
            &catalog,
        );
        assert!(!d_ok.iter().any(|d| d.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn pushdown_handles_depth_8_local_filter_without_exceeding_max_depth() {
        // Build an exact depth-8 local filter: wrapping it inside `any` would hit depth 9 (> 8).
        let mut deep = exact("repo", "acme/deep");
        for _ in 0..7 {
            deep = Filter::Not(Box::new(deep));
        }
        assert_eq!(filter_depth(&deep), MAX_FILTER_DEPTH);

        let subs = vec![
            LocalSubscription {
                filters: vec![deep],
                coalesce_seconds: 20,
            },
            LocalSubscription {
                filters: vec![exact("repo", "acme/shallow")],
                coalesce_seconds: 10,
            },
        ];
        let plan = compile_upstream_pushdown("github", &subs);
        assert!(!plan.coarsened);
        assert_eq!(plan.shards.len(), 2);
        assert_eq!(plan.coalesce_seconds, Some(10));
        for shard in &plan.shards {
            let val = serde_json::to_value(&shard.filters).unwrap();
            assert!(validate_filters(&val).is_ok());
        }
    }
}
