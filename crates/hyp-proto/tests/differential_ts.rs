//! McKeeman (1998) cross-language differential test suite:
//! Feeds 600+ seeded valid & nearby-mutated inputs to BOTH Rust `hyp-proto` AND the live
//! TypeScript v1 reference implementations (`src/core/address.ts`, `src/core/router/cloudevent.ts`,
//! `src/core/router/filter.ts`, `src/core/identity/scopes.ts`, `src/protocol.ts`, plus V8's
//! ECMA-262 serializer) via `node --experimental-strip-types`, asserting 100% identical outcomes.

use hyp_proto::address::{
    Address, Channel, is_valid_handle, is_valid_node_id, is_valid_topic,
};
use hyp_proto::cloudevent::{check_cloudevent_v1, event_digest_value};
use hyp_proto::filter::{matches_filters, validate_filters};
use hyp_proto::jcs::{format_ecma_number, to_jcs_string};
use hyp_proto::scopes::{RuntimeMode, ScopeSet, expand_v1_scopes};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SEED: u64 = 0x5EED_CAFE_2026_0001;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn find_node_bin() -> String {
    if let Ok(output) = Command::new("node").arg("--version").output() {
        if output.status.success() {
            return "node".to_string();
        }
    }
    let mise_node = "/Users/bogdan/.local/share/mise/installs/node/24.21.0/bin/node";
    if Path::new(mise_node).exists() {
        return mise_node.to_string();
    }
    panic!("Node 24+ binary not found in PATH or mise path");
}

fn run_node_oracle(script: &str, input: &Value) -> Value {
    let node = find_node_bin();
    let mut child = Command::new(node)
        .current_dir(repo_root())
        .args(["--experimental-strip-types", "--input-type=module", "-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn node oracle");

    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        let payload = serde_json::to_vec(input).expect("serialize oracle input");
        stdin.write_all(&payload).expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait for node oracle");
    assert!(
        output.status.success(),
        "node oracle failed (exit {:?}):\nstderr:\n{}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    serde_json::from_slice(&output.stdout).expect("parse oracle JSON stdout")
}

fn rand_ident(rng: &mut StdRng, len: usize, alphabet: &[u8]) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.gen_range(0..alphabet.len());
        s.push(alphabet[idx] as char);
    }
    s
}

#[test]
fn differential_address_validators_and_parsers_vs_ts() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut id_cases: Vec<String> = vec![
        "".into(),
        "a".into(),
        "0".into(),
        "alice@macbook".into(),
        "public.hyphae.to".into(),
        "a".repeat(64),
        "a".repeat(65),
        "-bad".into(),
        ".bad".into(),
        "_bad".into(),
        "@bad".into(),
        "Upper".into(),
        "space here".into(),
        "slash/here".into(),
        "valid_1.2-3@host".into(),
        "emoji🚀".into(),
    ];
    let alphabet_all = b"abcdefghijklmnopqrstuvwxyz0123456789@._-AZ /#!";
    let alphabet_valid = b"abcdefghijklmnopqrstuvwxyz0123456789@._-";
    for _ in 0..60 {
        let len = rng.gen_range(1..=68);
        let alpha = if rng.gen_bool(0.5) {
            alphabet_valid.as_slice()
        } else {
            alphabet_all.as_slice()
        };
        id_cases.push(rand_ident(&mut rng, len, alpha));
    }

    let mut addr_cases: Vec<String> = vec![
        "alice@macbook/claude".into(),
        "public.hyphae.to/codex".into(),
        "no-slash".into(),
        "/leading".into(),
        "trailing/".into(),
        "a/b/c".into(),
        "alice@macbook/bad@handle".into(),
        format!("{}/{}", "a".repeat(64), "b".repeat(64)),
        format!("{}/{}", "a".repeat(65), "b".repeat(64)),
        format!("{}/{}", "a".repeat(64), "b".repeat(65)),
    ];
    for _ in 0..50 {
        let a = &id_cases[rng.gen_range(0..id_cases.len())];
        let b = &id_cases[rng.gen_range(0..id_cases.len())];
        addr_cases.push(format!("{a}/{b}"));
    }

    let mut chan_cases: Vec<String> = vec![
        "incidents".into(),
        "#incidents".into(),
        "  #Deploys.Prod_1  ".into(),
        format!("#{}", "a".repeat(63)),
        format!("#{}", "a".repeat(64)),
        "#".into(),
        "##double".into(),
        "#bad/slash".into(),
        "#bad@at".into(),
        "".into(),
        "   ".into(),
    ];
    for _ in 0..30 {
        let raw = &id_cases[rng.gen_range(0..id_cases.len())];
        chan_cases.push(if rng.gen_bool(0.5) {
            format!("#{raw}")
        } else {
            raw.clone()
        });
    }

    let script = r#"
        import { readFileSync } from "node:fs";
        import { isConnectorId, isHandle, parseAddress } from "./src/core/address.ts";
        import { isTopic } from "./src/core/router/cloudevent.ts";
        import { normalizeChannelName } from "./src/protocol.ts";
        const input = JSON.parse(readFileSync(0, "utf8"));
        const out = {
            ids: input.ids.map((s) => ({
                node: isConnectorId(s),
                handle: isHandle(s),
                topic: isTopic(s),
            })),
            addrs: input.addrs.map((s) => {
                const p = parseAddress(s);
                return p ? [p.connectorId, p.handle] : null;
            }),
            chans: input.chans.map((s) => normalizeChannelName(s)),
        };
        process.stdout.write(JSON.stringify(out));
    "#;

    let oracle = run_node_oracle(
        script,
        &json!({ "ids": id_cases, "addrs": addr_cases, "chans": chan_cases }),
    );

    for (idx, s) in id_cases.iter().enumerate() {
        let row = &oracle["ids"][idx];
        assert_eq!(
            is_valid_node_id(s),
            row["node"].as_bool().unwrap(),
            "seed={SEED} is_valid_node_id divergence on case {idx}: {s:?}"
        );
        assert_eq!(
            is_valid_handle(s),
            row["handle"].as_bool().unwrap(),
            "seed={SEED} is_valid_handle divergence on case {idx}: {s:?}"
        );
        assert_eq!(
            is_valid_topic(s),
            row["topic"].as_bool().unwrap(),
            "seed={SEED} is_valid_topic divergence on case {idx}: {s:?}"
        );
    }

    for (idx, s) in addr_cases.iter().enumerate() {
        let ts_val = &oracle["addrs"][idx];
        let rust_val = Address::parse(s)
            .ok()
            .map(|a| json!([a.node_id.as_str(), a.handle.as_str()]))
            .unwrap_or(Value::Null);
        assert_eq!(
            rust_val, *ts_val,
            "seed={SEED} parseAddress divergence on case {idx}: {s:?}"
        );
    }

    for (idx, s) in chan_cases.iter().enumerate() {
        let ts_val = &oracle["chans"][idx];
        let rust_val = Channel::normalize(s)
            .ok()
            .map(|c| Value::String(c.into_inner()))
            .unwrap_or(Value::Null);
        assert_eq!(
            rust_val, *ts_val,
            "seed={SEED} normalizeChannelName divergence on case {idx}: {s:?}"
        );
    }
}

#[test]
fn differential_cloudevent_v1_validation_and_digest_vs_ts() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xCE01);
    let mut events: Vec<Value> = Vec::new();

    // Helper: base valid event.
    let base = || {
        json!({
            "specversion": "1.0",
            "id": "ev-001",
            "source": "github.com/acme/web",
            "type": "com.github.pull_request.opened",
            "datacontenttype": "application/json",
            "subject": "pull/42",
            "time": "2026-06-15T10:20:30.123Z",
            "repo": "acme/web",
            "data": { "number": 42, "draft": false, "labels": ["urgent", "ci"] }
        })
    };

    // Valid + boundary cases.
    events.push(base());
    let mut no_opt = base();
    no_opt.as_object_mut().unwrap().remove("subject");
    no_opt.as_object_mut().unwrap().remove("time");
    events.push(no_opt);

    let mut with_offset = base();
    with_offset["time"] = json!("2026-06-15T10:20:30+02:30");
    events.push(with_offset);

    // Exact attribute UTF-16 length boundary: 256 (valid) vs 257 (too_large), including emojis (2 UTF-16 units each!).
    let mut attr_256 = base();
    attr_256["repo"] = json!("a".repeat(256));
    events.push(attr_256);

    let mut attr_257 = base();
    attr_257["repo"] = json!("a".repeat(257));
    events.push(attr_257);

    let mut emoji_128 = base();
    emoji_128["repo"] = json!("🚀".repeat(128)); // 256 UTF-16 code units -> ok!
    events.push(emoji_128);

    let mut emoji_129 = base();
    emoji_129["repo"] = json!("🚀".repeat(129)); // 258 UTF-16 code units -> too_large!
    events.push(emoji_129);

    // Exact data byte boundary: 8192 (valid) vs 8193 (too_large).
    let mut data_ok = base();
    data_ok["data"] = json!({ "p": "x".repeat(8192 - 8) }); // {"p":"..."} = 8192 bytes
    events.push(data_ok);

    let mut data_big = base();
    data_big["data"] = json!({ "p": "x".repeat(8192 - 7) }); // 8193 bytes
    events.push(data_big);

    // Event > 12 KiB while data <= 8 KiB (via many valid 256-char extensions).
    let mut ev_big = base();
    ev_big["data"] = json!({ "p": "x".repeat(7500) });
    for i in 0..25 {
        ev_big[format!("ext{i:02}")] = json!("z".repeat(250));
    }
    events.push(ev_big);

    // Nearby single-field mutations (McKeeman Level 3-5 mutated valid inputs).
    type EventMutator = Box<dyn Fn(&mut Value)>;
    let mutations: Vec<EventMutator> = vec![
        Box::new(|v| *v = json!(null)),
        Box::new(|v| *v = json!([])),
        Box::new(|v| *v = json!("string")),
        Box::new(|v| { v["specversion"] = json!("0.3"); }),
        Box::new(|v| { v["specversion"] = json!(1.0); }),
        Box::new(|v| { v["datacontenttype"] = json!("text/plain"); }),
        Box::new(|v| { v.as_object_mut().unwrap().remove("datacontenttype"); }),
        Box::new(|v| { v["id"] = json!(""); }),
        Box::new(|v| { v["source"] = json!(""); }),
        Box::new(|v| { v["type"] = json!(""); }),
        Box::new(|v| { v["id"] = json!(123); }),
        Box::new(|v| { v["subject"] = json!(null); }),
        Box::new(|v| { v["subject"] = json!(42); }),
        Box::new(|v| { v["time"] = json!(null); }),
        Box::new(|v| { v["time"] = json!("not-a-time"); }),
        Box::new(|v| { v["time"] = json!("2026-06-15 10:20:30Z"); }),
        Box::new(|v| { v["time"] = json!("2026-06-15t10:20:30z"); }),
        Box::new(|v| { v["time"] = json!("2026-13-01T00:00:00Z"); }),
        Box::new(|v| { v["time"] = json!("2026-01-32T00:00:00Z"); }),
        Box::new(|v| { v["data"] = json!(null); }),
        Box::new(|v| { v["data"] = json!([1, 2, 3]); }),
        Box::new(|v| { v["data"] = json!("plain"); }),
        Box::new(|v| { v["UpperExt"] = json!("x"); }),
        Box::new(|v| { v["bad_ext"] = json!("x"); }),
        Box::new(|v| { v["bad-ext"] = json!("x"); }),
        Box::new(|v| { v["a".repeat(21)] = json!("x"); }),
        Box::new(|v| { v["a".repeat(20)] = json!("ok"); }),
        Box::new(|v| { v["numext"] = json!(42); }),
        Box::new(|v| { v["boolext"] = json!(true); }),
    ];
    for mutate in mutations {
        let mut ev = base();
        mutate(&mut ev);
        events.push(ev);
    }

    // 80 randomized valid & mutated events.
    for i in 0..80 {
        let mut ev = base();
        ev["id"] = json!(format!("rand-{i}"));
        let ext_len = rng.gen_range(1..=22);
        let ext_name = rand_ident(&mut rng, ext_len, b"abcdefghijklmnopqrstuvwxyz0123456789_-A");
        if rng.gen_bool(0.85) {
            let val_len = rng.gen_range(0..=265);
            ev[ext_name] = json!("k".repeat(val_len));
        } else {
            ev[ext_name] = json!(rng.gen_range(0..100));
        }
        ev["data"] = json!({
            "count": rng.gen_range(-1000..1000),
            "flag": rng.gen_bool(0.5),
            "note": format!("n-{i}"),
        });
        events.push(ev);
    }

    let script = r#"
        import { readFileSync } from "node:fs";
        import { checkCloudEvent, eventDigest } from "./src/core/router/cloudevent.ts";
        const events = JSON.parse(readFileSync(0, "utf8"));
        const out = events.map((ev) => {
            const res = checkCloudEvent(ev);
            if (res.ok) return { ok: true, digest: eventDigest(res.event) };
            return { ok: false, error: res.error };
        });
        process.stdout.write(JSON.stringify(out));
    "#;

    let oracle = run_node_oracle(script, &Value::Array(events.clone()));

    for (idx, ev) in events.iter().enumerate() {
        let ts = &oracle[idx];
        let rust = check_cloudevent_v1(ev);
        match (rust, ts["ok"].as_bool().unwrap()) {
            (Ok((parsed, _)), true) => {
                let ts_digest = ts["digest"].as_str().unwrap();
                assert_eq!(
                    parsed.digest(),
                    ts_digest,
                    "seed={SEED} eventDigest mismatch on case {idx}: {ev}"
                );
                assert_eq!(
                    event_digest_value(ev).unwrap(),
                    ts_digest,
                    "seed={SEED} event_digest_value mismatch on case {idx}"
                );
            }
            (Err(err), false) => {
                let ts_err = ts["error"].as_str().unwrap();
                assert_eq!(
                    err.code(),
                    ts_err,
                    "seed={SEED} error code mismatch on case {idx}: rust={err:?}, ts={ts_err}, ev={ev}"
                );
            }
            (rust_res, _ts_ok) => {
                panic!(
                    "seed={SEED} checkCloudEvent accept/reject divergence on case {idx}: rust={rust_res:?}, ts={ts}, ev={ev}"
                );
            }
        }
    }
}

fn gen_valid_filter(rng: &mut StdRng, depth: usize, max_depth: usize) -> Value {
    let keys = [
        "type",
        "source",
        "subject",
        "repo",
        "actor",
        "data.action",
        "data.number",
        "data.draft",
        "data.labels",
        "data.nested",
        "data.empty",
    ];
    let vals = [
        "com.github.push",
        "com.github.",
        "opened",
        "github.com/acme/web",
        "acme/web",
        "acme/",
        "pull/42",
        "42",
        "false",
        "true",
        "urgent",
        "missing",
        "",
    ];

    let choice = if depth >= max_depth {
        rng.gen_range(0..3)
    } else {
        rng.gen_range(0..6)
    };

    match choice {
        0..=2 => {
            let dialect = ["exact", "prefix", "suffix"][choice];
            let pair_count = rng.gen_range(1..=3);
            let mut pairs = Map::new();
            for _ in 0..pair_count {
                let k = keys[rng.gen_range(0..keys.len())];
                let v = vals[rng.gen_range(0..vals.len())];
                pairs.insert(k.to_string(), Value::String(v.to_string()));
            }
            let mut obj = Map::new();
            obj.insert(dialect.to_string(), Value::Object(pairs));
            Value::Object(obj)
        }
        3 | 4 => {
            let dialect = if choice == 3 { "all" } else { "any" };
            let count = rng.gen_range(1..=3);
            let children: Vec<Value> = (0..count)
                .map(|_| gen_valid_filter(rng, depth + 1, max_depth))
                .collect();
            let mut obj = Map::new();
            obj.insert(dialect.to_string(), Value::Array(children));
            Value::Object(obj)
        }
        _ => {
            let inner = gen_valid_filter(rng, depth + 1, max_depth);
            json!({ "not": inner })
        }
    }
}

#[test]
fn differential_filter_validation_and_matching_vs_ts() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xF117);

    let mut filter_cases: Vec<Value> = vec![
        // Empty array (matches all).
        json!([]),
        // Non-array.
        json!({ "exact": { "repo": "acme/web" } }),
        json!(null),
        // Depth 8 (valid) vs depth 9 (invalid).
        json!([{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"exact":{"repo":"acme/web"}}}}}}}}}]),
        json!([{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"exact":{"repo":"acme/web"}}}}}}}}}}]),
        // Oversized (> 4096 bytes).
        json!([{"exact": {"repo": "x".repeat(4096)}}]),
        // Mutated invalid filter structures.
        json!([{}]),
        json!([{"exact": {"repo": "a"}, "prefix": {"repo": "a"}}]),
        json!([{"unknown": {"repo": "a"}}]),
        json!([{"exact": {}}]),
        json!([{"prefix": []}]),
        json!([{"suffix": "str"}]),
        json!([{"all": []}]),
        json!([{"any": []}]),
        json!([{"all": "bad"}]),
        json!([{"not": "bad"}]),
        json!([{"exact": {"UPPER": "a"}}]),
        json!([{"exact": {"a".repeat(21): "a"}}]),
        json!([{"exact": {"data.": "a"}}]),
        json!([{"exact": {"data.has space": "a"}}]),
        json!([{"exact": {format!("data.{}", "x".repeat(128)): "a"}}]),
        json!([{"exact": {format!("data.{}", "x".repeat(129)): "a"}}]),
        json!([{"exact": {"repo": 123}}]),
        json!([{"exact": {"repo": true}}]),
        json!([{"exact": {"repo": null}}]),
        // Special keys like "data" itself (valid key syntax, looks up nothing).
        json!([{"exact": {"data": "anything"}}]),
        // Array & nested array & number/bool coercion tests.
        json!([{"exact": {"data.labels": "urgent"}}]),
        json!([{"exact": {"data.nested": "inner"}}]),
        json!([{"exact": {"data.number": "42"}}]),
        json!([{"exact": {"data.draft": "false"}}]),
        json!([{"exact": {"data.empty": ""}}]),
    ];

    // 180 seeded randomized valid filter lists.
    for _ in 0..180 {
        let count = rng.gen_range(0..=3);
        let list: Vec<Value> = (0..count)
            .map(|_| gen_valid_filter(&mut rng, 1, 5))
            .collect();
        filter_cases.push(Value::Array(list));
    }

    // Diverse CloudEvent corpus to evaluate EVERY valid filter against.
    let eval_events: Vec<Value> = vec![
        json!({
            "specversion": "1.0",
            "id": "e1",
            "source": "github.com/acme/web",
            "type": "com.github.pull_request.opened",
            "datacontenttype": "application/json",
            "subject": "pull/42",
            "repo": "acme/web",
            "actor": "alice",
            "data": {
                "action": "opened",
                "number": 42,
                "draft": false,
                "labels": ["urgent", "ci", 42, true, null, ["inner"]],
                "nested": [["inner"], "flat"],
                "empty": ""
            }
        }),
        json!({
            "specversion": "1.0",
            "id": "e2",
            "source": "github.com/other/api",
            "type": "com.github.push",
            "datacontenttype": "application/json",
            "repo": "other/api",
            "data": {
                "action": "closed",
                "number": 0.000001,
                "draft": true,
                "labels": [],
                "nested": { "inner": "obj" }
            }
        }),
        json!({
            "specversion": "1.0",
            "id": "e3",
            "source": "local/slack/ops",
            "type": "to.hyphae.bridge.slack",
            "datacontenttype": "application/json",
            "data": {}
        }),
    ];

    let script = r#"
        import { readFileSync } from "node:fs";
        import { checkFilters, matchesFilters } from "./src/core/router/filter.ts";
        const { cases, events } = JSON.parse(readFileSync(0, "utf8"));
        const out = cases.map((f) => {
            const res = checkFilters(f);
            if (!res.ok) return { ok: false, path: res.path };
            return {
                ok: true,
                matches: events.map((ev) => matchesFilters(res.filters, ev)),
            };
        });
        process.stdout.write(JSON.stringify(out));
    "#;

    let oracle = run_node_oracle(
        script,
        &json!({ "cases": filter_cases, "events": eval_events }),
    );

    let parsed_events: Vec<_> = eval_events
        .iter()
        .map(|v| check_cloudevent_v1(v).expect("valid eval event").0)
        .collect();

    for (idx, case) in filter_cases.iter().enumerate() {
        let ts = &oracle[idx];
        match (validate_filters(case), ts["ok"].as_bool().unwrap()) {
            (Ok(filters), true) => {
                let ts_matches: Vec<bool> = ts["matches"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|b| b.as_bool().unwrap())
                    .collect();
                let rust_matches: Vec<bool> = parsed_events
                    .iter()
                    .map(|ev| matches_filters(&filters, ev))
                    .collect();
                assert_eq!(
                    rust_matches, ts_matches,
                    "seed={SEED} matchesFilters divergence on case {idx}: filter={case}"
                );
            }
            (Err(err), false) => {
                let ts_path = ts["path"].as_str().unwrap();
                assert_eq!(
                    err.path, ts_path,
                    "seed={SEED} filter error path divergence on case {idx}: rust={err:?}, ts={ts}, filter={case}"
                );
            }
            (rust_res, _) => {
                panic!(
                    "seed={SEED} checkFilters accept/reject divergence on case {idx}: rust={rust_res:?}, ts={ts}, filter={case}"
                );
            }
        }
    }
}

#[test]
fn differential_v1_scopes_expansion_and_scopeset_vs_ts() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x5C0E);

    let valid_tokens = [
        "*",
        "messages:*",
        "events:*",
        "files:*",
        "forks:*",
        "messages:send",
        "messages:receive",
        "events:subscribe",
        "files:send",
        "files:send=alice@laptop",
        "files:send=bob@dev,alice@laptop,bob@dev",
        "files:receive",
        "forks:send",
        "forks:send=carol@box",
        "forks:receive/approval-required",
        "forks:receive/auto-accept-edits",
        "forks:receive/auto",
        "forks:receive/full-access",
    ];
    let invalid_tokens = [
        "",
        "unknown:scope",
        "messages:send=alice@laptop",
        "files:receive=alice@laptop",
        "files:send=",
        "files:send=BAD_UPPER",
        "forks:receive",
        "forks:receive/bogus",
        "forks:send=alice@laptop,",
        "events:publish", // valid in v2, NOT in v1 expandScopes!
        "dm:send",
    ];

    let mut expand_cases: Vec<Vec<String>> = vec![
        vec![],
        vec!["*".into()],
        vec!["messages:*".into(), "events:*".into()],
        vec!["files:send=bob@a,alice@b".into(), "files:send=alice@b,bob@a".into()],
        vec!["files:send".into(), "files:send=alice@b".into()],
        vec!["forks:receive/auto".into(), "forks:receive/full-access".into()],
        vec!["forks:receive/auto".into(), "forks:receive/auto".into()],
    ];
    for t in &valid_tokens {
        expand_cases.push(vec![(*t).to_string()]);
    }
    for t in &invalid_tokens {
        expand_cases.push(vec![(*t).to_string()]);
    }
    for _ in 0..80 {
        let len = rng.gen_range(1..=4);
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            if rng.gen_bool(0.75) {
                list.push(valid_tokens[rng.gen_range(0..valid_tokens.len())].to_string());
            } else {
                list.push(invalid_tokens[rng.gen_range(0..invalid_tokens.len())].to_string());
            }
        }
        expand_cases.push(list);
    }

    // ScopeSet query cases (including unknown future scopes ignored fail-closed).
    let set_cases: Vec<Vec<String>> = vec![
        vec![],
        vec!["unknown:future".into(), "messages:send".into()],
        vec!["files:send=alice@laptop,bob@dev".into(), "forks:receive/auto".into()],
        vec!["files:send".into(), "files:receive".into(), "events:subscribe".into()],
        vec!["forks:send=carol@box".into(), "forks:receive/approval-required".into()],
        vec!["messages:receive".into(), "forks:receive/full-access".into()],
    ];

    let script = r#"
        import { readFileSync } from "node:fs";
        import { expandScopes, ScopeSet } from "./src/core/identity/scopes.ts";
        const { expandCases, setCases } = JSON.parse(readFileSync(0, "utf8"));
        const expanded = expandCases.map((list) => {
            try {
                return { ok: true, scopes: expandScopes(list) };
            } catch {
                return { ok: false };
            }
        });
        const sets = setCases.map((list) => {
            const s = new ScopeSet(list);
            return {
                ms: s.has("messages:send"),
                mr: s.has("messages:receive"),
                es: s.has("events:subscribe"),
                fr: s.has("files:receive"),
                filesAlice: s.maySend("files", "alice@laptop"),
                filesOther: s.maySend("files", "other@host"),
                forksCarol: s.maySend("forks", "carol@box"),
                forksOther: s.maySend("forks", "other@host"),
                forkOut: s.mayForkOut(),
                ceiling: s.forkCeiling(),
            };
        });
        process.stdout.write(JSON.stringify({ expanded, sets }));
    "#;

    let oracle = run_node_oracle(
        script,
        &json!({ "expandCases": expand_cases, "setCases": set_cases }),
    );

    for (idx, list) in expand_cases.iter().enumerate() {
        let ts = &oracle["expanded"][idx];
        match (expand_v1_scopes(list), ts["ok"].as_bool().unwrap()) {
            (Ok(rust_out), true) => {
                let ts_out: Vec<String> = ts["scopes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                assert_eq!(
                    rust_out, ts_out,
                    "seed={SEED} expandScopes output mismatch on case {idx}: {list:?}"
                );
            }
            (Err(_), false) => {}
            (rust_res, _) => {
                panic!(
                    "seed={SEED} expandScopes accept/reject divergence on case {idx}: list={list:?}, rust={rust_res:?}, ts={ts}"
                );
            }
        }
    }

    for (idx, list) in set_cases.iter().enumerate() {
        let ts = &oracle["sets"][idx];
        let s = ScopeSet::from_strings(list);
        assert_eq!(s.has_v1("messages:send"), ts["ms"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.has_v1("messages:receive"), ts["mr"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.has_v1("events:subscribe"), ts["es"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.has_v1("files:receive"), ts["fr"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.may_send_files("alice@laptop", None), ts["filesAlice"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.may_send_files("other@host", None), ts["filesOther"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.may_send_forks("carol@box"), ts["forksCarol"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.may_send_forks("other@host"), ts["forksOther"].as_bool().unwrap(), "case {idx}");
        assert_eq!(s.may_fork_out(), ts["forkOut"].as_bool().unwrap(), "case {idx}");
        let rust_ceiling = s.fork_ceiling().map(|m: RuntimeMode| m.as_str().to_string());
        let ts_ceiling = ts["ceiling"].as_str().map(String::from);
        assert_eq!(rust_ceiling, ts_ceiling, "case {idx}");
    }
}

#[test]
fn differential_rfc8785_jcs_numbers_and_utf16_sorting_vs_v8() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x8785);

    // 100+ IEEE-754 edge-case & randomized floats compared directly against V8's Number.toString(10).
    let mut numbers: Vec<f64> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        0.2,
        0.3,
        0.1 + 0.2,
        1e-6,
        1e-7,
        -1e-6,
        -1e-7,
        1e20,
        1e21,
        -1e20,
        -1e21,
        1e-27,
        1e30,
        "333333333.33333329".parse::<f64>().unwrap(),
        f64::MIN_POSITIVE,
        f64::MAX,
        f64::from_bits(1), // 5e-324 smallest subnormal
        9007199254740991.0,
        9007199254740992.0,
        999999999999999900000.0,
    ];
    for _ in 0..100 {
        let bits: u64 = rng.r#gen();
        let f = f64::from_bits(bits);
        if f.is_finite() {
            numbers.push(f);
        }
    }

    // Complex JCS objects with tricky Unicode keys (UTF-16 surrogate pairs vs BMP).
    let objects: Vec<Value> = vec![
        json!({
            "\u{e000}": 1,
            "\u{1f600}": 2,
            "\r": 3,
            "1": 4,
            "\u{0080}": 5,
            "\u{fb33}": 6,
            "\u{20ac}": 7,
            "controls": "\u{0000}\u{0007}\u{0008}\u{0009}\u{000a}\u{000c}\u{000d}\u{001f}",
        }),
        json!({
            "nested": { "z": -0.0, "a": [1e21, 1e-7, 1e-6, true, null, "café/\"\\"] }
        }),
    ];

    // Pass f64 bit patterns as hex strings so JS reconstructs the exact IEEE-754 double!
    let bit_hexes: Vec<String> = numbers.iter().map(|f| format!("{:016x}", f.to_bits())).collect();

    let script = r#"
        import { readFileSync } from "node:fs";
        const { bitHexes, objects } = JSON.parse(readFileSync(0, "utf8"));
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        const numStrings = bitHexes.map((h) => {
            view.setBigUint64(0, BigInt("0x" + h), false);
            const n = view.getFloat64(0, false);
            return JSON.stringify(n);
        });
        function canonical(v) {
            if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
            if (v && typeof v === "object") {
                const keys = Object.keys(v).sort();
                return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
            }
            return JSON.stringify(v);
        }
        const objStrings = objects.map(canonical);
        process.stdout.write(JSON.stringify({ numStrings, objStrings }));
    "#;

    let oracle = run_node_oracle(
        script,
        &json!({ "bitHexes": bit_hexes, "objects": objects }),
    );

    for (idx, f) in numbers.iter().enumerate() {
        let rust_str = format_ecma_number(*f).unwrap();
        let v8_str = oracle["numStrings"][idx].as_str().unwrap();
        assert_eq!(
            rust_str, v8_str,
            "seed={SEED} RFC 8785 ECMA-262 number mismatch on idx {idx} (bits={:016x})",
            f.to_bits()
        );
    }

    for (idx, obj) in objects.iter().enumerate() {
        let rust_str = to_jcs_string(obj).unwrap();
        let v8_str = oracle["objStrings"][idx].as_str().unwrap();
        assert_eq!(
            rust_str, v8_str,
            "seed={SEED} RFC 8785 canonical JSON mismatch on object idx {idx}"
        );
    }
}
