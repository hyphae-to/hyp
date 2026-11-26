//! McKeeman Seeded Differential Protocol Fuzzer (`AGENTS.md`):
//!
//! Deterministic, `HYPHAE_TEST_SEED`-seeded fuzz tests covering:
//! 1. Upstream subscription pushdown compiler superset invariant & wire caps across 500+ Filter ASTs
//!    (depths 1..=8, nested `all`/`any`/`not`/`exact`/`prefix`/`suffix`, multi-shard splitting & coarsening).
//! 2. Dotted peer `NodeId` deterministic longest-prefix topic resolution, round-trip formatting,
//!    and `local.` non-ambiguity.
//! 3. v1/v2 `ScopeSet` & built-in preset privilege confinement (`*` / presets NEVER escalate
//!    to `bridge:post` or `forward:via`; `guest-ro` NEVER grants DM send, channel post, files, or KV write).

use std::collections::BTreeMap;

use hyp_proto::address::{
    LOCAL_NODE_ID, NodeId, NodeScope, QualifiedTopic, Topic, resolve_topic, validate_new_peer_alias,
};
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::{
    Filter, LocalSubscription, MAX_FILTER_DEPTH, MAX_FILTERS_BYTES, MAX_PUSHDOWN_SHARDS,
    compile_filters, compile_upstream_pushdown, filter_depth, matches_filters, validate_filters,
};
use hyp_proto::scopes::{ScopePreset, ScopeSet, expand_v1_scopes, expand_v2_scopes};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde_json::{Value, json};

fn resolve_seed(default: u64) -> u64 {
    match std::env::var("HYPHAE_TEST_SEED") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
                    .unwrap_or_else(|e| panic!("invalid hex HYPHAE_TEST_SEED={raw:?}: {e}"))
            } else {
                trimmed
                    .parse::<u64>()
                    .unwrap_or_else(|e| panic!("invalid decimal HYPHAE_TEST_SEED={raw:?}: {e}"))
            }
        }
        Err(_) => default,
    }
}

fn exact_f(k: &str, v: &str) -> Filter {
    Filter::Exact(BTreeMap::from([(k.to_string(), v.to_string())]))
}

fn prefix_f(k: &str, v: &str) -> Filter {
    Filter::Prefix(BTreeMap::from([(k.to_string(), v.to_string())]))
}

// =========================================================================
// 1. Upstream Pushdown Compiler Superset Invariant Fuzzer
// =========================================================================

fn build_diverse_cloudevent_corpus() -> Vec<CloudEvent> {
    let repos = [
        "acme/checkout",
        "acme/web",
        "acme/billing",
        "hyphae/hyp",
        "oss/runtime",
        "sec/scanner",
    ];
    let types = [
        "com.github.pull_request.opened",
        "com.github.pull_request.closed",
        "com.github.push",
        "com.github.issues.labeled",
        "to.hyphae.kv.set",
        "com.ci.build.failed",
    ];
    let envs = ["prod", "staging", "dev"];
    let actions = ["opened", "synchronize", "labeled", "completed", "failed"];
    let label_sets: &[&[&str]] = &[
        &["bug", "p0"],
        &["security", "urgent"],
        &["docs"],
        &["ci", "flaky", "p1"],
        &[],
    ];

    let mut events = Vec::with_capacity(30);
    for idx in 0..30usize {
        let repo = repos[idx % repos.len()];
        let ev_type = types[(idx * 7 + idx / 6) % types.len()];
        let env = envs[idx % envs.len()];
        let action = actions[idx % actions.len()];
        let labels = label_sets[idx % label_sets.len()];
        let source = if idx % 5 == 0 {
            format!("local/kv/{env}")
        } else if idx % 5 == 1 {
            format!("ci.acme.internal/{repo}")
        } else {
            format!("github.com/{repo}")
        };

        let data = if idx == 29 {
            Value::Null
        } else {
            json!({
                "action": action,
                "labels": labels,
                "draft": (idx % 2 == 0),
                "count": idx as u64,
                "score": (idx as f64) * 0.5,
                "nested": {
                    "env": env,
                    "tier": if idx % 3 == 0 { "gold" } else { "std" }
                },
                "a.b": if idx % 4 == 0 { "lit" } else { "other" },
                "optional": if idx % 3 == 0 { Value::Null } else { json!(format!("opt-{idx}")) },
            })
        };

        let mut ev = CloudEvent::new(format!("ev-{idx:02}"), source, ev_type, data);
        if idx == 29 {
            ev.data = None;
        }
        if idx % 3 != 0 {
            ev.subject = Some(format!("pr/{}", 100 + idx));
        }
        ev.set_extension("repo", repo);
        ev.set_extension("env", env);
        ev.set_extension("branch", if idx % 2 == 0 { "main" } else { "release/v2" });
        if idx % 4 == 0 {
            ev.set_extension("severity", "high");
        }
        events.push(ev);
    }
    assert_eq!(events.len(), 30);
    events
}

const FILTER_KEY_VALUES: &[(&str, &[&str])] = &[
    (
        "repo",
        &[
            "acme/checkout",
            "acme/web",
            "acme/billing",
            "hyphae/hyp",
            "oss/runtime",
            "acme/",
            "/checkout",
            "nope/repo",
        ],
    ),
    (
        "source",
        &[
            "github.com/acme/checkout",
            "github.com/",
            "local/kv/prod",
            "ci.acme.internal/",
            "/web",
        ],
    ),
    (
        "type",
        &[
            "com.github.pull_request.opened",
            "com.github.pull_request.",
            "com.github.",
            ".failed",
            "to.hyphae.kv.set",
        ],
    ),
    ("subject", &["pr/101", "pr/10", "pr/", "102"]),
    ("env", &["prod", "staging", "dev", "pr"]),
    ("branch", &["main", "release/v2", "release/", "v2"]),
    ("severity", &["high", "low"]),
    (
        "data.action",
        &["opened", "synchronize", "labeled", "completed", "ed"],
    ),
    ("data.labels", &["bug", "p0", "security", "ci", "docs"]),
    ("data.draft", &["true", "false"]),
    ("data.count", &["0", "1", "2", "15", "28"]),
    ("data.nested.env", &["prod", "staging", "dev"]),
    ("data.nested.tier", &["gold", "std"]),
    ("data.a.b", &["lit", "other"]),
    ("data.missing", &["x"]),
];

fn random_leaf_filter(rng: &mut StdRng) -> Filter {
    let pair_count = rng.gen_range(1..=3);
    let mut map = BTreeMap::new();
    for _ in 0..pair_count {
        let (k, vals) = FILTER_KEY_VALUES[rng.gen_range(0..FILTER_KEY_VALUES.len())];
        let v = vals[rng.gen_range(0..vals.len())];
        map.insert(k.to_string(), v.to_string());
    }
    match rng.gen_range(0..3) {
        0 => Filter::Exact(map),
        1 => Filter::Prefix(map),
        _ => Filter::Suffix(map),
    }
}

fn random_filter_ast(rng: &mut StdRng, max_depth: usize, current_depth: usize) -> Filter {
    if current_depth >= max_depth {
        return random_leaf_filter(rng);
    }
    // Bias toward leaves deeper in the tree so AST sizes stay well-behaved while still hitting depth 8.
    let choice = if current_depth == 1 && max_depth >= 5 && rng.gen_bool(0.5) {
        rng.gen_range(3..6) // force nesting on deep cases
    } else if current_depth >= 5 {
        rng.gen_range(0..5)
    } else {
        rng.gen_range(0..6)
    };
    match choice {
        0..=2 => random_leaf_filter(rng),
        3 => {
            let n = if current_depth >= 4 {
                rng.gen_range(1..=2)
            } else {
                rng.gen_range(1..=3)
            };
            let children = (0..n)
                .map(|_| random_filter_ast(rng, max_depth, current_depth + 1))
                .collect();
            Filter::All(children)
        }
        4 => {
            let n = if current_depth >= 4 {
                rng.gen_range(1..=2)
            } else {
                rng.gen_range(1..=3)
            };
            let children = (0..n)
                .map(|_| random_filter_ast(rng, max_depth, current_depth + 1))
                .collect();
            Filter::Any(children)
        }
        _ => Filter::Not(Box::new(random_filter_ast(
            rng,
            max_depth,
            current_depth + 1,
        ))),
    }
}

/// Generates a random valid `Vec<Filter>` within `MAX_FILTERS_BYTES` and `MAX_FILTER_DEPTH`.
fn random_valid_filter_list(rng: &mut StdRng, target_depth: usize) -> Vec<Filter> {
    let clamped_depth = target_depth.clamp(1, MAX_FILTER_DEPTH);
    for _ in 0..8 {
        let top_count = if clamped_depth >= 7 {
            1
        } else {
            rng.gen_range(1..=3)
        };
        let list: Vec<Filter> = (0..top_count)
            .map(|_| random_filter_ast(rng, clamped_depth, 1))
            .collect();
        if let Ok(val) = serde_json::to_value(&list) {
            if validate_filters(&val).is_ok() {
                return list;
            }
        }
    }
    vec![random_leaf_filter(rng)]
}

/// Generates a heavy valid filter list (~1.1 KiB) with `data.*` and routing predicates
/// so combining 5..=8 of them exceeds 4 KiB (sharding) and 32..=36 exceeds 32 KiB (coarsening).
fn random_heavy_filter_list(rng: &mut StdRng, sub_idx: usize, include_core: bool) -> Vec<Filter> {
    let mut data_map = BTreeMap::new();
    for j in 0..8 {
        data_map.insert(
            format!("data.payload_field_{sub_idx}_{j}"),
            format!("val-{sub_idx:03}-{j}-{}", "x".repeat(90)),
        );
    }
    let repo_vals = FILTER_KEY_VALUES[0].1;
    let chosen_repo = repo_vals[rng.gen_range(0..repo_vals.len())];
    let mut filters = vec![
        Filter::Any(vec![Filter::Exact(data_map), random_leaf_filter(rng)]),
        Filter::Not(Box::new(exact_f(
            "data.excluded_tag",
            &format!("never-{sub_idx:03}-{}", "z".repeat(64)),
        ))),
    ];
    if include_core {
        filters.push(exact_f("repo", chosen_repo));
    }
    let val = serde_json::to_value(&filters).unwrap();
    validate_filters(&val).expect("heavy filter list must be valid");
    filters
}

#[test]
fn fuzz_pushdown_compiler_superset_invariant_500_asts() {
    let seed = resolve_seed(0xD1FF_F022_0001);
    let mut rng = StdRng::seed_from_u64(seed);
    let corpus = build_diverse_cloudevent_corpus();

    let mut saw_multi_shard = false;
    let mut saw_coarsened = false;
    let mut saw_match_all_fallback = false;
    let mut saw_depth_8 = false;
    let mut matched_pairs = 0usize;
    let mut unmatched_pairs = 0usize;

    // 530 total seeded cases:
    // - steps 0..500: random depths 1..=8, 1..=5 local subscriptions per topic
    // - steps 500..520: multi-shard overflow sets (> 4 KiB combined, triggering sharding)
    // - steps 520..530: massive > 32 KiB sets triggering coarsening passes & match-all fallback
    for step in 0..530usize {
        let topic = format!("topic.{}", step % 7);
        let local_subs: Vec<LocalSubscription> = if step < 500 {
            let sub_count = rng.gen_range(1..=5);
            (0..sub_count)
                .map(|_| {
                    let depth = rng.gen_range(1..=MAX_FILTER_DEPTH);
                    let filters = if rng.gen_bool(0.03) {
                        Vec::new() // match-all local subscription
                    } else {
                        random_valid_filter_list(&mut rng, depth)
                    };
                    if filters.iter().any(|f| filter_depth(f) == MAX_FILTER_DEPTH) {
                        saw_depth_8 = true;
                    }
                    LocalSubscription {
                        filters,
                        coalesce_seconds: rng.gen_range(0..=300),
                    }
                })
                .collect()
        } else if step < 520 {
            // 5..=8 heavy subscriptions (~5.5..9 KiB total) -> triggers multi-shard splitting.
            let sub_count = rng.gen_range(5..=8);
            (0..sub_count)
                .map(|i| LocalSubscription {
                    filters: random_heavy_filter_list(&mut rng, step * 100 + i, true),
                    coalesce_seconds: rng.gen_range(5..=120),
                })
                .collect()
        } else {
            // 32..=38 heavy subscriptions (> 35 KiB total) -> exceeds 8 shards -> coarsening & fallback!
            let sub_count = rng.gen_range(32..=38);
            let force_fallback = step >= 525;
            (0..sub_count)
                .map(|i| {
                    let mut filters =
                        random_heavy_filter_list(&mut rng, step * 100 + i, !force_fallback);
                    if force_fallback {
                        // Unique long `repo` values on every sub so even CoreRoutingOnly exceeds 8 shards.
                        filters.push(exact_f(
                            "repo",
                            &format!(
                                "org-{step:03}/very-long-unique-repo-name-{i:04}-{}",
                                "r".repeat(900)
                            ),
                        ));
                    }
                    LocalSubscription {
                        filters,
                        coalesce_seconds: rng.gen_range(0..=60),
                    }
                })
                .collect()
        };

        let expected_min_coalesce = local_subs.iter().map(|s| s.coalesce_seconds).min();
        let plan = compile_upstream_pushdown(&topic, &local_subs);

        // 1. Metadata & shard count bounds
        assert_eq!(
            plan.coalesce_seconds, expected_min_coalesce,
            "seed=0x{seed:016x} step={step}: coalesce_seconds mismatch"
        );
        assert!(
            !plan.shards.is_empty() && plan.shards.len() <= MAX_PUSHDOWN_SHARDS,
            "seed=0x{seed:016x} step={step}: shard count {} out of bounds 1..={MAX_PUSHDOWN_SHARDS}",
            plan.shards.len()
        );

        if plan.shards.len() > 1 {
            saw_multi_shard = true;
        }
        if plan.coarsened {
            saw_coarsened = true;
            if plan.shards.len() == 1 && plan.shards[0].filters.is_empty() {
                saw_match_all_fallback = true;
            }
        }

        // 2. Every compiled shard MUST satisfy wire bounds (`<= MAX_FILTERS_BYTES`, `<= MAX_FILTER_DEPTH`, valid schema).
        for (shard_idx, shard) in plan.shards.iter().enumerate() {
            let shard_val = serde_json::to_value(&shard.filters).unwrap_or_else(|e| {
                panic!("seed=0x{seed:016x} step={step}: shard[{shard_idx}] JSON error: {e}")
            });
            validate_filters(&shard_val).unwrap_or_else(|e| {
                panic!(
                    "seed=0x{seed:016x} step={step}: shard[{shard_idx}] failed validate_filters: {e}\nshard={shard:?}"
                )
            });
            compile_filters(shard.filters.clone()).unwrap_or_else(|e| {
                panic!(
                    "seed=0x{seed:016x} step={step}: shard[{shard_idx}] failed compile_filters: {e}"
                )
            });
            let wire_len = serde_json::to_string(&shard.filters).unwrap().len();
            assert!(
                wire_len <= MAX_FILTERS_BYTES,
                "seed=0x{seed:016x} step={step}: shard[{shard_idx}] wire_len {wire_len} > {MAX_FILTERS_BYTES}"
            );
            for f in &shard.filters {
                let d = filter_depth(f);
                assert!(
                    d <= MAX_FILTER_DEPTH,
                    "seed=0x{seed:016x} step={step}: shard[{shard_idx}] filter_depth {d} > {MAX_FILTER_DEPTH}"
                );
            }
            assert_eq!(
                shard.coalesce_seconds,
                expected_min_coalesce.unwrap(),
                "seed=0x{seed:016x} step={step}: shard[{shard_idx}] coalesce mismatch"
            );
        }

        // 3. SUPERSET INVARIANT (Zero False Negatives) across every CloudEvent in the 30-event corpus!
        for (ev_idx, ev) in corpus.iter().enumerate() {
            let local_matched = local_subs
                .iter()
                .find(|sub| matches_filters(&sub.filters, ev));
            if let Some(matching_sub) = local_matched {
                matched_pairs += 1;
                let upstream_matched = plan
                    .shards
                    .iter()
                    .any(|shard| matches_filters(&shard.filters, ev));
                assert!(
                    upstream_matched,
                    "seed=0x{seed:016x} step={step}: FALSE NEGATIVE on corpus[{ev_idx}] (id={})\nfailing_local_filters={:?}\ncompiled_plan={:?}",
                    ev.id, matching_sub.filters, plan
                );
            } else {
                unmatched_pairs += 1;
            }
        }

        // 4. Determinism: permuting input subscription order MUST yield the identical PushdownPlan!
        if step % 10 == 0 && local_subs.len() > 1 {
            let mut shuffled = local_subs.clone();
            shuffled.shuffle(&mut rng);
            let plan2 = compile_upstream_pushdown(&topic, &shuffled);
            assert_eq!(
                plan, plan2,
                "seed=0x{seed:016x} step={step}: compile_upstream_pushdown is not order-invariant"
            );
        }
    }

    assert!(
        saw_multi_shard,
        "seed=0x{seed:016x}: fuzzer never exercised multi-shard splitting"
    );
    assert!(
        saw_coarsened,
        "seed=0x{seed:016x}: fuzzer never exercised coarsening"
    );
    assert!(
        saw_match_all_fallback,
        "seed=0x{seed:016x}: fuzzer never exercised final match-all fallback"
    );
    assert!(
        saw_depth_8,
        "seed=0x{seed:016x}: fuzzer never generated max-depth (8) ASTs"
    );
    assert!(
        matched_pairs > 500 && unmatched_pairs > 500,
        "seed=0x{seed:016x}: fuzzer corpus lacked selectivity (matched={matched_pairs}, unmatched={unmatched_pairs})"
    );
}

// =========================================================================
// 2. Dotted NodeId Longest-Prefix Resolution Fuzzer
// =========================================================================

fn reference_longest_prefix_resolve(
    input: &str,
    known_peers: &[NodeId],
    default_node: &NodeScope,
) -> Option<QualifiedTopic> {
    if let Some(rest) = input.strip_prefix("local.") {
        return Topic::new(rest).ok().map(|topic| QualifiedTopic {
            node: NodeScope::Local,
            topic,
        });
    }
    let mut matches: Vec<(&NodeId, Topic)> = known_peers
        .iter()
        .filter(|p| !p.is_local())
        .filter_map(|p| {
            let prefix = format!("{}.", p.as_str());
            let rest = input.strip_prefix(&prefix)?;
            let topic = Topic::new(rest).ok()?;
            Some((p, topic))
        })
        .collect();
    matches.sort_by(|a, b| b.0.as_str().len().cmp(&a.0.as_str().len()));
    if let Some((peer, topic)) = matches.first() {
        return Some(QualifiedTopic {
            node: NodeScope::Remote((*peer).clone()),
            topic: topic.clone(),
        });
    }
    Topic::new(input).ok().map(|topic| QualifiedTopic {
        node: default_node.clone(),
        topic,
    })
}

fn random_segment(rng: &mut StdRng) -> String {
    const SEGMENTS: &[&str] = &[
        "a", "b", "c", "org", "eu", "us", "prod", "staging", "public", "hyphae", "to", "acme",
        "team", "hub", "edge", "github", "prs", "ci", "builds", "alerts", "kv", "v2",
    ];
    if rng.gen_bool(0.75) {
        SEGMENTS[rng.gen_range(0..SEGMENTS.len())].to_string()
    } else {
        format!("n{}", rng.gen_range(0..99))
    }
}

#[test]
fn fuzz_dotted_node_id_longest_prefix_resolution() {
    let seed = resolve_seed(0xD1FF_F022_0002);
    let mut rng = StdRng::seed_from_u64(seed);

    let canonical_peers = [
        "a.b",
        "a.b.c",
        "public",
        "public.hyphae.to",
        "org.eu",
        "org.eu.prod",
        "alice.smith@macbook",
        "acme-team",
    ];
    let canonical_topics = [
        "github",
        "github.prs",
        "ci.builds",
        "k8s.prod.alerts",
        "b.github",
        "c.github.prs",
    ];

    for step in 0..520usize {
        // Build a peer table with deliberate overlapping dotted prefixes + random chains.
        let mut peers: Vec<NodeId> = canonical_peers
            .iter()
            .filter(|_| rng.gen_bool(0.7))
            .map(|s| NodeId::new(*s).unwrap())
            .collect();

        // Add a fresh random nested chain: s0, s0.s1, s0.s1.s2
        let s0 = random_segment(&mut rng);
        let s1 = random_segment(&mut rng);
        let s2 = random_segment(&mut rng);
        if s0 != LOCAL_NODE_ID {
            let p1 = NodeId::new(s0.clone()).unwrap();
            let p2 = NodeId::new(format!("{s0}.{s1}")).unwrap();
            let p3 = NodeId::new(format!("{s0}.{s1}.{s2}")).unwrap();
            peers.push(p1);
            if rng.gen_bool(0.85) {
                peers.push(p2);
            }
            if rng.gen_bool(0.85) {
                peers.push(p3);
            }
        }
        if peers.is_empty() {
            peers.push(NodeId::new("public.hyphae.to").unwrap());
        }

        let default_node = if rng.gen_bool(0.5) {
            NodeScope::Local
        } else {
            NodeScope::Remote(peers[rng.gen_range(0..peers.len())].clone())
        };

        // Pick a topic (canonical or random dotted topic).
        let topic_str = if rng.gen_bool(0.5) {
            canonical_topics[rng.gen_range(0..canonical_topics.len())].to_string()
        } else {
            let parts = rng.gen_range(1..=3);
            (0..parts)
                .map(|_| random_segment(&mut rng))
                .collect::<Vec<_>>()
                .join(".")
        };
        let topic = Topic::new(&topic_str).unwrap();

        // (a) Qualified remote topic: `<peer>.<topic>` must match independent longest-prefix oracle,
        //     remain invariant under peer list permutations, and round-trip deterministically.
        let target_peer = peers[rng.gen_range(0..peers.len())].clone();
        let qualified_input = format!("{target_peer}.{topic}");

        let resolved = resolve_topic(&qualified_input, &peers, &default_node).unwrap_or_else(|e| {
            panic!("seed=0x{seed:016x} step={step}: failed to resolve {qualified_input:?}: {e}")
        });
        let expected = reference_longest_prefix_resolve(&qualified_input, &peers, &default_node)
            .expect("oracle must resolve valid qualified topic");
        assert_eq!(
            resolved, expected,
            "seed=0x{seed:016x} step={step}: longest-prefix divergence for input={qualified_input:?} peers={peers:?}"
        );

        // Exact formatting round-trip & idempotence.
        let formatted = resolved.to_string();
        assert_eq!(
            formatted, qualified_input,
            "seed=0x{seed:016x} step={step}: formatted topic diverged from input"
        );
        let reparsed = resolve_topic(&formatted, &peers, &default_node).unwrap();
        assert_eq!(
            reparsed, resolved,
            "seed=0x{seed:016x} step={step}: resolve_topic(formatted) not idempotent"
        );

        // Order independence across random permutation of `known_peers`.
        let mut shuffled = peers.clone();
        shuffled.shuffle(&mut rng);
        let resolved_shuffled = resolve_topic(&qualified_input, &shuffled, &default_node).unwrap();
        assert_eq!(
            resolved_shuffled, resolved,
            "seed=0x{seed:016x} step={step}: resolve_topic depends on peer ordering for {qualified_input:?}"
        );

        // If `target_peer` has no longer peer prefixing `qualified_input`, it MUST resolve back to `target_peer` & `topic`.
        let shadowed_by_longer = peers.iter().any(|other| {
            !other.is_local()
                && other.as_str().len() > target_peer.as_str().len()
                && qualified_input
                    .strip_prefix(&format!("{}.", other.as_str()))
                    .is_some_and(|rest| Topic::new(rest).is_ok())
        });
        if !shadowed_by_longer {
            assert_eq!(
                resolved.node,
                NodeScope::Remote(target_peer.clone()),
                "seed=0x{seed:016x} step={step}: unshadowed peer did not round-trip"
            );
            assert_eq!(
                resolved.topic, topic,
                "seed=0x{seed:016x} step={step}: unshadowed topic did not round-trip"
            );
        }

        // (b) `local.<topic>` MUST ALWAYS resolve to `NodeScope::Local` with zero ambiguity —
        //     even when `default_node` is remote AND even if adversarial peers `local` / `local.<seg>` exist!
        let mut adversarial_peers = peers.clone();
        adversarial_peers.push(NodeId::new(LOCAL_NODE_ID).unwrap());
        adversarial_peers.push(NodeId::new(format!("local.{s1}")).unwrap());
        adversarial_peers.shuffle(&mut rng);

        let local_input = format!("local.{topic}");
        let remote_default = NodeScope::Remote(target_peer.clone());
        let local_resolved = resolve_topic(&local_input, &adversarial_peers, &remote_default)
            .unwrap_or_else(|e| {
                panic!("seed=0x{seed:016x} step={step}: local topic {local_input:?} failed: {e}")
            });
        assert_eq!(
            local_resolved.node,
            NodeScope::Local,
            "seed=0x{seed:016x} step={step}: local. prefix hijacked by peer for {local_input:?}"
        );
        assert_eq!(
            local_resolved.topic, topic,
            "seed=0x{seed:016x} step={step}: local. topic suffix corrupted"
        );
        assert_eq!(
            local_resolved.to_string(),
            local_input,
            "seed=0x{seed:016x} step={step}: local. round-trip mismatch"
        );
        assert!(
            validate_new_peer_alias(&NodeId::new(LOCAL_NODE_ID).unwrap(), &peers).is_err(),
            "seed=0x{seed:016x} step={step}: 'local' alias must always be rejected"
        );

        // (c) Explicit overlapping prefix invariant: `a.b` vs `a.b.c` -> `a.b.c.<topic>` ALWAYS picks `a.b.c`.
        let ab = NodeId::new("a.b").unwrap();
        let abc = NodeId::new("a.b.c").unwrap();
        let pair_peers = if step % 2 == 0 {
            vec![ab, abc.clone()]
        } else {
            vec![abc.clone(), ab]
        };
        let overlap_input = format!("a.b.c.{topic}");
        let overlap_res = resolve_topic(&overlap_input, &pair_peers, &NodeScope::Local).unwrap();
        assert_eq!(
            overlap_res.node,
            NodeScope::Remote(abc),
            "seed=0x{seed:016x} step={step}: a.b shadowed longer peer a.b.c for {overlap_input:?}"
        );
        assert_eq!(overlap_res.topic, topic);
    }
}

// =========================================================================
// 3. v1/v2 Scopes Privilege Non-Escalation Fuzzer
// =========================================================================

const NON_RESTRICTED_SCOPE_TOKENS: &[&str] = &[
    "*",
    "dm:*",
    "messages:*",
    "channel:*",
    "stream:*",
    "events:*",
    "files:*",
    "kv:*",
    "forks:*",
    "messages:send",
    "messages:receive",
    "events:subscribe",
    "events:publish",
    "dm:send",
    "dm:send=*",
    "dm:send=alice@mac/claude,bob@lap/*",
    "dm:receive",
    "channel:join=*",
    "channel:join=#lobby,#ops",
    "channel:post=*",
    "channel:post=#ops",
    "stream:subscribe=*",
    "stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]",
    "stream:subscribe=github[repo=acme/checkout,acme/web]",
    "stream:publish=*",
    "stream:publish=ci",
    "files:send",
    "files:send=50mb",
    "files:send=alice@mac:25mb",
    "files:receive",
    "files:receive=50mb",
    "kv:read=*",
    "kv:read=shared/*",
    "kv:write=*",
    "kv:write=shared/plan*",
    "forks:send",
    "forks:send=alice@mac",
    "forks:receive/approval-required",
    "forks:receive/auto-accept-edits",
    "forks:receive/auto",
    "forks:receive/full-access",
];

const MALFORMED_ESCALATION_ATTEMPTS: &[&str] = &[
    "bridge:*",
    "bridge:post",
    "bridge:post=*",
    "bridge:post=slack:",
    "bridge:post=:ops",
    "bridge:post=BAD:ops",
    "forward:*",
    "forward:via",
    "forward:via=",
    "forward:via=*.*",
    "forward:via=-bad",
    "admin:*",
    "**",
    "*:*",
    "superuser",
];

const V1_SCOPE_TOKENS: &[&str] = &[
    "*",
    "messages:*",
    "events:*",
    "files:*",
    "forks:*",
    "messages:send",
    "messages:receive",
    "events:subscribe",
    "files:send",
    "files:receive",
    "forks:send",
    "forks:receive/approval-required",
    "forks:receive/full-access",
];

#[test]
fn fuzz_v1_v2_scopes_never_escalate_restricted_privileges() {
    let seed = resolve_seed(0xD1FF_F022_0003);
    let mut rng = StdRng::seed_from_u64(seed);

    let all_presets = [
        ScopePreset::GuestRo,
        ScopePreset::Guest,
        ScopePreset::Observer,
        ScopePreset::Member,
        ScopePreset::Full,
    ];
    let probe_plugins = [
        "slack",
        "telegram",
        "whatsapp",
        "webhook",
        "prometheus",
        "*",
    ];
    let probe_targets = ["ops", "general", "C01234", "alerts", "*"];
    let probe_nodes = [
        "acme-team",
        "public.hyphae.to",
        "bob@laptop",
        "org.eu.prod",
        "local",
        "*",
    ];
    let probe_channels = ["#lobby", "#ops", "#incidents", "#deploys"];
    let probe_namespaces = ["shared", "private", "deploys", "kv"];
    let probe_keys = ["plan", "plan/v1", "secret", "state/x"];

    let guest_ro = ScopeSet::from_preset(ScopePreset::GuestRo);
    let observer = ScopeSet::from_preset(ScopePreset::Observer);
    let guest = ScopeSet::from_preset(ScopePreset::Guest);

    for step in 0..540usize {
        // 1. Build a random combination of presets + valid non-restricted tokens (+ occasional bogus attempts).
        let mut valid_tokens: Vec<String> = Vec::new();
        let preset_count = rng.gen_range(1..=4);
        for _ in 0..preset_count {
            let preset = all_presets[rng.gen_range(0..all_presets.len())];
            valid_tokens.extend(preset.expand());
        }
        let extra_count = rng.gen_range(1..=8);
        for _ in 0..extra_count {
            let tok =
                NON_RESTRICTED_SCOPE_TOKENS[rng.gen_range(0..NON_RESTRICTED_SCOPE_TOKENS.len())];
            valid_tokens.push(tok.to_string());
        }

        let expanded_v2 = expand_v2_scopes(&valid_tokens).unwrap_or_else(|e| {
            panic!("seed=0x{seed:016x} step={step}: expand_v2_scopes failed on valid tokens: {e}")
        });
        assert!(
            !expanded_v2
                .iter()
                .any(|s| s.starts_with("bridge:post") || s.starts_with("forward:via")),
            "seed=0x{seed:016x} step={step}: expand_v2_scopes leaked restricted scope in {expanded_v2:?}"
        );

        let mut combined_with_bogus = expanded_v2.clone();
        for _ in 0..rng.gen_range(0..=3) {
            let bad = MALFORMED_ESCALATION_ATTEMPTS
                [rng.gen_range(0..MALFORMED_ESCALATION_ATTEMPTS.len())];
            combined_with_bogus.push(bad.to_string());
        }
        combined_with_bogus.shuffle(&mut rng);

        let set_direct = ScopeSet::from_strings(&valid_tokens);
        let set_expanded = ScopeSet::from_strings(&combined_with_bogus);
        let set_rfc = ScopeSet::from_rfc6749(&combined_with_bogus.join(" "));

        // Also test v1 scope expansion sets.
        let v1_pick: Vec<&str> = (0..rng.gen_range(1..=3))
            .map(|_| V1_SCOPE_TOKENS[rng.gen_range(0..V1_SCOPE_TOKENS.len())])
            .collect();
        let set_v1 = match expand_v1_scopes(&v1_pick) {
            Ok(exp) => ScopeSet::from_strings(&exp),
            Err(_) => ScopeSet::from_strings(&v1_pick),
        };

        for (label, set) in [
            ("direct", &set_direct),
            ("expanded+bogus", &set_expanded),
            ("rfc6749", &set_rfc),
            ("v1", &set_v1),
        ] {
            for &plugin in &probe_plugins {
                for &target in &probe_targets {
                    assert!(
                        !set.may_bridge_post(plugin, target),
                        "seed=0x{seed:016x} step={step}: {label} ScopeSet escalated to bridge:post({plugin}:{target})! raw={:?}",
                        set.raw_scopes()
                    );
                }
            }
            for &node in &probe_nodes {
                assert!(
                    !set.may_forward_via(node),
                    "seed=0x{seed:016x} step={step}: {label} ScopeSet escalated to forward:via({node})! raw={:?}",
                    set.raw_scopes()
                );
            }
        }

        // 2. `guest-ro` strict confinement across randomized probes.
        let target = format!(
            "{}/{}",
            probe_nodes[rng.gen_range(0..probe_nodes.len())],
            if rng.gen_bool(0.5) { "claude" } else { "codex" }
        );
        let ch = probe_channels[rng.gen_range(0..probe_channels.len())];
        let ns = probe_namespaces[rng.gen_range(0..probe_namespaces.len())];
        let key = probe_keys[rng.gen_range(0..probe_keys.len())];
        let node = probe_nodes[rng.gen_range(0..probe_nodes.len())];
        let plugin = probe_plugins[rng.gen_range(0..probe_plugins.len())];
        let b_target = probe_targets[rng.gen_range(0..probe_targets.len())];
        let size = rng.gen_range(1u64..=10_000_000);

        assert!(
            !guest_ro.may_dm_send_any()
                && !guest_ro.may_dm_send(&target)
                && !guest_ro.may_dm_receive(),
            "seed=0x{seed:016x} step={step}: guest-ro granted DM privilege for {target}"
        );
        assert!(
            !guest_ro.may_channel_join(ch) && !guest_ro.may_channel_post(ch),
            "seed=0x{seed:016x} step={step}: guest-ro granted channel privilege for {ch}"
        );
        assert!(
            !guest_ro.may_send_files(node, Some(size))
                && !guest_ro.may_send_files(node, None)
                && !guest_ro.may_receive_files(size),
            "seed=0x{seed:016x} step={step}: guest-ro granted file transfer privilege"
        );
        assert!(
            !guest_ro.may_kv_read(ns, key) && !guest_ro.may_kv_write(ns, key),
            "seed=0x{seed:016x} step={step}: guest-ro granted KV privilege for {ns}/{key}"
        );
        assert!(
            !guest_ro.may_stream_publish("github") && !guest_ro.may_stream_publish("ci"),
            "seed=0x{seed:016x} step={step}: guest-ro granted stream:publish"
        );
        assert!(
            !guest_ro.may_bridge_post(plugin, b_target) && !guest_ro.may_forward_via(node),
            "seed=0x{seed:016x} step={step}: guest-ro granted bridge/forward privilege"
        );
        assert!(
            !guest_ro.may_fork_out()
                && !guest_ro.may_send_forks(node)
                && guest_ro.fork_ceiling().is_none(),
            "seed=0x{seed:016x} step={step}: guest-ro granted fork privilege"
        );

        // `guest-ro` stream confinement: reject non-github topics, unconstrained, prefix, negated, and >10 repos.
        assert!(
            guest_ro
                .check_stream_subscribe("ci", &[exact_f("repo", "acme/app")])
                .is_err(),
            "seed=0x{seed:016x} step={step}: guest-ro allowed non-github topic"
        );
        assert!(
            guest_ro.check_stream_subscribe("github", &[]).is_err(),
            "seed=0x{seed:016x} step={step}: guest-ro allowed empty filter"
        );
        assert!(
            guest_ro
                .check_stream_subscribe("github", &[prefix_f("repo", "acme/")])
                .is_err(),
            "seed=0x{seed:016x} step={step}: guest-ro allowed prefix.repo"
        );
        assert!(
            guest_ro
                .check_stream_subscribe(
                    "github",
                    &[Filter::Not(Box::new(exact_f("repo", "acme/app")))]
                )
                .is_err(),
            "seed=0x{seed:016x} step={step}: guest-ro allowed negated repo filter"
        );
        let n_repos = rng.gen_range(1usize..=15);
        let repo_branches: Vec<Filter> = (0..n_repos)
            .map(|i| exact_f("repo", &format!("org-{step}/repo-{i}")))
            .collect();
        let sub_res = guest_ro.check_stream_subscribe("github", &[Filter::Any(repo_branches)]);
        if n_repos <= 10 {
            assert!(
                sub_res.is_ok(),
                "seed=0x{seed:016x} step={step}: guest-ro rejected valid {n_repos}-repo exact filter"
            );
        } else {
            assert!(
                sub_res.is_err(),
                "seed=0x{seed:016x} step={step}: guest-ro accepted {n_repos} > maxValues(10) repos"
            );
        }

        // 3. `observer` is strictly read-only and `guest` is strictly confined to `#lobby` + DM.
        assert!(
            !observer.may_dm_send(&target)
                && !observer.may_channel_post(ch)
                && !observer.may_kv_write(ns, key)
                && !observer.may_send_files(node, Some(size))
                && !observer.may_stream_publish("github")
                && !observer.may_bridge_post(plugin, b_target)
                && !observer.may_forward_via(node),
            "seed=0x{seed:016x} step={step}: observer granted write/restricted privilege"
        );
        if ch != "#lobby" {
            assert!(
                !guest.may_channel_join(ch) && !guest.may_channel_post(ch),
                "seed=0x{seed:016x} step={step}: guest escaped #lobby to {ch}"
            );
        }
        assert!(
            !guest.may_kv_read(ns, key)
                && !guest.may_kv_write(ns, key)
                && !guest.may_send_files(node, Some(size))
                && !guest.may_bridge_post(plugin, b_target)
                && !guest.may_forward_via(node),
            "seed=0x{seed:016x} step={step}: guest granted file/kv/bridge/forward privilege"
        );
    }
}
