//! Pure-Rust frozen golden interoperability suite for `hyp-proto` (ZERO Node.js runtime!).
//!
//! Embeds 877 deterministic vectors captured from the real TypeScript v1 reference
//! implementation (`src/core/address.ts`, `src/core/router/cloudevent.ts`,
//! `src/core/router/filter.ts`, `src/core/identity/scopes.ts`, `src/protocol.ts`,
//! plus V8's ECMA-262 RFC 8785 serializer) in `fixtures/v1_interop_vectors.json`
//! and asserts 100% parity using ONLY pure Rust.

use hyp_proto::address::{Address, Channel, is_valid_handle, is_valid_node_id, is_valid_topic};
use hyp_proto::cloudevent::{check_cloudevent_v1, event_digest_value};
use hyp_proto::filter::{matches_filters, validate_filters};
use hyp_proto::jcs::{format_ecma_number, to_jcs_string};
use hyp_proto::scopes::{RuntimeMode, ScopeSet, expand_v1_scopes};
use serde::Deserialize;
use serde_json::{Value, json};

const VECTORS_JSON: &str = include_str!("fixtures/v1_interop_vectors.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtoFixture {
    schema_version: u32,
    address: AddressSection,
    cloudevents: Vec<CloudEventCase>,
    filters: FilterSection,
    scopes: ScopeSection,
    jcs: JcsSection,
}

#[derive(Debug, Deserialize)]
struct AddressSection {
    ids: Vec<IdCase>,
    addresses: Vec<AddressCase>,
    channels: Vec<ChannelCase>,
}

#[derive(Debug, Deserialize)]
struct IdCase {
    input: String,
    node: bool,
    handle: bool,
    topic: bool,
}

#[derive(Debug, Deserialize)]
struct AddressCase {
    input: String,
    parsed: Option<[String; 2]>,
}

#[derive(Debug, Deserialize)]
struct ChannelCase {
    input: String,
    normalized: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudEventCase {
    input: Value,
    ok: bool,
    digest: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FilterSection {
    eval_events: Vec<Value>,
    cases: Vec<FilterCase>,
}

#[derive(Debug, Deserialize)]
struct FilterCase {
    input: Value,
    ok: bool,
    matches: Option<Vec<bool>>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSection {
    expand_cases: Vec<ScopeExpandCase>,
    set_cases: Vec<ScopeSetCase>,
}

#[derive(Debug, Deserialize)]
struct ScopeExpandCase {
    input: Vec<String>,
    ok: bool,
    scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSetCase {
    input: Vec<String>,
    ms: bool,
    mr: bool,
    es: bool,
    fr: bool,
    files_alice: bool,
    files_other: bool,
    forks_carol: bool,
    forks_other: bool,
    fork_out: bool,
    ceiling: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JcsSection {
    numbers: Vec<JcsNumberCase>,
    objects: Vec<JcsObjectCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JcsNumberCase {
    bits_hex: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct JcsObjectCase {
    input: Value,
    expected: String,
}

fn load_fixture() -> ProtoFixture {
    let fixture: ProtoFixture =
        serde_json::from_str(VECTORS_JSON).expect("parse v1_interop_vectors.json");
    assert_eq!(fixture.schema_version, 1);
    fixture
}

#[test]
fn golden_v1_address_handle_topic_and_channel_parity() {
    let fixture = load_fixture();
    assert!(
        fixture.address.ids.len() >= 90,
        "expected >= 90 id vectors, got {}",
        fixture.address.ids.len()
    );
    assert!(
        fixture.address.addresses.len() >= 70,
        "expected >= 70 address vectors, got {}",
        fixture.address.addresses.len()
    );
    assert!(
        fixture.address.channels.len() >= 50,
        "expected >= 50 channel vectors, got {}",
        fixture.address.channels.len()
    );

    for (idx, c) in fixture.address.ids.iter().enumerate() {
        assert_eq!(
            is_valid_node_id(&c.input),
            c.node,
            "is_valid_node_id mismatch on vector {idx}: {:?}",
            c.input
        );
        assert_eq!(
            is_valid_handle(&c.input),
            c.handle,
            "is_valid_handle mismatch on vector {idx}: {:?}",
            c.input
        );
        assert_eq!(
            is_valid_topic(&c.input),
            c.topic,
            "is_valid_topic mismatch on vector {idx}: {:?}",
            c.input
        );
    }

    for (idx, c) in fixture.address.addresses.iter().enumerate() {
        let rust_val = Address::parse(&c.input)
            .ok()
            .map(|a| [a.node_id.into_inner(), a.handle.into_inner()]);
        assert_eq!(
            rust_val, c.parsed,
            "Address::parse mismatch on vector {idx}: {:?}",
            c.input
        );
    }

    for (idx, c) in fixture.address.channels.iter().enumerate() {
        let rust_val = Channel::normalize(&c.input).ok().map(Channel::into_inner);
        assert_eq!(
            rust_val, c.normalized,
            "Channel::normalize mismatch on vector {idx}: {:?}",
            c.input
        );
    }
}

#[test]
fn golden_v1_cloudevent_validation_boundaries_and_digest_parity() {
    let fixture = load_fixture();
    assert!(
        fixture.cloudevents.len() >= 130,
        "expected >= 130 cloudevent vectors, got {}",
        fixture.cloudevents.len()
    );

    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;

    for (idx, c) in fixture.cloudevents.iter().enumerate() {
        match (check_cloudevent_v1(&c.input), c.ok) {
            (Ok((parsed, _)), true) => {
                valid_count += 1;
                let expected_digest = c.digest.as_deref().expect("valid case must have digest");
                assert_eq!(
                    parsed.digest(),
                    expected_digest,
                    "CloudEvent::digest mismatch on vector {idx}: {}",
                    c.input
                );
                assert_eq!(
                    event_digest_value(&c.input).expect("event_digest_value"),
                    expected_digest,
                    "event_digest_value mismatch on vector {idx}"
                );
            }
            (Err(err), false) => {
                invalid_count += 1;
                let expected_err = c.error.as_deref().expect("invalid case must have error");
                assert_eq!(
                    err.code(),
                    expected_err,
                    "CloudEvent error code mismatch on vector {idx}: rust={err:?}, expected={expected_err}, input={}",
                    c.input
                );
            }
            (rust_res, expected_ok) => {
                panic!(
                    "check_cloudevent_v1 accept/reject divergence on vector {idx}: rust={rust_res:?}, expected_ok={expected_ok}, input={}",
                    c.input
                );
            }
        }
    }

    assert!(valid_count >= 40, "expected >= 40 valid CloudEvent vectors");
    assert!(
        invalid_count >= 50,
        "expected >= 50 invalid CloudEvent vectors"
    );

    // Confirm canonical key-order invariance on the paired digest-order-1 vectors.
    let order_digests: Vec<&str> = fixture
        .cloudevents
        .iter()
        .filter(|c| c.input.get("id") == Some(&json!("digest-order-1")))
        .map(|c| c.digest.as_deref().expect("digest"))
        .collect();
    assert_eq!(order_digests.len(), 2);
    assert_eq!(order_digests[0], order_digests[1]);
}

#[test]
fn golden_v1_subscriptions_api_filter_validation_and_matching_parity() {
    let fixture = load_fixture();
    assert!(
        fixture.filters.cases.len() >= 220,
        "expected >= 220 filter vectors, got {}",
        fixture.filters.cases.len()
    );
    assert_eq!(fixture.filters.eval_events.len(), 4);

    let parsed_events: Vec<_> = fixture
        .filters
        .eval_events
        .iter()
        .map(|ev| check_cloudevent_v1(ev).expect("valid eval event").0)
        .collect();

    for (idx, c) in fixture.filters.cases.iter().enumerate() {
        match (validate_filters(&c.input), c.ok) {
            (Ok(filters), true) => {
                let expected_matches = c
                    .matches
                    .as_ref()
                    .expect("valid filter vector must have matches");
                let rust_matches: Vec<bool> = parsed_events
                    .iter()
                    .map(|ev| matches_filters(&filters, ev))
                    .collect();
                assert_eq!(
                    &rust_matches, expected_matches,
                    "matches_filters mismatch on vector {idx}: filter={}",
                    c.input
                );
            }
            (Err(err), false) => {
                let expected_path = c
                    .path
                    .as_deref()
                    .expect("invalid filter vector must have path");
                assert_eq!(
                    err.path, expected_path,
                    "filter error path mismatch on vector {idx}: rust={err:?}, expected_path={expected_path}, filter={}",
                    c.input
                );
            }
            (rust_res, expected_ok) => {
                panic!(
                    "validate_filters accept/reject divergence on vector {idx}: rust={rust_res:?}, expected_ok={expected_ok}, filter={}",
                    c.input
                );
            }
        }
    }
}

#[test]
fn golden_v1_scopes_expansion_and_scopeset_parity() {
    let fixture = load_fixture();
    assert!(
        fixture.scopes.expand_cases.len() >= 120,
        "expected >= 120 scope expand vectors, got {}",
        fixture.scopes.expand_cases.len()
    );
    assert!(
        fixture.scopes.set_cases.len() >= 10,
        "expected >= 10 ScopeSet vectors, got {}",
        fixture.scopes.set_cases.len()
    );

    for (idx, c) in fixture.scopes.expand_cases.iter().enumerate() {
        match (expand_v1_scopes(&c.input), c.ok) {
            (Ok(rust_out), true) => {
                let expected = c
                    .scopes
                    .as_ref()
                    .expect("valid expand vector must have scopes");
                assert_eq!(
                    &rust_out, expected,
                    "expand_v1_scopes mismatch on vector {idx}: input={:?}",
                    c.input
                );
            }
            (Err(_), false) => {}
            (rust_res, expected_ok) => {
                panic!(
                    "expand_v1_scopes accept/reject divergence on vector {idx}: input={:?}, rust={rust_res:?}, expected_ok={expected_ok}",
                    c.input
                );
            }
        }
    }

    for (idx, c) in fixture.scopes.set_cases.iter().enumerate() {
        let s = ScopeSet::from_strings(&c.input);
        assert_eq!(s.has_v1("messages:send"), c.ms, "set vector {idx} ms");
        assert_eq!(s.has_v1("messages:receive"), c.mr, "set vector {idx} mr");
        assert_eq!(s.has_v1("events:subscribe"), c.es, "set vector {idx} es");
        assert_eq!(s.has_v1("files:receive"), c.fr, "set vector {idx} fr");
        assert_eq!(
            s.may_send_files("alice@laptop", None),
            c.files_alice,
            "set vector {idx} filesAlice"
        );
        assert_eq!(
            s.may_send_files("other@host", None),
            c.files_other,
            "set vector {idx} filesOther"
        );
        assert_eq!(
            s.may_send_forks("carol@box"),
            c.forks_carol,
            "set vector {idx} forksCarol"
        );
        assert_eq!(
            s.may_send_forks("other@host"),
            c.forks_other,
            "set vector {idx} forksOther"
        );
        assert_eq!(s.may_fork_out(), c.fork_out, "set vector {idx} forkOut");
        let rust_ceiling = s
            .fork_ceiling()
            .map(|m: RuntimeMode| m.as_str().to_string());
        assert_eq!(rust_ceiling, c.ceiling, "set vector {idx} ceiling");
    }
}

#[test]
fn golden_rfc8785_jcs_ecma262_numbers_and_utf16_object_sorting() {
    let fixture = load_fixture();
    assert!(
        fixture.jcs.numbers.len() >= 130,
        "expected >= 130 JCS number vectors, got {}",
        fixture.jcs.numbers.len()
    );
    assert!(
        fixture.jcs.objects.len() >= 4,
        "expected >= 4 JCS object vectors, got {}",
        fixture.jcs.objects.len()
    );

    for (idx, c) in fixture.jcs.numbers.iter().enumerate() {
        let bits = u64::from_str_radix(&c.bits_hex, 16).expect("valid 64-bit hex");
        let f = f64::from_bits(bits);
        let rust_str = format_ecma_number(f).expect("finite f64 must format");
        assert_eq!(
            rust_str, c.expected,
            "RFC 8785 number mismatch on vector {idx} (bits={})",
            c.bits_hex
        );
    }

    for (idx, c) in fixture.jcs.objects.iter().enumerate() {
        let rust_str = to_jcs_string(&c.input).expect("JCS canonicalize");
        assert_eq!(
            rust_str, c.expected,
            "RFC 8785 canonical JSON mismatch on object vector {idx}"
        );
    }
}
