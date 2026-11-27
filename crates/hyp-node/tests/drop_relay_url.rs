use hyp_node::engine::drop_client::validate_relay_url;

#[test]
fn relay_url_policy_is_strict_and_retains_accepted_spelling() {
    for (input, expected) in [
        (
            " https://Relay.invalid/base/// ",
            "https://Relay.invalid/base",
        ),
        ("http://127.0.0.1:4567/", "http://127.0.0.1:4567"),
        ("http://LOCALHOST/prefix//", "http://LOCALHOST/prefix"),
        ("https://[::1]/", "https://[::1]"),
    ] {
        assert_eq!(validate_relay_url(input).unwrap(), expected);
    }
    for input in [
        "http://[::1]/",
        "http://127.0.0.2/",
        "http://relay.invalid/",
        "ssh://localhost/",
        "https://user:pass@relay.invalid/",
        "https://relay.invalid/?x=1",
        "https://relay.invalid/#fragment",
        "https://relay.invalid/a\u{7f}",
    ] {
        assert!(
            validate_relay_url(input).is_err(),
            "relay URL must be rejected"
        );
    }
}

#[test]
fn relay_url_diagnostics_keep_each_callers_rejection_precedence() {
    let error = validate_relay_url("/relative").unwrap_err();
    assert_eq!(
        error.detailed,
        "Drop Relay URL '/relative' must include https:// scheme"
    );
    assert_eq!(error.compact, "Drop Relay URL is missing a valid host");

    let error = validate_relay_url("https://user:pass@relay.invalid/").unwrap_err();
    assert_eq!(
        error.detailed,
        "Drop Relay URL must not include embedded credentials"
    );
    assert_eq!(
        error.compact,
        "Drop Relay URL must not contain userinfo credentials"
    );

    let error = validate_relay_url("https://relay.invalid/?x=1").unwrap_err();
    assert_eq!(
        error.detailed,
        "Drop Relay URL must not contain query parameters or fragments"
    );
    assert_eq!(
        error.compact,
        "Drop Relay URL must use https:// (or loopback http://127.0.0.1 / http://localhost)"
    );
}
