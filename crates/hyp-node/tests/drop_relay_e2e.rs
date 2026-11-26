//! Comprehensive E2E, security tamper, anti-DoS, concurrency, and differential oracle tests
//! for the RAM-only Blind Drop Relay (`hyp_node::engine::drop_relay`).

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderMap, StatusCode};
use hyp_node::engine::drop_relay::{
    CREATE_RATE_WINDOW_MS, CreateDropRequest, DROP_CAP_PREFIX, DROP_ID_LEN, DropCapRole, DropRelay,
    DropRelayConfig, DropRelayError, DropSubscriberAuth, HARD_MAX_TTL_SECONDS,
    KEY_ROTATION_INTERVAL_MS,
};

const BASE_TS_MS: i64 = 1_764_000_000_000; // aligned base epoch ms

fn enabled_config() -> DropRelayConfig {
    DropRelayConfig {
        enabled: true,
        ..Default::default()
    }
}

#[test]
fn config_defaults_and_camel_case_serde_roundtrip() {
    let cfg = DropRelayConfig::default();
    assert!(!cfg.enabled);
    assert!(!cfg.local_drops_only);
    assert_eq!(cfg.max_memory_mb, 256);
    assert_eq!(cfg.max_memory_bytes(), 256 * 1024 * 1024);
    assert_eq!(cfg.default_ttl_seconds, 600);
    assert_eq!(cfg.max_ttl_seconds, 900);
    assert_eq!(cfg.max_items_per_drop, 16);
    assert_eq!(cfg.max_payload_bytes, 65_536);
    assert_eq!(cfg.max_active_drops, 4_096);
    assert_eq!(cfg.max_active_drops_per_node, 3);
    assert_eq!(cfg.creates_per_hour_per_node, 10);
    assert_eq!(cfg.creates_per_hour_per_ip, 20);
    assert_eq!(cfg.max_sse_streams, 4_096);
    assert_eq!(cfg.max_sse_streams_per_drop, 2);
    assert_eq!(cfg.max_sse_streams_per_ip, 16);
    assert_eq!(cfg.allowed_origins, vec!["https://hyphae.to".to_string()]);
    assert!(cfg.allow_private_network);

    let json = serde_json::to_value(&cfg).expect("serialize DropRelayConfig");
    assert_eq!(json["enabled"], false);
    assert_eq!(json["localDropsOnly"], false);
    assert_eq!(json["maxMemoryMb"], 256);
    assert_eq!(json["defaultTtlSeconds"], 600);
    assert_eq!(json["maxTtlSeconds"], 900);
    assert_eq!(json["maxItemsPerDrop"], 16);
    assert_eq!(json["maxPayloadBytes"], 65_536);
    assert_eq!(json["maxActiveDrops"], 4_096);
    assert_eq!(json["maxActiveDropsPerNode"], 3);
    assert_eq!(json["createsPerHourPerNode"], 10);
    assert_eq!(json["createsPerHourPerIp"], 20);
    assert_eq!(json["maxSseStreams"], 4_096);
    assert_eq!(json["maxSseStreamsPerDrop"], 2);
    assert_eq!(json["maxSseStreamsPerIp"], 16);
    assert_eq!(
        json["allowedOrigins"],
        serde_json::json!(["https://hyphae.to"])
    );
    assert_eq!(json["allowPrivateNetwork"], true);

    let roundtrip: DropRelayConfig =
        serde_json::from_value(json).expect("deserialize DropRelayConfig");
    assert_eq!(roundtrip, cfg);

    // Partial JSON fills defaults cleanly.
    let partial: DropRelayConfig =
        serde_json::from_str(r#"{"enabled": true, "maxMemoryMb": 64}"#).expect("partial json");
    assert!(partial.enabled);
    assert_eq!(partial.max_memory_mb, 64);
    assert_eq!(partial.default_ttl_seconds, 600);
    assert_eq!(
        partial.allowed_origins,
        vec!["https://hyphae.to".to_string()]
    );
}

#[test]
fn disabled_relay_fails_closed_with_404() {
    let relay = DropRelay::new(DropRelayConfig::default());
    assert!(!relay.is_enabled());

    let err = relay
        .create_drop(
            "ops@prod",
            "203.0.113.1",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .unwrap_err();
    assert_eq!(err, DropRelayError::Disabled);
    assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(err.to_problem_details().error, "drop_relay_disabled");

    let fake_id = "aaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        relay.verify_capability(fake_id, "hdcap1_invalid", DropCapRole::Post, BASE_TS_MS),
        Err(DropRelayError::Disabled)
    );
    assert_eq!(
        relay.post_drop(fake_id, "hdcap1_invalid", b"ct".to_vec(), BASE_TS_MS),
        Err(DropRelayError::Disabled)
    );
    assert_eq!(
        relay
            .subscribe_drop(
                fake_id,
                DropSubscriberAuth::CreatorNode("ops@prod"),
                "203.0.113.1",
                None,
                BASE_TS_MS
            )
            .unwrap_err(),
        DropRelayError::Disabled
    );
    assert_eq!(
        relay.ack_drop(
            fake_id,
            DropSubscriberAuth::CreatorNode("ops@prod"),
            1,
            true,
            BASE_TS_MS
        ),
        Err(DropRelayError::Disabled)
    );
}

#[tokio::test]
async fn happy_path_live_sse_and_burn_wipes_ram() {
    let relay = DropRelay::new(enabled_config());
    let created = relay
        .create_drop(
            "prod@eu-1",
            "198.51.100.10",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("create_drop");

    assert_eq!(created.drop_id.len(), DROP_ID_LEN);
    assert!(created.post_cap.starts_with(DROP_CAP_PREFIX));
    assert!(created.sub_cap.starts_with(DROP_CAP_PREFIX));
    assert_ne!(created.post_cap, created.sub_cap);
    assert_eq!(created.expires_at_ms, BASE_TS_MS + 600_000);
    assert_eq!(created.max_payload_bytes, 65_536);
    assert_eq!(created.max_items, 16);

    // Debug output must redact drop_id and capability tokens.
    let debug_str = format!("{created:?}");
    assert!(!debug_str.contains(&created.drop_id));
    assert!(!debug_str.contains(&created.post_cap));
    assert!(!debug_str.contains(&created.sub_cap));

    let mut sub = relay
        .subscribe_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            "198.51.100.10",
            None,
            BASE_TS_MS + 50,
        )
        .expect("subscribe_drop");
    assert_eq!(sub.backlog_len(), 0);
    assert_eq!(relay.health(BASE_TS_MS + 50).active_sse_streams, 1);

    let ciphertext = br#"{"v":1,"suite":"human.drop.v1","ct":"opaque-sealed-bytes"}"#.to_vec();
    let expected_len = ciphertext.len();

    let relay_poster = relay.clone();
    let drop_id = created.drop_id.clone();
    let post_cap = created.post_cap.clone();
    let poster_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(15)).await;
        relay_poster.post_drop(&drop_id, &post_cap, ciphertext, BASE_TS_MS + 100)
    });

    let item = tokio::time::timeout(Duration::from_secs(2), sub.recv())
        .await
        .expect("live SSE item arrived in time")
        .expect("live SSE item present");

    let posted = poster_task
        .await
        .expect("poster task join")
        .expect("post_drop");
    assert_eq!(posted.seq, 1);
    assert_eq!(posted.expires_at_ms, created.expires_at_ms);

    assert_eq!(item.seq, 1);
    assert_eq!(
        item.payload_bytes(),
        br#"{"v":1,"suite":"human.drop.v1","ct":"opaque-sealed-bytes"}"#
    );
    let sse_wire = item.to_sse_event().encode();
    assert!(sse_wire.contains("id: 1\n"));
    assert!(sse_wire.contains("event: drop\n"));
    assert!(sse_wire.contains("opaque-sealed-bytes"));

    let health_before_burn = relay.health(BASE_TS_MS + 150);
    assert_eq!(health_before_burn.active_drops, 1);
    assert_eq!(health_before_burn.buffered_bytes, expected_len);
    assert_eq!(health_before_burn.drops_created_total, 1);
    assert_eq!(health_before_burn.drops_delivered_total, 0);

    let ack = relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            1,
            true,
            BASE_TS_MS + 200,
        )
        .expect("ack_drop burn");
    assert_eq!(ack.acked_seq, 1);
    assert_eq!(ack.burned_items, 1);
    assert_eq!(ack.burned_bytes, expected_len);
    assert_eq!(ack.remaining_items, 0);
    assert!(!ack.slot_closed);

    drop(sub);
    let health_after_burn = relay.health(BASE_TS_MS + 250);
    assert_eq!(health_after_burn.buffered_bytes, 0);
    assert_eq!(health_after_burn.active_sse_streams, 0);
    assert_eq!(health_after_burn.drops_delivered_total, 1);
}

#[tokio::test]
async fn late_subscriber_catch_up_last_event_id_and_burn_reconnect() {
    let relay = DropRelay::new(enabled_config());
    let created = relay
        .create_drop(
            "prod@eu-1",
            "198.51.100.20",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("create_drop");

    // Post #1 and #2 BEFORE any subscriber connects.
    let p1 = relay
        .post_drop(
            &created.drop_id,
            &created.post_cap,
            b"sealed-item-1".to_vec(),
            BASE_TS_MS + 10,
        )
        .expect("post #1");
    let p2 = relay
        .post_drop(
            &created.drop_id,
            &created.post_cap,
            b"sealed-item-2".to_vec(),
            BASE_TS_MS + 20,
        )
        .expect("post #2");
    assert_eq!(p1.seq, 1);
    assert_eq!(p2.seq, 2);

    // Late subscriber with last_event_id = None replays #1 and #2 in exact order.
    {
        let mut sub1 = relay
            .subscribe_drop(
                &created.drop_id,
                DropSubscriberAuth::SubCap(&created.sub_cap),
                "198.51.100.20",
                None,
                BASE_TS_MS + 30,
            )
            .expect("subscribe None");
        assert_eq!(sub1.backlog_len(), 2);

        let r1 = sub1.recv().await.expect("replay #1");
        let r2 = sub1.recv().await.expect("replay #2");
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.payload_bytes(), b"sealed-item-1");
        assert_eq!(r2.seq, 2);
        assert_eq!(r2.payload_bytes(), b"sealed-item-2");
        assert!(sub1.try_recv().is_none());
    }

    // Reconnect with last_event_id = Some(1) replays ONLY #2, then receives live #3.
    {
        let mut sub2 = relay
            .subscribe_drop(
                &created.drop_id,
                DropSubscriberAuth::SubCap(&created.sub_cap),
                "198.51.100.20",
                Some(1),
                BASE_TS_MS + 40,
            )
            .expect("subscribe Some(1)");
        assert_eq!(sub2.backlog_len(), 1);

        let r2 = sub2.recv().await.expect("replay #2 only");
        assert_eq!(r2.seq, 2);
        assert_eq!(r2.payload_bytes(), b"sealed-item-2");

        // Post live #3 while connected.
        let p3 = relay
            .post_drop(
                &created.drop_id,
                &created.post_cap,
                b"sealed-item-3".to_vec(),
                BASE_TS_MS + 50,
            )
            .expect("post #3");
        assert_eq!(p3.seq, 3);

        let r3 = tokio::time::timeout(Duration::from_secs(1), sub2.recv())
            .await
            .expect("live #3 timeout")
            .expect("live #3");
        assert_eq!(r3.seq, 3);
        assert_eq!(r3.payload_bytes(), b"sealed-item-3");
    }

    // Burn up to seq = 2 -> only #3 remains buffered.
    let ack2 = relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            2,
            true,
            BASE_TS_MS + 60,
        )
        .expect("ack burn <=2");
    assert_eq!(ack2.burned_items, 2);
    assert_eq!(ack2.remaining_items, 1);
    assert_eq!(
        relay.health(BASE_TS_MS + 60).buffered_bytes,
        b"sealed-item-3".len()
    );

    // Burn seq = 3 -> wipes remaining RAM completely.
    let ack3 = relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            3,
            true,
            BASE_TS_MS + 70,
        )
        .expect("ack burn <=3");
    assert_eq!(ack3.burned_items, 1);
    assert_eq!(ack3.remaining_items, 0);
    assert_eq!(relay.health(BASE_TS_MS + 70).buffered_bytes, 0);
    assert_eq!(relay.health(BASE_TS_MS + 70).drops_delivered_total, 3);

    // Reconnect after full burn gets 0 items!
    let mut sub3 = relay
        .subscribe_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            "198.51.100.20",
            None,
            BASE_TS_MS + 80,
        )
        .expect("reconnect after burn");
    assert_eq!(sub3.backlog_len(), 0);
    assert!(sub3.try_recv().is_none());
}

#[tokio::test]
async fn burn_after_read_closes_slot_and_terminates_live_stream() {
    let relay = DropRelay::new(enabled_config());
    let created = relay
        .create_drop(
            "prod@eu-1",
            "198.51.100.25",
            CreateDropRequest {
                burn_after_read: true,
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("create burn_after_read drop");

    let mut sub = relay
        .subscribe_drop(
            &created.drop_id,
            DropSubscriberAuth::CreatorNode("prod@eu-1"),
            "198.51.100.25",
            None,
            BASE_TS_MS + 10,
        )
        .expect("creator subscribe");

    relay
        .post_drop(
            &created.drop_id,
            &created.post_cap,
            b"one-shot-secret".to_vec(),
            BASE_TS_MS + 20,
        )
        .expect("post one-shot");

    let item = sub.recv().await.expect("receive one-shot");
    assert_eq!(item.payload_bytes(), b"one-shot-secret");

    let ack = relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::CreatorNode("prod@eu-1"),
            1,
            true,
            BASE_TS_MS + 30,
        )
        .expect("ack burn_after_read");
    assert!(ack.slot_closed);
    assert_eq!(ack.burned_items, 1);

    // Broadcast channel closed cleanly when slot was removed.
    assert!(sub.recv().await.is_none());

    // Subsequent post/subscribe sees NotFound and active_drops == 0.
    assert_eq!(
        relay.post_drop(
            &created.drop_id,
            &created.post_cap,
            b"late".to_vec(),
            BASE_TS_MS + 40
        ),
        Err(DropRelayError::NotFound)
    );
    assert_eq!(relay.health(BASE_TS_MS + 40).active_drops, 0);
    assert_eq!(relay.health(BASE_TS_MS + 40).buffered_bytes, 0);
}

#[test]
fn fail_closed_capability_tampering_role_confusion_swap_expiry_and_size_bounds() {
    let relay = DropRelay::new(enabled_config());
    let drop_a = relay
        .create_drop(
            "alice@macbook",
            "198.51.100.30",
            CreateDropRequest {
                ttl_seconds: Some(60),
                max_items: Some(2),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("create drop_a");
    let drop_b = relay
        .create_drop(
            "bob@laptop",
            "198.51.100.31",
            CreateDropRequest {
                ttl_seconds: Some(60),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("create drop_b");

    // 1. Bad / malformed / oversized tokens fail closed with 401.
    for bad in [
        "",
        "not_a_token",
        "hdcap1_",
        "hdcap1_short",
        &format!("hdcap1_{}", "A".repeat(4096)),
    ] {
        let err = relay
            .post_drop(&drop_a.drop_id, bad, b"ct".to_vec(), BASE_TS_MS + 1)
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    // 2. Flipping ANY single bit across the entire decoded 41-byte postCap fails closed!
    let encoded_part = drop_a.post_cap.strip_prefix(DROP_CAP_PREFIX).unwrap();
    let raw_cap = URL_SAFE_NO_PAD.decode(encoded_part).expect("decode cap");
    assert_eq!(raw_cap.len(), 41);
    for byte_idx in [0usize, 1, 4, 8, 9, 20, 40] {
        for bit in [0u8, 3, 7] {
            let mut mutated = raw_cap.clone();
            mutated[byte_idx] ^= 1 << bit;
            let tampered_cap = format!("{DROP_CAP_PREFIX}{}", URL_SAFE_NO_PAD.encode(&mutated));
            let err = relay
                .post_drop(
                    &drop_a.drop_id,
                    &tampered_cap,
                    b"ct".to_vec(),
                    BASE_TS_MS + 1,
                )
                .unwrap_err();
            assert_eq!(
                err.status_code(),
                StatusCode::UNAUTHORIZED,
                "1-bit flip at byte {byte_idx} bit {bit} MUST fail closed"
            );
        }
    }

    // 3. Role confusion: subCap on post_drop, postCap on subscribe_drop and ack_drop.
    assert_eq!(
        relay
            .post_drop(
                &drop_a.drop_id,
                &drop_a.sub_cap,
                b"ct".to_vec(),
                BASE_TS_MS + 1
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay
            .subscribe_drop(
                &drop_a.drop_id,
                DropSubscriberAuth::SubCap(&drop_a.post_cap),
                "198.51.100.30",
                None,
                BASE_TS_MS + 1,
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay
            .ack_drop(
                &drop_a.drop_id,
                DropSubscriberAuth::SubCap(&drop_a.post_cap),
                1,
                true,
                BASE_TS_MS + 1,
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );

    // 4. Cross-drop capability swap & wrong creator node fail closed.
    assert_eq!(
        relay
            .post_drop(
                &drop_b.drop_id,
                &drop_a.post_cap,
                b"ct".to_vec(),
                BASE_TS_MS + 1
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay
            .subscribe_drop(
                &drop_b.drop_id,
                DropSubscriberAuth::SubCap(&drop_a.sub_cap),
                "198.51.100.31",
                None,
                BASE_TS_MS + 1,
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay
            .subscribe_drop(
                &drop_a.drop_id,
                DropSubscriberAuth::CreatorNode("bob@laptop"),
                "198.51.100.31",
                None,
                BASE_TS_MS + 1,
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        relay
            .ack_drop(
                &drop_a.drop_id,
                DropSubscriberAuth::CreatorNode("bob@laptop"),
                1,
                true,
                BASE_TS_MS + 1,
            )
            .unwrap_err()
            .status_code(),
        StatusCode::UNAUTHORIZED
    );

    // 5. Payload size boundaries: empty rejected (400), > 64 KiB rejected (413), exact 64 KiB ok!
    assert_eq!(
        relay
            .post_drop(
                &drop_a.drop_id,
                &drop_a.post_cap,
                Vec::new(),
                BASE_TS_MS + 2
            )
            .unwrap_err()
            .status_code(),
        StatusCode::BAD_REQUEST
    );
    let oversized = vec![0x42u8; 65_537];
    let oversize_err = relay
        .post_drop(&drop_a.drop_id, &drop_a.post_cap, oversized, BASE_TS_MS + 2)
        .unwrap_err();
    assert_eq!(
        oversize_err,
        DropRelayError::PayloadTooLarge {
            size: 65_537,
            max_bytes: 65_536
        }
    );
    assert_eq!(oversize_err.status_code(), StatusCode::PAYLOAD_TOO_LARGE);

    let exact_max = vec![0x55u8; 65_536];
    let p1 = relay
        .post_drop(&drop_a.drop_id, &drop_a.post_cap, exact_max, BASE_TS_MS + 3)
        .expect("exact 64 KiB succeeds");
    assert_eq!(p1.seq, 1);

    let p2 = relay
        .post_drop(
            &drop_a.drop_id,
            &drop_a.post_cap,
            b"second".to_vec(),
            BASE_TS_MS + 4,
        )
        .expect("item #2 succeeds");
    assert_eq!(p2.seq, 2);

    // 6. Per-drop max_items cap (2) enforced with 409 DropFull.
    let full_err = relay
        .post_drop(
            &drop_a.drop_id,
            &drop_a.post_cap,
            b"third".to_vec(),
            BASE_TS_MS + 5,
        )
        .unwrap_err();
    assert_eq!(full_err, DropRelayError::DropFull { max_items: 2 });
    assert_eq!(full_err.status_code(), StatusCode::CONFLICT);

    // 7. Expired capability / slot fails closed at exact boundary now_ms == expires_at_ms.
    let exp_err = relay
        .post_drop(
            &drop_b.drop_id,
            &drop_b.post_cap,
            b"late".to_vec(),
            drop_b.expires_at_ms,
        )
        .unwrap_err();
    assert_eq!(exp_err, DropRelayError::Expired);
    assert_eq!(exp_err.status_code(), StatusCode::GONE);

    assert_eq!(
        relay
            .subscribe_drop(
                &drop_b.drop_id,
                DropSubscriberAuth::SubCap(&drop_b.sub_cap),
                "198.51.100.31",
                None,
                drop_b.expires_at_ms,
            )
            .unwrap_err(),
        DropRelayError::Expired
    );
}

#[test]
fn hourly_hmac_key_rotation_preserves_inflight_15m_drops() {
    let relay = DropRelay::new(enabled_config());

    // Create a 15-minute drop 5 minutes before an hour boundary (bucket H -> H+1).
    let hour_boundary = ((BASE_TS_MS / KEY_ROTATION_INTERVAL_MS) + 1) * KEY_ROTATION_INTERVAL_MS;
    let t_create = hour_boundary - 5 * 60 * 1_000;
    let created = relay
        .create_drop(
            "ops@eu-1",
            "198.51.100.40",
            CreateDropRequest {
                ttl_seconds: Some(900),
                ..Default::default()
            },
            t_create,
        )
        .expect("create near hour boundary");
    assert_eq!(created.expires_at_ms, t_create + 900_000);

    // Advance 7 minutes -> now 2 minutes INTO the next hour (triggers key rotation!).
    let t_after_rotation = hour_boundary + 2 * 60 * 1_000;

    // A brand-new drop in the new hour mints under the new current key.
    let fresh = relay
        .create_drop(
            "ops@eu-1",
            "198.51.100.40",
            CreateDropRequest::default(),
            t_after_rotation,
        )
        .expect("create after rotation");
    relay
        .post_drop(
            &fresh.drop_id,
            &fresh.post_cap,
            b"new-key".to_vec(),
            t_after_rotation + 1,
        )
        .expect("new key post works");

    // The pre-rotation drop MUST still verify cleanly via the previous key!
    let posted = relay
        .post_drop(
            &created.drop_id,
            &created.post_cap,
            b"cross-boundary-payload".to_vec(),
            t_after_rotation + 2,
        )
        .expect("pre-rotation postCap still valid across hour boundary");
    assert_eq!(posted.seq, 1);

    let mut sub = relay
        .subscribe_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            "198.51.100.40",
            None,
            t_after_rotation + 3,
        )
        .expect("pre-rotation subCap still valid across hour boundary");
    assert_eq!(
        sub.try_recv().expect("catch-up item").payload_bytes(),
        b"cross-boundary-payload"
    );

    relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            1,
            true,
            t_after_rotation + 4,
        )
        .expect("pre-rotation ack works");

    // Advance 2+ hours: old key is retired & zeroized; old token fails closed.
    let t_two_hours_later = hour_boundary + 2 * KEY_ROTATION_INTERVAL_MS + 1_000;
    let err = relay
        .verify_capability(
            &created.drop_id,
            &created.post_cap,
            DropCapRole::Post,
            t_two_hours_later,
        )
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
}

#[test]
fn ttl_clamping_and_local_drops_only_enforcement() {
    let cfg = DropRelayConfig {
        enabled: true,
        local_drops_only: true,
        max_ttl_seconds: 99_999, // must still hard-cap at 900s!
        ..Default::default()
    };
    let relay = DropRelay::new(cfg).with_local_node_id("alice@tailnet");

    // Different creator node rejected with 403.
    let err = relay
        .create_drop(
            "bob@tailnet",
            "100.64.0.2",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);

    // Self creator targeting another node rejected with 403.
    let err = relay
        .create_drop(
            "alice@tailnet",
            "100.64.0.1",
            CreateDropRequest {
                target_node_id: Some("bob@tailnet".into()),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);

    // Self-targeted drop succeeds; ttl_seconds=0 clamps to 1s; ttl_seconds=5000 clamps to 900s.
    let d_min = relay
        .create_drop(
            "alice@tailnet",
            "100.64.0.1",
            CreateDropRequest {
                ttl_seconds: Some(0),
                target_node_id: Some("alice@tailnet".into()),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("min ttl drop");
    assert_eq!(d_min.expires_at_ms, BASE_TS_MS + 1_000);

    let d_max = relay
        .create_drop(
            "alice@tailnet",
            "100.64.0.1",
            CreateDropRequest {
                ttl_seconds: Some(5_000),
                target_node_id: Some("alice@tailnet".into()),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("max ttl drop");
    assert_eq!(
        d_max.expires_at_ms,
        BASE_TS_MS + (HARD_MAX_TTL_SECONDS as i64) * 1_000
    );
}

#[test]
fn anti_dos_per_node_active_cap_hourly_limits_and_per_ip_limits() {
    // 1. Per-node active drop cap = 3.
    let relay = DropRelay::new(enabled_config());
    for i in 0..3 {
        relay
            .create_drop(
                "guest@node-1",
                "198.51.100.50",
                CreateDropRequest {
                    ttl_seconds: Some(30),
                    ..Default::default()
                },
                BASE_TS_MS + i * 100,
            )
            .expect("within active cap");
    }
    let active_err = relay
        .create_drop(
            "guest@node-1",
            "198.51.100.50",
            CreateDropRequest::default(),
            BASE_TS_MS + 500,
        )
        .unwrap_err();
    assert_eq!(active_err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(active_err.retry_after_secs().unwrap_or(0) >= 1);

    // Once the 30s drops expire, active cap clears automatically on next create.
    relay
        .create_drop(
            "guest@node-1",
            "198.51.100.50",
            CreateDropRequest {
                ttl_seconds: Some(5),
                ..Default::default()
            },
            BASE_TS_MS + 35_000,
        )
        .expect("expired drops swept before rejecting");

    // 2. Per-node hourly rate limit = 10/hr.
    let relay_node_rate = DropRelay::new(DropRelayConfig {
        enabled: true,
        max_active_drops_per_node: 20,
        creates_per_hour_per_node: 10,
        creates_per_hour_per_ip: 100,
        ..Default::default()
    });
    for i in 0..10 {
        relay_node_rate
            .create_drop(
                "noisy@node",
                "198.51.100.60",
                CreateDropRequest {
                    ttl_seconds: Some(5),
                    ..Default::default()
                },
                BASE_TS_MS + i * 1_000,
            )
            .expect("within 10/hr node quota");
    }
    let node_rate_err = relay_node_rate
        .create_drop(
            "noisy@node",
            "198.51.100.61",
            CreateDropRequest::default(),
            BASE_TS_MS + 15_000,
        )
        .unwrap_err();
    assert_eq!(node_rate_err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(node_rate_err.retry_after_secs().unwrap_or(0) >= 1);

    // After sliding window passes (> 1h), node can create again.
    relay_node_rate
        .create_drop(
            "noisy@node",
            "198.51.100.61",
            CreateDropRequest::default(),
            BASE_TS_MS + CREATE_RATE_WINDOW_MS + 1,
        )
        .expect("window rolled over");

    // 3. Per-IP hourly rate limit = 20/hr across multiple distinct nodes.
    let relay_ip_rate = DropRelay::new(DropRelayConfig {
        enabled: true,
        max_active_drops_per_node: 10,
        creates_per_hour_per_node: 10,
        creates_per_hour_per_ip: 20,
        ..Default::default()
    });
    for i in 0..20 {
        let node = format!("node-{}@fleet", i / 5);
        relay_ip_rate
            .create_drop(
                &node,
                "198.51.100.77",
                CreateDropRequest::default(),
                BASE_TS_MS + i * 100,
            )
            .expect("within 20/hr IP quota");
    }
    let ip_rate_err = relay_ip_rate
        .create_drop(
            "fresh-node@fleet",
            "198.51.100.77",
            CreateDropRequest::default(),
            BASE_TS_MS + 5_000,
        )
        .unwrap_err();
    assert_eq!(ip_rate_err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(ip_rate_err.retry_after_secs().unwrap_or(0) >= 1);

    // Different IP is completely unaffected.
    relay_ip_rate
        .create_drop(
            "fresh-node@fleet",
            "198.51.100.78",
            CreateDropRequest::default(),
            BASE_TS_MS + 5_000,
        )
        .expect("other IP unaffected");
}

#[tokio::test]
async fn global_memory_and_slot_caps_return_503_without_evicting_honest_drops() {
    // Configure 1 MiB RAM cap (exact 16 * 64 KiB).
    let cfg = DropRelayConfig {
        enabled: true,
        max_memory_mb: 1,
        max_active_drops: 100,
        max_active_drops_per_node: 50,
        creates_per_hour_per_node: 100,
        creates_per_hour_per_ip: 100,
        ..Default::default()
    };
    let relay = DropRelay::new(cfg);

    // Honest node creates drop #1 and stores a 64 KiB ciphertext payload.
    let honest = relay
        .create_drop(
            "honest@prod",
            "198.51.100.1",
            CreateDropRequest {
                ttl_seconds: Some(600),
                ..Default::default()
            },
            BASE_TS_MS,
        )
        .expect("honest create");
    let mut honest_payload = vec![0xAAu8; 65_536];
    honest_payload[0..11].copy_from_slice(b"HONEST-DROP");
    relay
        .post_drop(
            &honest.drop_id,
            &honest.post_cap,
            honest_payload.clone(),
            BASE_TS_MS + 10,
        )
        .expect("honest post");

    // Noisy neighbor fills the remaining 15 * 64 KiB = 960 KiB with shorter 30s drops.
    let noisy = relay
        .create_drop(
            "noisy@guest",
            "198.51.100.2",
            CreateDropRequest {
                ttl_seconds: Some(30),
                ..Default::default()
            },
            BASE_TS_MS + 20,
        )
        .expect("noisy create");
    for i in 0..15 {
        relay
            .post_drop(
                &noisy.drop_id,
                &noisy.post_cap,
                vec![0xBBu8; 65_536],
                BASE_TS_MS + 30 + i,
            )
            .expect("fill to exact 1 MiB");
    }
    assert_eq!(relay.health(BASE_TS_MS + 100).buffered_bytes, 1024 * 1024);

    // 17th payload MUST fail closed with 503 CapacityExceeded + Retry-After, WITHOUT evicting honest drop!
    let cap_err = relay
        .post_drop(
            &noisy.drop_id,
            &noisy.post_cap,
            vec![0xCCu8; 1024],
            BASE_TS_MS + 200,
        )
        .unwrap_err();
    assert_eq!(cap_err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(cap_err.retry_after_secs().unwrap_or(0) >= 1);
    assert_eq!(cap_err.to_problem_details().error, "drop_capacity_exceeded");

    // Verify honest drop was NEVER evicted and its full ciphertext is intact!
    let mut sub = relay
        .subscribe_drop(
            &honest.drop_id,
            DropSubscriberAuth::SubCap(&honest.sub_cap),
            "198.51.100.1",
            None,
            BASE_TS_MS + 250,
        )
        .expect("honest drop still alive");
    let received = sub.recv().await.expect("honest ciphertext intact");
    assert_eq!(received.payload_bytes(), honest_payload.as_slice());

    // Once noisy drop expires (t + 35s), sweep reclaims its 960 KiB and new posts succeed!
    let honest2 = relay
        .create_drop(
            "honest@prod",
            "198.51.100.1",
            CreateDropRequest::default(),
            BASE_TS_MS + 35_000,
        )
        .expect("create after noisy expiry");
    relay
        .post_drop(
            &honest2.drop_id,
            &honest2.post_cap,
            vec![0xDDu8; 32_768],
            BASE_TS_MS + 35_010,
        )
        .expect("post succeeds after expired RAM swept");

    let health = relay.health(BASE_TS_MS + 35_020);
    assert_eq!(health.active_drops, 2);
    assert_eq!(health.buffered_bytes, 65_536 + 32_768);

    // Also test global max_active_drops non-eviction (503).
    let slot_cap_relay = DropRelay::new(DropRelayConfig {
        enabled: true,
        max_active_drops: 2,
        max_active_drops_per_node: 5,
        ..Default::default()
    });
    let s1 = slot_cap_relay
        .create_drop(
            "n1@a",
            "198.51.100.1",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("slot 1");
    slot_cap_relay
        .create_drop(
            "n2@a",
            "198.51.100.2",
            CreateDropRequest::default(),
            BASE_TS_MS + 1,
        )
        .expect("slot 2");
    let s3_err = slot_cap_relay
        .create_drop(
            "n3@a",
            "198.51.100.3",
            CreateDropRequest::default(),
            BASE_TS_MS + 2,
        )
        .unwrap_err();
    assert_eq!(s3_err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(s3_err.retry_after_secs().unwrap_or(0) >= 1);
    // Slot 1 must still exist!
    slot_cap_relay
        .post_drop(
            &s1.drop_id,
            &s1.post_cap,
            b"still-here".to_vec(),
            BASE_TS_MS + 3,
        )
        .expect("slot 1 not evicted");
}

#[test]
fn sse_stream_caps_enforced_and_raii_drop_releases_slots() {
    let relay = DropRelay::new(DropRelayConfig {
        enabled: true,
        max_sse_streams: 3,
        max_sse_streams_per_drop: 2,
        max_sse_streams_per_ip: 2,
        ..Default::default()
    });

    let d1 = relay
        .create_drop(
            "n1@a",
            "198.51.100.1",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("d1");
    let d2 = relay
        .create_drop(
            "n2@a",
            "198.51.100.2",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("d2");

    // 2 streams on d1 from ip A succeed; 3rd on d1 fails with 429 (per-drop cap = 2).
    let s1 = relay
        .subscribe_drop(
            &d1.drop_id,
            DropSubscriberAuth::SubCap(&d1.sub_cap),
            "198.51.100.90",
            None,
            BASE_TS_MS + 1,
        )
        .expect("stream 1");
    let s2 = relay
        .subscribe_drop(
            &d1.drop_id,
            DropSubscriberAuth::SubCap(&d1.sub_cap),
            "198.51.100.90",
            None,
            BASE_TS_MS + 2,
        )
        .expect("stream 2");
    assert_eq!(relay.health(BASE_TS_MS + 3).active_sse_streams, 2);

    let per_drop_err = relay
        .subscribe_drop(
            &d1.drop_id,
            DropSubscriberAuth::SubCap(&d1.sub_cap),
            "198.51.100.91",
            None,
            BASE_TS_MS + 3,
        )
        .unwrap_err();
    assert_eq!(per_drop_err.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Same IP 198.51.100.90 trying d2 hits per-IP cap = 2 (429).
    let per_ip_err = relay
        .subscribe_drop(
            &d2.drop_id,
            DropSubscriberAuth::SubCap(&d2.sub_cap),
            "198.51.100.90",
            None,
            BASE_TS_MS + 4,
        )
        .unwrap_err();
    assert_eq!(per_ip_err.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Different IP on d2 takes the 3rd global stream slot; 4th hits global cap = 3 (503).
    let s3 = relay
        .subscribe_drop(
            &d2.drop_id,
            DropSubscriberAuth::SubCap(&d2.sub_cap),
            "198.51.100.92",
            None,
            BASE_TS_MS + 5,
        )
        .expect("stream 3");
    assert_eq!(relay.health(BASE_TS_MS + 6).active_sse_streams, 3);

    let global_err = relay
        .subscribe_drop(
            &d2.drop_id,
            DropSubscriberAuth::SubCap(&d2.sub_cap),
            "198.51.100.93",
            None,
            BASE_TS_MS + 6,
        )
        .unwrap_err();
    assert_eq!(global_err.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    // RAII Drop of s1 cleanly releases global, per-drop, and per-IP counters!
    drop(s1);
    assert_eq!(relay.health(BASE_TS_MS + 7).active_sse_streams, 2);

    let s4 = relay
        .subscribe_drop(
            &d1.drop_id,
            DropSubscriberAuth::SubCap(&d1.sub_cap),
            "198.51.100.90",
            None,
            BASE_TS_MS + 8,
        )
        .expect("re-acquired after RAII drop");
    assert_eq!(relay.health(BASE_TS_MS + 9).active_sse_streams, 3);

    drop(s2);
    drop(s3);
    drop(s4);
    assert_eq!(relay.health(BASE_TS_MS + 10).active_sse_streams, 0);
}

#[test]
fn cors_allowlist_and_pna_headers_fail_closed() {
    let relay = DropRelay::new(DropRelayConfig {
        enabled: true,
        allowed_origins: vec![
            "https://hyphae.to".into(),
            "https://drop.example.com/".into(),
            "*".into(),    // malicious/misconfigured wildcard MUST be ignored!
            "null".into(), // null origin MUST be ignored!
        ],
        allow_private_network: true,
        ..Default::default()
    });

    assert_eq!(
        relay.cors_origin_for(Some("https://hyphae.to")),
        Some("https://hyphae.to")
    );
    assert_eq!(
        relay.cors_origin_for(Some("https://drop.example.com")),
        Some("https://drop.example.com")
    );
    assert!(relay.allow_private_network());

    // Rejected origins
    for bad in [
        None,
        Some(""),
        Some("*"),
        Some("null"),
        Some("NULL"),
        Some("https://evil.example"),
        Some("http://hyphae.to"),
        Some("https://hyphae.to.evil.example"),
        Some("https://hyphae.to\r\nX-Injected: 1"),
    ] {
        assert_eq!(
            relay.cors_origin_for(bad),
            None,
            "origin {bad:?} must be rejected"
        );
    }

    // Response header helper emits ACAO + PNA only for allowed origin.
    let mut allowed_headers = HeaderMap::new();
    assert!(relay.apply_cors_headers(Some("https://hyphae.to"), &mut allowed_headers));
    assert_eq!(
        allowed_headers.get("access-control-allow-origin").unwrap(),
        "https://hyphae.to"
    );
    assert_eq!(
        allowed_headers
            .get("access-control-allow-private-network")
            .unwrap(),
        "true"
    );
    assert_eq!(allowed_headers.get("vary").unwrap(), "Origin");

    let mut blocked_headers = HeaderMap::new();
    assert!(!relay.apply_cors_headers(Some("https://evil.example"), &mut blocked_headers));
    assert!(blocked_headers.get("access-control-allow-origin").is_none());
    assert!(
        blocked_headers
            .get("access-control-allow-private-network")
            .is_none()
    );
    assert_eq!(blocked_headers.get("vary").unwrap(), "Origin");

    // When allow_private_network is false, PNA header is omitted.
    let no_pna = DropRelay::new(DropRelayConfig {
        enabled: true,
        allow_private_network: false,
        ..Default::default()
    });
    assert!(!no_pna.allow_private_network());
    let mut no_pna_headers = HeaderMap::new();
    assert!(no_pna.apply_cors_headers(Some("https://hyphae.to"), &mut no_pna_headers));
    assert_eq!(
        no_pna_headers.get("access-control-allow-origin").unwrap(),
        "https://hyphae.to"
    );
    assert!(
        no_pna_headers
            .get("access-control-allow-private-network")
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_post_and_subscribe_zero_gap_zero_duplication() {
    let relay = DropRelay::new(DropRelayConfig {
        enabled: true,
        max_items_per_drop: 16,
        max_sse_streams_per_drop: 8,
        ..Default::default()
    });

    let created = relay
        .create_drop(
            "prod@eu-1",
            "198.51.100.99",
            CreateDropRequest::default(),
            BASE_TS_MS,
        )
        .expect("create");

    let relay_post = relay.clone();
    let drop_id_post = created.drop_id.clone();
    let post_cap = created.post_cap.clone();
    let poster = tokio::spawn(async move {
        for i in 1..=16u64 {
            let body = format!("payload-{i:02}").into_bytes();
            let resp = relay_post
                .post_drop(&drop_id_post, &post_cap, body, BASE_TS_MS + (i as i64) * 5)
                .expect("concurrent post");
            assert_eq!(resp.seq, i);
            tokio::task::yield_now().await;
        }
    });

    // Spawn 4 subscribers staggered during posting — each MUST see all 16 items 1..=16 with zero
    // gaps and zero duplicates!
    let mut sub_handles = Vec::new();
    for s_idx in 0..4u64 {
        let r = relay.clone();
        let did = created.drop_id.clone();
        let scap = created.sub_cap.clone();
        sub_handles.push(tokio::spawn(async move {
            for _ in 0..s_idx {
                tokio::task::yield_now().await;
            }
            let mut sub = r
                .subscribe_drop(
                    &did,
                    DropSubscriberAuth::SubCap(&scap),
                    &format!("198.51.100.{}", 100 + s_idx),
                    None,
                    BASE_TS_MS + 10,
                )
                .expect("concurrent subscribe");
            let mut seen = Vec::with_capacity(16);
            while seen.len() < 16 {
                let item = tokio::time::timeout(Duration::from_secs(2), sub.recv())
                    .await
                    .expect("no hang")
                    .expect("item present");
                seen.push((item.seq, item.payload_bytes().to_vec()));
            }
            seen
        }));
    }

    poster.await.expect("poster join");
    for handle in sub_handles {
        let seen = handle.await.expect("sub join");
        let expected: Vec<(u64, Vec<u8>)> = (1..=16u64)
            .map(|i| (i, format!("payload-{i:02}").into_bytes()))
            .collect();
        assert_eq!(seen, expected);
    }

    // Burn all 16 items and confirm zero RAM remains.
    let ack = relay
        .ack_drop(
            &created.drop_id,
            DropSubscriberAuth::SubCap(&created.sub_cap),
            16,
            true,
            BASE_TS_MS + 200,
        )
        .expect("burn all");
    assert_eq!(ack.burned_items, 16);
    assert_eq!(relay.health(BASE_TS_MS + 200).buffered_bytes, 0);
    assert_eq!(relay.health(BASE_TS_MS + 200).active_sse_streams, 0);
}

/// McKeeman differential oracle: compares real `DropRelay` step-by-step against a simple pure
/// in-memory model across a deterministic 120-step seeded sequence of creates, posts, catch-up
/// subscribes, partial/full burns, sweeps, and TTL expirations.
#[test]
fn differential_model_vs_drop_relay_stateful_sequence() {
    #[derive(Clone)]
    struct ModelSlot {
        expires_at_ms: i64,
        post_cap: String,
        sub_cap: String,
        next_seq: u64,
        highest_acked: u64,
        items: VecDeque<(u64, Vec<u8>)>,
    }

    let cfg = DropRelayConfig {
        enabled: true,
        max_active_drops: 64,
        max_active_drops_per_node: 32,
        creates_per_hour_per_node: 1_000,
        creates_per_hour_per_ip: 1_000,
        max_items_per_drop: 8,
        max_payload_bytes: 512,
        ..Default::default()
    };
    let relay = DropRelay::with_memory_cap_bytes(cfg, 4_096);

    let mut model: BTreeMap<String, ModelSlot> = BTreeMap::new();
    let mut created_total = 0u64;
    let mut delivered_total = 0u64;
    let mut now_ms = BASE_TS_MS;

    // Deterministic xorshift64 PRNG.
    let mut seed: u64 = 0x5EED_C0DE_D209_1234;
    let mut next_rand = || -> u64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for step in 0..120u64 {
        now_ms += ((next_rand() % 15) * 1_000) as i64;
        let op = next_rand() % 5;

        match op {
            0 => {
                // Create drop with short TTL (10..60s)
                let ttl = 10 + (next_rand() % 50);
                let node = format!("node-{}@fleet", next_rand() % 4);
                let ip = format!("198.51.100.{}", 1 + (next_rand() % 4));
                let res = relay
                    .create_drop(
                        &node,
                        &ip,
                        CreateDropRequest {
                            ttl_seconds: Some(ttl),
                            ..Default::default()
                        },
                        now_ms,
                    )
                    .expect("model create");
                created_total += 1;
                model.insert(
                    res.drop_id.clone(),
                    ModelSlot {
                        expires_at_ms: res.expires_at_ms,
                        post_cap: res.post_cap,
                        sub_cap: res.sub_cap,
                        next_seq: 1,
                        highest_acked: 0,
                        items: VecDeque::new(),
                    },
                );
            }
            1 => {
                // Post payload to random known drop
                if !model.is_empty() {
                    let keys: Vec<String> = model.keys().cloned().collect();
                    let id = keys[(next_rand() as usize) % keys.len()].clone();
                    let payload_len = 16 + ((next_rand() as usize) % 400);
                    let payload = vec![(step & 0xff) as u8; payload_len];
                    let post_cap = model[&id].post_cap.clone();

                    // Sweep expired in model first when checking global RAM
                    let real_res = relay.post_drop(&id, &post_cap, payload.clone(), now_ms);

                    if now_ms >= model[&id].expires_at_ms {
                        model.remove(&id);
                        assert_eq!(real_res, Err(DropRelayError::Expired));
                    } else if model[&id].next_seq > 8 {
                        assert_eq!(real_res, Err(DropRelayError::DropFull { max_items: 8 }));
                    } else {
                        // Compute live RAM after sweeping expired slots
                        let expired_ids: Vec<String> = model
                            .iter()
                            .filter(|(_, s)| now_ms >= s.expires_at_ms)
                            .map(|(k, _)| k.clone())
                            .collect();
                        let current_bytes: usize = model
                            .values()
                            .flat_map(|s| s.items.iter())
                            .map(|(_, b)| b.len())
                            .sum();
                        let live_bytes: usize = model
                            .iter()
                            .filter(|(k, _)| !expired_ids.contains(k))
                            .flat_map(|(_, s)| s.items.iter())
                            .map(|(_, b)| b.len())
                            .sum();
                        if current_bytes + payload_len > 4_096 {
                            for ek in expired_ids {
                                model.remove(&ek);
                            }
                            if live_bytes + payload_len > 4_096 {
                                assert_eq!(
                                    real_res.unwrap_err().status_code(),
                                    StatusCode::SERVICE_UNAVAILABLE
                                );
                            } else {
                                let p = real_res.expect("fits after sweep");
                                let slot = model.get_mut(&id).unwrap();
                                assert_eq!(p.seq, slot.next_seq);
                                slot.items.push_back((slot.next_seq, payload));
                                slot.next_seq += 1;
                            }
                        } else {
                            let p = real_res.expect("fits in RAM");
                            let slot = model.get_mut(&id).unwrap();
                            assert_eq!(p.seq, slot.next_seq);
                            slot.items.push_back((slot.next_seq, payload));
                            slot.next_seq += 1;
                        }
                    }
                }
            }
            2 => {
                // Subscribe with random Last-Event-ID and compare exact backlog replay!
                if !model.is_empty() {
                    let keys: Vec<String> = model.keys().cloned().collect();
                    let id = keys[(next_rand() as usize) % keys.len()].clone();
                    let sub_cap = model[&id].sub_cap.clone();
                    let last_id = match next_rand() % 4 {
                        0 => None,
                        n => Some(n),
                    };
                    let real_sub = relay.subscribe_drop(
                        &id,
                        DropSubscriberAuth::SubCap(&sub_cap),
                        "198.51.100.1",
                        last_id,
                        now_ms,
                    );
                    if now_ms >= model[&id].expires_at_ms {
                        model.remove(&id);
                        assert_eq!(real_sub.unwrap_err(), DropRelayError::Expired);
                    } else {
                        let mut sub = real_sub.expect("live subscribe");
                        let got: Vec<(u64, Vec<u8>)> = sub
                            .drain_backlog()
                            .into_iter()
                            .map(|i| (i.seq, i.payload_bytes().to_vec()))
                            .collect();
                        let expected: Vec<(u64, Vec<u8>)> = model[&id]
                            .items
                            .iter()
                            .filter(|(seq, _)| *seq > last_id.unwrap_or(0))
                            .cloned()
                            .collect();
                        assert_eq!(got, expected);
                    }
                }
            }
            3 => {
                // Ack (burn true/false)
                if !model.is_empty() {
                    let keys: Vec<String> = model.keys().cloned().collect();
                    let id = keys[(next_rand() as usize) % keys.len()].clone();
                    let sub_cap = model[&id].sub_cap.clone();
                    let burn = (next_rand() % 2) == 0;
                    let ack_seq = next_rand() % 9;
                    let real_ack = relay.ack_drop(
                        &id,
                        DropSubscriberAuth::SubCap(&sub_cap),
                        ack_seq,
                        burn,
                        now_ms,
                    );
                    if now_ms >= model[&id].expires_at_ms {
                        model.remove(&id);
                        assert_eq!(real_ack, Err(DropRelayError::Expired));
                    } else {
                        let ack = real_ack.expect("live ack");
                        let slot = model.get_mut(&id).unwrap();
                        let effective = ack_seq.min(slot.next_seq.saturating_sub(1));
                        let newly = effective.saturating_sub(slot.highest_acked);
                        if effective > slot.highest_acked {
                            slot.highest_acked = effective;
                        }
                        delivered_total += newly;
                        let mut model_burned_items = 0usize;
                        let mut model_burned_bytes = 0usize;
                        if burn && ack_seq > 0 {
                            while let Some((seq, _)) = slot.items.front() {
                                if *seq <= ack_seq {
                                    let (_, b) = slot.items.pop_front().unwrap();
                                    model_burned_items += 1;
                                    model_burned_bytes += b.len();
                                } else {
                                    break;
                                }
                            }
                        }
                        assert_eq!(ack.acked_seq, effective);
                        assert_eq!(ack.burned_items, model_burned_items);
                        assert_eq!(ack.burned_bytes, model_burned_bytes);
                        assert_eq!(ack.remaining_items, slot.items.len());
                    }
                }
            }
            _ => {
                // Explicit sweep
                let before = model.len();
                model.retain(|_, s| now_ms < s.expires_at_ms);
                let expected_swept = before - model.len();
                let real_swept = relay.sweep_expired(now_ms);
                assert_eq!(real_swept, expected_swept);
            }
        }

        // Verify post-step health invariant matches reference model identically!
        model.retain(|_, s| now_ms < s.expires_at_ms);
        let expected_bytes: usize = model
            .values()
            .flat_map(|s| s.items.iter())
            .map(|(_, b)| b.len())
            .sum();
        let health = relay.health(now_ms);
        assert_eq!(health.active_drops, model.len(), "step {step} active_drops");
        assert_eq!(
            health.buffered_bytes, expected_bytes,
            "step {step} buffered_bytes"
        );
        assert_eq!(
            health.active_sse_streams, 0,
            "step {step} active_sse_streams"
        );
        assert_eq!(
            health.drops_created_total, created_total,
            "step {step} created_total"
        );
        assert_eq!(
            health.drops_delivered_total, delivered_total,
            "step {step} delivered_total"
        );
    }
}
