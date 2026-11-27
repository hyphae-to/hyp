use http::{Method, header};
use http_body_util::Full;
use hyp_node::engine::DROP_CAP_HEADER;
use hyp_node::engine::drop_client::{self, CreateSlotOptions, RelayAuth};
use hyp_node::engine::http_util::{SseParser, build_http_client};
use hyper::body::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn create_slot_signs_exact_json_and_keeps_caller_headers() {
    for (node_header, max_items) in [(Some("node@test"), 1), (None, 4)] {
        let expected = format!(
            r#"{{"ttlSeconds":90,"maxItems":{max_items},"targetNodeId":"node@test","burnAfterRead":true}}"#
        );
        let sign = |method: &str, path: &str, body: &[u8]| {
            assert_eq!((method, path), ("POST", "/v1/drops"));
            assert!(body == expected.as_bytes(), "signed create bytes changed");
            Ok("fixture-auth".into())
        };
        let request = drop_client::create_slot(
            "https://relay.invalid",
            CreateSlotOptions {
                node_id: "node@test",
                ttl_seconds: 90,
                max_items,
            },
            RelayAuth::Signed {
                public_key: "fixture-public",
                node_header,
                sign: &sign,
            },
            |bytes| bytes,
        )
        .unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), "https://relay.invalid/v1/drops");
        assert_eq!(request.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(request.headers()[header::AUTHORIZATION], "fixture-auth");
        assert_eq!(request.headers()["X-Hyphae-Public-Key"], "fixture-public");
        assert_eq!(
            request
                .headers()
                .get("x-hyphae-node")
                .map(|value| value.to_str().unwrap()),
            node_header
        );
        assert!(
            request.body() == expected.as_bytes(),
            "wire create bytes changed"
        );
    }
}

#[test]
fn stream_and_ack_preserve_cursor_capability_and_signed_paths() {
    let stream_path = "/v1/drops/fixture%2Did/stream";
    let ack_path = "/v1/drops/fixture%2Did/ack";
    let ack_bytes = br#"{"burn":true,"seq":7}"#;
    let sign = |method: &str, path: &str, bytes: &[u8]| {
        match method {
            "GET" => {
                assert_eq!(path, stream_path);
                assert!(bytes.is_empty());
            }
            "POST" => {
                assert_eq!(path, ack_path);
                assert!(bytes == ack_bytes);
            }
            other => panic!("unexpected signing method {other}"),
        }
        Ok("fixture-auth".into())
    };
    for capability in [None, Some("fixture-cap")] {
        let auth = || match capability {
            Some(capability) => RelayAuth::Capability(capability),
            None => RelayAuth::Signed {
                public_key: "fixture-public",
                node_header: Some("node@test"),
                sign: &sign,
            },
        };
        let stream = drop_client::stream_request(
            "https://relay.invalid",
            stream_path,
            Some("6"),
            auth(),
            (),
        )
        .unwrap();
        let ack =
            drop_client::ack("https://relay.invalid", ack_path, 7, auth(), |bytes| bytes).unwrap();
        assert_eq!(stream.method(), Method::GET);
        assert_eq!(stream.uri().path(), stream_path);
        assert_eq!(stream.headers()[header::ACCEPT], "text/event-stream");
        assert_eq!(stream.headers()["Last-Event-ID"], "6");
        assert_eq!(ack.method(), Method::POST);
        assert_eq!(ack.uri().path(), ack_path);
        assert_eq!(ack.headers()[header::CONTENT_TYPE], "application/json");
        assert!(ack.body() == ack_bytes);
        for headers in [stream.headers(), ack.headers()] {
            assert_eq!(
                headers
                    .get(DROP_CAP_HEADER)
                    .map(|value| value.to_str().unwrap()),
                capability
            );
            assert_eq!(
                headers.contains_key(header::AUTHORIZATION),
                capability.is_none()
            );
        }
    }
}

#[tokio::test]
async fn stream_next_keeps_partial_frames_and_all_event_types() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert!(socket.read(&mut [0; 1024]).await.unwrap() != 0);
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for data in [
            "id: 7\nevent: dr",
            "op\ndata: first\n\nid: 8\n",
            "event: other\ndata: second\n\n",
        ] {
            socket
                .write_all(format!("{:x}\r\n{data}\r\n", data.len()).as_bytes())
                .await
                .unwrap();
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let client = build_http_client::<Full<Bytes>>().unwrap();
    let request = http::Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let mut body = client.request(request).await.unwrap().into_body();
    let mut parser = SseParser::new();
    let mut events = Vec::new();
    while let Some(batch) = drop_client::stream_next(&mut body, &mut parser).await {
        events.extend(batch.unwrap());
    }
    assert_eq!(
        events
            .iter()
            .map(|event| (
                event.id.as_deref(),
                event.event.as_deref(),
                event.data.as_str()
            ))
            .collect::<Vec<_>>(),
        [
            (Some("7"), Some("drop"), "first"),
            (Some("8"), Some("other"), "second")
        ],
    );
    assert_eq!(parser.last_event_id(), Some("8"));
    server.await.unwrap();
}
