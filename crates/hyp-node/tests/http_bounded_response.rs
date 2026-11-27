use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Empty;
use hyp_node::engine::http_util::{
    BoundedBodyError, BoundedRequestError, build_http_client, request_bounded,
};
use hyper::body::Incoming;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Default)]
struct Reply {
    headers: &'static [u8],
    body: &'static [u8],
    header_delay: Duration,
    body_delay: Duration,
    header_gate: Option<oneshot::Receiver<()>>,
    body_gate: Option<oneshot::Receiver<()>>,
}

async fn server(reply: Reply) -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            request.push(byte[0]);
        }
        if let Some(gate) = reply.header_gate {
            let _ = gate.await;
        }
        tokio::time::sleep(reply.header_delay).await;
        if stream.write_all(reply.headers).await.is_err() {
            return;
        }
        if let Some(gate) = reply.body_gate {
            let _ = gate.await;
        }
        tokio::time::sleep(reply.body_delay).await;
        let _ = stream.write_all(reply.body).await;
    });
    (address, task)
}

async fn fetch(
    address: SocketAddr,
    inspect: impl FnOnce(&Response<Incoming>) -> Result<(), &'static str>,
) -> Result<((), Vec<u8>), BoundedRequestError<hyper_util::client::legacy::Error, &'static str>> {
    let client = build_http_client::<Empty<Bytes>>().unwrap();
    let request = Request::builder()
        .uri(format!("http://{address}/"))
        .body(Empty::new())
        .unwrap();
    request_bounded(client.request(request), Duration::from_secs(1), 8, inspect).await
}

#[tokio::test]
async fn headers_and_body_receive_independent_timeout_windows() {
    let (address, task) = server(Reply {
        headers: b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
        body: b"x",
        // Each phase fits one second, while the combined time exceeds one second.
        header_delay: Duration::from_millis(650),
        body_delay: Duration::from_millis(650),
        ..Reply::default()
    })
    .await;
    let (_, body) = fetch(address, |_| Ok(())).await.unwrap();
    task.await.unwrap();
    assert_eq!(body, b"x");
}

#[tokio::test]
async fn caller_policy_rejects_headers_before_waiting_for_body() {
    let (release, gate) = oneshot::channel();
    let (address, task) = server(Reply {
        headers: b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
        body_gate: Some(gate),
        ..Reply::default()
    })
    .await;
    let result = fetch(address, |response| {
        if response.status().as_u16() == 403 {
            Err("caller rejected status")
        } else {
            Ok(())
        }
    })
    .await;
    let _ = release.send(());
    task.await.unwrap();
    assert!(matches!(
        result,
        Err(BoundedRequestError::Policy("caller rejected status"))
    ));
}

#[tokio::test]
async fn body_failures_retain_observed_http_status() {
    let (address, task) = server(Reply {
        headers: b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
        body: b"x",
        ..Reply::default()
    })
    .await;
    let result = fetch(address, |_| Ok(())).await;
    task.await.unwrap();
    assert!(matches!(
        result,
        Err(BoundedRequestError::Body {
            status: 403,
            error: BoundedBodyError::Read(_)
        })
    ));

    let (address, task) = server(Reply {
        headers: b"HTTP/1.1 500 Error\r\nContent-Length: 9\r\nConnection: close\r\n\r\n",
        body: b"xxxxxxxxx",
        ..Reply::default()
    })
    .await;
    let result = fetch(address, |_| Ok(())).await;
    task.await.unwrap();
    assert!(matches!(
        result,
        Err(BoundedRequestError::Body {
            status: 500,
            error: BoundedBodyError::TooLarge
        })
    ));
}

#[tokio::test]
async fn timeouts_identify_the_phase_and_preserve_body_status() {
    for headers_blocked in [true, false] {
        let (release, gate) = oneshot::channel();
        let mut reply = Reply {
            headers: b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
            ..Reply::default()
        };
        if headers_blocked {
            reply.header_gate = Some(gate);
        } else {
            reply.body_gate = Some(gate);
        }
        let (address, task) = server(reply).await;
        let result = fetch(address, |_| Ok(())).await;
        let _ = release.send(());
        task.await.unwrap();
        if headers_blocked {
            assert!(matches!(result, Err(BoundedRequestError::RequestTimeout)));
        } else {
            assert!(matches!(
                result,
                Err(BoundedRequestError::BodyTimeout { status: 403 })
            ));
        }
    }
}
