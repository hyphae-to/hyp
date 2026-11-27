//! Shared one-shot IPv4 loopback server mechanics; handlers and diagnostics stay with callers.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Request, Response};
use http_body_util::Full;
use hyp_crypto::keystore::SecretStore;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use ring::rand::{SecureRandom, SystemRandom};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub(crate) async fn bind(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], port))).await
}

#[derive(Debug)]
pub(crate) enum WaitError {
    ChannelClosed,
    TimedOut,
}

pub(crate) async fn serve<T, S, H, F>(
    listener: TcpListener,
    state: Arc<S>,
    mut done_rx: oneshot::Receiver<T>,
    timeout: Duration,
    completion_grace: Duration,
    handler: H,
) -> Result<T, WaitError>
where
    S: Send + Sync + 'static,
    H: Fn(Arc<S>, Request<Incoming>) -> F + Copy + Send + 'static,
    F: Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let timeout = tokio::time::sleep(timeout);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            result = &mut done_rx => {
                tokio::time::sleep(completion_grace).await;
                return result.map_err(|_| WaitError::ChannelClosed);
            }
            _ = &mut timeout => return Err(WaitError::TimedOut),
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else {
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |request| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(handler(state, request).await) }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                });
            }
        }
    }
}

pub(crate) fn random_b64url(len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

pub(crate) fn should_skip_browser_open(no_open: bool, store: &SecretStore) -> bool {
    if no_open {
        return true;
    }
    if std::env::var_os("HYPHAE_NO_OPEN").is_some() || std::env::var_os("CI").is_some() {
        return true;
    }
    let tmp = std::env::temp_dir();
    let canon_tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
    let dir = store.config_dir();
    let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    canon_dir.starts_with(&canon_tmp)
        || dir.starts_with("/tmp")
        || dir.starts_with("/private/tmp")
        || dir.starts_with("/var/folders")
        || dir.starts_with("/private/var/folders")
}

pub(crate) fn try_open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = url;
}
