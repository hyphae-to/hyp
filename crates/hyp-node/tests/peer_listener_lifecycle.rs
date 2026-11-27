use hyp_crypto::SecretBackend;
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test(flavor = "current_thread")]
async fn shutdown_before_spawned_listeners_run_stops_and_cleans_up() {
    let dir = TempDir::new().unwrap();
    let mut config = NodeConfig::p2p(NodeId::new("queued-shutdown").unwrap(), dir.path());
    config.secret_backend = Some(SecretBackend::File);
    let node = UnifiedNode::open(config).unwrap();
    let (address, tcp) = node
        .clone()
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    #[cfg(unix)]
    let path = dir.path().join("peer.sock");
    #[cfg(unix)]
    let (_, unix) = node.clone().serve_unix(path.clone()).await.unwrap();

    // Both binds complete without yielding this single-thread runtime to the spawned tasks.
    // Their shutdown subscriptions must already exist when shutdown changes the watch value.
    node.shutdown();
    tokio::time::timeout(Duration::from_secs(5), tcp)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    #[cfg(unix)]
    {
        tokio::time::timeout(Duration::from_secs(5), unix)
            .await
            .unwrap()
            .unwrap();
        assert!(!path.exists(), "shutdown must unlink the peer socket");
    }
}
