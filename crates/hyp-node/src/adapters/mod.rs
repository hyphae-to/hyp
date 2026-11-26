//! Unified `NodeAdapter` trait, cross-platform fd-3/loopback-TCP `SubprocessSupervisor`,
//! native in-process webhook source adapters, and the demand-driven `github-public`
//! ETag poller + GitHub App push adapter powering `public.hyphae.to` and `local.github-public`.

pub mod github_public;
pub mod supervisor;
pub mod trait_def;
pub mod webhooks;

pub use github_public::{
    GitHubPublicAdapter, GitHubPublicConfig, GitHubPublicStats, normalize_github_api_event,
};
pub use supervisor::{
    PluginTransportMode, SubprocessConfig, SubprocessSupervisor, build_isolated_env,
};
pub use trait_def::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, CompiledSubscription, NodeAdapter,
    NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus,
};
pub use webhooks::{
    GenericWebhookAdapter, GenericWebhookConfig, GitHubNormalizeOutcome, GitHubWebhookAdapter,
    GitHubWebhookConfig, PrometheusWebhookAdapter, PrometheusWebhookConfig, WebhookIngestOutcome,
    compute_hmac_sha256_header, normalize_generic_webhook, normalize_github_webhook,
    normalize_prometheus_webhook, verify_hmac_sha256_header,
};

/// Flushes due batches for local-session subscribers of the source topic `topic` into their
/// mailboxes and wakes them, returning how many sessions were reached.
///
/// Compiled-in adapters get this from the node's own adapter host after every stored publish.
/// Hosts that publish on behalf of external subprocess `source` plugins must call it too:
/// `UnifiedNode::publish_event` only stores the event and opens batches, so without this flush a
/// plugin's events reach paired remote subscribers but never a session on the same node.
///
/// The node drains each subscription in bounded passes. Repeat while sessions are reached so one
/// publish also clears a larger backlog left by a failed flush or restart. Per-subscription wake caps and holds still apply: a capped subscription
/// simply stops contributing, which ends the loop.
pub fn deliver_source_topic_to_local_sessions(
    node: &crate::engine::UnifiedNode,
    topic: &str,
) -> Result<usize, crate::engine::NodeError> {
    const MAX_PASSES: usize = 64;
    let mut delivered = 0;
    for _ in 0..MAX_PASSES {
        let pass = node.deliver_local_topic_batches(
            topic,
            &hyp_store::MailboxPutOptions::default(),
            None,
            None,
            hyp_store::now_ms(),
        )?;
        if pass == 0 {
            break;
        }
        delivered += pass;
    }
    Ok(delivered)
}
