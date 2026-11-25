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
    HelloMode, PluginTransportMode, SubprocessConfig, SubprocessSupervisor, WireProtocol,
    build_isolated_env,
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
