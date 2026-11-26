//! Golden storage and Serde tokens for the persisted store enums.
use hyp_store::StoreError;

macro_rules! assert_tokens {
    ($ty:ident, $error:ident, $label:literal, { $($variant:ident => $token:literal),+ $(,)? }) => {{
        use hyp_store::$ty;
        $(
            assert_eq!($ty::$variant.as_str(), $token);
            assert_eq!($ty::parse($token).unwrap(), $ty::$variant);
            let json = concat!("\"", $token, "\"");
            assert_eq!(serde_json::to_string(&$ty::$variant).unwrap(), json);
            assert_eq!(serde_json::from_str::<$ty>(json).unwrap(), $ty::$variant);
        )+
        let err = $ty::parse(" INVALID ").unwrap_err();
        assert!(matches!(
            err,
            StoreError::$error(ref message) if message == concat!("invalid ", $label, " ' INVALID '")
        ), "unexpected error: {err:?}");
    }};
}

#[test]
fn persisted_enum_strings_are_stable() {
    assert_tokens!(DeliveryMode, InvalidInput, "delivery mode", {
        Full => "full",
        Notify => "notify",
    });
    assert_tokens!(GateState, InvalidInput, "gate state", {
        Pending => "pending",
        Delivered => "delivered",
        Quarantined => "quarantined",
        Rejected => "rejected",
    });
    assert_tokens!(GateDecision, InvalidInput, "gate decision", {
        Allow => "allow",
        Quarantine => "quarantine",
        Block => "block",
        Error => "error",
    });
    assert_tokens!(GateDirection, InvalidInput, "gate direction", {
        Inbound => "inbound",
        Outbound => "outbound",
        Review => "review",
    });
    assert_tokens!(MailboxKind, InvalidInput, "mailbox kind", {
        Message => "message",
        Event => "event",
        Plugin => "plugin",
        Transfer => "transfer",
        Kv => "kv",
    });
    assert_tokens!(WriteModel, InvalidInput, "kv write model", {
        Owner => "owner",
        Shared => "shared",
        Allowlist => "allowlist",
    });
    assert_tokens!(PeerProfile, InvalidInput, "peer profile", {
        Local => "local",
        Router => "router",
        P2p => "p2p",
    });
    assert_tokens!(TrustTier, InvalidInput, "trust tier", {
        SelfNode => "self",
        Org => "org",
        Peer => "peer",
        Guest => "guest",
    });
    assert_tokens!(PeerStatus, InvalidInput, "peer status", {
        Pending => "pending",
        Active => "active",
        Paused => "paused",
        Revoked => "revoked",
    });
    assert_tokens!(GrantDirection, InvalidInput, "grant direction", {
        Inbound => "inbound",
        Outbound => "outbound",
    });
    assert_tokens!(KeyUse, InvalidInput, "key use", {
        Signing => "signing",
        Encryption => "encryption",
        Prekey => "prekey",
        Admin => "admin",
    });
    assert_tokens!(KeyStatus, InvalidInput, "key status", {
        Active => "active",
        Retired => "retired",
        Revoked => "revoked",
    });
    assert_tokens!(BatchState, InvalidInput, "batch state", {
        Open => "open",
        Pending => "pending",
        Delivered => "delivered",
        Rejected => "rejected",
        Dropped => "dropped",
    });
    assert_tokens!(MessageState, InvalidInput, "message state", {
        Pending => "pending",
        Delivered => "delivered",
        Rejected => "rejected",
        Expired => "expired",
    });
    assert_tokens!(TransferState, InvalidInput, "transfer state", {
        Pending => "pending",
        Delivered => "delivered",
        Rejected => "rejected",
        Expired => "expired",
    });
    assert_tokens!(HumanAuthorityRole, InvalidState, "human authority role", {
        Admin => "admin",
        Signer => "signer",
    });
    assert_tokens!(HumanAuthorityStatus, InvalidState, "human authority status", {
        Active => "active",
        Revoked => "revoked",
    });
    assert_tokens!(HumanClaimKind, InvalidState, "human claim kind", {
        Directive => "directive",
        Secret => "secret",
        HumanInvite => "human_invite",
        Approval => "approval",
    });
}
