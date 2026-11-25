# Phone Drops, Secrets & `hyp exec`

Hand your node an API key or a cryptographically signed directive from your phone — without pasting secrets into chat, shell history, SQLite, or an agent's LLM context — and run user commands with stored secrets via `hyp exec --env`.

---

## 1. Capturing Local Secrets (`hyp secret`)

Store tokens out-of-band directly into your OS secret store (macOS Keychain, Linux Secret Service, or `0600` file fallback):

```sh
# Opens a one-shot 127.0.0.1 CSRF-protected browser form (recommended on laptops)
hyp secret set stripe-key --web

# Headless servers (stdin only — never CLI argv!)
printf '%s' "$STRIPE_KEY" | hyp secret set stripe-key

# Audit secret names & permissions (never prints values)
hyp secret list
```

---

## 2. Running User Commands with Secrets (`hyp exec --env`)

Instead of exporting API keys into `.env` files or printing them in an agent's shell, inject stored application secrets directly into a child process's environment:

```sh
hyp exec --env STRIPE_API_KEY=stripe-key -- ./scripts/check-billing.sh
```

How `hyp exec` works:
- Executes the program directly (`exec`) with **zero shell interpolation** and zero secrets in argv.
- **Blocks fail-closed:** reserved Hyphae system keys (`node-sign-*`, `admin-ca*`, `gate-*`, `human-authority*`, `peer-auth-*`, `pair-*`, `drop-relay-*`, `t3-*`, etc.), **all secrets referenced in `node.json`**, and dangerous loader/shell env vars (`PATH`, `LD_*`, `DYLD_*`, `HYPHAE_*`, `NODE_OPTIONS`, `PYTHON*`, `BASH_ENV`, etc.).
- **Streaming stdout/stderr redaction:** Replaces exact, trimmed, whole-value Base64/Base64url, and URL-encoded forms with `[REDACTED:<secret-name>]` across chunk boundaries.

> **Honest security note:** The stream scrubber guards against **accidental echo** (e.g., verbose `curl -v` or tracebacks), **not** intentional exfiltration or custom encoding by a malicious child process. See [Threat Model](../security/threat-model.md).

---

## 3. Enroll a Phone Passkey for Verified Human Drops

Verified Human Drops let you send zero-knowledge secrets or `TrustTier::HumanVerified` directives from your phone (`https://hyphae.to/drop`) to any Hyphae node (even behind NAT):

```sh
# 1. Pair your phone's WebAuthn Passkey+PRF (derives Ed25519 signing + X25519 draft-encryption keys in 1 prompt)
hyp auth init --web

# 2. Point at Hyphae's public Blind Drop Relay (15-min alarm-wiped ciphertext on spore.hyphae.to)
#    or your own private relay (`workers/drop-relay/` or RAM-only `hyp deploy init drop-relay`)
hyp relay set https://spore.hyphae.to
hyp relay status --probe
```

*(Re-initializing an already-initialized node or revoking keys with `hyp auth revoke <kid> --bump-epoch` requires interactive TTY confirmation in your terminal.)*

---

## 4. Mint and Complete a One-Shot Drop

### Send a secret from your phone straight into OS Keychain

```sh
hyp drop create --kind secret --secret-name stripe-key
hyp drop wait
```

Scan the QR code (or tap the link) on your phone, authenticate with Face ID / Touch ID, and type or paste the secret fresh (prefilled drafts are strictly forbidden for `kind: "secret"`). The phone seals an `hdrop1_` HPKE+Ed25519 envelope to your node's certified X25519 key; your node decrypts it in memory, writes it straight into `SecretStore`, and notifies the waiting agent with metadata only.

### Approve an agent-proposed directive from your phone

Agents (or the CLI) can propose an encrypted directive draft:

```sh
hyp drop create --kind directive --draft "Deploy checkout-api sha 8f3a1c to staging"
hyp drop wait
```

The draft is HPKE-encrypted (`encDraft`) directly into the `#drop=` URL fragment so zero plaintext leaks even if pasted into Slack, Telegram, or SMS. One Face ID / Touch ID tap on `hyphae.to/drop` decrypts the draft in RAM under an amber *"Draft proposed by agent (untrusted)"* banner for review before signing.

For relay storage guarantees (`spore.hyphae.to` ephemeral DO storage with hard 15-minute `storage.deleteAll()` alarm vs. strictly RAM-only self-hosted Rust relays), see [Human Authority & Drop Relay](../security/human-authority.md).

---

## What You Should See

- After scanning and submitting a secret drop, `hyp drop wait` exits `0` with metadata confirmation and `hyp secret list` includes `stripe-key` (never printing its value).
- Running `hyp exec --env TEST_KEY=stripe-key -- env` prints `TEST_KEY=[REDACTED:stripe-key]`.

If the relay probe fails or enrollment times out, check `hyp relay status --probe`, `hyp doctor`, and [Troubleshooting](../operations/troubleshooting.md).
