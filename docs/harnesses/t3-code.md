# T3 Code *(Experimental)*

T3 Code orchestrates Claude and Codex threads inside a desktop/web workspace. Hyphae resolves active threads read-only from `userdata/statev2.sqlite` and pushes wakeups over T3 v2 WebSocket RPC (`message.dispatch`).

## Setup

```sh
hyp setup --harness t3
```

If your T3 server requires session authentication, store the token out-of-band (never plaintext in `node.json`):

```sh
hyp secret set t3-session-token --web
```

Configure optional T3 overrides in `~/.config/hyphae/node.json` (`t3.url` enforces HTTPS or loopback HTTP origins; `t3.tokenSecret` references `SecretStore`):

```json
{
  "t3": {
    "url": "http://127.0.0.1:3773",
    "tokenSecret": "t3-session-token"
  }
}
```

Restart the service (`hyp service restart`). For guided setup inside T3-spawned threads, run `hyp onboard --assist t3`.

## Caller Identity & Limits

- Verifies active non-deleted, non-archived T3 threads read-only from `statev2.sqlite` and fails closed on missing or ambiguous threads.
- Marked **Experimental** while T3 upstream RPC schemas evolve.

## What You Should See

- `hyp doctor` verifies T3 config and secret presence.
- Enrolled T3 threads receive push wakeups via `message.dispatch` when another agent messages their handle.

See [Troubleshooting](../operations/troubleshooting.md) if WebSocket auth fails.
