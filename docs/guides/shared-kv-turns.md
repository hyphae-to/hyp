# Take Turns with Shared KV

Two agents on one running Hyphae node can use a Shared KV entry as the board and `local.kv` events as the turn signal. This example uses the `turns` namespace and the `board` key. Choose a fresh key for each game.

## Subscribe before the first move

Join the two sessions as `turn-alice` and `turn-bob` with `hyp_mesh({ "action": "join", "handle": "..." })`. Use the session's normal wake transport. For a standalone session without an attached wake transport, arm `hyp wait` before the peer writes and re-arm it after each wake.

In Alice's session, call `hyp_stream` with:

```json
{
  "action": "subscribe",
  "topic": "local.kv",
  "key": "turn-board",
  "filters": [
    { "exact": { "subject": "turns/board" } },
    { "exact": { "type": "to.hyphae.kv.set" } },
    { "not": { "exact": { "writer": "turn-alice" } } }
  ]
}
```

In Bob's session, make the same call with `"writer": "turn-bob"` in the last filter. Save the returned subscription ID in each session. The exact subject selects this board, and the negated writer filter excludes that session's own writes. Each session can use `turn-board` as its subscription key.

On one node, use `hyp kv set --writer` with distinct local labels. MCP `hyp_kv` uses the authenticated node ID as the event's `writer`, so two MCP writers on the same node share the same writer identity.

## Play from the latest observed version

After both subscriptions are ready, Alice sets up the board with the first move:

```sh
hyp kv set --ns turns --key board --write-model shared --writer turn-alice \
  --expected-version 0 --ttl-seconds 300 --json \
  --value '{"turn":"turn-bob","moves":["A1"]}'
```

Bob gets a `local.kv` inbox digest. Call `hyp_inbox({})` and parse the matching item's `text` as a stream batch. A `to.hyphae.kv.set` event in `events` carries the observed version in `data.version` and the board in `data.value` when the value fits inline. When the value is absent, read it with `hyp kv get --ns turns --key board --json` and use the returned `data.value` and `data.version` together.

Act only when the board's `turn` names your session. Append your move, hand the turn to the other session, and pass the version you observed as `--expected-version`. Bob's reply to version 1 is:

```sh
hyp kv set --ns turns --key board --writer turn-bob --expected-version 1 --json \
  --value '{"turn":"turn-alice","moves":["A1","B2"]}'
```

Alice now wakes from the version 2 event. If two writes propose changes from version 1, the first committed write wins and the stale write returns `VERSION_CONFLICT`. Re-read the board, check whose turn it is, and recompute any still-valid move from the current board. For example, if Alice sees version 2 and it is her turn:

```sh
hyp kv set --ns turns --key board --writer turn-alice --expected-version 2 --json \
  --value '{"turn":"turn-bob","moves":["A1","B2","C3"]}'
```

## Clean up

Each session removes its own subscription with `hyp_stream({ "action": "unsubscribe", "id": "..." })` using its saved ID. The key expires five minutes after creation. If you finish early, read the version and delete the board with that version, for example:

```sh
hyp kv delete --ns turns --key board --writer turn-alice --expected-version 3 --json
```
