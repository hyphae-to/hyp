# Plugin v2 regression preservation

The positive legacy supervisor fixture is replaced by a host-first v2 fixture retaining publication, post correlation, status, oversized-frame rejection, secret/environment isolation, and shutdown checks. A nearby legacy frame is explicitly rejected on that live connection; all eight retired frame variants remain negative parser cases. The existing v2 child discovery request is still exercised after the deterministic host greeting.

Real Node/Python SDK and bundled bridge subprocess tests retain stored/duplicate results, invalid-event/unknown-target failures, posts/reactions, status delivery, Windows TCP authentication and token scrubbing, Unix fd3, crash-loop handling, logs, and native-adapter differential parity. Assertions now inspect v2 results and numeric errors. Source fixtures retain unavailable-store retry/cursor behavior.

A shared Node/Python subprocess scenario sends concurrent events with the same CloudEvent ID, reverses RPC replies, and interleaves a host post/status while publication is pending. Nearby invalid cases reject a legacy hello, oversized input/output, partial EOF and disconnect without waiting for request timeout. A blocked real supervisor publication proves post responses continue to be read before that publication can finish. Frame bounds and pending-work caps prevent unbounded queues; disconnect/stop aborts outstanding host work and the writer.

Bundled file integrity pins remain generated from normalized source bytes by `crates/hyp-cli/build.rs`; existing packaging/installation mutation tests verify the changed SDK and consumers rather than replacing those checks with fixed hashes.
