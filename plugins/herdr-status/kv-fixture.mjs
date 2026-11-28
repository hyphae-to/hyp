// Used by the native CLI E2E test. All terminal facts are fictional.
import { localKv, parseBinding, publishStatus } from "./publish.mjs";

const [binary, stateDir] = process.argv.slice(2);
const terminal = (address, state) => ({ address, created_ms: 100, state: "live", status: { state } });
const frame = (seq, terminal, type, data) => ({ method: "event", params: { seq, terminal, type, data } });
const a = parseBinding(["builder-a", "t1", "100", stateDir]);
const b = parseBinding(["builder-b", "t2", "100", stateDir]);
await publishStatus(a, [
  { seq: 0, terminals: [terminal("t1", "working")] },
  frame(1, "t1", "status", { status: { state: "working", msg: "fictional-private-message" } }),
  frame(2, "t1", "status", { status: { state: "blocked", kind: "question" } }),
  frame(3, "t1", "finished", {}),
], localKv(a, binary));
await publishStatus(b, [{ seq: 0, terminals: [terminal("t2", "idle")] }], localKv(b, binary));
