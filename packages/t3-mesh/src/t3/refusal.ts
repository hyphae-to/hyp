// What to do when T3 refuses a message.dispatch (SPEC.md section 5). A refused command ID can never
// be reused, so every outcome here moves the item to its next attempt; this decides whether that
// attempt happens (hold) or the item is dropped (rejected).
import type { InboundOutcome } from "../router/types.ts";

/** T3's refusals of a steer into a run that is ending (orchestration-v2 Orchestrator steering checks). */
const STEER_RACE =
  /cannot be steered|No running provider turn found|no active provider session for steering|before steering the thread|has no root node/i;
/** A message T3 refuses this many times for other reasons is rejected for good. */
export const MAX_REFUSED_ATTEMPTS = 3;

export interface Refusal {
  readonly outcome: InboundOutcome;
  /** Retry without deliveryIntent, as a plain queued message. */
  readonly queueNext: boolean;
}

/** `attempt` is the number of the attempt T3 just refused (1 for the first). */
export function classifyRefusal(message: string, attempt: number): Refusal {
  if (/previously rejected/i.test(message)) return { outcome: { kind: "hold", reason: "stale_command_id" }, queueNext: false };
  // T3 resolved "auto" to a steer, but the run's turn finished (or its session went away) before the
  // steer landed. That is a race, not a refusal of the message: queue it instead. Not counted
  // against the limit, since the next attempt cannot steer.
  if (STEER_RACE.test(message)) return { outcome: { kind: "hold", reason: `t3_steer_race: ${message}` }, queueNext: true };
  // Other refusals may also be passing thread states; drop only after a few tries.
  if (attempt < MAX_REFUSED_ATTEMPTS) return { outcome: { kind: "hold", reason: `t3_refused_retrying: ${message}` }, queueNext: false };
  return { outcome: { kind: "rejected", reason: `t3_rejected: ${message}` }, queueNext: false };
}
