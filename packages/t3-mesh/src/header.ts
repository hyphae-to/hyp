// The first line of a delivered mesh message, plus T3 message context pointing at the sending thread.
//
// The model reads the sender address and reply instruction from the header. For people, when the
// sending thread is known, the address is a T3 context reference to a `thread` record carrying the
// sender's environment and thread ID: web and mobile clients render it as a chip that opens that
// thread in its own environment (if the client is connected to it). Origin IDs come from the
// sending connector, so they are only used when they look like T3 IDs.
import { ComposerContextId, EnvironmentId, ThreadId, type OrchestrationMessageContext } from "@t3tools/contracts";
import type { InboundMessage } from "./router/types.ts";

const ID = /^[A-Za-z0-9][A-Za-z0-9:._~-]{0,199}$/;
const SENDER_CONTEXT_ID = ComposerContextId.make("mesh_sender");
/** `[label](t3-context://v1/<kind>/<contextId>)`, as in @t3tools/shared composerContextReferences. */
const SENDER_HREF = `t3-context://v1/thread/${SENDER_CONTEXT_ID}`;

export interface Delivery {
  readonly text: string;
  readonly context: OrchestrationMessageContext | null;
}

/** A thread link that T3 renders as a chip opening the thread in its own environment. */
export const threadContext = (label: string, environmentId: string, threadId: string): OrchestrationMessageContext => ({
  version: 1,
  records: [
    {
      version: 1,
      kind: "thread",
      contextId: SENDER_CONTEXT_ID,
      label,
      environmentId: EnvironmentId.make(environmentId),
      threadId: ThreadId.make(threadId),
      title: label,
    },
  ],
});

export function senderContext(message: Pick<InboundMessage, "from" | "origin">): OrchestrationMessageContext | null {
  const origin = message.origin;
  if (origin === null || !ID.test(origin.environmentId) || !ID.test(origin.threadId)) return null;
  return threadContext(message.from, origin.environmentId, origin.threadId);
}

/** The header link that points at the thread in `threadContext` (`[label](...)`). */
export const contextLink = (label: string): string => `[${label}](${SENDER_HREF})`;

/** Whether a string is safe to use as an environment or thread ID in a context record. */
export const isContextId = (value: string): boolean => ID.test(value);

/**
 * T3 expands `[label](t3-context://v1/<kind>/<id>)` anywhere in a message into a `<t3_context>`
 * block appended after the text, before the provider sees it. A body must not be able to add such
 * blocks, so `](t3-context:` is escaped to `]\(t3-context:`: no longer a link to T3, and
 * Markdown still renders it as the same characters.
 */
export const neutralizeContextLinks = (text: string): string => text.replaceAll("](t3-context:", "]\\(t3-context:");

export function formatDelivery(message: InboundMessage): Delivery {
  const context = senderContext(message);
  // No brackets around the header: T3's context-link pattern allows "[" in a label, so an outer
  // "[" would be swallowed into the chip. Short on purpose; the message ID stays in the connector and router logs. "remote thread" tells the
  // model the referenced thread is not readable with t3_thread_read (T3's context note suggests it).
  const header =
    context === null
      ? `mesh from ${message.from} · reply with mesh_send`
      : `mesh from [${message.from}](${SENDER_HREF}) · remote thread · reply with mesh_send`;
  return { text: `${header}\n\n${neutralizeContextLinks(message.text)}`, context };
}
