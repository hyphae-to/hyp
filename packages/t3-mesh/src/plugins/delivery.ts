// The text of a delivered plugin batch (SPEC.md section 13.4): section 12.6's framing, headed by the
// plugin name from config.json. Per-event lines carry `type`, `source` and `subject`, each checked
// against a strict pattern; the data stays below the untrusted-data line in an escaped fence.
import { eventCount, eventLine, formatEventText, PATTERNS, safe } from "../eventDelivery.ts";
import type { InboundEventBatch } from "../router/types.ts";

/** `plugin` is a configured name, already checked against PLUGIN_NAME. */
export function formatPluginDelivery(plugin: string, batch: InboundEventBatch): string {
  const header = `mesh event plugin:${plugin} · ${eventCount(batch.events.length)}`;
  const lines = batch.events.map((event) =>
    eventLine(safe(PATTERNS.type, event.type), safe(PATTERNS.source, event.source), safe(PATTERNS.subject, event.subject)),
  );
  return formatEventText(header, lines, batch.events);
}
