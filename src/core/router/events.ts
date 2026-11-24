// Topics, publishers, subscriptions and coalesced event batches (SPEC.md section 12), on the
// router's SQLite database. RouterCore owns the database, the connector attachments and the inbox;
// it asks this class which batches are due and offers them next to messages.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import * as Schema from "../validate.ts";
import { isConnectorId } from "../address.ts";
import { checkCloudEvent, eventDigest, isTopic, type CloudEvent } from "./cloudevent.ts";
import { checkFilters, matchesFilters, type Filter } from "./filter.ts";
import type { InboundOutcome, InboxItem, SubscriptionDelivery } from "./types.ts";

export interface EventLimits {
  readonly retentionMs: number;
  readonly maxPendingBatchesPerSubscription: number;
  /** Wake cap: batches delivered per subscription per hour. Over it, closed batches wait. */
  readonly maxBatchesPerHourPerSubscription: number;
  readonly maxBatchEvents: number;
  /** A batch closes this long after its first event even if events keep coming. */
  readonly maxBatchAgeMs: number;
  readonly maxCoalesceSeconds: number;
  readonly maxSubscriptionsPerConnector: number;
  /** How long (topic, publisher, source, id) and the content digest are kept after the event body is gone. */
  readonly idempotencyMs: number;
}

export const DEFAULT_EVENT_LIMITS: EventLimits = {
  retentionMs: 24 * 60 * 60 * 1000,
  maxPendingBatchesPerSubscription: 100,
  maxBatchesPerHourPerSubscription: 30,
  maxBatchEvents: 20,
  maxBatchAgeMs: 5 * 60 * 1000,
  maxCoalesceSeconds: 600,
  maxSubscriptionsPerConnector: 200,
  idempotencyMs: 7 * 24 * 60 * 60 * 1000,
};

const HOUR_MS = 60 * 60 * 1000;
/** Retention is measured in hours, so pruning once a minute is enough and keeps the per-second tick read-only. */
const PRUNE_INTERVAL_MS = 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Per-subscription batch counts for one connector. Reached through the connector's subscriptions
 * (subscriptions_connector, then batches_subscription), so the cost follows that connector's
 * batches rather than every connector's.
 */
export const DELIVERY_STATUS_SQL =
  "SELECT subscription_id, state, reason, COUNT(*) AS n, MIN(opened_at) AS oldest, MAX(settled_at) AS last, MAX(hold_until) AS held FROM batches " +
  "WHERE subscription_id IN (SELECT id FROM subscriptions WHERE connector_id = ?) AND connector_id = ? AND state <> 'open' " +
  "GROUP BY subscription_id, state, reason";

export const EVENTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS publishers (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS publisher_grants (
  publisher_id TEXT NOT NULL REFERENCES publishers(id) ON DELETE CASCADE,
  topic TEXT NOT NULL,
  PRIMARY KEY (publisher_id, topic)
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL,
  topic TEXT NOT NULL,
  filters TEXT NOT NULL,
  coalesce_seconds INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  max_batch_age_ms INTEGER,
  max_batches_per_hour INTEGER
);
CREATE INDEX IF NOT EXISTS subscriptions_topic ON subscriptions (topic);
CREATE INDEX IF NOT EXISTS subscriptions_connector ON subscriptions (connector_id);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  topic TEXT NOT NULL,
  publisher TEXT NOT NULL,
  source TEXT NOT NULL,
  id TEXT NOT NULL,
  digest TEXT NOT NULL,
  body TEXT,
  bytes INTEGER NOT NULL,
  matched INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL,
  UNIQUE (topic, publisher, source, id)
);
CREATE INDEX IF NOT EXISTS events_received ON events (received_at);
CREATE INDEX IF NOT EXISTS events_with_body ON events (received_at) WHERE body IS NOT NULL;
CREATE TABLE IF NOT EXISTS batches (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  topic TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open', 'pending', 'delivered', 'rejected', 'dropped')),
  event_count INTEGER NOT NULL DEFAULT 0,
  opened_at INTEGER NOT NULL,
  last_event_at INTEGER NOT NULL,
  closed_at INTEGER,
  hold_until INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS batches_subscription ON batches (subscription_id, state, closed_at);
CREATE INDEX IF NOT EXISTS batches_state ON batches (state);
CREATE TABLE IF NOT EXISTS batch_events (
  batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  event_seq INTEGER NOT NULL,
  PRIMARY KEY (batch_id, position)
);
CREATE INDEX IF NOT EXISTS batch_events_event ON batch_events (event_seq);
`;

const SubscriptionRow = Schema.Struct({
  id: Schema.String,
  connector_id: Schema.String,
  topic: Schema.String,
  filters: Schema.String,
  coalesce_seconds: Schema.Number,
  created_at: Schema.Number,
  max_batch_age_ms: Schema.NullOr(Schema.Number),
  max_batches_per_hour: Schema.NullOr(Schema.Number),
});
type SubscriptionRow = typeof SubscriptionRow.Type;
const decodeSubscriptionRows = Schema.decodeUnknownSync(Schema.Array(SubscriptionRow));
const BatchRow = Schema.Struct({
  id: Schema.String,
  subscription_id: Schema.String,
  connector_id: Schema.String,
  topic: Schema.String,
  state: Schema.String,
  event_count: Schema.Number,
  opened_at: Schema.Number,
  last_event_at: Schema.Number,
  closed_at: Schema.NullOr(Schema.Number),
  hold_until: Schema.Number,
});
type BatchRow = typeof BatchRow.Type;
const decodeBatchRow = Schema.decodeUnknownSync(BatchRow);
const decodeBatchRows = Schema.decodeUnknownSync(Schema.Array(BatchRow));
const EventKeyRow = Schema.Struct({ digest: Schema.String, matched: Schema.Number });
const decodeEventKeyRow = Schema.decodeUnknownSync(EventKeyRow);
const BodyRow = Schema.Struct({ body: Schema.NullOr(Schema.String) });
const decodeBodyRows = Schema.decodeUnknownSync(Schema.Array(BodyRow));
const IdRow = Schema.Struct({ id: Schema.String });
const decodeIdRow = Schema.decodeUnknownSync(IdRow);
const TopicRow = Schema.Struct({ topic: Schema.String });
const decodeTopicRows = Schema.decodeUnknownSync(Schema.Array(TopicRow));
const CountRow = Schema.Struct({ n: Schema.Number });
const decodeCount = (row: unknown): number => Schema.decodeUnknownSync(CountRow)(row).n;
const SeqRow = Schema.Struct({ seq: Schema.Number });
const BatchLimitsRow = Schema.Struct({ coalesce_seconds: Schema.Number, max_batch_age_ms: Schema.NullOr(Schema.Number) });
const decodeBatchLimitsRow = Schema.decodeUnknownSync(BatchLimitsRow);
const PendingRow = Schema.Struct({ subscription_id: Schema.String, n: Schema.Number, oldest: Schema.Number });
const decodePendingRows = Schema.decodeUnknownSync(Schema.Array(PendingRow));
const decodeSeqRow = Schema.decodeUnknownSync(SeqRow);
const StatusRow = Schema.Struct({
  subscription_id: Schema.String,
  state: Schema.String,
  reason: Schema.NullOr(Schema.String),
  n: Schema.Number,
  oldest: Schema.Number,
  last: Schema.NullOr(Schema.Number),
  held: Schema.Number,
});
const decodeStatusRows = Schema.decodeUnknownSync(Schema.Array(StatusRow));

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

export type PublishError = "unknown_topic" | "not_granted" | "invalid_event" | "too_large" | "id_conflict";

export type PublishResult =
  | { readonly ok: true; readonly status: "stored"; readonly matched: number }
  | { readonly ok: false; readonly error: PublishError; readonly message: string };

/** A subscription as the connector sends it in `PUT /v1/subscriptions` (SPEC.md section 12.3). */
export interface SubscriptionSpec {
  readonly id: string;
  readonly topic: string;
  readonly filters: unknown;
  readonly coalesceSeconds: number;
  /**
   * Per-subscription overrides of `maxBatchAgeMs` and `maxBatchesPerHourPerSubscription`, for the
   * connector's local plugin store (SPEC.md section 13.4). The HTTP router never decodes them.
   */
  readonly maxBatchAgeMs?: number | undefined;
  readonly maxBatchesPerHour?: number | undefined;
}

export type SubscriptionsResult =
  | {
      readonly ok: true;
      /** Topics of the set that the router does not serve; their subscriptions are kept but match nothing. */
      readonly unknownTopics: readonly string[];
      /** Per-subscription reachability & filter lint diagnostics (empty map entries omitted). */
      readonly diagnostics: Readonly<Record<string, readonly SubscriptionDiagnostic[]>>;
    }
  | {
      readonly ok: false;
      readonly error: "invalid" | "invalid_filter" | "too_many_subscriptions" | "id_conflict";
      readonly message: string;
      readonly id?: string;
      readonly path?: string;
    };

export interface TopicScope {
  readonly repos?: readonly string[];
  readonly orgs?: readonly string[];
  readonly subjects?: readonly string[];
}

export interface TopicSchema {
  readonly attributes?: readonly string[];
  readonly eventTypes?: readonly string[];
  readonly filterExamples?: readonly string[];
}

export interface TopicMetadata {
  readonly kind?: string;
  readonly description?: string;
  readonly scope?: TopicScope;
  readonly schema?: TopicSchema;
  readonly setupGuide?: string;
}

export interface TopicInfo {
  readonly topic: string;
  readonly publishers: readonly { readonly id: string; readonly provisioned: boolean }[];
  readonly metadata: TopicMetadata | null;
  readonly observed: {
    readonly eventCount: number;
    readonly lastEventAt: string | null;
    readonly sources: readonly string[];
    readonly repos: readonly string[];
  };
}

export interface SubscriptionDiagnostic {
  readonly severity: "error" | "warn" | "info";
  readonly code:
    | "unknown_topic"
    | "unprovisioned_publisher"
    | "invalid_github_subject_filter"
    | "invalid_github_repo_format"
    | "invalid_github_source_format"
    | "unknown_filter_attribute"
    | "unmonitored_repo"
    | "unobserved_repo"
    | "topic_no_events_yet";
  readonly message: string;
  readonly remediation?: string;
  readonly suggestedFilter?: Readonly<Record<string, unknown>>;
}

export interface Publisher {
  readonly id: string;
  readonly topics: ReadonlySet<string>;
}

export interface EventRouterOptions {
  /** Topic -> publisher IDs allowed to publish to it, from the router's startup config. */
  readonly topics: ReadonlyMap<string, readonly string[]>;
  readonly limits: EventLimits;
  readonly holdRetryMs: number;
  readonly now: () => number;
  readonly audit: (fields: Readonly<Record<string, unknown>>) => void;
  /** Called when a connector may have newly due batches. */
  readonly ready: (connectorId: string) => void;
  /** Whether the batch is offered to its connector and not yet answered. */
  readonly inFlight: (connectorId: string, batchId: string) => boolean;
}

interface Subscription {
  readonly id: string;
  readonly connectorId: string;
  readonly topic: string;
  readonly filters: readonly Filter[];
  readonly coalesceSeconds: number;
  readonly maxBatchAgeMs: number | null;
}

/** Pending batches of one subscription, for reporting a backlog. */
export interface PendingSummary {
  readonly subscriptionId: string;
  readonly pending: number;
  /** When the oldest pending batch's first event arrived. */
  readonly oldestOpenedAt: number;
}

const isPositiveInteger = (value: number | undefined): boolean =>
  value === undefined || (Number.isInteger(value) && value > 0);

const STANDARD_CE_ATTRIBUTES = new Set([
  "specversion",
  "id",
  "source",
  "type",
  "subject",
  "time",
  "datacontenttype",
  "dataschema",
]);

const GITHUB_SUBJECT_PREFIXES = ["pull/", "issues/", "actions/", "refs/"];
const OWNER_REPO_LIKE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/.*)?$/;

interface FlatPredicate {
  readonly dialect: "exact" | "prefix" | "suffix";
  readonly key: string;
  readonly value: string;
}

function collectPositivePredicates(filters: readonly Filter[], out: FlatPredicate[] = []): FlatPredicate[] {
  for (const filter of filters) {
    if ("exact" in filter) {
      for (const [key, value] of Object.entries(filter.exact)) out.push({ dialect: "exact", key, value });
    } else if ("prefix" in filter) {
      for (const [key, value] of Object.entries(filter.prefix)) out.push({ dialect: "prefix", key, value });
    } else if ("suffix" in filter) {
      for (const [key, value] of Object.entries(filter.suffix)) out.push({ dialect: "suffix", key, value });
    } else if ("all" in filter) {
      collectPositivePredicates(filter.all, out);
    } else if ("any" in filter) {
      collectPositivePredicates(filter.any, out);
    }
    // Intentionally skip `not` branches: excluding a repo/source is not subscribing to it.
  }
  return out;
}

function normalizeRepoRef(raw: string): string {
  return raw
    .trim()
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/^github\.com\//i, "")
    .replace(/\/+$/, "");
}

export class EventRouter {
  readonly #db: DatabaseSync;
  readonly #options: EventRouterOptions;
  readonly #limits: EventLimits;
  readonly #topicMetadata = new Map<string, TopicMetadata>();
  #lastPrune = Number.NEGATIVE_INFINITY;
  /** Audit lines of the open transaction, written after COMMIT so a rollback leaves none. */
  #auditBuffer: Array<Readonly<Record<string, unknown>>> | null = null;

  constructor(db: DatabaseSync, options: EventRouterOptions) {
    this.#db = db;
    this.#options = options;
    this.#limits = options.limits;
  }

  /** Creates the event tables. RouterCore runs it inside its schema transaction. */
  static migrate(db: DatabaseSync): void {
    db.exec(EVENTS_SCHEMA);
    const columns = db.prepare("SELECT name FROM pragma_table_info('events')").all();
    if (!columns.some((row) => row["name"] === "publisher")) {
      // Only builds of the events branch before review created this table.
      throw new Error("the events table predates publisher-scoped event keys; recreate the router database");
    }
    // Per-subscription limits came later; NULL means the router-wide limit.
    const subscriptionColumns = db.prepare("SELECT name FROM pragma_table_info('subscriptions')").all();
    for (const column of ["max_batch_age_ms", "max_batches_per_hour"]) {
      if (!subscriptionColumns.some((row) => row["name"] === column)) {
        db.exec(`ALTER TABLE subscriptions ADD COLUMN ${column} INTEGER`);
      }
    }
  }

  get topics(): ReadonlyMap<string, readonly string[]> {
    return this.#options.topics;
  }

  /** Attaches declared scope, CloudEvents schema, and setup guidance for a router topic. */
  setTopicMetadata(topic: string, metadata: TopicMetadata): void {
    this.#topicMetadata.set(topic, metadata);
  }

  topicInfo(topic: string): TopicInfo | null {
    const allowedPublishers = this.#options.topics.get(topic);
    if (allowedPublishers === undefined) return null;
    const publishers = allowedPublishers.map((id) => {
      const granted = this.#db
        .prepare(
          "SELECT p.id FROM publishers p JOIN publisher_grants g ON g.publisher_id = p.id " +
            "WHERE p.id = ? AND g.topic = ? AND p.revoked_at IS NULL",
        )
        .get(id, topic);
      return { id, provisioned: granted !== undefined };
    });
    const stats = this.#db
      .prepare("SELECT COUNT(*) AS n, MAX(received_at) AS last FROM events WHERE topic = ?")
      .get(topic) as { n?: unknown; last?: unknown } | undefined;
    const eventCount = Number(stats?.n ?? 0);
    const lastMs = stats?.last === null || stats?.last === undefined ? null : Number(stats.last);
    const sourceRows = this.#db
      .prepare("SELECT DISTINCT source FROM events WHERE topic = ? ORDER BY source LIMIT 50")
      .all(topic) as Array<{ source?: unknown }>;
    const sources = sourceRows.map((row) => String(row.source));
    const repos = sources
      .filter((s) => s.startsWith("github.com/") && s.split("/").length >= 3)
      .map((s) => s.slice("github.com/".length));
    return {
      topic,
      publishers,
      metadata: this.#topicMetadata.get(topic) ?? null,
      observed: {
        eventCount,
        lastEventAt: lastMs === null ? null : new Date(lastMs).toISOString(),
        sources,
        repos,
      },
    };
  }

  /** Lists every configured topic, its publisher provisioning state, declared scope/schema, and observed sources. */
  topicCatalog(): TopicInfo[] {
    return [...this.#options.topics.keys()]
      .sort()
      .map((topic) => this.topicInfo(topic))
      .filter((info): info is TopicInfo => info !== null);
  }

  /**
   * Static + dynamic reachability lint for a subscription's filters against a topic's declared
   * scope, CloudEvents schema, and observed webhook deliveries. Catches dead subscriptions (such
   * as filtering GitHub `subject` instead of `repo`, or subscribing to a repo without the GitHub
   * webhook/App installed).
   */
  diagnoseSubscription(topic: string, filters: readonly Filter[]): SubscriptionDiagnostic[] {
    const info = this.topicInfo(topic);
    if (info === null) {
      const available = [...this.#options.topics.keys()].sort();
      return [{
        severity: "error",
        code: "unknown_topic",
        message: `Topic '${topic}' is not configured on this router (available: ${available.length > 0 ? available.join(", ") : "none"}).`,
        remediation: "Call hyp_topics to inspect available topics, or add the stream on your router host via `hyp connect add`.",
      }];
    }

    const diagnostics: SubscriptionDiagnostic[] = [];
    if (info.publishers.length === 0 || info.publishers.every((p) => !p.provisioned)) {
      diagnostics.push({
        severity: "warn",
        code: "unprovisioned_publisher",
        message: `Topic '${topic}' has no active provisioned publisher token on this router.`,
        remediation: "Provision a publisher (`hyp node add-publisher <id> --topic " + topic + "`) or verify the stream started cleanly.",
      });
    }

    const predicates = collectPositivePredicates(filters);
    const isGithub = info.metadata?.kind === "github-webhook" || topic === "github";
    const allowedAttributes = info.metadata?.schema?.attributes
      ? new Set([...STANDARD_CE_ATTRIBUTES, ...info.metadata.schema.attributes])
      : null;
    const referencedRepos = new Set<string>();

    for (const pred of predicates) {
      if (allowedAttributes && !pred.key.startsWith("data.") && !allowedAttributes.has(pred.key)) {
        diagnostics.push({
          severity: "warn",
          code: "unknown_filter_attribute",
          message: `Filter references attribute '${pred.key}', which is not in '${topic}' schema attributes (${[...allowedAttributes].join(", ")}).`,
          remediation: info.metadata?.schema?.filterExamples?.length
            ? `Example valid filter: ${info.metadata.schema.filterExamples[0]}`
            : undefined,
        });
      }

      if (!isGithub) continue;

      if (
        pred.key === "subject" &&
        pred.dialect !== "suffix" &&
        OWNER_REPO_LIKE.test(pred.value) &&
        !GITHUB_SUBJECT_PREFIXES.some((prefix) => pred.value.startsWith(prefix))
      ) {
        const cleanRepo = normalizeRepoRef(pred.value).split("/").slice(0, 2).join("/");
        referencedRepos.add(cleanRepo);
        diagnostics.push({
          severity: "error",
          code: "invalid_github_subject_filter",
          message:
            `Filter '${pred.dialect}.subject = ${JSON.stringify(pred.value)}' will NEVER match GitHub CloudEvents. ` +
            `GitHub events put the repository in 'repo' ("owner/repo") and 'source' ("github.com/owner/repo"); ` +
            `'subject' holds "pull/<n>", "issues/<n>", "actions/runs/<id>", or "refs/heads/<branch>".`,
          remediation: `Replace the filter with { exact: { repo: ${JSON.stringify(cleanRepo)} } } (or { prefix: { repo: "owner/" } } for an org).`,
          suggestedFilter: { exact: { repo: cleanRepo } },
        });
      } else if (pred.key === "repo") {
        if (/^(?:https?:\/\/)?github\.com\//i.test(pred.value)) {
          const cleanRepo = normalizeRepoRef(pred.value);
          referencedRepos.add(cleanRepo);
          diagnostics.push({
            severity: "error",
            code: "invalid_github_repo_format",
            message:
              `Filter '${pred.dialect}.repo = ${JSON.stringify(pred.value)}' includes a URL/host prefix and will NEVER match. ` +
              `GitHub 'repo' is formatted as "owner/repo".`,
            remediation: `Use { ${pred.dialect}: { repo: ${JSON.stringify(cleanRepo)} } }.`,
            suggestedFilter: { [pred.dialect]: { repo: cleanRepo } },
          });
        } else if (pred.dialect !== "suffix" && pred.value.trim().length > 0) {
          referencedRepos.add(normalizeRepoRef(pred.value));
        }
      } else if (pred.key === "source" && pred.dialect !== "suffix") {
        if (/^github\.com\//i.test(pred.value)) {
          const rest = normalizeRepoRef(pred.value);
          if (rest.length > 0) referencedRepos.add(rest);
        } else if (OWNER_REPO_LIKE.test(pred.value)) {
          const cleanRepo = normalizeRepoRef(pred.value);
          referencedRepos.add(cleanRepo);
          diagnostics.push({
            severity: "error",
            code: "invalid_github_source_format",
            message:
              `Filter '${pred.dialect}.source = ${JSON.stringify(pred.value)}' omits the "github.com/" prefix and will NEVER match.`,
            remediation: `Use { ${pred.dialect}: { source: ${JSON.stringify(`github.com/${cleanRepo}`)} } } or { ${pred.dialect}: { repo: ${JSON.stringify(cleanRepo)} } }.`,
            suggestedFilter: { [pred.dialect]: { repo: cleanRepo } },
          });
        }
      }
    }

    const scopeRepos = (info.metadata?.scope?.repos ?? []).map((r) => normalizeRepoRef(r).toLowerCase()).filter(Boolean);
    const scopeOrgs = (info.metadata?.scope?.orgs ?? []).map((o) => o.trim().toLowerCase()).filter(Boolean);
    const hasDeclaredScope = scopeRepos.length > 0 || scopeOrgs.length > 0;
    const isCoveredByScope = (ref: string): boolean => {
      const target = ref.toLowerCase();
      if (scopeRepos.some((r) => r === target || r.startsWith(`${target}/`))) return true;
      if (scopeOrgs.some((o) => target === o || target.startsWith(`${o}/`))) return true;
      return false;
    };

    for (const ref of referencedRepos) {
      if (hasDeclaredScope && !isCoveredByScope(ref)) {
        const coveredSummary = [
          ...(scopeRepos.length > 0 ? [`repos: [${scopeRepos.join(", ")}]`] : []),
          ...(scopeOrgs.length > 0 ? [`orgs: [${scopeOrgs.join(", ")}]`] : []),
        ].join(", ");
        diagnostics.push({
          severity: "error",
          code: "unmonitored_repo",
          message:
            `Repository/org '${ref}' is NOT in the configured '${topic}' stream scope (${coveredSummary}). ` +
            `This subscription will NEVER receive notifications until the GitHub App or webhook is installed on '${ref}' and added to GITHUB_REPOS / GITHUB_ORGS.`,
          remediation:
            info.metadata?.setupGuide ??
            `Install the GitHub App or webhook on '${ref}' pointing to /hooks/github, add '${ref}' to GITHUB_REPOS in connector.json, and restart the daemon.`,
        });
      } else if (
        info.observed.eventCount > 0 &&
        !info.observed.repos.some((obs) => {
          const low = obs.toLowerCase();
          const target = ref.toLowerCase();
          return low === target || low.startsWith(`${target}/`);
        })
      ) {
        diagnostics.push({
          severity: "warn",
          code: "unobserved_repo",
          message:
            `No webhook deliveries from '${ref}' have been observed on topic '${topic}' yet ` +
            `(observed repos: ${info.observed.repos.length > 0 ? info.observed.repos.join(", ") : "none"}).`,
          remediation:
            `Confirm the GitHub App or webhook is installed on '${ref}' and check Settings -> Webhooks -> Recent Deliveries (or send a ping delivery).`,
        });
      }
    }

    if (info.observed.eventCount === 0) {
      diagnostics.push({
        severity: "info",
        code: "topic_no_events_yet",
        message: `Topic '${topic}' has received 0 events so far on this router.`,
        ...(info.metadata?.setupGuide ? { remediation: info.metadata.setupGuide } : {}),
      });
    }

    return diagnostics;
  }

  #now(): number {
    return this.#options.now();
  }

  #audit(fields: Readonly<Record<string, unknown>>): void {
    if (this.#auditBuffer !== null) this.#auditBuffer.push(fields);
    else this.#options.audit(fields);
  }

  #transaction<T>(body: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    const buffer: Array<Readonly<Record<string, unknown>>> = [];
    this.#auditBuffer = buffer;
    let result: T;
    try {
      result = body();
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    } finally {
      this.#auditBuffer = null;
    }
    for (const fields of buffer) this.#options.audit(fields);
    return result;
  }

  // ---- publishers ----

  /**
   * Registers a publisher with `publish:<topic>` grants and returns its bearer token (shown once;
   * only the hash is stored). A revoked publisher can be added again, with a new token.
   */
  addPublisher(id: string, topics: readonly string[]): string {
    if (!isConnectorId(id)) throw new Error(`invalid publisher id ${id}`);
    if (topics.length === 0) throw new Error("a publisher needs at least one topic");
    const bad = topics.filter((topic) => !isTopic(topic));
    if (bad.length > 0) throw new Error(`invalid topic ${bad.join(", ")}`);
    if (this.#db.prepare("SELECT id FROM connectors WHERE id = ?").get(id) !== undefined) {
      throw new Error(`${id} is a connector; publishers and connectors need different ids`);
    }
    const existing = this.#db.prepare("SELECT id FROM publishers WHERE id = ? AND revoked_at IS NULL").get(id);
    if (existing !== undefined) throw new Error(`publisher ${id} exists; revoke it first to issue a new token`);
    const token = `t3p_${randomBytes(32).toString("base64url")}`;
    this.#transaction(() => {
      this.#db.prepare("DELETE FROM publishers WHERE id = ?").run(id);
      this.#db
        .prepare("INSERT INTO publishers (id, token_hash, created_at) VALUES (?, ?, ?)")
        .run(id, hashToken(token), this.#now());
      for (const topic of new Set(topics)) {
        this.#db.prepare("INSERT INTO publisher_grants (publisher_id, topic) VALUES (?, ?)").run(id, topic);
      }
    });
    this.#audit({ event: "publisher.added", publisher: id, topics: [...new Set(topics)] });
    return token;
  }

  revokePublisher(id: string): boolean {
    const changed = this.#db
      .prepare("UPDATE publishers SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .run(this.#now(), id).changes;
    if (Number(changed) === 0) return false;
    this.#audit({ event: "publisher.revoked", publisher: id });
    return true;
  }

  isPublisher(id: string): boolean {
    return this.#db.prepare("SELECT id FROM publishers WHERE id = ?").get(id) !== undefined;
  }

  /** The publisher for a valid, unrevoked publisher token, with its granted topics. */
  authenticatePublisher(token: string): Publisher | null {
    const row = this.#db
      .prepare("SELECT id FROM publishers WHERE token_hash = ? AND revoked_at IS NULL")
      .get(hashToken(token));
    if (row === undefined) return null;
    const { id } = decodeIdRow(row);
    const grants = decodeTopicRows(
      this.#db.prepare("SELECT topic FROM publisher_grants WHERE publisher_id = ?").all(id),
    );
    return { id, topics: new Set(grants.map((grant) => grant.topic)) };
  }

  /** Configured (topic, publisher) pairs without an active publisher token granted that topic. */
  unprovisionedPublishers(): Array<{ readonly topic: string; readonly publisher: string }> {
    const missing: Array<{ topic: string; publisher: string }> = [];
    for (const [topic, publishers] of this.#options.topics) {
      for (const publisher of publishers) {
        const granted = this.#db
          .prepare(
            "SELECT p.id FROM publishers p JOIN publisher_grants g ON g.publisher_id = p.id " +
              "WHERE p.id = ? AND g.topic = ? AND p.revoked_at IS NULL",
          )
          .get(publisher, topic);
        if (granted === undefined) missing.push({ topic, publisher });
      }
    }
    return missing;
  }

  // ---- publishing ----

  publish(publisher: Publisher, topic: string, value: unknown): PublishResult {
    // The grant first, so a publisher cannot probe for topic names it was not given.
    const notGranted = (): PublishResult => {
      this.#audit({ event: "event.refused", topic, publisher: publisher.id, error: "not_granted" });
      return { ok: false, error: "not_granted", message: `${publisher.id} may not publish to ${topic}` };
    };
    if (!publisher.topics.has(topic)) return notGranted();
    const allowed = this.#options.topics.get(topic);
    if (allowed === undefined) return { ok: false, error: "unknown_topic", message: `no topic ${topic}` };
    if (!allowed.includes(publisher.id)) return notGranted();
    const checked = checkCloudEvent(value);
    if (!checked.ok) {
      this.#audit({ event: "event.refused", topic, publisher: publisher.id, error: checked.error });
      return checked;
    }
    const { event, bytes } = checked;
    const digest = eventDigest(event);
    const existing = this.#db
      .prepare("SELECT digest, matched FROM events WHERE topic = ? AND publisher = ? AND source = ? AND id = ?")
      .get(topic, publisher.id, event.source, event.id);
    if (existing !== undefined) {
      const original = decodeEventKeyRow(existing);
      if (original.digest !== digest) {
        this.#audit({ event: "event.conflict", topic, source: event.source, id: event.id });
        return { ok: false, error: "id_conflict", message: `event ${event.id} from ${event.source} was published with different content` };
      }
      this.#audit({ event: "event.duplicate", topic, source: event.source, id: event.id });
      return { ok: true, status: "stored", matched: original.matched };
    }

    const now = this.#now();
    const ready = new Set<string>();
    const matched = this.#transaction(() => {
      const { seq } = decodeSeqRow(
        this.#db
          .prepare(
            "INSERT INTO events (topic, publisher, source, id, digest, body, bytes, received_at) " +
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
          )
          .get(topic, publisher.id, event.source, event.id, digest, JSON.stringify(event), bytes, now),
      );
      let count = 0;
      for (const subscription of this.#subscriptionsOn(topic)) {
        if (!matchesFilters(subscription.filters, event)) continue;
        count += 1;
        this.#append(subscription, event.id, seq, now);
        ready.add(subscription.connectorId);
      }
      // No batch needs an event nobody matched; only its key and digest are kept, for idempotency.
      this.#db
        .prepare("UPDATE events SET matched = ?1, body = CASE WHEN ?1 = 0 THEN NULL ELSE body END WHERE seq = ?2")
        .run(count, seq);
      return count;
    });
    this.#audit({
      event: "event.published",
      topic,
      publisher: publisher.id,
      source: event.source,
      id: event.id,
      type: event.type,
      bytes,
      matched,
    });
    for (const connectorId of ready) this.#options.ready(connectorId);
    return { ok: true, status: "stored", matched };
  }

  /** Whether (topic, publisher, source, id) is already taken; publish then answers as a duplicate or conflict. */
  isKnownEvent(topic: string, publisherId: string, source: string, id: string): boolean {
    return (
      this.#db
        .prepare("SELECT seq FROM events WHERE topic = ? AND publisher = ? AND source = ? AND id = ?")
        .get(topic, publisherId, source, id) !== undefined
    );
  }

  #subscriptionsOn(topic: string): Subscription[] {
    return this.#parseSubscriptions(
      decodeSubscriptionRows(this.#db.prepare("SELECT * FROM subscriptions WHERE topic = ? ORDER BY created_at, id").all(topic)),
    );
  }

  #parseSubscriptions(rows: readonly SubscriptionRow[]): Subscription[] {
    return rows.flatMap((row) => {
      const filters = checkFilters(JSON.parse(row.filters));
      return filters.ok
        ? [
            {
              id: row.id,
              connectorId: row.connector_id,
              topic: row.topic,
              filters: filters.filters,
              coalesceSeconds: row.coalesce_seconds,
              maxBatchAgeMs: row.max_batch_age_ms,
            },
          ]
        : [];
    });
  }

  /** Adds an event to the subscription's open batch, opening one if needed. */
  #append(subscription: Subscription, eventId: string, seq: number, now: number): void {
    let batch = this.#openBatch(subscription.id);
    if (batch !== undefined && this.#isDue(batch, subscription.coalesceSeconds, subscription.maxBatchAgeMs, now)) {
      this.#close(batch, now);
      batch = undefined;
    }
    if (batch === undefined) {
      const id = randomUUID();
      this.#db
        .prepare(
          "INSERT INTO batches (id, subscription_id, connector_id, topic, state, opened_at, last_event_at) " +
            "VALUES (?, ?, ?, ?, 'open', ?, ?)",
        )
        .run(id, subscription.id, subscription.connectorId, subscription.topic, now, now);
      batch = this.#openBatch(subscription.id);
      if (batch === undefined) throw new Error(`batch ${id} vanished`);
    }
    this.#db
      .prepare("INSERT INTO batch_events (batch_id, position, event_seq) VALUES (?, ?, ?)")
      .run(batch.id, batch.event_count, seq);
    this.#db
      .prepare("UPDATE batches SET event_count = event_count + 1, last_event_at = ? WHERE id = ?")
      .run(now, batch.id);
    this.#audit({
      event: "event.matched",
      topic: subscription.topic,
      id: eventId,
      subscription: subscription.id,
      batch: batch.id,
    });
    const updated = { ...batch, event_count: batch.event_count + 1, last_event_at: now };
    if (updated.event_count >= this.#limits.maxBatchEvents || subscription.coalesceSeconds === 0) this.#close(updated, now);
  }

  #openBatch(subscriptionId: string): BatchRow | undefined {
    const row = this.#db
      .prepare("SELECT * FROM batches WHERE subscription_id = ? AND state = 'open' LIMIT 1")
      .get(subscriptionId);
    return row === undefined ? undefined : decodeBatchRow(row);
  }

  #isDue(batch: BatchRow, coalesceSeconds: number, maxBatchAgeMs: number | null, now: number): boolean {
    return (
      now - batch.last_event_at >= coalesceSeconds * 1000 ||
      now - batch.opened_at >= (maxBatchAgeMs ?? this.#limits.maxBatchAgeMs)
    );
  }

  /**
   * Closes an open batch into a pending inbox item, then enforces the per-subscription pending cap
   * by dropping the oldest pending batches that are not in flight: an offered batch may be in T3
   * already, and its ack must still settle it.
   */
  #close(batch: BatchRow, now: number): void {
    this.#db.prepare("UPDATE batches SET state = 'pending', closed_at = ? WHERE id = ?").run(now, batch.id);
    const bytes = decodeCount(
      this.#db
        .prepare(
          "SELECT COALESCE(SUM(e.bytes), 0) AS n FROM batch_events be JOIN events e ON e.seq = be.event_seq WHERE be.batch_id = ?",
        )
        .get(batch.id),
    );
    this.#audit({
      event: "event.batch_closed",
      topic: batch.topic,
      subscription: batch.subscription_id,
      batch: batch.id,
      events: batch.event_count,
      bytes,
    });
    const pending = decodeBatchRows(
      this.#db
        .prepare("SELECT * FROM batches WHERE subscription_id = ? AND state = 'pending' ORDER BY closed_at, rowid")
        .all(batch.subscription_id),
    );
    const excess = pending.length - this.#limits.maxPendingBatchesPerSubscription;
    if (excess <= 0) return;
    const droppable = pending.filter((row) => !this.#options.inFlight(row.connector_id, row.id));
    for (const dropped of droppable.slice(0, excess)) this.#drop(dropped, "queue_full", now);
  }

  #drop(batch: BatchRow, reason: string, now: number): void {
    this.#db
      .prepare("UPDATE batches SET state = 'dropped', reason = ?, settled_at = ? WHERE id = ?")
      .run(reason, now, batch.id);
    this.#audit({
      event: "event.dropped",
      topic: batch.topic,
      subscription: batch.subscription_id,
      batch: batch.id,
      events: batch.event_count,
      reason,
    });
  }

  // ---- subscriptions ----

  /** Replaces a connector's subscription set. Removed subscriptions lose their batches; changed filters keep them. */
  setSubscriptions(connectorId: string, specs: readonly SubscriptionSpec[]): SubscriptionsResult {
    if (specs.length > this.#limits.maxSubscriptionsPerConnector) {
      return {
        ok: false,
        error: "too_many_subscriptions",
        message: `at most ${this.#limits.maxSubscriptionsPerConnector} subscriptions per connector`,
      };
    }
    const seen = new Set<string>();
    const parsed: Array<{ spec: SubscriptionSpec; filters: readonly Filter[] }> = [];
    for (const spec of specs) {
      if (!UUID.test(spec.id)) return { ok: false, error: "invalid", message: "subscription ids are UUIDs", id: spec.id };
      if (seen.has(spec.id)) return { ok: false, error: "invalid", message: "duplicate subscription id", id: spec.id };
      seen.add(spec.id);
      if (!isTopic(spec.topic)) return { ok: false, error: "invalid", message: `invalid topic name ${spec.topic}`, id: spec.id };
      if (
        !Number.isInteger(spec.coalesceSeconds) ||
        spec.coalesceSeconds < 0 ||
        spec.coalesceSeconds > this.#limits.maxCoalesceSeconds
      ) {
        return {
          ok: false,
          error: "invalid",
          message: `coalesceSeconds must be an integer 0-${this.#limits.maxCoalesceSeconds}`,
          id: spec.id,
        };
      }
      if (!isPositiveInteger(spec.maxBatchAgeMs) || !isPositiveInteger(spec.maxBatchesPerHour)) {
        return { ok: false, error: "invalid", message: "per-subscription limits must be positive integers", id: spec.id };
      }
      const filters = checkFilters(spec.filters);
      if (!filters.ok) return { ok: false, error: "invalid_filter", message: filters.message, id: spec.id, path: filters.path };
      const owner = this.#db.prepare("SELECT connector_id AS id FROM subscriptions WHERE id = ?").get(spec.id);
      if (owner !== undefined && decodeIdRow(owner).id !== connectorId) {
        return { ok: false, error: "id_conflict", message: "subscription id is used by another connector", id: spec.id };
      }
      parsed.push({ spec, filters: filters.filters });
    }

    const current = new Map(this.#subscriptionsOf(connectorId).map((row) => [row.id, row]));
    const now = this.#now();
    this.#transaction(() => {
      for (const row of current.values()) {
        if (!seen.has(row.id)) this.#removeSubscription(row, "unsubscribed");
      }
      for (const { spec, filters } of parsed) {
        const previous = current.get(spec.id);
        const filtersText = JSON.stringify(filters);
        const maxBatchAgeMs = spec.maxBatchAgeMs ?? null;
        const maxBatchesPerHour = spec.maxBatchesPerHour ?? null;
        if (previous === undefined) {
          this.#db
            .prepare(
              "INSERT INTO subscriptions (id, connector_id, topic, filters, coalesce_seconds, created_at, " +
                "max_batch_age_ms, max_batches_per_hour) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .run(spec.id, connectorId, spec.topic, filtersText, spec.coalesceSeconds, now, maxBatchAgeMs, maxBatchesPerHour);
          this.#audit({ event: "subscription.added", connector: connectorId, subscription: spec.id, topic: spec.topic });
          continue;
        }
        if (
          previous.topic === spec.topic &&
          previous.filters === filtersText &&
          previous.coalesce_seconds === spec.coalesceSeconds &&
          previous.max_batch_age_ms === maxBatchAgeMs &&
          previous.max_batches_per_hour === maxBatchesPerHour
        ) {
          continue;
        }
        // Batches hold events of the old topic; they go with it.
        if (previous.topic !== spec.topic) this.#deleteBatches(previous, "topic_changed");
        this.#db
          .prepare(
            "UPDATE subscriptions SET topic = ?, filters = ?, coalesce_seconds = ?, max_batch_age_ms = ?, " +
              "max_batches_per_hour = ? WHERE id = ?",
          )
          .run(spec.topic, filtersText, spec.coalesceSeconds, maxBatchAgeMs, maxBatchesPerHour, spec.id);
        this.#audit({ event: "subscription.changed", connector: connectorId, subscription: spec.id, topic: spec.topic });
      }
    });
    this.#options.ready(connectorId);
    const unknownTopics = [...new Set(parsed.map(({ spec }) => spec.topic))].filter(
      (topic) => !this.#options.topics.has(topic),
    );
    const diagnostics: Record<string, readonly SubscriptionDiagnostic[]> = {};
    for (const { spec, filters } of parsed) {
      const issues = this.diagnoseSubscription(spec.topic, filters);
      if (issues.length > 0) diagnostics[spec.id] = issues;
    }
    return { ok: true, unknownTopics, diagnostics };
  }

  /** Deletes all of a connector's subscriptions and their batches (connector revoked). */
  removeConnector(connectorId: string): void {
    this.#transaction(() => {
      for (const row of this.#subscriptionsOf(connectorId)) this.#removeSubscription(row, "connector_revoked");
    });
  }

  #subscriptionsOf(connectorId: string): readonly SubscriptionRow[] {
    return decodeSubscriptionRows(
      this.#db.prepare("SELECT * FROM subscriptions WHERE connector_id = ? ORDER BY created_at, id").all(connectorId),
    );
  }

  #removeSubscription(row: SubscriptionRow, reason: string): void {
    const dropped = this.#deleteBatches(row, reason);
    this.#db.prepare("DELETE FROM subscriptions WHERE id = ?").run(row.id);
    this.#audit({ event: "subscription.removed", connector: row.connector_id, subscription: row.id, topic: row.topic, dropped });
  }

  /** Deletes every batch of a subscription; returns how many were still open or pending. */
  #deleteBatches(row: SubscriptionRow, reason: string): number {
    const live = decodeBatchRows(
      this.#db
        .prepare("SELECT * FROM batches WHERE subscription_id = ? AND state IN ('open', 'pending')")
        .all(row.id),
    );
    for (const batch of live) {
      this.#audit({
        event: "event.dropped",
        topic: batch.topic,
        subscription: batch.subscription_id,
        batch: batch.id,
        events: batch.event_count,
        reason,
      });
    }
    this.#db.prepare("DELETE FROM batches WHERE subscription_id = ?").run(row.id);
    return live.length;
  }

  // ---- delivery ----

  /**
   * The next batch to offer for each of the connector's subscriptions: the oldest pending one,
   * unless it is in flight, held, expired, or the subscription is over its wake cap.
   */
  dueBatches(connectorId: string, inFlight: (id: string) => boolean): Array<Extract<InboxItem, { kind: "event" }>> {
    const now = this.#now();
    const items: Array<Extract<InboxItem, { kind: "event" }>> = [];
    for (const subscription of this.#subscriptionsOf(connectorId)) {
      const row = this.#db
        .prepare(
          "SELECT * FROM batches WHERE subscription_id = ? AND state = 'pending' ORDER BY closed_at, rowid LIMIT 1",
        )
        .get(subscription.id);
      if (row === undefined) continue;
      const batch = decodeBatchRow(row);
      if (inFlight(batch.id) || batch.hold_until > now || now - batch.opened_at >= this.#limits.retentionMs) continue;
      const delivered = decodeCount(
        this.#db
          .prepare(
            "SELECT COUNT(*) AS n FROM batches WHERE subscription_id = ? AND state = 'delivered' AND settled_at > ?",
          )
          .get(subscription.id, now - HOUR_MS),
      );
      if (delivered >= (subscription.max_batches_per_hour ?? this.#limits.maxBatchesPerHourPerSubscription)) continue;
      items.push({
        kind: "event",
        id: batch.id,
        subscriptionId: batch.subscription_id,
        topic: batch.topic,
        events: this.#batchEvents(batch.id),
        sentAt: new Date(batch.closed_at ?? batch.last_event_at).toISOString(),
      });
    }
    return items;
  }

  #batchEvents(batchId: string): CloudEvent[] {
    const rows = decodeBodyRows(
      this.#db
        .prepare(
          "SELECT e.body FROM batch_events be JOIN events e ON e.seq = be.event_seq WHERE be.batch_id = ? ORDER BY be.position",
        )
        .all(batchId),
    );
    return rows.flatMap((row) => {
      if (row.body === null) return [];
      const checked = checkCloudEvent(JSON.parse(row.body));
      return checked.ok ? [checked.event] : [];
    });
  }

  /** Settles or holds a pending batch. Only the subscribing connector may. */
  ack(connectorId: string, id: string, outcome: InboundOutcome): boolean {
    const row = this.#db.prepare("SELECT * FROM batches WHERE id = ? AND state = 'pending'").get(id);
    if (row === undefined) return false;
    const batch = decodeBatchRow(row);
    if (batch.connector_id !== connectorId) return false;
    const now = this.#now();
    switch (outcome.kind) {
      case "delivered":
        this.#db.prepare("UPDATE batches SET state = 'delivered', settled_at = ? WHERE id = ?").run(now, id);
        break;
      case "rejected":
        this.#db
          .prepare("UPDATE batches SET state = 'rejected', reason = ?, settled_at = ? WHERE id = ?")
          .run(outcome.reason, now, id);
        break;
      case "hold":
        this.#db
          .prepare("UPDATE batches SET reason = ?, hold_until = ? WHERE id = ?")
          .run(outcome.reason, now + this.#options.holdRetryMs, id);
        break;
    }
    this.#audit({
      event: outcome.kind === "hold" ? "event.held" : `event.${outcome.kind}`,
      topic: batch.topic,
      subscription: batch.subscription_id,
      batch: id,
      events: batch.event_count,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    return true;
  }

  // ---- housekeeping ----

  /**
   * Closes batches whose window ended, drops expired ones, and prunes old records. Looks first and
   * takes the write lock only when there is something to change, so admin commands on the same
   * database (add-publisher and friends, run against the live router) rarely have to wait.
   */
  tick(): void {
    const now = this.#now();
    const prune = now - this.#lastPrune >= PRUNE_INTERVAL_MS;
    if (!prune && this.#dueOpenBatches(now).length === 0 && this.#expiredBatches(now).length === 0) return;
    this.#transaction(() => {
      for (const batch of this.#dueOpenBatches(now)) this.#close(batch, now);
      for (const batch of this.#expiredBatches(now)) this.#drop(batch, "expired", now);
      if (!prune) return;
      const cutoff = now - this.#limits.retentionMs;
      this.#db
        .prepare("DELETE FROM batches WHERE state IN ('delivered', 'rejected', 'dropped') AND settled_at <= ?")
        .run(cutoff);
      // Event content is kept only while a pending batch needs it; the key and digest stay for idempotency.
      this.#db
        .prepare(
          "UPDATE events SET body = NULL WHERE body IS NOT NULL AND received_at <= ? AND NOT EXISTS (" +
            "SELECT 1 FROM batch_events be JOIN batches b ON b.id = be.batch_id " +
            "WHERE be.event_seq = events.seq AND b.state IN ('open', 'pending'))",
        )
        .run(cutoff);
      this.#db
        .prepare(
          "DELETE FROM events WHERE received_at <= ? AND NOT EXISTS (SELECT 1 FROM batch_events be WHERE be.event_seq = events.seq)",
        )
        .run(now - this.#limits.idempotencyMs);
    });
    if (prune) this.#lastPrune = now;
  }

  #dueOpenBatches(now: number): readonly BatchRow[] {
    return decodeBatchRows(this.#db.prepare("SELECT * FROM batches WHERE state = 'open'").all()).filter((batch) => {
      const row = this.#db
        .prepare("SELECT coalesce_seconds, max_batch_age_ms FROM subscriptions WHERE id = ?")
        .get(batch.subscription_id);
      if (row === undefined) return true;
      const limits = decodeBatchLimitsRow(row);
      return this.#isDue(batch, limits.coalesce_seconds, limits.max_batch_age_ms, now);
    });
  }

  /**
   * Delivery state of each of the connector's subscriptions, from its batches still kept (pending ones,
   * and settled ones for the retention window). Subscriptions without batches are listed too.
   */
  deliveryStatus(connectorId: string): SubscriptionDelivery[] {
    const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());
    const rows = decodeStatusRows(
      this.#db
        .prepare(DELIVERY_STATUS_SQL)
        .all(connectorId, connectorId),
    );
    const byId = new Map<string, { pending: number; oldest: number | null; held: string | null; heldAt: number; delivered: number;
      lastDelivered: number | null; rejected: Record<string, number>; dropped: Record<string, number>; lastDropped: number | null }>();
    for (const row of this.#subscriptionsOf(connectorId)) {
      byId.set(row.id, { pending: 0, oldest: null, held: null, heldAt: 0, delivered: 0, lastDelivered: null, rejected: {}, dropped: {}, lastDropped: null });
    }
    for (const row of rows) {
      const entry = byId.get(row.subscription_id);
      if (entry === undefined) continue;
      const reason = row.reason ?? "unknown";
      if (row.state === "pending") {
        entry.pending += row.n;
        entry.oldest = entry.oldest === null ? row.oldest : Math.min(entry.oldest, row.oldest);
        // The latest hold: each hold moves a batch's hold_until forward.
        if (row.reason !== null && row.held >= entry.heldAt) {
          entry.held = row.reason;
          entry.heldAt = row.held;
        }
      } else if (row.state === "delivered") {
        entry.delivered += row.n;
        entry.lastDelivered = Math.max(entry.lastDelivered ?? 0, row.last ?? 0);
      } else if (row.state === "rejected") {
        entry.rejected[reason] = (entry.rejected[reason] ?? 0) + row.n;
      } else if (row.state === "dropped") {
        entry.dropped[reason] = (entry.dropped[reason] ?? 0) + row.n;
        entry.lastDropped = Math.max(entry.lastDropped ?? 0, row.last ?? 0);
      }
    }
    return [...byId].map(([id, entry]) => ({
      id,
      pending: entry.pending,
      oldestPendingAt: iso(entry.oldest),
      heldReason: entry.held,
      delivered: entry.delivered,
      lastDeliveredAt: iso(entry.lastDelivered),
      rejected: entry.rejected,
      dropped: entry.dropped,
      lastDroppedAt: iso(entry.lastDropped),
    }));
  }

  /** Pending (closed, unsettled) batches per subscription of the connector, with the oldest one's age. */
  pendingSummary(connectorId: string): PendingSummary[] {
    return decodePendingRows(
      this.#db
        .prepare(
          "SELECT subscription_id, COUNT(*) AS n, MIN(opened_at) AS oldest FROM batches " +
            "WHERE connector_id = ? AND state = 'pending' GROUP BY subscription_id",
        )
        .all(connectorId),
    ).map((row) => ({ subscriptionId: row.subscription_id, pending: row.n, oldestOpenedAt: row.oldest }));
  }

  #expiredBatches(now: number): readonly BatchRow[] {
    return decodeBatchRows(
      this.#db
        .prepare("SELECT * FROM batches WHERE state = 'pending' AND opened_at <= ?")
        .all(now - this.#limits.retentionMs),
    );
  }
}
