// Shared metadata and command model for the Herdr and Claude KV panels.

const MAX_NAMESPACES = 32;
const MAX_SNAPSHOT_KEYS = 4;
const MAX_KEY_PAGE = 64;
const MAX_PREVIEW_CHARS = 4096;

function validNamespace(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(value);
}

function validOrigin(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9@._-]{0,63}$/.test(value);
}

function validKey(value) {
  if (typeof value !== "string" || !value || value.length > 256
    || /[\p{White_Space}\p{Cc}\p{Cs}]/u.test(value)) return false;
  let bytes = 0;
  for (const character of value) {
    const point = character.codePointAt(0);
    bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
  }
  return bytes <= 256 && value.split("/").every((segment) => segment && segment !== "." && segment !== "..");
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function readKeys(value, limit) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).filter((entry) => validKey(entry?.key)).map((entry) => ({
    key: entry.key,
    version: nonnegative(entry.version),
    updatedBy: typeof entry.updatedBy === "string" ? entry.updatedBy.slice(0, 256) : "",
    updatedAt: nonnegative(entry.updatedAt),
    expiresAt: entry.expiresAt == null ? null : nonnegative(entry.expiresAt),
    sizeBytes: nonnegative(entry.sizeBytes),
  }));
}

export function parseKvInspection(value) {
  if (!Array.isArray(value?.namespaces)) return null;
  return {
    namespacesTruncated: value.namespacesTruncated === true,
    namespaces: value.namespaces.slice(0, MAX_NAMESPACES)
      .filter((namespace) => validNamespace(namespace?.name) && validOrigin(namespace?.originNode))
      .map((namespace) => ({
        name: namespace.name,
        originNode: namespace.originNode,
        epoch: namespace.epoch == null ? null : nonnegative(namespace.epoch),
        memberCount: nonnegative(namespace.memberCount),
        entryCount: nonnegative(namespace.entryCount),
        watchCount: nonnegative(namespace.watchCount),
        entries: readKeys(namespace.entries, MAX_SNAPSHOT_KEYS),
      })),
  };
}

export function parseKvKeyPage(value) {
  if (!Array.isArray(value?.entries)) return null;
  return {
    entries: readKeys(value.entries, MAX_KEY_PAGE),
    nextAfter: validKey(value.nextAfter) ? value.nextAfter : null,
  };
}

export function parseKvPreview(value, sanitizeLine) {
  if (typeof value?.text !== "string") return null;
  const text = value.text.slice(0, MAX_PREVIEW_CHARS).split(/\r?\n/).map((line) => {
    const indent = line.match(/^ */)?.[0] ?? "";
    return indent + sanitizeLine(line, MAX_PREVIEW_CHARS);
  }).join("\n");
  return {
    text,
    version: nonnegative(value.version),
    truncated: value.truncated === true || value.text.length > MAX_PREVIEW_CHARS,
  };
}

export function buildKvCommandArgs(action, coordinate = {}) {
  if (action === "inspect") return ["inspect", "--all", "--json"];
  const { originNode, namespace, key, after } = coordinate;
  if (!validOrigin(originNode) || !validNamespace(namespace)) return null;
  const args = ["kv", action, `--node=${originNode}`, `--ns=${namespace}`, "--json"];
  if (action === "preview" && validKey(key)) return [...args, `--key=${key}`];
  if (action === "keys" && after == null) return args;
  if (action === "keys" && validKey(after)) return [...args, `--after=${after}`];
  return null;
}

export function readKvCommandData(stdout, code) {
  if (code !== 0 || typeof stdout !== "string") return null;
  try {
    const envelope = JSON.parse(stdout);
    return envelope?.ok === true ? envelope.data : null;
  } catch {
    return null;
  }
}

export class KvBrowser {
  constructor() {
    this.requestId = 0;
    this.reset();
  }

  reset() {
    this.requestId += 1;
    this.inspection = null;
    this.namespace = null;
    this.page = null;
    this.preview = null;
    this.cursorHistory = [];
    this.busy = false;
    this.error = null;
  }

  reconcileSnapshot(snapshot, localOrigin) {
    if (!this.namespace || this.namespace.originNode !== localOrigin || !snapshot || snapshot.namespacesTruncated) return;
    if (!snapshot.namespaces.some((ns) => ns.originNode === localOrigin && ns.name === this.namespace.name)) {
      this.requestId += 1;
      this.namespace = null;
      this.page = null;
      this.preview = null;
      this.cursorHistory = [];
      this.busy = false;
    }
  }

  back() {
    this.requestId += 1;
    this.busy = false;
    this.error = null;
    if (this.preview) {
      this.preview = null;
    } else {
      this.namespace = null;
      this.page = null;
      this.cursorHistory = [];
    }
  }

  async request(action, coordinate, run, apply) {
    const args = buildKvCommandArgs(action, coordinate);
    if (!args) return;
    const request = ++this.requestId;
    this.busy = true;
    this.error = null;
    try {
      const data = await run(args);
      if (request === this.requestId && !apply(data)) {
        this.error = "Could not load KV data.";
      }
    } catch {
      if (request === this.requestId) this.error = "Could not load KV data.";
    } finally {
      if (request === this.requestId) this.busy = false;
    }
  }

  async inspect(run) {
    this.preview = null;
    await this.request("inspect", {}, run, (data) => {
      this.inspection = parseKvInspection(data?.kv);
      if (!this.inspection || !this.inspection.namespaces.some(
        (ns) => ns.originNode === this.namespace?.originNode && ns.name === this.namespace?.name,
      )) {
        this.namespace = null;
        this.page = null;
        this.cursorHistory = [];
      }
      return this.inspection !== null;
    });
  }

  async open(namespace, run) {
    this.preview = null;
    await this.readPage(namespace, null, [null], run);
  }

  async turnPage(next, run) {
    if (!this.namespace || !this.page) return;
    const history = this.cursorHistory.slice();
    if (next) {
      if (!this.page.nextAfter) return;
      history.push(this.page.nextAfter);
    } else {
      if (history.length < 2) return;
      history.pop();
    }
    this.preview = null;
    await this.readPage(this.namespace, history.at(-1), history, run);
  }

  async refreshPage(run) {
    if (!this.namespace || !this.page) return;
    await this.readPage(this.namespace, this.cursorHistory.at(-1), this.cursorHistory, run);
  }

  async readPage(namespace, after, history, run) {
    const coordinate = { originNode: namespace.originNode, namespace: namespace.name, after };
    await this.request("keys", coordinate, run, (data) => {
      const page = parseKvKeyPage(data);
      if (!page) {
        this.preview = null;
        return false;
      }
      if (this.preview && !page.entries.some(
        (entry) => entry.key === this.preview.key && entry.version === this.preview.version,
      )) this.preview = null;
      this.namespace = namespace;
      this.page = page;
      this.cursorHistory = history;
      return true;
    });
  }

  async show(key, run, sanitizeLine) {
    if (!this.namespace) return;
    const coordinate = { originNode: this.namespace.originNode, namespace: this.namespace.name, key };
    await this.request("preview", coordinate, run, (data) => {
      const preview = parseKvPreview(data, sanitizeLine);
      this.preview = preview && { ...preview, key };
      return this.preview !== null;
    });
  }
}

export function combineKvInspection(snapshot, fetched, localOrigin) {
  if (!snapshot) return fetched;
  if (!fetched) return snapshot;
  const names = new Set(snapshot.namespaces.map((ns) => `${ns.originNode}/${ns.name}`));
  const namespaces = snapshot.namespaces.concat(
    fetched.namespaces.filter((ns) => ns.originNode !== localOrigin && !names.has(`${ns.originNode}/${ns.name}`)),
  );
  return {
    namespaces: namespaces.slice(0, MAX_NAMESPACES),
    namespacesTruncated: snapshot.namespacesTruncated || fetched.namespacesTruncated || namespaces.length > MAX_NAMESPACES,
  };
}
