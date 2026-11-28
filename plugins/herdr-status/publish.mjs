#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const namespace = "herdr-status";
const leaseNamespace = "herdr-status-lease";
const statusSchema = "hyphae.herdr.status/v1";
const leaseSchema = "hyphae.herdr.lease/v1";
const leaseMs = 75_000;
const renewalMs = 30_000;
const heartbeatTimeoutMs = 45_000;
const states = new Set(["idle", "working", "done", "blocked", "error"]);
const kinds = new Set(["permission", "question", "auth"]);
const changes = new Set(["created", "lost", "restarted", "finished", "removed", "status"]);

export function parseBinding([key, terminal, created, stateDir, ...extra]) {
  const createdMs = Number(created);
  if (extra.length || !/^[a-z0-9][a-z0-9_-]{0,47}$/.test(key ?? "") ||
      !/^t[a-z0-9]+$/.test(terminal ?? "") || !/^[1-9][0-9]*$/.test(created ?? "") ||
      !Number.isSafeInteger(createdMs) || !stateDir) {
    throw new Error("Usage: node publish.mjs <builder-key> <local-terminal> <created_ms> <state-dir>");
  }
  const session = createHash("sha256").update(JSON.stringify([key, terminal, createdMs])).digest("hex");
  return { key, terminal, createdMs, stateDir, session };
}

export function projectTerminal(terminal, binding) {
  if (terminal?.address !== binding.terminal || terminal.created_ms !== binding.createdMs) {
    throw new Error("Herdr terminal identity changed or is unavailable");
  }
  if (terminal.state === "finished") return { state: "finished" };
  if (terminal.state !== "live") return { state: "unknown" };
  return projectStatus(terminal.status);
}

function projectStatus(status) {
  const { state, kind } = status ?? {};
  if (!states.has(state)) return { state: "unknown" };
  if (state === "blocked" && kinds.has(kind)) return { state, kind };
  return { state };
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Invalid ${label} response`);
  }
}

export function localKv(binding) {
  async function run(action, ns, flags = []) {
    const args = ["kv", action, "--ns", ns, "--key", binding.key,
      "--state-dir", binding.stateDir, "--json", ...flags];
    let result;
    try {
      result = await exec("hyp", args, { timeout: 10_000, maxBuffer: 1024 * 1024 });
    } catch (error) {
      if (action === "get" && error.stdout &&
          parseJson(error.stdout, "Hyphae")?.error?.code === "NOT_FOUND") return null;
      throw new Error(`Hyphae KV ${action} failed`);
    }
    const response = parseJson(result.stdout, "Hyphae");
    if (!response?.ok || !response.data || response.data.key !== binding.key ||
        response.data.namespace !== ns) {
      throw new Error(`Unexpected Hyphae KV ${action} response`);
    }
    return response.data;
  }

  return {
    get: (ns) => run("get", ns),
    set: (ns, value, version) => run("set", ns, [
      "--write-model", "owner", "--expected-version", String(version),
      "--value", JSON.stringify(value), "--clear-ttl",
    ]),
  };
}

export async function publishStatus(binding, frames, kv, now = Date.now) {
  let stored = await kv.get(namespace);
  if (stored && (stored.writeModel !== "owner" || stored.value?.schema !== statusSchema ||
                 stored.value?.session !== binding.session)) {
    throw new Error("Builder key already belongs to another session");
  }
  let ownerLease = await kv.get(leaseNamespace);
  if (ownerLease && (ownerLease.writeModel !== "owner" ||
      ownerLease.value?.schema !== leaseSchema || ownerLease.value.session !== binding.session ||
      !Number.isSafeInteger(ownerLease.value.validUntil))) {
    throw new Error("Builder lease already belongs to another session");
  }
  if (ownerLease?.value.validUntil > now()) {
    throw new Error("Builder already has an active publisher");
  }
  let ownsLease = false;
  let lastSeq;
  let observation;

  async function observe(status) {
    observation = status;
    const value = { schema: statusSchema, session: binding.session, ...observation };
    if (stored?.value?.state === value.state && stored.value.kind === value.kind) return;
    stored = await kv.set(namespace, value, stored?.version ?? 0);
  }

  async function lease() {
    const stamp = now();
    if (ownsLease && ownerLease.value.validUntil <= stamp) {
      throw new Error("Builder lease expired while publishing");
    }
    if (ownsLease && ownerLease.value.validUntil - stamp > leaseMs - renewalMs) return;
    ownerLease = await kv.set(leaseNamespace, {
      schema: leaseSchema, session: binding.session, validUntil: stamp + leaseMs,
    }, ownerLease?.version ?? 0);
    ownsLease = true;
  }

  async function snapshot(frame) {
    if (!Array.isArray(frame?.terminals) || !Number.isSafeInteger(frame.seq) || frame.seq < 0) {
      throw new Error("Unexpected Herdr event snapshot");
    }
    const terminal = frame.terminals.find((entry) => entry?.address === binding.terminal);
    const status = projectTerminal(terminal, binding);
    await lease();
    await observe(status);
    lastSeq = frame.seq;
  }

  try {
    for await (const frame of frames) {
      if (lastSeq === undefined) {
        await snapshot(frame);
      } else if (frame?.method === "missed") {
        await snapshot(frame.params);
      } else if (frame?.method === "event") {
        const event = frame.params;
        if (event?.terminal !== binding.terminal || !Number.isSafeInteger(event.seq) ||
            event.seq <= lastSeq || !changes.has(event.type)) continue;
        lastSeq = event.seq;
        if (event.type === "removed") return;
        await lease();
        const status = event.type === "created" || event.type === "restarted"
          ? projectTerminal(event.data, binding)
          : event.type === "status"
            ? projectStatus(event.data?.status)
            : { state: event.type === "finished" ? "finished" : "unknown" };
        await observe(status);
      } else if (frame?.method === "heartbeat") {
        await lease();
      }
      if (observation?.state === "finished") return;
    }
  } finally {
    if (ownsLease) {
      // CAS prevents a late exit from clearing a replacement publisher's lease.
      try {
        await kv.set(leaseNamespace, {
          schema: leaseSchema, session: binding.session, validUntil: 0,
        }, ownerLease.version);
      } catch {
        // If the node is unavailable, readers still have the bounded deadline.
      }
    }
  }
}

async function run(binding) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  const child = spawn("hc", ["events", "--json", "--terminal", binding.terminal], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  let streamError = false;
  child.on("error", () => { streamError = true; });
  controller.signal.addEventListener("abort", () => child.kill(), { once: true });
  const lines = createInterface({ input: child.stdout });
  async function* frames() {
    let timeout = setTimeout(stop, heartbeatTimeoutMs);
    try {
      for await (const line of lines) {
        clearTimeout(timeout);
        timeout = setTimeout(stop, heartbeatTimeoutMs);
        yield parseJson(line, "Herdr");
      }
      if (streamError) throw new Error("Cannot start Herdr event stream");
    } finally {
      clearTimeout(timeout);
    }
  }
  try {
    await publishStatus(binding, frames(), localKv(binding));
  } finally {
    lines.close();
    child.kill();
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    await run(parseBinding(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
