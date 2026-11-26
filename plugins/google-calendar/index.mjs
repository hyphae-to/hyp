#!/usr/bin/env node
/**
 * Zero-dependency Google Calendar event source for Hyphae (Node 24+).
 *
 * Outbound only: polls the Calendar API with the user's own OAuth refresh token. Emits
 *   com.google.calendar.event.created / .updated / .cancelled  when an event changes, and
 *   com.google.calendar.event.starting                         a few minutes before it begins.
 *
 * One-time consent (run where a browser can reach the loopback port):
 *   node ../sdk/google-oauth.mjs auth --client-file <client_secret.json> --scopes calendar
 *
 * Configuration via env:
 *   GOOGLE_CLIENT_ID          - OAuth client ID (Desktop app) (required)
 *   GOOGLE_CLIENT_SECRET      - OAuth client secret, when the client has one
 *   GOOGLE_REFRESH_TOKEN / GOOGLE_REFRESH_TOKEN_FILE - Refresh token from the consent step (required)
 *   CALENDAR_IDS              - Comma-separated calendar IDs (default primary)
 *   CALENDAR_POLL_SECONDS     - Poll interval (default 60, min 20)
 *   CALENDAR_REMIND_MINUTES   - Lead time for "starting" events (default 10; 0 disables them)
 *   CALENDAR_PREVIEW_CHARS    - Max description characters per event (default 200; 0 = none)
 *   CALENDAR_API_BASE         - API base (default https://www.googleapis.com)
 *   CALENDAR_STATE_FILE       - State file (defaults to $HYPHAE_STATE_DIR/google-calendar-state.json)
 *   CALENDAR_TARGET           - Target name (defaults to first target in hello)
 */
import { googleAccessTokenProvider } from "../sdk/google-oauth.mjs";
import {
  boundKeys, clip, connectSource, envInt, envList, fetchJson, HttpError, pollForever, resolveBaseUrl, StateFile,
} from "../sdk/source-kit.mjs";

const accessToken = googleAccessTokenProvider();
const apiBase = resolveBaseUrl("CALENDAR_API_BASE", "https://www.googleapis.com");
const calendars = envList("CALENDAR_IDS");
if (calendars.length === 0) calendars.push("primary");
for (const id of calendars) if (id.length > 256 || /[\s/?#]/.test(id)) throw new Error(`CALENDAR_IDS has an invalid calendar ID '${clip(id, 40)}'`);
const intervalMs = envInt("CALENDAR_POLL_SECONDS", 60, { min: 20, max: 3600 }) * 1000;
const remindMinutes = envInt("CALENDAR_REMIND_MINUTES", 10, { max: 1440 });
const previewChars = envInt("CALENDAR_PREVIEW_CHARS", 200, { max: 1000 });
const state = new StateFile("CALENDAR", "google-calendar-state.json");
const { target, publish } = await connectSource("CALENDAR", "google-calendar");

async function listEvents(calendarId, query) {
  const items = [];
  let pageToken = "";
  for (let page = 0; page < 10; page += 1) {
    const params = new URLSearchParams({ ...query, maxResults: "250" });
    if (pageToken) params.set("pageToken", pageToken);
    const body = await fetchJson(`${apiBase}/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events?${params}`, {
      headers: { authorization: `Bearer ${await accessToken()}` },
    });
    if (Array.isArray(body?.items)) items.push(...body.items);
    if (typeof body?.nextPageToken !== "string" || !body.nextPageToken) break;
    pageToken = body.nextPageToken;
  }
  return items.filter((item) => item && typeof item.id === "string");
}

const when = (point) => (point && typeof point === "object" ? (point.dateTime ?? point.date ?? null) : null);

function eventData(calendarId, item, action, extra = {}) {
  const attendees = Array.isArray(item.attendees) ? item.attendees : [];
  const self = attendees.find((a) => a?.self === true);
  const video = (item.conferenceData?.entryPoints ?? []).find((e) => e?.entryPointType === "video");
  return {
    action,
    calendar_id: clip(calendarId, 256),
    event_id: clip(item.id, 256),
    title: clip(item.summary ?? "", 300),
    start: when(item.start),
    end: when(item.end),
    all_day: Boolean(item.start?.date && !item.start?.dateTime),
    status: clip(item.status ?? "", 20) || null,
    location: clip(item.location ?? "", 300) || null,
    organizer: clip(item.organizer?.email ?? "", 320) || null,
    attendees: attendees.length,
    my_response: clip(self?.responseStatus ?? "", 20) || null,
    meeting_url: clip(item.hangoutLink ?? video?.uri ?? "", 500) || null,
    url: clip(item.htmlLink ?? "", 500) || null,
    recurring_event_id: clip(item.recurringEventId ?? "", 256) || null,
    description: clip(item.description ?? "", previewChars),
    ...extra,
  };
}

if (typeof state.data.cursor !== "string" || Number.isNaN(Date.parse(state.data.cursor))) {
  // First run starts at "now": existing events are not replayed as changes.
  state.data = { cursor: new Date().toISOString(), seen: {}, reminded: {} };
  state.save();
}
for (const key of ["seen", "reminded"]) if (!state.data[key] || typeof state.data[key] !== "object") state.data[key] = {};
console.error(`google-calendar plugin polling ${calendars.join(", ")} every ${intervalMs / 1000}s -> target ${target}`);

async function pollChanges(calendarId) {
  let items;
  try {
    items = await listEvents(calendarId, { updatedMin: state.data.cursor, showDeleted: "true", orderBy: "updated" });
  } catch (error) {
    if (error instanceof HttpError && error.status === 410) {
      // Google rejects an updatedMin that lies too far in the past; resume from "now".
      state.data.cursor = new Date().toISOString();
      state.save();
      console.error("google-calendar plugin change cursor expired; resumed from the current time");
      return;
    }
    throw error;
  }
  for (const item of items) {
    const updatedMs = Date.parse(item.updated ?? "");
    if (Number.isNaN(updatedMs)) continue;
    const key = `${calendarId}/${item.id}`;
    if (state.data.seen[key] === item.updated) continue;
    const createdMs = Date.parse(item.created ?? "");
    const action = item.status === "cancelled" ? "cancelled" : !Number.isNaN(createdMs) && Math.abs(updatedMs - createdMs) < 5_000 ? "created" : "updated";
    await publish({
      id: `gcal:${key}:${item.updated}`,
      source: `google-calendar/${clip(calendarId, 200)}`,
      type: `com.google.calendar.event.${action}`,
      subject: clip(item.id, 256),
      time: new Date(updatedMs).toISOString(),
      data: eventData(calendarId, item, action),
    });
    state.data.seen[key] = item.updated;
    boundKeys(state.data.seen, 1000);
    if (updatedMs > Date.parse(state.data.cursor)) state.data.cursor = new Date(updatedMs).toISOString();
    state.save();
  }
}

async function pollStarting(calendarId) {
  const now = Date.now();
  const items = await listEvents(calendarId, {
    timeMin: new Date(now).toISOString(),
    timeMax: new Date(now + remindMinutes * 60_000).toISOString(),
    singleEvents: "true",
    orderBy: "startTime",
  });
  for (const item of items) {
    const startMs = Date.parse(item.start?.dateTime ?? "");
    // All-day events have no start instant; events already under way or declined are not announced.
    if (Number.isNaN(startMs) || startMs <= now || item.status === "cancelled") continue;
    if ((item.attendees ?? []).some((a) => a?.self === true && a.responseStatus === "declined")) continue;
    const key = `${calendarId}/${item.id}/${item.start.dateTime}`;
    if (state.data.reminded[key]) continue;
    await publish({
      id: `gcal:${key}:starting`,
      source: `google-calendar/${clip(calendarId, 200)}`,
      type: "com.google.calendar.event.starting",
      subject: clip(item.id, 256),
      time: new Date().toISOString(),
      data: eventData(calendarId, item, "starting", { minutes_until: Math.max(Math.round((startMs - now) / 60_000), 0) }),
    });
    state.data.reminded[key] = 1;
    boundKeys(state.data.reminded, 500);
    state.save();
  }
}

await pollForever("google-calendar", intervalMs, async () => {
  for (const calendarId of calendars) {
    await pollChanges(calendarId);
    if (remindMinutes > 0) await pollStarting(calendarId);
  }
});
