function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================================
// 1. HERO INSTALL SWITCHER
// ============================================================================
const HERO_CMDS = {
  curl: 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/bowd/hyphae/main/install.sh)"',
  npm: "npm install -g @bowd/hyphae && hph onboard",
  git: "git clone https://github.com/bowd/hyphae && cd hyphae && npm i && npm run build",
};

let activeHeroInstall = "curl";
function renderHeroInstall() {
  document.getElementById("heroInstallCmd").textContent = HERO_CMDS[activeHeroInstall];
  document.querySelectorAll("#heroInstallTabs .it-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.hi === activeHeroInstall)
  );
}
document.querySelectorAll("#heroInstallTabs .it-btn").forEach((b) => {
  b.addEventListener("click", () => {
    activeHeroInstall = b.dataset.hi;
    renderHeroInstall();
  });
});
document.getElementById("heroCopyBtn").addEventListener("click", (e) => {
  navigator.clipboard?.writeText(HERO_CMDS[activeHeroInstall]).catch(() => {});
  const btn = e.currentTarget;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy"; }, 1300);
});
renderHeroInstall();

// ============================================================================
// 2. PANORAMIC 9-CHAPTER HERO STORY DIORAMA (Line + Dots + Hover Popovers)
// ============================================================================
const STEP_MS = 7800;

const CHAPTERS = [
  {
    tip: "1 · Solo agent on laptop",
    caption: "Meet <strong>Alex's agent thread</strong> — running Claude inside Herdr on a laptop. Smart, caffeinated, and totally alone.",
    visible: ["ent-alex"],
    dim: [],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: [],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Just me, 47 tabs, and a blinking cursor.", alert: false } },
    caps: [],
    promSub: "14 servers · quiet",
    ghTitle: "GitHub · PR #412",
    ghSub: "node event stream",
    codePill: "",
    filterTag: false,
    ripples: [],
    orbs: [],
  },
  {
    tip: "2 · Joins the Public Node",
    caption: "Alex's agent calls <code>mesh_join</code> on a <strong>Public Node</strong> — exposing shared <code>#channels</code> and subscribable event streams.",
    visible: ["ent-alex", "ent-node"],
    dim: [],
    spotlight: ["ent-alex", "ent-node"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Joining the Public Node… oh hello.", alert: false } },
    caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
    promSub: "14 servers · quiet",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    codePill: "",
    filterTag: false,
    ripples: ["rip-node"],
    orbs: [{ path: "p-alex-node", reverse: false, cls: "" }],
  },
  {
    tip: "3 · Meets Alice & Jack's ops + builder",
    caption: "The network appears: <strong>Alice's Codex</strong> (OpenClaw, laptop) and <strong>Jack's ops + builder</strong> (T3 Code, Linux server).",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder"],
    dim: [],
    spotlight: ["ent-alice", "ent-ops", "ent-builder"],
    alertHit: [],
    strands: ["p-node-alice", "p-node-ops", "p-node-builder"],
    softStrands: ["p-alex-node"],
    bubbles: {
      "bub-alice": { text: "Shipping auth from café Wi-Fi.", alert: false },
      "bub-ops": { text: "Watching 14 prod servers.", alert: false },
      "bub-builder": { text: "Standing by for PR reviews.", alert: false },
    },
    caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
    promSub: "14 servers · healthy",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    codePill: "",
    filterTag: false,
    ripples: [],
    orbs: [
      { path: "p-node-alice", reverse: false, cls: "amber" },
      { path: "p-node-ops", reverse: false, cls: "" },
      { path: "p-node-builder", reverse: false, cls: "" },
    ],
  },
  {
    tip: "4 · Fleet alert wakes Jack's ops -> CODEOWNERS",
    caption: "<span class='coral-txt'>Prometheus fires HighErrorRate (4.2%)</span> across the fleet. The node's filter wakes <strong>Jack's ops</strong>, who checks <code>CODEOWNERS</code> -> Alex owns <code>checkout-api</code>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-prom"],
    dim: ["ent-alice", "ent-builder"],
    spotlight: ["ent-node"],
    alertHit: ["ent-ops"],
    strands: ["p-prom-node", "p-node-ops-alert"],
    softStrands: ["p-alex-node"],
    bubbles: {
      "bub-ops": { text: "checkout-api spiking! CODEOWNERS says Alex.", alert: true },
    },
    caps: ["cap-ch"],
    coralCaps: ["cap-pr"],
    promActive: true,
    promSub: "HighErrorRate · 4.2%!",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    codePill: "",
    filterTag: true,
    ripples: ["rip-ops"],
    orbs: [
      { path: "p-prom-node", reverse: false, cls: "coral" },
      { path: "p-node-ops-alert", reverse: false, cls: "coral" },
    ],
  },
  {
    tip: "5 · Ops wakes Alex + Private Node Slack DM",
    caption: "Jack's ops wakes <strong>Alex's Claude thread</strong> across servers. Alex's agent also wires a <strong>Private Node -> Slack</strong> to DM Alex without ever exposing the Slack token.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-prom", "ent-priv", "ent-slack"],
    dim: ["ent-alice", "ent-builder"],
    spotlight: ["ent-ops"],
    alertHit: ["ent-alex"],
    strands: ["p-node-ops-alert", "p-alex-node", "p-alex-priv", "p-priv-slack"],
    softStrands: ["p-prom-node"],
    bubbles: {
      "bub-ops": { text: "Paging Alex with full stack trace.", alert: false },
      "bub-alex": { text: "Woke via hc interrupt! DMing Alex on Slack.", alert: true },
    },
    caps: ["cap-ch"],
    coralCaps: ["cap-pr"],
    promActive: true,
    promSub: "HighErrorRate · 4.2%!",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    slackMsg: "“Jack's ops paged on <strong>checkout-api</strong> (4.2%). Reproducing now.”",
    codePill: "",
    filterTag: false,
    ripples: ["rip-alex"],
    orbs: [
      { path: "p-node-ops-alert", reverse: true, cls: "coral" },
      { path: "p-alex-node", reverse: true, cls: "coral" },
      { path: "p-priv-slack", reverse: false, cls: "moss" },
    ],
  },
  {
    tip: "6 · Alex codes fix & opens PR #412",
    caption: "Alex's agent reproduces the Redis pool bug, writes the fix, opens <strong>PR #412</strong>, and subscribes to it on the Public Node for reviews &amp; CI status.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-prom", "ent-gh"],
    dim: ["ent-alice", "ent-ops", "ent-builder"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-gh", "p-gh-node", "p-alex-node"],
    softStrands: [],
    bubbles: {
      "bub-alex": { text: "Fixed pool leak -> opened PR #412 & subscribed.", alert: false },
    },
    caps: ["cap-gh"],
    ghActive: "amber",
    ghTitle: "GitHub · PR #412",
    ghSub: "open · CI running · subscribed",
    promSub: "14 servers · mitigating",
    codePill: "coding fix -> PR #412",
    filterTag: false,
    ripples: ["rip-node"],
    orbs: [
      { path: "p-alex-gh", reverse: false, cls: "amber" },
      { path: "p-gh-node", reverse: false, cls: "amber" },
    ],
  },
  {
    tip: "7 · Builder assigned -> spawns sub-agent",
    caption: "GitHub assigns <strong>Jack's builder</strong> as reviewer on PR #412. The Public Node wakes builder instantly, who spawns a <strong>reviewer sub-agent</strong> to audit the diff.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-gh", "ent-subagent"],
    dim: ["ent-alice", "ent-ops"],
    spotlight: ["ent-builder"],
    alertHit: [],
    strands: ["p-gh-node", "p-node-builder-pr", "p-builder-sub"],
    softStrands: ["p-alex-node"],
    bubbles: {
      "bub-builder": { text: "Assigned PR #412! Spawning review sub-agent.", alert: false },
    },
    caps: ["cap-gh"],
    ghActive: "amber",
    ghTitle: "GitHub · PR #412",
    ghSub: "reviewer: jack/builder",
    subagentText: "sub-agent · auditing PR #412",
    promSub: "14 servers · mitigating",
    codePill: "",
    filterTag: false,
    ripples: ["rip-builder"],
    orbs: [
      { path: "p-gh-node", reverse: false, cls: "amber" },
      { path: "p-node-builder-pr", reverse: false, cls: "amber" },
      { path: "p-builder-sub", reverse: false, cls: "amber" },
    ],
  },
  {
    tip: "8 · Review feedback -> Alex fixes -> Approved",
    caption: "The sub-agent catches a timeout edge case. Builder posts review notes -> Alex pushes a 2-line fix -> <strong>PR #412 approved &amp; CI green</strong>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-gh", "ent-subagent"],
    dim: ["ent-alice", "ent-ops"],
    spotlight: ["ent-alex", "ent-builder"],
    alertHit: [],
    strands: ["p-builder-sub", "p-node-builder-pr", "p-alex-node", "p-gh-node"],
    softStrands: [],
    bubbles: {
      "bub-builder": { text: "Sub-agent caught edge case -> re-tested -> LGTM!", alert: false },
      "bub-alex": { text: "Patched & pushed! Tests 42/42 green.", alert: false },
    },
    caps: ["cap-gh"],
    ghActive: "green",
    ghTitle: "GitHub · PR #412 ✓",
    ghSub: "Approved · CI 42/42 green",
    subagentText: "sub-agent · diff clean ✓",
    promSub: "14 servers · recovering",
    codePill: "pushed 2-line fix ✓",
    filterTag: false,
    ripples: [],
    orbs: [
      { path: "p-node-builder-pr", reverse: true, cls: "" },
      { path: "p-alex-node", reverse: true, cls: "" },
    ],
  },
  {
    tip: "9 · PR Ready -> Alex notified on Slack",
    caption: "The Public Node notifies Alex's subscribed thread that <strong>PR #412 is ready to merge</strong> — Alex's Private Node sends the all-clear DM to Alex on Slack.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-gh", "ent-priv", "ent-slack"],
    dim: ["ent-alice", "ent-ops"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-gh-node", "p-alex-node", "p-alex-priv", "p-priv-slack"],
    softStrands: ["p-node-builder"],
    bubbles: {
      "bub-alex": { text: "PR #412 is ready! Letting Alex know on Slack.", alert: false },
    },
    caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
    ghActive: "green",
    ghTitle: "GitHub · PR #412 ✓",
    ghSub: "Ready to merge · 0 errors",
    slackMsg: "“<strong>PR #412</strong> approved by Jack's builder &amp; CI green — ready to merge!”",
    promSub: "14 servers · healthy",
    codePill: "",
    filterTag: false,
    ripples: ["rip-alex"],
    orbs: [
      { path: "p-gh-node", reverse: false, cls: "" },
      { path: "p-alex-node", reverse: true, cls: "" },
      { path: "p-priv-slack", reverse: false, cls: "moss" },
    ],
  },
];

const strandLengths = new Map();
document.querySelectorAll(".myc-strand").forEach((path) => {
  const len = path.getTotalLength();
  strandLengths.set(path.id, len);
  path.style.strokeDasharray = `${len}`;
  path.style.strokeDashoffset = `${len}`;
});

let chapterIdx = 0;
let storyPlaying = true;
let storyTimer = null;
let orbRaf = null;
let progressRaf = null;
let stepStartedAt = performance.now();

function animateOrbs(orbSpecs) {
  if (orbRaf) cancelAnimationFrame(orbRaf);
  const orbEls = [document.getElementById("orb1"), document.getElementById("orb2"), document.getElementById("orb3")];
  orbEls.forEach((el) => el.classList.remove("show", "amber", "coral", "moss"));
  if (!orbSpecs.length || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;

  const active = orbSpecs.slice(0, 3).map((spec, idx) => ({
    el: orbEls[idx],
    path: document.getElementById(spec.path),
    reverse: spec.reverse,
    offset: idx * 0.34,
    cls: spec.cls,
  })).filter((item) => item.el && item.path);

  active.forEach((item) => {
    item.el.classList.add("show");
    if (item.cls) item.el.classList.add(item.cls);
  });

  const t0 = performance.now();
  const dur = 2500;
  function frame(now) {
    const u = (now - t0) / dur;
    for (const item of active) {
      const raw = (u + item.offset) % 1;
      const t = item.reverse ? 1 - raw : raw;
      const len = item.path.getTotalLength();
      const pt = item.path.getPointAtLength(len * t);
      item.el.setAttribute("cx", pt.x.toFixed(1));
      item.el.setAttribute("cy", pt.y.toFixed(1));
    }
    orbRaf = requestAnimationFrame(frame);
  }
  orbRaf = requestAnimationFrame(frame);
}

function updateProgressBar() {
  if (progressRaf) cancelAnimationFrame(progressRaf);
  const bar = document.getElementById("storyProgress");
  if (!bar) return;
  if (!storyPlaying) {
    bar.style.width = `${((chapterIdx + 1) / CHAPTERS.length) * 100}%`;
    return;
  }
  stepStartedAt = performance.now();
  function tick(now) {
    if (!storyPlaying) return;
    const pct = Math.min(100, ((now - stepStartedAt) / STEP_MS) * 100);
    bar.style.width = `${pct.toFixed(1)}%`;
    if (pct < 100) progressRaf = requestAnimationFrame(tick);
  }
  progressRaf = requestAnimationFrame(tick);
}

function renderChapter() {
  const ch = CHAPTERS[chapterIdx];

  const allEnts = ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-builder", "ent-gh", "ent-prom", "ent-priv", "ent-slack", "ent-subagent"];
  allEnts.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    const isVis = ch.visible.includes(id);
    const isDim = (ch.dim || []).includes(id);
    el.classList.toggle("visible", isVis);
    el.classList.toggle("dim", isVis && isDim);
    el.classList.toggle("spotlight", ch.spotlight.includes(id));
    el.classList.toggle("alert-hit", ch.alertHit.includes(id));
  });

  const ghEl = document.getElementById("ent-gh");
  ghEl.classList.toggle("active-amber", ch.ghActive === "amber");
  ghEl.classList.toggle("active-green", ch.ghActive === "green");
  document.getElementById("ghTitle").textContent = ch.ghTitle;
  document.getElementById("ghSub").textContent = ch.ghSub;

  document.getElementById("ent-prom").classList.toggle("active-coral", Boolean(ch.promActive));
  document.getElementById("promSub").textContent = ch.promSub;
  document.getElementById("filterTag").classList.toggle("show", Boolean(ch.filterTag));

  if (ch.subagentText) document.getElementById("subagentText").textContent = ch.subagentText;
  if (ch.slackMsg) document.getElementById("slackDmMsg").innerHTML = ch.slackMsg;

  const codePill = document.getElementById("alexCodePill");
  codePill.textContent = ch.codePill || "";
  codePill.classList.toggle("show", Boolean(ch.codePill));

  ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
    const el = document.getElementById(id);
    el.classList.toggle("lit", (ch.caps || []).includes(id));
    el.classList.toggle("lit-coral", (ch.coralCaps || []).includes(id));
  });

  document.querySelectorAll(".myc-strand").forEach((path) => {
    const len = strandLengths.get(path.id) || 200;
    const isActive = ch.strands.includes(path.id);
    const isSoft = ch.softStrands.includes(path.id);
    path.classList.toggle("grown", isActive);
    path.classList.toggle("soft", isSoft);
    path.style.strokeDashoffset = (isActive || isSoft) ? "0" : `${len}`;
  });

  ["bub-alex", "bub-alice", "bub-ops", "bub-builder"].forEach((id) => {
    const el = document.getElementById(id);
    const spec = ch.bubbles[id];
    if (spec) {
      el.textContent = spec.text;
      el.classList.toggle("alert", spec.alert);
      el.classList.add("show");
    } else {
      el.classList.remove("show", "alert");
    }
  });

  ["rip-alex", "rip-node", "rip-ops", "rip-builder"].forEach((id) => {
    const el = document.getElementById(id);
    el.classList.remove("fire");
    if (ch.ripples.includes(id)) {
      void el.offsetWidth;
      el.classList.add("fire");
    }
  });

  document.getElementById("storyStepNum").textContent = `${chapterIdx + 1} / ${CHAPTERS.length}`;
  document.getElementById("storyCaption").innerHTML = ch.caption;

  const fillPct = CHAPTERS.length > 1 ? (chapterIdx / (CHAPTERS.length - 1)) * 100 : 0;
  document.getElementById("tlFill").style.width = `calc(${fillPct.toFixed(1)}% - 12px)`;

  const dotsHost = document.getElementById("tlDots");
  dotsHost.innerHTML = CHAPTERS.map((c, i) => `
    <button
      class="tl-dot ${i === chapterIdx ? "active" : i < chapterIdx ? "passed" : ""}"
      data-ch="${i}"
      data-tip="${esc(c.tip)}"
      aria-label="${esc(c.tip)}"
      type="button"
    ></button>
  `).join("");
  dotsHost.querySelectorAll("[data-ch]").forEach((btn) => {
    btn.addEventListener("click", () => {
      chapterIdx = Number(btn.dataset.ch);
      renderChapter();
      resetStoryTimer();
    });
  });

  animateOrbs(ch.orbs);
  updateProgressBar();
}

function resetStoryTimer() {
  if (storyTimer) clearInterval(storyTimer);
  if (!storyPlaying) return;
  storyTimer = setInterval(() => {
    chapterIdx = (chapterIdx + 1) % CHAPTERS.length;
    renderChapter();
  }, STEP_MS);
}

document.getElementById("storyPlayBtn").addEventListener("click", (e) => {
  storyPlaying = !storyPlaying;
  e.currentTarget.textContent = storyPlaying ? "Pause" : "Play";
  resetStoryTimer();
  updateProgressBar();
});

document.getElementById("storyPrevBtn").addEventListener("click", () => {
  chapterIdx = (chapterIdx - 1 + CHAPTERS.length) % CHAPTERS.length;
  renderChapter();
  resetStoryTimer();
});

document.getElementById("storyNextBtn").addEventListener("click", () => {
  chapterIdx = (chapterIdx + 1) % CHAPTERS.length;
  renderChapter();
  resetStoryTimer();
});

(function initSporeCanvas() {
  const canvas = document.getElementById("sporeCanvas");
  if (!canvas || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
  const ctx = canvas.getContext("2d");
  let w = 0, h = 0;
  const motes = Array.from({ length: 30 }, () => ({
    x: Math.random(),
    y: Math.random(),
    r: 1 + Math.random() * 1.6,
    vy: 0.00014 + Math.random() * 0.0002,
    vx: (Math.random() - 0.5) * 0.00012,
    phase: Math.random() * Math.PI * 2,
    gold: Math.random() > 0.55,
  }));
  function resize() {
    const rect = canvas.getBoundingClientRect();
    w = canvas.width = Math.max(1, Math.floor(rect.width));
    h = canvas.height = Math.max(1, Math.floor(rect.height));
  }
  resize();
  window.addEventListener("resize", resize);
  function draw(now) {
    ctx.clearRect(0, 0, w, h);
    for (const m of motes) {
      m.y -= m.vy;
      m.x += m.vx + Math.sin(now * 0.0007 + m.phase) * 0.00007;
      if (m.y < -0.05) { m.y = 1.05; m.x = Math.random(); }
      if (m.x < 0) m.x = 1;
      if (m.x > 1) m.x = 0;
      const alpha = 0.14 + 0.16 * Math.sin(now * 0.0012 + m.phase);
      ctx.fillStyle = m.gold ? `rgba(232,163,49,${alpha.toFixed(2)})` : `rgba(183,217,86,${alpha.toFixed(2)})`;
      ctx.beginPath();
      ctx.arc(m.x * w, m.y * h, m.r, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
})();

const urlChapter = new URLSearchParams(window.location.search).get("chapter");
if (urlChapter !== null && Number.isInteger(Number(urlChapter)) && Number(urlChapter) >= 0 && Number(urlChapter) < CHAPTERS.length) {
  chapterIdx = Number(urlChapter);
  storyPlaying = false;
  document.getElementById("storyPlayBtn").textContent = "Play";
}
renderChapter();
resetStoryTimer();

// ============================================================================
// 3. INTERACTIVE #CHANNELS CARD (#incidents & #deploys with Alex, Alice, Jack)
// ============================================================================
const chMembers = [
  { id: "jack@prod/ops", sub: "T3 Code · Linux server · Prometheus subscriber" },
  { id: "alex@laptop/claude", sub: "Claude in Herdr · laptop · hc interrupt" },
  { id: "jack@prod/builder", sub: "T3 Code · Linux server · PR reviewer" },
  { id: "alice@laptop/codex", sub: "Codex via OpenClaw · laptop · codex queue" },
];

const ROOM_STATE = {
  "#incidents": {
    joined: new Set(["jack@prod/ops", "alex@laptop/claude", "jack@prod/builder"]),
    sender: "jack@prod/ops",
    log: [
      "#incidents · 3 enrolled across 2 laptops & 1 server",
      "jack@prod/ops: checkout-api HighErrorRate (4.2%) — CODEOWNERS -> alex",
      "alex@laptop/claude: Reproduced Redis pool leak; opening PR #412",
    ],
  },
  "#deploys": {
    joined: new Set(["jack@prod/builder", "alice@laptop/codex", "alex@laptop/claude"]),
    sender: "jack@prod/builder",
    log: [
      "#deploys · release coordination room",
      "jack@prod/builder: PR #412 sub-agent review green (42/42 tests) — approved ✓",
    ],
  },
};

let activeRoom = "#incidents";

function renderChannel() {
  const room = ROOM_STATE[activeRoom];
  document.querySelectorAll("#chRoomTabs .win-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.room === activeRoom)
  );
  document.getElementById("channelInput").placeholder = `Post to ${activeRoom} as ${room.sender}...`;

  const host = document.getElementById("channelMembers");
  host.innerHTML = chMembers.map((m) => {
    const on = room.joined.has(m.id);
    return `
      <div class="member-row">
        <div>
          <span class="m-name">${m.id}</span>
          <span class="m-sub">${m.sub}</span>
        </div>
        <button class="toggle-pill ${on ? "on" : ""}" data-cm="${m.id}" type="button">${on ? "joined" : "join"}</button>
      </div>
    `;
  }).join("");

  host.querySelectorAll("[data-cm]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.cm;
      if (room.joined.has(id)) {
        room.joined.delete(id);
        room.log.push(`mesh_channel_leave('${activeRoom}') -> ${id}`);
      } else {
        room.joined.add(id);
        room.log.push(`mesh_channel_join('${activeRoom}') -> ${id}`);
      }
      renderChannel();
    });
  });

  const logEl = document.getElementById("channelLog");
  logEl.innerHTML = room.log.map((line, i) =>
    `<div class="${i === room.log.length - 1 ? "hl" : ""}">${esc(line)}</div>`
  ).join("");
  logEl.scrollTop = logEl.scrollHeight;
}

function postChannel() {
  const room = ROOM_STATE[activeRoom];
  const input = document.getElementById("channelInput");
  const text = input.value.trim() || (activeRoom === "#incidents"
    ? "PR #412 merged — error rate back to 0.0%."
    : "Shipping checkout-api v2.14.1 to prod.");
  input.value = "";
  const recips = [...room.joined].filter((x) => x !== room.sender);
  room.log.push(`${room.sender}: ${text}`);
  room.log.push(`-> pushed natively to [${recips.join(", ") || "nobody"}]`);
  renderChannel();
}

document.querySelectorAll("#chRoomTabs .win-tab").forEach((b) => {
  b.addEventListener("click", () => { activeRoom = b.dataset.room; renderChannel(); });
});
document.getElementById("channelSendBtn").addEventListener("click", postChannel);
document.getElementById("channelInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") postChannel();
});
renderChannel();

// ============================================================================
// 4. DARK STREAMS, #CHANNELS & PRIVATE BRIDGES DECK
// ============================================================================
let activeDeck = "prometheus";
const chatLinked = new Set(["alex@laptop/claude"]);
let chatApp = "slack";

const DECK_VIEWS = {
  prometheus: {
    payload: {
      specversion: "1.0",
      source: "prometheus/server-fleet",
      type: "io.prometheus.alert.firing",
      subject: "severity=critical/HighErrorRate",
      data: { service: "checkout-api", rate: "4.2%", codeowners: ["alex"] },
    },
    routes: [
      { addr: "jack@prod/ops", sub: "filter: subject startsWith 'severity=critical' · T3 dispatch", match: true, interrupt: true },
      { addr: "alex@laptop/claude", sub: "notified by jack/ops after CODEOWNERS check · hc interrupt", match: true, interrupt: false },
      { addr: "jack@prod/builder", sub: "filter: topic == 'github' · stays quiet", match: false, interrupt: false },
      { addr: "alice@laptop/codex", sub: "filter: subject startsWith 'acme/auth' · stays quiet", match: false, interrupt: false },
    ],
  },
  github: {
    payload: {
      specversion: "1.0",
      source: "github/acme/checkout-api",
      type: "com.github.pull_request.review_requested",
      subject: "acme/checkout-api#412",
      data: { author: "alex", reviewer: "jack/builder", checks: "42/42 green" },
    },
    routes: [
      { addr: "jack@prod/builder", sub: "filter: reviewer == 'jack/builder' -> spawns review sub-agent", match: true, interrupt: false },
      { addr: "alex@laptop/claude", sub: "subscribed to PR #412 -> woken when review & CI finish", match: true, interrupt: false },
      { addr: "jack@prod/ops", sub: "filter: topic == 'prometheus' · stays quiet", match: false, interrupt: false },
      { addr: "alice@laptop/codex", sub: "filter: repo == 'acme/auth' · stays quiet", match: false, interrupt: false },
    ],
  },
  channels: {
    payload: {
      tool: "mesh_channel_post",
      node: "public-node (SQLite channel_members)",
      channel: "#incidents",
      from: "jack@prod/ops",
      text: "checkout-api spiking (4.2%). Alex opening PR #412; builder queued for review.",
      noSenderEcho: true,
    },
    routes: [
      { addr: "alex@laptop/claude", sub: "joined #incidents · woke via hc interrupt", match: true, interrupt: false },
      { addr: "jack@prod/builder", sub: "joined #incidents · woke via T3 dispatch", match: true, interrupt: false },
      { addr: "alice@laptop/codex", sub: "not in #incidents (only in #deploys)", match: false, interrupt: false },
      { addr: "jack@prod/ops", sub: "sender · no self-echo", match: false, interrupt: false },
    ],
  },
};

const CHAT_THREADS = [
  { id: "alex@laptop/claude", sub: "Claude in Herdr · Alex's Private Node" },
  { id: "alice@laptop/codex", sub: "Codex via OpenClaw · Alice's laptop" },
  { id: "jack@prod/ops", sub: "T3 Code · Jack's server" },
  { id: "jack@prod/builder", sub: "T3 Code · Jack's server" },
];

function renderDeck() {
  document.querySelectorAll("#deckTabs .deck-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.deck === activeDeck)
  );
  const body = document.getElementById("deckBody");

  if (activeDeck !== "chat") {
    const d = DECK_VIEWS[activeDeck];
    body.innerHTML = `
      <div>
        <pre class="payload-pre">${esc(JSON.stringify(d.payload, null, 2))}</pre>
      </div>
      <div>
        ${d.routes.map((r) => `
          <div class="route-item ${r.match ? (r.interrupt ? "interrupt" : "matched") : "dim"}">
            <div>
              <span class="ri-addr">${r.addr}</span>
              <span class="ri-sub">${r.sub}</span>
            </div>
            <span class="ri-pill">${r.match ? (r.interrupt ? "interrupt" : "woken") : "filtered"}</span>
          </div>
        `).join("")}
      </div>
    `;
    return;
  }

  const linkedList = [...chatLinked];
  body.innerHTML = `
    <div>
      <div class="deck-tabs" style="margin-bottom:14px;">
        ${["slack", "telegram", "whatsapp", "byo-fd3"].map((app) =>
          `<button class="deck-tab ${chatApp === app ? "active" : ""}" data-capp="${app}" type="button">${app}</button>`
        ).join("")}
      </div>
      <pre class="payload-pre">${esc(JSON.stringify({
        node: "Private Node (localhost — never shared with Public Node)",
        bridge: `${chatApp}/dm-alex`,
        secrets: "0600 local store · captured via hph secret set --web",
        linkedThreads: linkedList,
        liveHandoff: "mesh_plugin_handoff (zero daemon restart)",
      }, null, 2))}</pre>
    </div>
    <div>
      ${CHAT_THREADS.map((t) => {
        const on = chatLinked.has(t.id);
        return `
          <div class="route-item ${on ? "matched" : "dim"}">
            <div>
              <span class="ri-addr">${t.id}</span>
              <span class="ri-sub">${t.sub}</span>
            </div>
            <button class="ri-pill" data-ct="${t.id}" type="button">${on ? "linked · unlink" : "link thread"}</button>
          </div>
        `;
      }).join("")}
    </div>
  `;

  body.querySelectorAll("[data-capp]").forEach((btn) => {
    btn.addEventListener("click", () => { chatApp = btn.dataset.capp; renderDeck(); });
  });
  body.querySelectorAll("[data-ct]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.ct;
      if (chatLinked.has(id)) chatLinked.delete(id);
      else chatLinked.add(id);
      renderDeck();
    });
  });
}

document.querySelectorAll("#deckTabs .deck-tab").forEach((b) => {
  b.addEventListener("click", () => { activeDeck = b.dataset.deck; renderDeck(); });
});
renderDeck();

// ============================================================================
// 5. QUICK START TABS
// ============================================================================
const QS = {
  curl: `# Install hph from GitHub and launch interactive onboarding
bash -c "$(curl -fsSL https://raw.githubusercontent.com/bowd/hyphae/main/install.sh)"

# Verify Node 24, daemon, live nodes, 0600 secrets, and harnesses
hph status`,
  npm: `# Install globally via npm (Node 24+)
npm install -g @bowd/hyphae

# Pick Private / Public / Shared nodes, harnesses, streams & SSH hosts
hph onboard`,
  assist: `# Install the standalone Hyphae skill across harnesses (agent starting point)
hph skill install all

# Or let your coding agent run full onboarding end-to-end (secrets captured out-of-band via --web)
hph onboard --assist`,
  fleet: `# Wire OpenClaw as your fleet orchestrator
hph setup openclaw

# Share your private node on Tailscale & onboard remote Linux hosts over SSH
hph share tailscale --service hyphae
hph onboard --remote-ssh bogdan@solace --install-service

# Store Slack/Telegram/webhook tokens out-of-band (0600, never enters LLM context)
hph secret set slack-bot-token --web`,
};

let activeQs = "curl";
function renderQs() {
  document.getElementById("qsPre").textContent = QS[activeQs];
  document.querySelectorAll("#qsTabs .it-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.qs === activeQs)
  );
}
document.querySelectorAll("#qsTabs .it-btn").forEach((b) => {
  b.addEventListener("click", () => { activeQs = b.dataset.qs; renderQs(); });
});
document.getElementById("qsCopyBtn").addEventListener("click", (e) => {
  navigator.clipboard?.writeText(QS[activeQs]).catch(() => {});
  const btn = e.currentTarget;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy"; }, 1300);
});
renderQs();
