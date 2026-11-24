function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================================
// 1. HERO INSTALL SWITCHER (Real GitHub curl | bash + npm + from-source)
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
// 2. LIVING HERO STORY DIORAMA (7 unhurried chapters + organic mycelium growth)
// ============================================================================
const STEP_MS = 7200;

const CHAPTERS = [
  {
    pill: "1 Solo",
    caption: "Meet <strong>Alex's agent thread</strong> — running Claude inside Herdr on Alex's laptop. Smart, caffeinated, and completely isolated.",
    visible: ["ent-alex"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: [],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Just me, 47 tabs, and a blinking cursor.", alert: false } },
    caps: [],
    promSub: "14 servers · quiet",
    filterTag: false,
    ripples: [],
    orbs: [],
  },
  {
    pill: "2 Join",
    caption: "Alex's agent calls <code>mesh_join</code> to plug into a <strong>Public Node</strong> — immediately unlocking shared <code>#channels</code> and subscribable event flows.",
    visible: ["ent-alex", "ent-node"],
    spotlight: ["ent-alex", "ent-node"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Plugging into the Public Node… oh hello.", alert: false } },
    caps: ["cap-ch", "cap-gh", "cap-pr"],
    promSub: "14 servers · quiet",
    filterTag: false,
    ripples: ["rip-node"],
    orbs: [{ path: "p-alex-node", reverse: false, cls: "" }],
  },
  {
    pill: "3 Peers",
    caption: "The network lights up: Alex can now reach <strong>Alice's Codex</strong> (running via OpenClaw on her laptop) and <strong>Jack's builder &amp; ops</strong> (T3 Code on a Linux server).",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom"],
    spotlight: ["ent-alice", "ent-jack"],
    alertHit: [],
    strands: ["p-node-alice", "p-node-jack"],
    softStrands: ["p-alex-node"],
    bubbles: {
      "bub-alice": { text: "Shipping auth from café Wi-Fi.", alert: false },
      "bub-jack": { text: "Builder + ops live on prod-01.", alert: false },
    },
    caps: ["cap-ch", "cap-gh", "cap-pr"],
    promSub: "14 servers · healthy",
    filterTag: false,
    ripples: [],
    orbs: [
      { path: "p-node-alice", reverse: false, cls: "amber" },
      { path: "p-node-jack", reverse: false, cls: "" },
    ],
  },
  {
    pill: "4 Subscribe",
    caption: "Jack's ops agent subscribes to the Public Node's <strong>GitHub</strong> stream and fleet <strong>Prometheus</strong> feed with a filter (<code>severity=critical</code>) — zero polling.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom"],
    spotlight: ["ent-node", "ent-jack"],
    alertHit: [],
    strands: ["p-gh-node", "p-node-jack"],
    softStrands: ["p-alex-node", "p-node-alice", "p-prom-node"],
    bubbles: {
      "bub-jack": { text: "Subscribed: GitHub PRs + critical fleet alerts.", alert: false },
    },
    caps: ["cap-gh", "cap-pr"],
    ghActive: true,
    promSub: "14 servers · watching",
    filterTag: true,
    ripples: [],
    orbs: [
      { path: "p-gh-node", reverse: false, cls: "amber" },
      { path: "p-node-jack", reverse: false, cls: "amber" },
    ],
  },
  {
    pill: "5 Alert",
    caption: "Right after PR #412, <span class='coral-txt'>Prometheus fires HighErrorRate (4.2%)</span> across the server fleet. The Public Node matches Jack's filter and wakes Jack's ops instantly.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom"],
    spotlight: ["ent-node"],
    alertHit: ["ent-jack"],
    strands: ["p-prom-node", "p-node-jack-alert"],
    softStrands: ["p-alex-node", "p-node-alice", "p-gh-node"],
    bubbles: {
      "bub-jack": { text: "Pager! checkout-api spiked right after PR #412.", alert: true },
    },
    caps: ["cap-gh"],
    coralCaps: ["cap-pr"],
    ghActive: true,
    promActive: true,
    promSub: "HighErrorRate · 4.2%!",
    filterTag: true,
    ripples: ["rip-jack"],
    orbs: [
      { path: "p-prom-node", reverse: false, cls: "coral" },
      { path: "p-node-jack-alert", reverse: false, cls: "coral" },
    ],
  },
  {
    pill: "6 Wake Alex",
    caption: "Jack's ops pushes the alert &amp; PR context through the Public Node to <strong>Alex's Claude thread</strong> — interrupting it cleanly on Alex's laptop across harnesses and servers.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom"],
    spotlight: ["ent-jack"],
    alertHit: ["ent-alex"],
    strands: ["p-node-jack-alert", "p-alex-node"],
    softStrands: ["p-node-alice", "p-gh-node", "p-prom-node"],
    bubbles: {
      "bub-jack": { text: "Forwarding stack trace + PR #412 to Alex.", alert: false },
      "bub-alex": { text: "Woke via hc interrupt! Checking Redis pool now.", alert: true },
    },
    caps: ["cap-ch", "cap-gh"],
    coralCaps: ["cap-pr"],
    promSub: "HighErrorRate · 4.2%!",
    filterTag: false,
    ripples: ["rip-alex"],
    orbs: [
      { path: "p-node-jack-alert", reverse: true, cls: "coral" },
      { path: "p-alex-node", reverse: true, cls: "coral" },
    ],
  },
  {
    pill: "7 Slack",
    caption: "Alex's agent also wires its own <strong>Private Node</strong> bridged to <strong>Slack</strong> — DMing Alex directly while keeping the Slack token completely off the Public Node and out of the LLM.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom", "ent-priv", "ent-slack"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-priv", "p-priv-slack"],
    softStrands: ["p-alex-node", "p-node-alice", "p-node-jack"],
    bubbles: {
      "bub-alex": { text: "Keeping my Slack token safe on my Private Node.", alert: false },
    },
    caps: ["cap-ch", "cap-gh", "cap-pr"],
    promSub: "14 servers · mitigating",
    filterTag: false,
    ripples: [],
    orbs: [
      { path: "p-alex-priv", reverse: false, cls: "moss" },
      { path: "p-priv-slack", reverse: false, cls: "moss" },
    ],
  },
];

// Pre-measure every SVG path length for genuine stroke-dashoffset growth
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
  orbEls.forEach((el) => {
    el.classList.remove("show", "amber", "coral", "moss");
  });
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
  const dur = 2400; // Deliberate, easy-to-follow glide
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

  // Entities visibility & states
  const allEnts = ["ent-alex", "ent-node", "ent-alice", "ent-jack", "ent-gh", "ent-prom", "ent-priv", "ent-slack"];
  allEnts.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle("visible", ch.visible.includes(id));
    el.classList.toggle("spotlight", ch.spotlight.includes(id));
    el.classList.toggle("alert-hit", ch.alertHit.includes(id));
  });

  // Flow chips active highlight
  document.getElementById("ent-gh").classList.toggle("active-amber", Boolean(ch.ghActive));
  document.getElementById("ent-prom").classList.toggle("active-coral", Boolean(ch.promActive));
  document.getElementById("promSub").textContent = ch.promSub;
  document.getElementById("filterTag").classList.toggle("show", Boolean(ch.filterTag));

  // Public Node capability pills
  ["cap-ch", "cap-gh", "cap-pr"].forEach((id) => {
    const el = document.getElementById(id);
    el.classList.toggle("lit", (ch.caps || []).includes(id));
    el.classList.toggle("lit-coral", (ch.coralCaps || []).includes(id));
  });

  // Growing SVG mycelium strands
  document.querySelectorAll(".myc-strand").forEach((path) => {
    const len = strandLengths.get(path.id) || 200;
    const isActive = ch.strands.includes(path.id);
    const isSoft = ch.softStrands.includes(path.id);
    path.classList.toggle("grown", isActive);
    path.classList.toggle("soft", isSoft);
    path.style.strokeDashoffset = (isActive || isSoft) ? "0" : `${len}`;
  });

  // Witty speech bubbles
  ["bub-alex", "bub-alice", "bub-jack"].forEach((id) => {
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

  // Ripple rings
  ["rip-alex", "rip-node", "rip-jack"].forEach((id) => {
    const el = document.getElementById(id);
    el.classList.remove("fire");
    if (ch.ripples.includes(id)) {
      void el.offsetWidth;
      el.classList.add("fire");
    }
  });

  // Caption & chapter pills
  document.getElementById("storyStepNum").textContent = `${chapterIdx + 1} / ${CHAPTERS.length}`;
  document.getElementById("storyCaption").innerHTML = ch.caption;
  const pillsHost = document.getElementById("chapterPills");
  pillsHost.innerHTML = CHAPTERS.map((c, i) =>
    `<button class="ch-pill ${i === chapterIdx ? "active" : ""}" data-ch="${i}" type="button">${c.pill}</button>`
  ).join("");
  pillsHost.querySelectorAll("[data-ch]").forEach((btn) => {
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

// Subtle drifting organic spore motes in the dark diorama backdrop
(function initSporeCanvas() {
  const canvas = document.getElementById("sporeCanvas");
  if (!canvas || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
  const ctx = canvas.getContext("2d");
  let w = 0, h = 0;
  const motes = Array.from({ length: 24 }, () => ({
    x: Math.random(),
    y: Math.random(),
    r: 0.9 + Math.random() * 1.5,
    vy: 0.00018 + Math.random() * 0.00025,
    vx: (Math.random() - 0.5) * 0.00015,
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
      m.x += m.vx + Math.sin(now * 0.0008 + m.phase) * 0.00008;
      if (m.y < -0.05) { m.y = 1.05; m.x = Math.random(); }
      if (m.x < 0) m.x = 1;
      if (m.x > 1) m.x = 0;
      const alpha = 0.16 + 0.16 * Math.sin(now * 0.0014 + m.phase);
      ctx.fillStyle = m.gold ? `rgba(232,163,49,${alpha.toFixed(2)})` : `rgba(183,217,86,${alpha.toFixed(2)})`;
      ctx.beginPath();
      ctx.arc(m.x * w, m.y * h, m.r, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
})();

// Allow ?chapter=0..5 query param for direct linking / visual inspection; default starts at Beat 1 (0)
const urlChapter = new URLSearchParams(window.location.search).get("chapter");
if (urlChapter !== null && Number.isInteger(Number(urlChapter)) && Number(urlChapter) >= 0 && Number(urlChapter) < CHAPTERS.length) {
  chapterIdx = Number(urlChapter);
  storyPlaying = false;
  document.getElementById("storyPlayBtn").textContent = "Play";
}
renderChapter();
resetStoryTimer();

// ============================================================================
// 3. INTERACTIVE #INCIDENTS CHANNEL CARD (Inside Granola-style collage)
// ============================================================================
const chMembers = [
  { id: "ops@gn/openclaw", sub: "OpenClaw · great-northern" },
  { id: "bogdan@macbook/agy", sub: "Antigravity · MacBook Pro · hph wait" },
  { id: "maya@solace/codex", sub: "Codex · solace · codex queue" },
  { id: "ops@solace/herdr", sub: "Herdr Core · solace · hc interrupt" },
];
const chJoined = new Set(["ops@gn/openclaw", "bogdan@macbook/agy", "maya@solace/codex"]);
const chLog = [
  "#incidents ready · 3 members across 3 machines",
  "ops@gn/openclaw: Checkout error rate spiked to 4.2%",
];

function renderChannel() {
  const host = document.getElementById("channelMembers");
  host.innerHTML = chMembers.map((m) => {
    const on = chJoined.has(m.id);
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
      if (chJoined.has(id)) {
        chJoined.delete(id);
        chLog.push(`leave #incidents -> ${id}`);
      } else {
        chJoined.add(id);
        chLog.push(`join #incidents -> ${id}`);
      }
      renderChannel();
    });
  });

  const logEl = document.getElementById("channelLog");
  logEl.innerHTML = chLog.map((line, i) =>
    `<div class="${i === chLog.length - 1 ? "hl" : ""}">${esc(line)}</div>`
  ).join("");
  logEl.scrollTop = logEl.scrollHeight;
}

function postChannel() {
  const input = document.getElementById("channelInput");
  const text = input.value.trim() || "PR #412 green — merging now.";
  input.value = "";
  const recips = [...chJoined].filter((x) => x !== "ops@gn/openclaw");
  chLog.push(`ops@gn/openclaw: ${text}`);
  chLog.push(`-> pushed to [${recips.join(", ") || "nobody"}]`);
  renderChannel();
}

document.getElementById("channelSendBtn").addEventListener("click", postChannel);
document.getElementById("channelInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") postChannel();
});
renderChannel();

// ============================================================================
// 4. DARK STREAMS & CHAT BRIDGES DECK
// ============================================================================
let activeDeck = "prometheus";
const chatLinked = new Set(["bogdan@macbook/agy", "ops@gn/openclaw"]);
let chatApp = "telegram";

const DECK_EVENTS = {
  prometheus: {
    payload: {
      specversion: "1.0",
      source: "alertmanager/prod",
      type: "io.prometheus.alert.firing",
      subject: "severity=critical/HighErrorRate",
      data: { service: "checkout-api", rate: "4.2%" },
    },
    routes: [
      { addr: "ops@solace/herdr", sub: "filter: subject startsWith 'severity=critical' · hc interrupt", match: true, interrupt: true },
      { addr: "ops@gn/openclaw", sub: "filter: topic == 'prometheus' · queue", match: true, interrupt: false },
      { addr: "maya@gn/pr-bot", sub: "filter: topic == 'github' · T3 dispatch", match: false, interrupt: false },
      { addr: "bogdan@macbook/agy", sub: "filter: topic == 'ci' · hph wait", match: false, interrupt: false },
    ],
  },
  github: {
    payload: {
      specversion: "1.0",
      source: "github/acme/payments",
      type: "com.github.pull_request.opened",
      subject: "acme/payments#412",
      data: { title: "Cap Redis pool wait queue", author: "maya" },
    },
    routes: [
      { addr: "maya@gn/pr-bot", sub: "filter: subject startsWith 'acme/payments' · T3 dispatch", match: true, interrupt: false },
      { addr: "ops@gn/openclaw", sub: "filter: type == 'com.github.pull_request.opened'", match: true, interrupt: false },
      { addr: "ops@solace/herdr", sub: "filter: topic == 'prometheus'", match: false, interrupt: false },
      { addr: "bogdan@macbook/agy", sub: "filter: topic == 'ci'", match: false, interrupt: false },
    ],
  },
};

const CHAT_THREADS = [
  { id: "bogdan@macbook/agy", sub: "Antigravity · MacBook Pro · 0-CPU hph wait" },
  { id: "ops@gn/openclaw", sub: "OpenClaw · great-northern" },
  { id: "maya@solace/codex", sub: "Codex · solace · codex queue" },
  { id: "ops@solace/herdr", sub: "Herdr · solace · hc send" },
];

function renderDeck() {
  document.querySelectorAll("#deckTabs .deck-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.deck === activeDeck)
  );
  const body = document.getElementById("deckBody");

  if (activeDeck !== "chat") {
    const d = DECK_EVENTS[activeDeck];
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
            <span class="ri-pill">${r.match ? (r.interrupt ? "interrupt" : "matched") : "filtered"}</span>
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
        ${["telegram", "whatsapp", "slack", "byo-fd3"].map((app) =>
          `<button class="deck-tab ${chatApp === app ? "active" : ""}" data-capp="${app}" type="button">${app}</button>`
        ).join("")}
      </div>
      <pre class="payload-pre">${esc(JSON.stringify({
        bridge: `${chatApp}/ops`,
        transport: "local fd-3 pipe (0600 token isolated from LLM)",
        linkedThreads: linkedList,
        liveHandoff: "hph mesh_plugin_handoff (zero daemon restart)",
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
    btn.addEventListener("click", () => {
      chatApp = btn.dataset.capp;
      renderDeck();
    });
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
  b.addEventListener("click", () => {
    activeDeck = b.dataset.deck;
    renderDeck();
  });
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
  b.addEventListener("click", () => {
    activeQs = b.dataset.qs;
    renderQs();
  });
});
document.getElementById("qsCopyBtn").addEventListener("click", (e) => {
  navigator.clipboard?.writeText(QS[activeQs]).catch(() => {});
  const btn = e.currentTarget;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy"; }, 1300);
});
renderQs();
