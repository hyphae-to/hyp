function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================================
// 1. HERO INSTALL SWITCHER (Real GitHub curl | bash + npm + from-source)
// ============================================================================
const HERO_CMDS = {
  curl: 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/bowd/hyphae/main/install.sh)"',
  npm: "npm install -g @hyphae-sh/cli && hph onboard",
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
// 2. HERO ART STAGE — LIVE CROSS-OWNER / CROSS-HARNESS / STREAM ANIMATION
// ============================================================================
const STAGE_SCENES = [
  {
    alert: true,
    active: ["stream", "gn", "solace"],
    wire: "Prometheus HighErrorRate -> hc interrupt (solace) + queue (openclaw)",
    stream: { addr: "prometheus/prod", tag: "topic:prometheus", msg: "HighErrorRate firing on checkout-api (severity=critical)", meta: "HMAC verified · CloudEvents" },
    macbook: { tag: "Antigravity", msg: "Parked on 0-CPU hph wait. Not woken by noise.", mech: "hph wait (idle)" },
    gn: { tag: "OpenClaw · woke", msg: "Received critical alert -> gathering logs & posting to #incidents.", mech: "queue wakeup" },
    solace: { tag: "Herdr · interrupted", msg: "ops@solace/herdr interrupted mid-turn to inspect checkout-api.", mech: "hc interrupt" },
  },
  {
    alert: false,
    active: ["gn", "macbook", "solace"],
    wire: "ops@gn/openclaw -> #incidents -> bogdan@macbook/agy + maya@solace/codex",
    stream: { addr: "#incidents", tag: "channel fan-out", msg: "3 owners, 3 servers, 3 harnesses synced in one SQLite room.", meta: "mesh_channel_post" },
    macbook: { tag: "Antigravity · woke", msg: "Woke via hph wait! Running regression suite on MacBook Pro.", mech: "0-CPU hph wait" },
    gn: { tag: "OpenClaw · posted", msg: "\"Checkout pool exhausted at 4.2% error rate — Maya check Redis.\"", mech: "mesh_channel_post" },
    solace: { tag: "Codex · woke", msg: "Woke natively via codex queue. Reproducing Redis timeout locally.", mech: "codex queue" },
  },
  {
    alert: false,
    active: ["stream", "gn", "solace"],
    wire: "GitHub pull_request.opened (#412) -> T3 Code pr-bot (maya@gn)",
    stream: { addr: "github/acme/payments", tag: "topic:github", msg: "PR #412 opened by maya@solace/codex: Cap Redis wait queue", meta: "X-Hub-Signature-256 ok" },
    macbook: { tag: "Antigravity", msg: "Tests green on checkout-api (42/42 passed).", mech: "mesh_send" },
    gn: { tag: "T3 Code · woke", msg: "maya@gn/pr-bot dispatched via T3 RPC to review PR #412.", mech: "T3 dispatch" },
    solace: { tag: "Codex · pushed", msg: "Pushed fix & notified bogdan@macbook/agy directly.", mech: "rollout verified" },
  },
  {
    alert: false,
    active: ["macbook", "stream"],
    wire: "bogdan@macbook/agy -> fd-3 bridge -> Telegram @OpsBot (0600 token)",
    stream: { addr: "telegram/@OpsBot", tag: "fd-3 bridge", msg: "Posted to #ops: \"PR #412 verified & merged — p99 38ms, 0 errors.\"", meta: "0600 secret isolated" },
    macbook: { tag: "Antigravity · replied", msg: "Sent summary through local fd-3 pipe without touching bot token.", mech: "fd-3 post" },
    gn: { tag: "OpenClaw", msg: "Incident #412 marked resolved across #incidents.", mech: "idle" },
    solace: { tag: "Codex · Herdr", msg: "Cleanly back to work on solace.", mech: "idle" },
  },
];

let sceneIdx = 0;
let sceneTimer = null;

function renderStage() {
  const s = STAGE_SCENES[sceneIdx];
  const pill = document.getElementById("stageWirePill");
  pill.classList.toggle("alert", s.alert);
  document.getElementById("stageWireText").textContent = s.wire;

  document.getElementById("addr-stream").textContent = s.stream.addr;
  document.getElementById("tag-stream").textContent = s.stream.tag;
  document.getElementById("msg-stream").textContent = s.stream.msg;
  document.getElementById("meta-stream").textContent = s.stream.meta;

  for (const k of ["macbook", "gn", "solace"]) {
    document.getElementById(`tag-${k}`).textContent = s[k].tag;
    document.getElementById(`msg-${k}`).textContent = s[k].msg;
    document.getElementById(`mech-${k}`).textContent = s[k].mech;
  }

  document.querySelectorAll("#artStage .float-card").forEach((card) => {
    const on = s.active.includes(card.dataset.node);
    card.classList.toggle("active", on);
    card.classList.toggle("alert", s.alert && on);
  });

  const pips = document.getElementById("stagePips");
  pips.innerHTML = STAGE_SCENES.map((_, i) =>
    `<button class="step-pip ${i === sceneIdx ? "active" : ""}" data-pip="${i}" aria-label="Step ${i + 1}" type="button"></button>`
  ).join("");
  pips.querySelectorAll("[data-pip]").forEach((btn) => {
    btn.addEventListener("click", () => {
      sceneIdx = Number(btn.dataset.pip);
      renderStage();
      resetSceneTimer();
    });
  });
}

function resetSceneTimer() {
  if (sceneTimer) clearInterval(sceneTimer);
  sceneTimer = setInterval(() => {
    sceneIdx = (sceneIdx + 1) % STAGE_SCENES.length;
    renderStage();
  }, 3800);
}

document.querySelectorAll("#artStage .float-card").forEach((card) => {
  card.addEventListener("click", () => {
    sceneIdx = (sceneIdx + 1) % STAGE_SCENES.length;
    renderStage();
    resetSceneTimer();
  });
});

renderStage();
resetSceneTimer();

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

# Verify Node 24, daemon, live router, 0600 secrets, and harnesses
hph status`,
  npm: `# Install globally via npm (Node 24+)
npm install -g @hyphae-sh/cli

# Pick Private / Public / Shared routers, harnesses, streams & SSH hosts
hph onboard`,
  assist: `# Install the standalone Hyphae skill across harnesses (agent starting point)
hph skill install all

# Or let your coding agent run full onboarding end-to-end (secrets captured out-of-band via --web)
hph onboard --assist`,
  fleet: `# Wire OpenClaw as your fleet orchestrator
hph setup openclaw

# Share your private router on Tailscale & onboard remote Linux hosts over SSH
hph share tailscale --service hyphae
hph onboard --remote-ssh bogdan@solace --install-service

# Store webhook & chat tokens out-of-band (0600, never enters LLM context)
hph secret set telegram-bot-token --web`,
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
