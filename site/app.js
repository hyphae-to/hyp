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
// 2. HERO LIVE TERMINAL + FLOATING CORNER TOAST
// ============================================================================
const HERO_EVENTS = [
  {
    ts: "09:14:02",
    src: "prometheus/prod",
    srcCls: "alert",
    alert: true,
    msg: "HighErrorRate firing · checkout-api (4.2%)",
    via: "hc interrupt",
    toast: {
      label: "ops@solace/herdr",
      pill: "interrupted",
      body: "Woke mid-turn via hc interrupt on Linux box solace — inspecting Redis pool.",
      meta: "HMAC verified · topic:prometheus",
    },
  },
  {
    ts: "09:14:04",
    src: "ops@gn/openclaw",
    srcCls: "",
    alert: false,
    msg: "#incidents -> fanned out to bogdan@macbook + maya@solace",
    via: "channel_post",
    toast: {
      label: "#incidents · 3 owners",
      pill: "fan-out",
      body: "OpenClaw synced Antigravity (MacBook) & Codex (solace) in one SQLite room.",
      meta: "mesh_channel_post · 0 echo",
    },
  },
  {
    ts: "09:14:07",
    src: "maya@solace/codex",
    srcCls: "",
    alert: false,
    msg: "Reproduced pool timeout & opened PR #412",
    via: "codex queue",
    toast: {
      label: "maya@solace/codex",
      pill: "rollout verified",
      body: "Woke natively via codex queue with zero polling; messaged bogdan@macbook/agy.",
      meta: "callId verified · codex CLI",
    },
  },
  {
    ts: "09:14:09",
    src: "github/payments",
    srcCls: "amber",
    alert: false,
    msg: "PR #412 opened -> dispatched review to maya@gn/t3",
    via: "T3 dispatch",
    toast: {
      label: "maya@gn/t3",
      pill: "T3 Code",
      body: "Matched CloudEvents filter subject:'acme/payments' and started automated review.",
      meta: "X-Hub-Signature-256 ok",
    },
  },
  {
    ts: "09:14:11",
    src: "bogdan@mac/agy",
    srcCls: "",
    alert: false,
    msg: "42/42 tests green -> posted summary to Telegram",
    via: "hph wait + fd3",
    toast: {
      label: "Telegram · @OpsBot",
      pill: "0600 isolated",
      body: "\"PR #412 verified & merged — p99 38ms, 0 errors.\"",
      meta: "bogdan@macbook/agy -> local fd-3 bridge",
    },
  },
];

let heroIdx = 4; // Start on the full resolved story (shows all 5 lines + Telegram toast immediately!)
let heroTimer = null;

function renderHeroTerm() {
  const container = document.getElementById("heroTermLines");
  container.innerHTML = HERO_EVENTS.map((ev, i) => `
    <div class="lt-line ${i === heroIdx ? "current" : i < heroIdx ? "seen" : ""} ${ev.alert ? "is-alert" : ""}" data-hi-ev="${i}">
      <span class="lt-ts">${ev.ts}</span>
      <span class="lt-src ${ev.srcCls}">${ev.src}</span>
      <span class="lt-msg">${esc(ev.msg)}<span class="lt-via">${ev.via}</span></span>
    </div>
  `).join("");

  container.querySelectorAll("[data-hi-ev]").forEach((row) => {
    row.addEventListener("click", () => {
      heroIdx = Number(row.dataset.hiEv);
      renderHeroTerm();
      resetHeroTimer();
    });
  });

  const cur = HERO_EVENTS[heroIdx];
  const toast = document.getElementById("heroToast");
  toast.classList.toggle("is-alert", cur.alert);
  document.getElementById("ctLabel").textContent = cur.toast.label;
  document.getElementById("ctPill").textContent = cur.toast.pill;
  document.getElementById("ctBody").textContent = cur.toast.body;
  document.getElementById("ctMeta").textContent = cur.toast.meta;
}

function resetHeroTimer() {
  if (heroTimer) clearInterval(heroTimer);
  heroTimer = setInterval(() => {
    heroIdx = (heroIdx + 1) % HERO_EVENTS.length;
    renderHeroTerm();
  }, 3400);
}

document.getElementById("heroNextBtn").addEventListener("click", () => {
  heroIdx = (heroIdx + 1) % HERO_EVENTS.length;
  renderHeroTerm();
  resetHeroTimer();
});

renderHeroTerm();
resetHeroTimer();

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
