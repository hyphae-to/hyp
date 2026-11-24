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
// 2. PANORAMIC 9-CHAPTER HERO STORY DIORAMA (Causal staged reveals + one-shot messages)
// ============================================================================
const CHAPTERS = [
  {
    durationMs: 5200,
    tip: "1 · Solo agent on laptop",
    caption: "<strong>1/9</strong> · Meet <strong>Alex's agent thread</strong> — running Claude inside Herdr on a laptop. Smart, caffeinated, and totally alone.",
    visible: ["ent-alex"],
    dim: [],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: [],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Just me, 47 tabs, and a blinking cursor.", alert: false } },
    caps: [],
    subs: [],
    promState: "",
    promSub: "14 servers · quiet",
    ghTitle: "GitHub · PR #412",
    ghSub: "node event stream",
    filterTag: false,
    ripples: [],
    packets: [],
    stages: [],
  },
  {
    durationMs: 6200,
    tip: "2 · Joins the Team Node",
    caption: "<strong>2/9</strong> · Alex calls <code>mesh_join</code> on the <strong>Team Node</strong> — unlocking shared <code>#channels</code> and subscribable event flows.",
    visible: ["ent-alex", "ent-node"],
    dim: [],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Joining the Team Node… oh hello.", alert: false } },
    caps: [],
    subs: [],
    promState: "",
    promSub: "14 servers · quiet",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-node", reverse: false, cls: "", label: "mesh_join", delay: 250, dur: 1450 },
    ],
    stages: [
      {
        at: 1650,
        spotlight: ["ent-alex", "ent-node"],
        caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
        ripples: ["rip-node"],
      },
    ],
  },
  {
    durationMs: 7400,
    tip: "3 · Meets Alice & Jack's ops + release manager",
    caption: "<strong>3/9</strong> · The network lights up: <strong>Alice's Codex</strong> (OpenClaw, laptop) plus <strong>Jack's ops &amp; release manager</strong> (T3 Code, server).",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release"],
    dim: [],
    spotlight: ["ent-node"],
    alertHit: [],
    strands: ["p-node-alice", "p-node-ops", "p-node-release"],
    softStrands: ["p-alex-node"],
    bubbles: {},
    caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
    subs: [],
    promState: "",
    promSub: "14 servers · healthy",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-node-alice", reverse: false, cls: "amber", label: "peer online", delay: 250, dur: 1250 },
      { path: "p-node-ops", reverse: false, cls: "", label: "peer online", delay: 450, dur: 1250 },
      { path: "p-node-release", reverse: false, cls: "", label: "sub: approved PRs", delay: 650, dur: 1300 },
    ],
    stages: [
      {
        at: 1450,
        spotlight: ["ent-alice", "ent-ops", "ent-release"],
        bubbles: {
          "bub-alice": { text: "Shipping auth from café Wi-Fi.", alert: false },
          "bub-ops": { text: "Watching 14 prod servers.", alert: false },
        },
      },
      {
        at: 1950,
        bubbles: {
          "bub-release": { text: "Subscribed to approved PRs for deploy.", alert: false },
        },
        subs: ["sub-rel-pr"],
      },
    ],
  },
  {
    durationMs: 7800,
    tip: "4 · Fleet alert wakes Jack's ops -> CODEOWNERS",
    caption: "<strong>4/9</strong> · <span class='coral-txt'>Prometheus fires HighErrorRate (4.2%)</span>. The node filter wakes <strong>Jack's ops</strong>, who checks <code>CODEOWNERS</code> -> Alex owns <code>checkout-api</code>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-prom"],
    dim: ["ent-alice", "ent-release"],
    spotlight: ["ent-node"],
    alertHit: [],
    strands: ["p-prom-node"],
    softStrands: ["p-alex-node"],
    bubbles: {},
    caps: ["cap-ch"],
    coralCaps: [],
    subs: ["sub-rel-pr"],
    promState: "coral",
    promSub: "HighErrorRate · 4.2%!",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-prom-node", reverse: false, cls: "coral", label: "HighErrorRate 4.2%", delay: 200, dur: 1200 },
      { path: "p-node-ops-alert", reverse: false, cls: "coral", label: "alert -> jack/ops", delay: 1500, dur: 1350 },
    ],
    stages: [
      {
        at: 1400,
        coralCaps: ["cap-pr"],
        filterTag: true,
        addStrands: ["p-node-ops-alert"],
      },
      {
        at: 2850,
        alertHit: ["ent-ops"],
        ripples: ["rip-ops"],
        bubbles: {
          "bub-ops": { text: "checkout-api spiking! CODEOWNERS says Alex.", alert: true },
        },
      },
    ],
  },
  {
    durationMs: 8800,
    tip: "5 · Ops calls mesh_send -> Alex + Private Slack + #deploys",
    caption: "<strong>5/9</strong> · Jack's ops sends a <code>mesh_send</code> to <strong>Alex</strong>. Alex joins <code>#deploys</code> with ops and wires a <strong>Private Node -> Slack</strong> to DM Alex.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-prom"],
    dim: ["ent-alice", "ent-release"],
    spotlight: ["ent-ops"],
    alertHit: [],
    strands: ["p-node-ops-alert", "p-alex-node"],
    softStrands: ["p-prom-node"],
    bubbles: {
      "bub-ops": { text: "mesh_send -> alex: trace attached. Joining #deploys.", alert: false },
    },
    caps: ["cap-ch", "cap-dep"],
    coralCaps: ["cap-pr"],
    subs: ["sub-ops-dep", "sub-rel-pr"],
    promState: "coral",
    promSub: "HighErrorRate · 4.2%!",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    slackMsg: "“Jack's ops sent a trace on <strong>checkout-api</strong> (4.2%). Investigating now.”",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-node-ops-alert", reverse: true, cls: "coral", label: "mesh_send(trace)", delay: 200, dur: 1250 },
      { path: "p-alex-node", reverse: true, cls: "coral", label: "mesh_send -> alex", delay: 1500, dur: 1300 },
      { path: "p-priv-slack", reverse: false, cls: "moss", label: "DM: 4.2% error", delay: 3550, dur: 1100 },
    ],
    stages: [
      {
        at: 2800,
        spotlight: ["ent-ops", "ent-alex"],
        ripples: ["rip-alex"],
        addSubs: ["sub-alex-dep"],
        bubbles: {
          "bub-alex": { text: "Got it! Joining #deploys & DMing Alex on Slack.", alert: false },
        },
        addVisible: ["ent-priv"],
        addStrands: ["p-alex-priv"],
      },
      {
        at: 3450,
        addStrands: ["p-priv-slack"],
      },
      {
        at: 4650,
        addVisible: ["ent-slack"],
      },
    ],
  },
  {
    durationMs: 9400,
    tip: "6 · Alex fixes bug, opens PR #412 & subscribes -> CI Done ✓",
    caption: "<strong>6/9</strong> · Alex fixes the Redis pool leak, opens <strong>PR #412</strong>, subscribes to it on the Team Node, and receives <strong>CI Done ✓</strong> from GitHub.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-prom", "ent-code"],
    dim: ["ent-alice", "ent-ops", "ent-release"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-gh", "p-alex-node"],
    softStrands: [],
    bubbles: {
      "bub-alex": { text: "Fixed Redis pool leak — opening PR #412 & subscribing.", alert: false },
    },
    caps: [],
    subs: ["sub-alex-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "amber",
    ghTitle: "GitHub · PR #412",
    ghSub: "open · CI running…",
    ccAction: "→ opened PR #412 · mesh_subscribe(PR #412)",
    promState: "coral",
    promSub: "HighErrorRate · 4.2%!",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-gh", reverse: false, cls: "amber", label: "open PR #412", delay: 250, dur: 1150 },
      { path: "p-alex-node", reverse: false, cls: "", label: "mesh_subscribe(PR #412)", delay: 450, dur: 1150 },
      { path: "p-gh-node", reverse: false, cls: "", label: "CI Done ✓", delay: 2550, dur: 1150 },
      { path: "p-alex-node", reverse: true, cls: "", label: "CI Done ✓", delay: 3750, dur: 1250 },
    ],
    stages: [
      {
        at: 1450,
        addVisible: ["ent-gh"],
        addSubs: ["sub-alex-pr"],
        caps: ["cap-gh"],
        addStrands: ["p-gh-node"],
      },
      {
        at: 2450,
        ghActive: "green",
        ghSub: "open · CI Done ✓ · subscribed",
      },
      {
        at: 5000,
        ripples: ["rip-alex"],
        bubbles: {
          "bub-alex": { text: "PR #412 open & subscribed — CI Done ✓ just arrived!", alert: false },
        },
      },
    ],
  },
  {
    durationMs: 9600,
    tip: "7 · Alex hands PR #412 to Alice -> spawns review sub-agent",
    caption: "<strong>7/9</strong> · Alex hands <strong>PR #412</strong> to <strong>Alice</strong>. Alice subscribes to PR #412 + <code>#deploys</code> and spawns a <strong>review sub-agent</strong>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh"],
    dim: ["ent-alice", "ent-ops", "ent-release"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: ["p-gh-node"],
    bubbles: {
      "bub-alex": { text: "Handing PR #412 to Alice for review.", alert: false },
    },
    caps: ["cap-gh"],
    subs: ["sub-alex-pr", "sub-alex-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "green",
    ghTitle: "GitHub · PR #412",
    ghSub: "CI Done ✓ · ready for review",
    subagentText: "sub-agent · auditing PR #412",
    promState: "",
    promSub: "14 servers · mitigating",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-node", reverse: false, cls: "amber", label: "handover PR #412", delay: 250, dur: 1200 },
      { path: "p-node-alice", reverse: false, cls: "amber", label: "review PR #412", delay: 1500, dur: 1300 },
      { path: "p-alice-sub", reverse: false, cls: "amber", label: "spawn sub-agent", delay: 3000, dur: 1100 },
    ],
    stages: [
      {
        at: 1450,
        addStrands: ["p-node-alice"],
        ghActive: "amber",
        ghSub: "reviewer: alice/codex",
      },
      {
        at: 2800,
        undim: ["ent-alice"],
        spotlight: ["ent-alice"],
        ripples: ["rip-alice"],
        caps: ["cap-gh", "cap-dep"],
        addSubs: ["sub-alice-pr", "sub-alice-dep"],
        bubbles: {
          "bub-alice": { text: "Subscribed to PR #412 + #deploys! Spawning reviewer.", alert: false },
        },
        addStrands: ["p-alice-sub"],
      },
      {
        at: 4100,
        addVisible: ["ent-subagent"],
      },
    ],
  },
  {
    durationMs: 9600,
    tip: "8 · Review loop -> Alex patches -> Alice approves PR #412 ✓",
    caption: "<strong>8/9</strong> · Alice's sub-agent catches a timeout edge case -> Alex pushes a 2-line fix -> <strong>Alice approves PR #412 ✓</strong>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh", "ent-subagent"],
    dim: ["ent-ops", "ent-release"],
    spotlight: ["ent-alice"],
    alertHit: [],
    strands: ["p-alice-sub", "p-node-alice", "p-alex-node"],
    softStrands: ["p-gh-node"],
    bubbles: {
      "bub-alice": { text: "Sub-agent caught a timeout edge case — sending to Alex.", alert: false },
    },
    caps: ["cap-gh"],
    subs: ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "amber",
    ghTitle: "GitHub · PR #412",
    ghSub: "changes requested · timeout guard",
    subagentText: "sub-agent · found edge case",
    promState: "",
    promSub: "14 servers · recovering",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-node-alice", reverse: true, cls: "amber", label: "review: timeout fix", delay: 250, dur: 1150 },
      { path: "p-alex-node", reverse: true, cls: "amber", label: "review: timeout fix", delay: 1450, dur: 1150 },
      { path: "p-alex-gh", reverse: false, cls: "", label: "push 2-line fix", delay: 2800, dur: 1100 },
      { path: "p-node-alice-green", reverse: true, cls: "", label: "PR #412 Approved ✓", delay: 4200, dur: 1200 },
    ],
    stages: [
      {
        at: 2650,
        spotlight: ["ent-alex", "ent-alice"],
        ripples: ["rip-alex"],
        addStrands: ["p-alex-gh"],
        bubbles: {
          "bub-alex": { text: "2-line timeout patch pushed! All checks green.", alert: false },
        },
      },
      {
        at: 4050,
        subagentText: "sub-agent · diff clean ✓",
        addStrands: ["p-node-alice-green", "p-gh-node"],
        ghActive: "green",
        ghTitle: "GitHub · PR #412 ✓",
        ghSub: "Approved by Alice · CI green",
        bubbles: {
          "bub-alice": { text: "Sub-agent verified fix — Approved ✓!", alert: false },
        },
      },
    ],
  },
  {
    durationMs: 10600,
    tip: "9 · Release Mgr ships -> Alert fixed -> #deploys fan-out",
    caption: "<strong>9/9</strong> · <strong>Jack's release mgr</strong> merges &amp; ships <code>v2.14.1</code> -> <span style='color:var(--chartreuse);font-weight:600;'>alert fixed (0.0%)</span> -> <code>#deploys</code> notifies Alex, Alice &amp; Jack's ops (+ Slack DM).",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh", "ent-prom"],
    dim: [],
    spotlight: ["ent-release"],
    alertHit: [],
    strands: ["p-node-release"],
    softStrands: ["p-gh-node", "p-prom-node"],
    bubbles: {
      "bub-release": { text: "PR #412 approved! Merging & shipping v2.14.1.", alert: false },
    },
    caps: ["cap-ch", "cap-gh"],
    coralCaps: ["cap-pr"],
    subs: ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "green",
    ghTitle: "GitHub · PR #412 Merged ✓",
    ghSub: "released v2.14.1",
    promState: "coral",
    promSub: "HighErrorRate · rolling out…",
    slackMsg: "“<strong>v2.14.1</strong> shipped by Jack's release mgr — <strong>checkout-api</strong> alert resolved (0.0%)!”",
    filterTag: false,
    ripples: ["rip-release"],
    packets: [
      { path: "p-node-release", reverse: true, cls: "", label: "ship v2.14.1 -> #deploys", delay: 250, dur: 1300 },
      { path: "p-alex-node", reverse: true, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1650, dur: 1350 },
      { path: "p-node-alice-green", reverse: false, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1650, dur: 1350 },
      { path: "p-node-ops", reverse: false, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1650, dur: 1350 },
      { path: "p-priv-slack", reverse: false, cls: "moss", label: "DM: alert fixed ✓", delay: 3700, dur: 1050 },
    ],
    stages: [
      {
        at: 1600,
        caps: ["cap-ch", "cap-dep", "cap-gh"],
        addStrands: ["p-alex-node", "p-node-alice-green", "p-node-ops"],
      },
      {
        at: 2400,
        caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
        coralCaps: [],
        addStrands: ["p-prom-node-ok"],
        promState: "green",
        promSub: "0.0% · Alert resolved ✓",
      },
      {
        at: 3050,
        spotlight: ["ent-release", "ent-alex", "ent-alice", "ent-ops"],
        ripples: ["rip-alex", "rip-alice", "rip-ops"],
        bubbles: {
          "bub-alex": { text: "v2.14.1 live & alert cleared! DMing Alex on Slack.", alert: false },
        },
        addVisible: ["ent-priv"],
        addStrands: ["p-alex-priv"],
      },
      {
        at: 3650,
        addStrands: ["p-priv-slack"],
      },
      {
        at: 4750,
        addVisible: ["ent-slack"],
      },
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

const vineMain = document.getElementById("tlVineMain");
const vineSub = document.getElementById("tlVineSub");
const vineMainLen = vineMain ? vineMain.getTotalLength() : 1000;
const vineSubLen = vineSub ? vineSub.getTotalLength() : 1000;
if (vineMain) { vineMain.style.strokeDasharray = `${vineMainLen}`; vineMain.style.strokeDashoffset = `${vineMainLen}`; }
if (vineSub) { vineSub.style.strokeDasharray = `${vineSubLen}`; vineSub.style.strokeDashoffset = `${vineSubLen}`; }

let chapterIdx = 0;
let storyPlaying = true;
let storyTimer = null;
let pktRaf = null;
let stagedTimers = [];

function clearStagedTimers() {
  for (const t of stagedTimers) clearTimeout(t);
  stagedTimers = [];
}

function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

/**
 * Plays ONE-SHOT sequential labeled message packets along the exact SVG paths.
 * Packets travel cleanly from source to destination and dissolve upon arrival
 * (no orphaned pills parked on top of sprites or badges).
 */
function playWirePackets(specs) {
  if (pktRaf) cancelAnimationFrame(pktRaf);
  const host = document.getElementById("wirePackets");
  if (!host) return;
  host.innerHTML = "";
  if (!specs || !specs.length) return;

  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  if (reduced) return;

  const items = specs.map((spec) => {
    const path = document.getElementById(spec.path);
    if (!path) return null;
    const el = document.createElement("div");
    el.className = `wire-pkt ${spec.cls || ""}`.trim();
    el.innerHTML = `<span class="pkt-dot"></span><span>${esc(spec.label)}</span>`;
    host.appendChild(el);
    return { ...spec, el, path, len: path.getTotalLength() };
  }).filter(Boolean);

  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime;
    let anyPending = false;

    for (const item of items) {
      const local = elapsed - item.delay;
      if (local < 0) {
        anyPending = true;
        item.el.style.opacity = "0";
        continue;
      }
      const raw = Math.min(1, local / item.dur);
      if (raw < 1) anyPending = true;

      const travel = easeInOutCubic(raw) * 0.94;
      const t = item.reverse ? 1 - travel : travel;
      const pt = item.path.getPointAtLength(item.len * t);

      item.el.style.left = `${(pt.x / 1200) * 100}%`;
      item.el.style.top = `${(pt.y / 580) * 100}%`;

      let opacity = 1;
      if (raw < 0.14) opacity = raw / 0.14;
      else if (raw > 0.80) opacity = Math.max(0, (1 - raw) / 0.20);

      item.el.style.opacity = opacity.toFixed(2);
      item.el.style.transform = `translate(-50%, -50%) scale(${(0.88 + 0.12 * Math.min(1, raw * 4)).toFixed(3)})`;
    }

    if (anyPending) pktRaf = requestAnimationFrame(tick);
  }
  pktRaf = requestAnimationFrame(tick);
}

function applyStage(st) {
  if (st.addVisible) {
    st.addVisible.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.add("visible");
    });
  }
  if (st.undim) {
    st.undim.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.remove("dim");
    });
  }
  if (st.spotlight) {
    ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle("spotlight", st.spotlight.includes(id));
    });
  }
  if (st.alertHit) {
    st.alertHit.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.add("alert-hit");
    });
  }
  if (st.addStrands) {
    st.addStrands.forEach((id) => {
      const path = document.getElementById(id);
      if (path) {
        path.classList.remove("soft");
        path.classList.add("grown");
        path.style.strokeDashoffset = "0";
      }
    });
  }
  if (st.caps) {
    ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle("lit", st.caps.includes(id));
    });
  }
  if (st.coralCaps) {
    ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle("lit-coral", st.coralCaps.includes(id));
    });
  }
  if (st.subs) {
    ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle("show", st.subs.includes(id));
    });
  }
  if (st.addSubs) {
    st.addSubs.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.add("show");
    });
  }
  if (st.filterTag !== undefined) {
    document.getElementById("filterTag")?.classList.toggle("show", Boolean(st.filterTag));
  }
  if (st.ghActive !== undefined) {
    const ghEl = document.getElementById("ent-gh");
    ghEl.classList.toggle("active-amber", st.ghActive === "amber");
    ghEl.classList.toggle("active-green", st.ghActive === "green");
  }
  if (st.ghTitle) document.getElementById("ghTitle").textContent = st.ghTitle;
  if (st.ghSub) document.getElementById("ghSub").textContent = st.ghSub;
  if (st.promState !== undefined) {
    const promEl = document.getElementById("ent-prom");
    promEl.classList.toggle("active-coral", st.promState === "coral");
    promEl.classList.toggle("active-green", st.promState === "green");
  }
  if (st.promSub) document.getElementById("promSub").textContent = st.promSub;
  if (st.subagentText) document.getElementById("subagentText").textContent = st.subagentText;
  if (st.bubbles) {
    Object.entries(st.bubbles).forEach(([id, spec]) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = spec.text;
      el.classList.toggle("alert", Boolean(spec.alert));
      el.classList.add("show");
    });
  }
  if (st.ripples) {
    st.ripples.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.remove("fire");
      void el.offsetWidth;
      el.classList.add("fire");
    });
  }
}

function updateVineProgress() {
  const frac = CHAPTERS.length > 1 ? chapterIdx / (CHAPTERS.length - 1) : 1;
  if (vineMain) vineMain.style.strokeDashoffset = `${(vineMainLen * (1 - frac)).toFixed(1)}`;
  if (vineSub) vineSub.style.strokeDashoffset = `${(vineSubLen * (1 - frac)).toFixed(1)}`;
}

let forceSettled = new URLSearchParams(window.location.search).get("settled") === "1";

function renderChapter() {
  clearStagedTimers();
  const ch = CHAPTERS[chapterIdx];

  const allEnts = ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh", "ent-prom", "ent-priv", "ent-slack", "ent-subagent", "ent-code"];
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
  if (ch.ccAction) document.getElementById("ccAction").textContent = ch.ccAction;

  const promEl = document.getElementById("ent-prom");
  promEl.classList.toggle("active-coral", ch.promState === "coral");
  promEl.classList.toggle("active-green", ch.promState === "green");
  document.getElementById("promSub").textContent = ch.promSub;
  document.getElementById("filterTag").classList.toggle("show", Boolean(ch.filterTag));

  if (ch.subagentText) document.getElementById("subagentText").textContent = ch.subagentText;
  if (ch.slackMsg) document.getElementById("slackDmMsg").innerHTML = ch.slackMsg;

  // Dynamic subscription & #deploys channel badges under each agent
  ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("show", (ch.subs || []).includes(id));
  });

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

  ["bub-alex", "bub-alice", "bub-ops", "bub-release"].forEach((id) => {
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

  ["rip-alex", "rip-node", "rip-alice", "rip-ops", "rip-release"].forEach((id) => {
    const el = document.getElementById(id);
    el.classList.remove("fire");
    if (ch.ripples.includes(id)) {
      void el.offsetWidth;
      el.classList.add("fire");
    }
  });

  // In-scene subtitle + single-line mycelial timeline
  document.getElementById("storyCaption").innerHTML = ch.caption;
  updateVineProgress();

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

  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const settleNow = reduced || forceSettled;
  forceSettled = false;
  if (ch.stages && ch.stages.length) {
    if (settleNow) {
      ch.stages.forEach((st) => applyStage(st));
    } else {
      ch.stages.forEach((st) => {
        stagedTimers.push(setTimeout(() => applyStage(st), st.at));
      });
    }
  }

  playWirePackets(settleNow ? [] : ch.packets);
}

function resetStoryTimer() {
  if (storyTimer) clearTimeout(storyTimer);
  if (!storyPlaying) return;
  const delay = CHAPTERS[chapterIdx]?.durationMs ?? 8000;
  storyTimer = setTimeout(() => {
    chapterIdx = (chapterIdx + 1) % CHAPTERS.length;
    renderChapter();
    resetStoryTimer();
  }, delay);
}

document.getElementById("storyPlayBtn").addEventListener("click", (e) => {
  storyPlaying = !storyPlaying;
  e.currentTarget.textContent = storyPlaying ? "Pause" : "Play";
  resetStoryTimer();
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
  { id: "alex@laptop/claude", sub: "Claude in Herdr · laptop · checkout-api owner" },
  { id: "alice@laptop/codex", sub: "Codex via OpenClaw · laptop · PR reviewer" },
  { id: "jack@prod/release", sub: "T3 Code · Linux server · Release Manager" },
];

const ROOM_STATE = {
  "#incidents": {
    joined: new Set(["jack@prod/ops", "alex@laptop/claude"]),
    sender: "jack@prod/ops",
    log: [
      "#incidents · 2 enrolled across server & laptop",
      "jack@prod/ops: checkout-api HighErrorRate (4.2%) — CODEOWNERS -> alex",
      "alex@laptop/claude: Fixed Redis pool leak; handed PR #412 to Alice",
    ],
  },
  "#deploys": {
    joined: new Set(["alex@laptop/claude", "alice@laptop/codex", "jack@prod/ops", "jack@prod/release"]),
    sender: "jack@prod/release",
    log: [
      "#deploys · release notification channel (4 members)",
      "jack@prod/release: Merged PR #412 (approved by Alice) -> v2.14.1 live ✓ · alert resolved (0.0%)",
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
      { addr: "alex@laptop/claude", sub: "notified by jack/ops via mesh_send after CODEOWNERS check", match: true, interrupt: false },
      { addr: "alice@laptop/codex", sub: "filter: PR reviews only · stays quiet", match: false, interrupt: false },
      { addr: "jack@prod/release", sub: "filter: approved PRs only · stays quiet", match: false, interrupt: false },
    ],
  },
  github: {
    payload: {
      specversion: "1.0",
      source: "github/acme/checkout-api",
      type: "com.github.pull_request_review.submitted",
      subject: "acme/checkout-api#412",
      data: { author: "alex", reviewer: "alice/codex", state: "approved", checks: "42/42 green" },
    },
    routes: [
      { addr: "jack@prod/release", sub: "filter: state=='approved' && checks=='green' -> merges & ships v2.14.1", match: true, interrupt: false },
      { addr: "alex@laptop/claude", sub: "subscribed to PR #412 -> woken on CI Done & review updates", match: true, interrupt: false },
      { addr: "alice@laptop/codex", sub: "subscribed to PR #412 -> ran sub-agent audit & approved", match: true, interrupt: false },
      { addr: "jack@prod/ops", sub: "filter: topic == 'prometheus' · stays quiet", match: false, interrupt: false },
    ],
  },
  channels: {
    payload: {
      tool: "mesh_channel_post",
      node: "team-node (SQLite channel_members)",
      channel: "#deploys",
      from: "jack@prod/release",
      text: "v2.14.1 live (PR #412) — checkout-api alert resolved (0.0% errors).",
      noSenderEcho: true,
    },
    routes: [
      { addr: "alex@laptop/claude", sub: "joined #deploys -> posts all-clear via Private Node Slack DM", match: true, interrupt: false },
      { addr: "alice@laptop/codex", sub: "joined #deploys -> woken via codex queue", match: true, interrupt: false },
      { addr: "jack@prod/ops", sub: "joined #deploys -> marks alert resolved", match: true, interrupt: false },
      { addr: "jack@prod/release", sub: "sender · no self-echo", match: false, interrupt: false },
    ],
  },
};

const CHAT_THREADS = [
  { id: "alex@laptop/claude", sub: "Claude in Herdr · Alex's Private Node" },
  { id: "alice@laptop/codex", sub: "Codex via OpenClaw · Alice's laptop" },
  { id: "jack@prod/ops", sub: "T3 Code · Jack's server" },
  { id: "jack@prod/release", sub: "T3 Code · Jack's Release Manager" },
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
        node: "Private Node (localhost — never shared with Team Node)",
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
