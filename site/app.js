function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================================
// 0. SMART SCROLL-AWARE HEADER (Frosted dark over hero -> frosted white below)
// ============================================================================
(function initSmartHeader() {
  const header = document.getElementById("siteHeader");
  const heroBand = document.getElementById("story");
  if (!header || !heroBand) return;

  function syncHeaderTheme() {
    const heroBottom = heroBand.getBoundingClientRect().bottom;
    const headerH = header.offsetHeight || 68;
    const pastHero = heroBottom <= headerH + 6;
    header.classList.toggle("header-light", pastHero);
    header.classList.toggle("header-dark", !pastHero);
  }

  syncHeaderTheme();
  window.addEventListener("scroll", syncHeaderTheme, { passive: true });
  window.addEventListener("resize", syncHeaderTheme, { passive: true });
})();

// Proportional 1200x590 stage scaling so sprites, wires, bubbles & packets stay pixel-exact from mobile to ultrawide displays
(function initResponsiveStage() {
  const viewport = document.getElementById("storyViewport");
  const stage = document.getElementById("storyStage");
  if (!viewport || !stage) return;

  const LOGICAL_W = 1200;
  const LOGICAL_H = 590;

  function fitStage() {
    const availW = viewport.clientWidth || LOGICAL_W;
    const vh = window.innerHeight || 900;
    // Scale down cleanly on narrow viewports; on large/tall displays scale smoothly up to 1.28x
    // while keeping the subtitle, timeline, and hero CTA comfortably balanced on screen.
    const maxScaleByHeight = Math.max(0.72, Math.min(1.28, (vh - 340) / LOGICAL_H));
    const maxScale = vh >= 960 ? maxScaleByHeight : Math.min(1, Math.max(0.84, (vh - 300) / LOGICAL_H));
    const scale = Math.min(maxScale, availW / LOGICAL_W);
    const offsetX = Math.max(0, (availW - LOGICAL_W * scale) / 2);
    stage.style.transform = `translateX(${offsetX.toFixed(1)}px) scale(${scale.toFixed(4)})`;
    viewport.style.height = `${Math.round(LOGICAL_H * scale)}px`;
  }

  fitStage();
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(fitStage).observe(viewport);
  }
  window.addEventListener("resize", fitStage, { passive: true });
})();

// ============================================================================
// 1. HERO INSTALL SWITCHER
// ============================================================================
const HERO_CMDS = {
  curl: 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/hyphae-to/hyp/main/install.sh)"',
  npm: "npm install -g @hyphae-to/hyp && hyp onboard",
  git: "git clone https://github.com/hyphae-to/hyp && cd hyp && npm i && npm run build",
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
// 2. PANORAMIC 7-CHAPTER HERO STORY DIORAMA (Causal staged reveals + living mycelium)
// ============================================================================
const CHAPTERS = [
  {
    durationMs: 7400,
    tip: "1 · Alex joins Team Node -> peers bloom one by one",
    caption: "<strong>1/7</strong> · <strong>Alex</strong> (Claude in Herdr) joins the <strong>Team Node</strong> — immediately unlocking <code>#channels</code>, streams, <strong>Alice's Codex</strong> (OpenClaw), and <strong>Jack's ops &amp; release mgr</strong> (T3 Code).",
    visible: ["ent-alex", "ent-node"],
    dim: [],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Calling hyp_join on the Team Node…", alert: false } },
    caps: [],
    subs: [],
    promState: "",
    promSub: "14 servers · healthy",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-node", reverse: false, cls: "", label: "hyp_join", delay: 150, dur: 900 },
      { path: "p-node-alice", reverse: false, cls: "amber", label: "alice · Codex online", delay: 1240, dur: 860 },
      { path: "p-node-ops", reverse: false, cls: "", label: "jack · ops online", delay: 2420, dur: 860 },
      { path: "p-node-release", reverse: false, cls: "", label: "sub: approved PRs", delay: 3620, dur: 900 },
    ],
    stages: [
      {
        at: 1080,
        spotlight: ["ent-node"],
        caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
        ripples: ["rip-node"],
        bubbles: { "bub-alex": { text: "Connected! #channels & streams unlocked.", alert: false } },
        addStrands: ["p-node-alice"],
      },
      {
        at: 2120,
        addVisible: ["ent-alice"],
        spotlight: ["ent-alice"],
        ripples: ["rip-alice"],
        bubbles: { "bub-alice": { text: "Subscribed to PRs assigned to me.", alert: false } },
      },
      {
        at: 2360,
        addStrands: ["p-node-ops"],
      },
      {
        at: 3300,
        addVisible: ["ent-ops"],
        spotlight: ["ent-alice", "ent-ops"],
        ripples: ["rip-ops"],
        bubbles: { "bub-ops": { text: "Watching 14 prod servers.", alert: false } },
      },
      {
        at: 3560,
        addStrands: ["p-node-release"],
      },
      {
        at: 4540,
        addVisible: ["ent-release"],
        spotlight: ["ent-alice", "ent-ops", "ent-release"],
        ripples: ["rip-release"],
        bubbles: { "bub-release": { text: "Subscribed to approved PRs for deploy.", alert: false } },
        subs: ["sub-rel-pr"],
      },
    ],
  },
  {
    durationMs: 5400,
    tip: "2 · Fleet alert wakes Jack's ops -> CODEOWNERS",
    caption: "<strong>2/7</strong> · <span class='coral-txt'>Prometheus fires HighErrorRate (4.2%)</span>. The node filter wakes <strong>Jack's ops</strong>, who checks <code>CODEOWNERS</code> -> Alex owns <code>checkout-api</code>.",
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
      { path: "p-prom-node", reverse: false, cls: "coral", label: "HighErrorRate 4.2%", delay: 150, dur: 920 },
      { path: "p-node-ops-alert", reverse: false, cls: "coral", label: "alert -> jack/ops", delay: 1150, dur: 1020 },
    ],
    stages: [
      {
        at: 1090,
        coralCaps: ["cap-pr"],
        filterTag: true,
        addStrands: ["p-node-ops-alert"],
      },
      {
        at: 2190,
        alertHit: ["ent-ops"],
        ripples: ["rip-ops"],
        bubbles: {
          "bub-ops": { text: "checkout-api spiking! CODEOWNERS says Alex.", alert: true },
        },
      },
    ],
  },
  {
    durationMs: 7000,
    tip: "3 · Ops calls hyp_send -> Alex + Private Slack + #deploys",
    caption: "<strong>3/7</strong> · Jack's ops sends a <code>hyp_send</code> to <strong>Alex</strong>. Alex joins <code>#deploys</code> with ops and wires a <strong>Private Node -> Slack</strong> to DM Alex.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-prom"],
    dim: ["ent-alice", "ent-release"],
    spotlight: ["ent-ops"],
    alertHit: [],
    strands: ["p-node-ops-alert", "p-alex-node"],
    softStrands: ["p-prom-node"],
    bubbles: {
      "bub-ops": { text: "hyp_send -> alex: trace attached. Joining #deploys.", alert: false },
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
      { path: "p-node-ops-alert", reverse: true, cls: "coral", label: "hyp_send(trace)", delay: 150, dur: 940 },
      { path: "p-alex-node", reverse: true, cls: "coral", label: "hyp_send -> alex", delay: 1150, dur: 1000 },
      { path: "p-priv-slack", reverse: false, cls: "moss", label: "DM: 4.2% error", delay: 2700, dur: 880 },
    ],
    stages: [
      {
        at: 2170,
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
        at: 2620,
        addStrands: ["p-priv-slack"],
      },
      {
        at: 3600,
        addVisible: ["ent-slack"],
      },
    ],
  },
  {
    durationMs: 7000,
    tip: "4 · Alex fixes bug, opens PR #412 & subscribes -> CI Done ✓",
    caption: "<strong>4/7</strong> · Alex fixes the Redis pool leak, opens <strong>PR #412</strong>, subscribes to it on the Team Node, and receives <strong>CI Done ✓</strong> from GitHub.",
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
    ccAction: "→ opened PR #412 · hyp_subscribe(PR #412)",
    promState: "coral",
    promSub: "HighErrorRate · 4.2%!",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-gh", reverse: false, cls: "amber", label: "open PR #412", delay: 150, dur: 900 },
      { path: "p-alex-node", reverse: false, cls: "", label: "hyp_subscribe(PR #412)", delay: 280, dur: 920 },
      { path: "p-gh-node", reverse: false, cls: "", label: "CI Done ✓", delay: 2000, dur: 880 },
      { path: "p-alex-node", reverse: true, cls: "", label: "CI Done ✓", delay: 2940, dur: 940 },
    ],
    stages: [
      {
        at: 1080,
        addVisible: ["ent-gh"],
        addSubs: ["sub-alex-pr"],
        caps: ["cap-gh"],
        addStrands: ["p-gh-node"],
      },
      {
        at: 1900,
        ghActive: "green",
        ghSub: "open · CI Done ✓ · subscribed",
      },
      {
        at: 3900,
        ripples: ["rip-alex"],
        bubbles: {
          "bub-alex": { text: "PR #412 open & subscribed — CI Done ✓ just arrived!", alert: false },
        },
      },
    ],
  },
  {
    durationMs: 7400,
    tip: "5 · Alex assigns Alice on GitHub -> GitHub notifies Alice -> spawns sub-agent",
    caption: "<strong>5/7</strong> · Alex assigns <strong>@alice</strong> as reviewer on <strong>GitHub PR #412</strong> -> Team Node notifies <strong>Alice</strong> -> Alice joins <code>#deploys</code> &amp; spawns a <strong>review sub-agent</strong>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh"],
    dim: ["ent-alice", "ent-ops", "ent-release"],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-gh"],
    softStrands: ["p-alex-node"],
    bubbles: {
      "bub-alex": { text: "Assigning @alice as reviewer on GitHub PR #412.", alert: false },
    },
    caps: ["cap-gh"],
    subs: ["sub-alex-pr", "sub-alex-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "green",
    ghTitle: "GitHub · PR #412",
    ghSub: "CI Done ✓ · assigning reviewer…",
    subagentText: "sub-agent · auditing PR #412",
    promState: "",
    promSub: "14 servers · mitigating",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-gh", reverse: false, cls: "amber", label: "assign @alice", delay: 150, dur: 900 },
      { path: "p-gh-node", reverse: false, cls: "amber", label: "review_requested(@alice)", delay: 1120, dur: 900 },
      { path: "p-node-alice", reverse: false, cls: "amber", label: "assigned: PR #412", delay: 2080, dur: 960 },
      { path: "p-alice-sub", reverse: false, cls: "amber", label: "spawn sub-agent", delay: 3240, dur: 880 },
    ],
    stages: [
      {
        at: 1080,
        addStrands: ["p-gh-node"],
        ghActive: "amber",
        ghSub: "reviewer assigned: @alice",
      },
      {
        at: 2040,
        addStrands: ["p-node-alice"],
      },
      {
        at: 3060,
        undim: ["ent-alice"],
        spotlight: ["ent-alice"],
        ripples: ["rip-alice"],
        caps: ["cap-gh", "cap-dep"],
        addSubs: ["sub-alice-pr", "sub-alice-dep"],
        bubbles: {
          "bub-alice": { text: "GitHub notified me: assigned to PR #412! Spawning reviewer.", alert: false },
        },
        addStrands: ["p-alice-sub"],
      },
      {
        at: 4140,
        addVisible: ["ent-subagent"],
      },
    ],
  },
  {
    durationMs: 8800,
    tip: "6 · Alice rejects PR on GitHub -> Alex notified & patches -> Alice approves ✓",
    caption: "<strong>6/7</strong> · Alice's sub-agent finds an edge case -> Alice <strong>rejects PR #412 on GitHub</strong> -> <strong>Alex is notified</strong> &amp; pushes a 2-line fix -> <strong>Alice approves PR #412 ✓</strong>.",
    visible: ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release", "ent-gh", "ent-subagent"],
    dim: ["ent-ops", "ent-release"],
    spotlight: ["ent-alice"],
    alertHit: [],
    strands: ["p-alice-sub", "p-alice-gh-reject"],
    softStrands: ["p-node-alice"],
    bubbles: {
      "bub-alice": { text: "Sub-agent found a timeout bug — rejecting PR #412 on GitHub.", alert: false },
    },
    caps: ["cap-gh"],
    subs: ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"],
    ghActive: "amber",
    ghTitle: "GitHub · PR #412",
    ghSub: "under review by @alice",
    subagentText: "sub-agent · timeout edge case",
    promState: "",
    promSub: "14 servers · recovering",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alice-gh-reject", reverse: false, cls: "coral", label: "reject PR #412", delay: 150, dur: 960 },
      { path: "p-gh-node-reject", reverse: false, cls: "coral", label: "PR #412 rejected", delay: 1180, dur: 860 },
      { path: "p-alex-node", reverse: true, cls: "coral", label: "PR #412 rejected", delay: 2100, dur: 900 },
      { path: "p-alex-gh", reverse: false, cls: "", label: "push 2-line fix", delay: 3250, dur: 860 },
      { path: "p-alice-gh-ok", reverse: false, cls: "", label: "approve PR #412 ✓", delay: 4320, dur: 960 },
    ],
    stages: [
      {
        at: 1130,
        ghActive: "coral",
        ghTitle: "GitHub · PR #412 Rejected",
        ghSub: "changes requested · timeout guard",
        coralCaps: ["cap-gh"],
        addStrands: ["p-gh-node-reject"],
      },
      {
        at: 2060,
        addStrands: ["p-alex-node"],
      },
      {
        at: 3020,
        spotlight: ["ent-alex", "ent-alice"],
        alertHit: ["ent-alex"],
        ripples: ["rip-alex"],
        addStrands: ["p-alex-gh"],
        bubbles: {
          "bub-alex": { text: "PR #412 rejected on timeout guard — pushing 2-line fix!", alert: false },
        },
      },
      {
        at: 4160,
        subagentText: "sub-agent · diff clean ✓",
        coralCaps: [],
        caps: ["cap-gh"],
        hideStrands: ["p-alice-gh-reject", "p-gh-node-reject"],
        addStrands: ["p-alice-gh-ok"],
        bubbles: {
          "bub-alice": { text: "Fix verified — approving PR #412 on GitHub ✓!", alert: false },
        },
      },
      {
        at: 5300,
        ghActive: "green",
        ghTitle: "GitHub · PR #412 Approved ✓",
        ghSub: "Approved by Alice · CI green",
        addStrands: ["p-gh-node"],
      },
    ],
  },
  {
    durationMs: 8200,
    tip: "7 · Release Mgr ships -> Alert fixed -> #deploys fan-out & banter",
    caption: "<strong>7/7</strong> · <strong>Jack's release mgr</strong> ships <code>v2.14.1</code> -> <span style='color:var(--chartreuse);font-weight:600;'>alert fixed (0.0%)</span> -> <code>#deploys</code> notifies everyone (+ Slack DM).",
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
      { path: "p-node-release", reverse: true, cls: "", label: "ship v2.14.1 -> #deploys", delay: 150, dur: 1000 },
      { path: "p-alex-node", reverse: true, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1220, dur: 1040 },
      { path: "p-node-alice-green", reverse: false, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1220, dur: 1040 },
      { path: "p-node-ops", reverse: false, cls: "", label: "#deploys: v2.14.1 ✓", delay: 1220, dur: 1040 },
      { path: "p-priv-slack", reverse: false, cls: "moss", label: "DM: alert fixed ✓", delay: 2740, dur: 860 },
    ],
    stages: [
      {
        at: 1160,
        caps: ["cap-ch", "cap-dep", "cap-gh"],
        addStrands: ["p-alex-node", "p-node-alice-green", "p-node-ops"],
      },
      {
        at: 1820,
        caps: ["cap-ch", "cap-dep", "cap-gh", "cap-pr"],
        coralCaps: [],
        addStrands: ["p-prom-node-ok"],
        promState: "green",
        promSub: "0.0% · Alert resolved ✓",
      },
      {
        at: 2280,
        spotlight: ["ent-release", "ent-alex", "ent-alice", "ent-ops"],
        ripples: ["rip-alex", "rip-alice", "rip-ops"],
        bubbles: {
          "bub-alex": { text: "v2.14.1 live & alert cleared! DMing Alex on Slack.", alert: false },
        },
        addVisible: ["ent-priv"],
        addStrands: ["p-alex-priv"],
      },
      {
        at: 2660,
        addStrands: ["p-priv-slack"],
      },
      {
        at: 3620,
        addVisible: ["ent-slack"],
      },
      {
        at: 4450,
        bubbles: {
          "bub-ops": { text: "0.0% errors across all 14 servers. Nice save, team.", alert: false },
        },
      },
      {
        at: 5350,
        bubbles: {
          "bub-alice": { text: "Glad my sub-agent caught that timeout. Coffee's on Alex.", alert: false },
        },
      },
      {
        at: 6300,
        bubbles: {
          "bub-alex": { text: "Deal. Next outage is Jack's turn.", alert: false },
          "bub-release": { text: "Please don't jinx v2.14.1.", alert: false },
        },
        showReplay: true,
      },
    ],
  },
];

// Procedurally weave companion hyphal strands + forked lateral rootlets around every main strand
const SVG_NS = "http://www.w3.org/2000/svg";
const strandLengths = new Map();
const hyphaBundleMap = new Map();

function buildOrganicHyphaBundles() {
  const host = document.getElementById("hyphaBundles");
  document.querySelectorAll(".myc-strand").forEach((path, idx) => {
    const len = path.getTotalLength();
    strandLengths.set(path.id, len);
    path.style.strokeDasharray = `${len}`;
    path.style.strokeDashoffset = `${len}`;
    if (!host) return;

    const g = document.createElementNS(SVG_NS, "g");
    const colorCls = path.classList.contains("amber")
      ? "amber"
      : path.classList.contains("coral")
      ? "coral"
      : path.classList.contains("moss")
      ? "moss"
      : "";
    g.setAttribute("class", `hypha-bundle ${colorCls}`.trim());
    g.dataset.for = path.id;

    const steps = Math.max(12, Math.min(28, Math.round(len / 14)));
    const amp = Math.min(9.5, Math.max(4.5, len * 0.032));
    const seed = (idx + 1) * 1.37;

    const ptsA = [];
    const ptsB = [];
    for (let i = 0; i <= steps; i++) {
      const f = i / steps;
      const d = f * len;
      const p = path.getPointAtLength(d);
      const pNext = path.getPointAtLength(Math.min(len, d + 2));
      const pPrev = path.getPointAtLength(Math.max(0, d - 2));
      const dx = pNext.x - pPrev.x;
      const dy = pNext.y - pPrev.y;
      const mag = Math.hypot(dx, dy) || 1;
      const nx = -dy / mag;
      const ny = dx / mag;
      const env = Math.sin(f * Math.PI);
      const offA = env * Math.sin(f * Math.PI * 3.1 + seed) * amp;
      const offB = env * Math.cos(f * Math.PI * 4.4 - seed) * (amp * 0.68);
      ptsA.push(`${(p.x + nx * offA).toFixed(1)} ${(p.y + ny * offA).toFixed(1)}`);
      ptsB.push(`${(p.x + nx * offB).toFixed(1)} ${(p.y + ny * offB).toFixed(1)}`);
    }

    const subPaths = [];
    for (const [pts, cls] of [[ptsA, "myc-weave"], [ptsB, "myc-weave fine"]]) {
      const w = document.createElementNS(SVG_NS, "path");
      w.setAttribute("class", cls);
      w.setAttribute("d", `M ${pts[0]} L ${pts.slice(1).join(" L ")}`);
      g.appendChild(w);
      subPaths.push(w);
    }

    // Add 2-4 delicate forked lateral rootlets + spore tips along the strand
    const twigFracs = len > 240 ? [0.24, 0.48, 0.72, 0.86] : [0.34, 0.68];
    twigFracs.forEach((f, ti) => {
      const d = f * len;
      const p = path.getPointAtLength(d);
      const pNext = path.getPointAtLength(Math.min(len, d + 3));
      const dx = pNext.x - p.x;
      const dy = pNext.y - p.y;
      const mag = Math.hypot(dx, dy) || 1;
      const tx = dx / mag, ty = dy / mag;
      const side = (ti + idx) % 2 === 0 ? 1 : -1;
      const nx = -ty * side, ny = tx * side;
      const reach = Math.min(26, Math.max(13, len * 0.085));
      const c1x = p.x + tx * (reach * 0.45) + nx * (reach * 0.55);
      const c1y = p.y + ty * (reach * 0.45) + ny * (reach * 0.55);
      const ex = p.x + tx * (reach * 0.82) + nx * reach;
      const ey = p.y + ty * (reach * 0.82) + ny * reach;

      const twig = document.createElementNS(SVG_NS, "path");
      twig.setAttribute("class", "myc-twig");
      twig.setAttribute("d", `M ${p.x.toFixed(1)} ${p.y.toFixed(1)} Q ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${ex.toFixed(1)} ${ey.toFixed(1)}`);
      g.appendChild(twig);
      subPaths.push(twig);

      const spore = document.createElementNS(SVG_NS, "circle");
      spore.setAttribute("class", "myc-spore");
      spore.setAttribute("cx", ex.toFixed(1));
      spore.setAttribute("cy", ey.toFixed(1));
      spore.setAttribute("r", "1.6");
      g.appendChild(spore);
    });

    host.appendChild(g);
    const meta = subPaths.map((sp) => {
      const sl = sp.getTotalLength();
      sp.style.strokeDasharray = `${sl}`;
      sp.style.strokeDashoffset = `${sl}`;
      return { el: sp, len: sl };
    });
    hyphaBundleMap.set(path.id, { group: g, subPaths: meta });
  });
}
buildOrganicHyphaBundles();

function setStrandState(id, state) {
  const path = document.getElementById(id);
  const len = strandLengths.get(id) || 200;
  if (path) {
    path.classList.toggle("grown", state === "grown");
    path.classList.toggle("soft", state === "soft");
    path.style.strokeDashoffset = state === "hidden" ? `${len}` : "0";
  }
  const bundle = hyphaBundleMap.get(id);
  if (bundle) {
    bundle.group.classList.toggle("grown", state === "grown");
    bundle.group.classList.toggle("soft", state === "soft");
    bundle.subPaths.forEach(({ el, len: sl }) => {
      el.style.strokeDashoffset = state === "hidden" ? `${sl}` : "0";
    });
  }
}

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

function easeInOutQuad(t) {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
}

/**
 * Plays ONE-SHOT sequential labeled message packets along the exact SVG paths.
 * Stays fully visible all the way to the destination (0..100% of strand), then
 * absorbs right at the target with a crisp arrival pulse.
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
    return { ...spec, el, path, len: path.getTotalLength(), landed: false };
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

      // Emerge cleanly from sender's rim and land squarely at receiver's rim (full visible travel)
      const inset = Math.min(0.14, 34 / item.len);
      const travel = inset + easeInOutQuad(raw) * (1 - inset * 2);
      const t = item.reverse ? 1 - travel : travel;
      const pt = item.path.getPointAtLength(item.len * t);

      item.el.style.left = `${(pt.x / 1200) * 100}%`;
      item.el.style.top = `${(pt.y / 580) * 100}%`;

      let opacity = 1;
      let scale = 1;
      if (raw < 0.08) {
        opacity = raw / 0.08;
        scale = 0.86 + 0.14 * (raw / 0.08);
      } else if (raw > 0.93) {
        const tail = (raw - 0.93) / 0.07;
        opacity = Math.max(0, 1 - tail);
        scale = 1 - 0.2 * tail;
      }

      if (raw >= 0.96 && !item.landed) {
        item.landed = true;
        const endT = item.reverse ? inset : 1 - inset;
        const endPt = item.path.getPointAtLength(item.len * endT);
        const pulse = document.createElement("div");
        pulse.className = `pkt-arrive ${item.cls || ""}`.trim();
        pulse.style.left = `${(endPt.x / 1200) * 100}%`;
        pulse.style.top = `${(endPt.y / 580) * 100}%`;
        host.appendChild(pulse);
        setTimeout(() => pulse.remove(), 520);
      }

      item.el.style.opacity = opacity.toFixed(2);
      item.el.style.transform = `translate(-50%, -50%) scale(${scale.toFixed(3)})`;
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
  if (st.hideStrands) {
    st.hideStrands.forEach((id) => setStrandState(id, "hidden"));
  }
  if (st.addStrands) {
    st.addStrands.forEach((id) => setStrandState(id, "grown"));
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
    ghEl.classList.toggle("active-coral", st.ghActive === "coral");
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
  if (st.showReplay) {
    document.getElementById("storyReplayBtn")?.classList.add("show");
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
  document.getElementById("storyReplayBtn")?.classList.remove("show");
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
  ghEl.classList.toggle("active-coral", ch.ghActive === "coral");
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
    const isActive = ch.strands.includes(path.id);
    const isSoft = ch.softStrands.includes(path.id);
    setStrandState(path.id, isActive ? "grown" : isSoft ? "soft" : "hidden");
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
  const isLast = chapterIdx >= CHAPTERS.length - 1;
  if (isLast) {
    // Stop cleanly at the end instead of auto-looping; show Play again CTA
    storyTimer = setTimeout(() => {
      storyPlaying = false;
      const playBtn = document.getElementById("storyPlayBtn");
      if (playBtn) playBtn.textContent = "Replay";
      document.getElementById("storyReplayBtn")?.classList.add("show");
    }, CHAPTERS[chapterIdx]?.durationMs ?? 8000);
    return;
  }
  const delay = CHAPTERS[chapterIdx]?.durationMs ?? 7200;
  storyTimer = setTimeout(() => {
    chapterIdx += 1;
    renderChapter();
    resetStoryTimer();
  }, delay);
}

function replayStory() {
  chapterIdx = 0;
  storyPlaying = true;
  document.getElementById("storyPlayBtn").textContent = "Pause";
  renderChapter();
  resetStoryTimer();
}

document.getElementById("storyReplayBtn")?.addEventListener("click", replayStory);

document.getElementById("storyPlayBtn").addEventListener("click", (e) => {
  if (!storyPlaying && chapterIdx === CHAPTERS.length - 1) {
    replayStory();
    return;
  }
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
// 3. REAL CLOUDEVENTS SUBSCRIPTIONS API v1.0 EVALUATOR (mirrors src/core/router/filter.ts)
// ============================================================================
function ceTexts(value) {
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean") return [JSON.stringify(value)];
  if (Array.isArray(value)) return value.flatMap((item) => (Array.isArray(item) ? [] : ceTexts(item)));
  return [];
}

function ceLookup(event, key) {
  if (key.startsWith("data.")) {
    const field = key.slice(5);
    return event.data && Object.prototype.hasOwnProperty.call(event.data, field) ? ceTexts(event.data[field]) : [];
  }
  if (key === "data" || !Object.prototype.hasOwnProperty.call(event, key)) return [];
  return ceTexts(event[key]);
}

function ceCompare(pairs, event, fn) {
  return Object.entries(pairs).every(([k, expected]) => ceLookup(event, k).some((actual) => fn(actual, expected)));
}

function ceMatchesFilter(filter, event) {
  if ("exact" in filter) return ceCompare(filter.exact, event, (a, e) => a === e);
  if ("prefix" in filter) return ceCompare(filter.prefix, event, (a, e) => a.startsWith(e));
  if ("suffix" in filter) return ceCompare(filter.suffix, event, (a, e) => a.endsWith(e));
  if ("all" in filter) return filter.all.every((inner) => ceMatchesFilter(inner, event));
  if ("any" in filter) return filter.any.some((inner) => ceMatchesFilter(inner, event));
  if ("not" in filter) return !ceMatchesFilter(filter.not, event);
  return false;
}

function ceMatchesFilters(filters, event) {
  return filters.every((f) => ceMatchesFilter(f, event));
}

// ============================================================================
// 3B. LOCAL NODE INBOUND CONTROL-GATE LIVING ANIMATION (#streams)
// ============================================================================
(function initControlGate() {
  const viewport = document.getElementById("gateViewport");
  const stage = document.getElementById("gateStage");
  const packetsHost = document.getElementById("gatePackets");
  const mobileHost = document.getElementById("gateMobile");
  if (!viewport || !stage) return;

  const LOGICAL_W = 1120;
  const LOGICAL_H = 336;
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  function fitGateStage() {
    if (window.innerWidth <= 760) return;
    const availW = viewport.clientWidth || LOGICAL_W;
    const scale = Math.min(1.08, availW / LOGICAL_W);
    const offsetX = Math.max(0, (availW - LOGICAL_W * scale) / 2);
    stage.style.transform = `translateX(${offsetX.toFixed(1)}px) scale(${scale.toFixed(4)})`;
    viewport.style.height = `${Math.round(LOGICAL_H * scale)}px`;
  }

  fitGateStage();
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(fitGateStage).observe(viewport);
  }
  window.addEventListener("resize", fitGateStage, { passive: true });

  const GATE_SOURCES = [
    { name: "GitHub · PR #412", sub: "review: approved", cls: "amber" },
    { name: "Prometheus · p99", sub: "severity=critical", cls: "coral" },
    { name: "CI · noisy flake ×8", sub: "retry chatter", cls: "amber-muted" },
    { name: "#deploys · chatter", sub: "build room noise", cls: "olive" },
    { name: "E2EE · diff.patch", sub: "X25519 · 42 KB", cls: "moss" },
  ];

  const GATE_MODES = {
    filter: {
      cmd: 'hyp_subscribe({ topic: "ci", filters: [{ not: ... }] })',
      ruleText: "CloudEvents filter active",
      ruleCls: "",
      deflectText: "✕ 8 CI flakes dropped · 0 tokens",
      delivered: "3 signals",
      blocked: "8 flakes dropped",
      blockedCls: "amber",
      saved: "94%",
      barPct: 94,
      foot: "E2EE saved to disk · path-only ref",
      caption:
        "Your <strong>Local Node</strong> evaluates CloudEvents v1.0 filters before touching the LLM — passing <code>PR #412</code>, critical alerts, and E2EE file paths while dropping noisy CI flakes at zero token cost.",
      sources: [
        { state: "pass", badge: "pass" },
        { state: "pass", badge: "pass" },
        { state: "blocked", badge: "filtered" },
        { state: "idle", badge: "idle" },
        { state: "pass", badge: "-> disk" },
      ],
      strands: {
        "g-in-0": "active",
        "g-in-1": "active",
        "g-in-2": "blocked",
        "g-in-3": "dim",
        "g-in-4": "active",
        "g-out-0": "active",
        "g-out-1": "active",
        "g-out-2": "active",
      },
      packets: [
        { path: "g-in-0", cls: "amber", label: "PR #412", phase: 0.04, dur: 1700, startT: 0.2, endT: 0.8 },
        { path: "g-out-1", cls: "amber", label: "PR #412 approved", phase: 0.44, dur: 1750, startT: 0.2, endT: 0.8, rippleAgent: true },
        { path: "g-in-1", cls: "coral", label: "p99 critical", phase: 0.22, dur: 1600, startT: 0.2, endT: 0.8 },
        { path: "g-out-0", cls: "coral", label: "p99 critical", phase: 0.62, dur: 1650, startT: 0.2, endT: 0.8, rippleAgent: true },
        { path: "g-in-2", cls: "blocked", label: "flake ×8 ✕", phase: 0.14, dur: 1550, startT: 0.2, endT: 0.68, deflect: "amber" },
        { path: "g-in-4", cls: "moss", label: "🔒 diff.patch", phase: 0.36, dur: 1750, startT: 0.2, endT: 0.8 },
        { path: "g-out-2", cls: "moss", label: "saved -> disk", phase: 0.76, dur: 1700, startT: 0.2, endT: 0.8, rippleAgent: true },
      ],
    },
    mute: {
      cmd: 'hyp_mute({ channel: "#deploys", ttl: "2h" })',
      ruleText: "Muted: #deploys (local)",
      ruleCls: "coral",
      deflectText: "✕ #deploys muted at node",
      delivered: "2 urgent",
      blocked: "#deploys muted",
      blockedCls: "coral",
      saved: "96%",
      barPct: 96,
      foot: "Mute rules run on your Local Node",
      caption:
        "Call <code>hyp_mute()</code> on noisy rooms, peers, or senders — your <strong>Local Node</strong> drops matching chatter before it ever enters context, while urgent alerts and E2EE files keep flowing.",
      sources: [
        { state: "idle", badge: "quiet" },
        { state: "pass", badge: "pass" },
        { state: "idle", badge: "quiet" },
        { state: "muted", badge: "muted" },
        { state: "pass", badge: "-> disk" },
      ],
      strands: {
        "g-in-0": "dim",
        "g-in-1": "active",
        "g-in-2": "dim",
        "g-in-3": "blocked",
        "g-in-4": "active",
        "g-out-0": "active",
        "g-out-1": "dim",
        "g-out-2": "active",
      },
      packets: [
        { path: "g-in-3", cls: "coral", label: "#deploys ✕ muted", phase: 0.06, dur: 1650, startT: 0.2, endT: 0.68, deflect: "coral" },
        { path: "g-in-3", cls: "coral", label: "build log ✕", phase: 0.56, dur: 1650, startT: 0.2, endT: 0.68, deflect: "coral" },
        { path: "g-in-1", cls: "coral", label: "p99 critical", phase: 0.18, dur: 1600, startT: 0.2, endT: 0.8 },
        { path: "g-out-0", cls: "coral", label: "p99 critical", phase: 0.58, dur: 1650, startT: 0.2, endT: 0.8, rippleAgent: true },
        { path: "g-in-4", cls: "moss", label: "🔒 diff.patch", phase: 0.34, dur: 1750, startT: 0.2, endT: 0.8 },
        { path: "g-out-2", cls: "moss", label: "saved -> disk", phase: 0.74, dur: 1700, startT: 0.2, endT: 0.8, rippleAgent: true },
      ],
    },
    digest: {
      cmd: 'hyp_mode("notify") // 1-line SQLite digest',
      ruleText: "Digest-only · SQLite batch",
      ruleCls: "amber",
      deflectText: "4 bursts -> 1 calm digest line",
      delivered: "1 digest line",
      blocked: "4 batched locally",
      blockedCls: "amber",
      saved: "91%",
      barPct: 91,
      foot: "Full msgs wait in local SQLite",
      caption:
        "Switch to <code>notify</code> (digest-only) mode during deep work — your <strong>Local Node</strong> buffers bursts in SQLite and sends your agent one calm <code>1-line digest</code> instead of flooding prompts.",
      sources: [
        { state: "batched", badge: "batched" },
        { state: "batched", badge: "batched" },
        { state: "batched", badge: "batched" },
        { state: "batched", badge: "batched" },
        { state: "pass", badge: "-> disk" },
      ],
      strands: {
        "g-in-0": "active",
        "g-in-1": "active",
        "g-in-2": "active",
        "g-in-3": "active",
        "g-in-4": "active",
        "g-out-0": "dim",
        "g-out-1": "active",
        "g-out-2": "dim",
      },
      packets: [
        { path: "g-in-0", cls: "amber", label: "PR #412", phase: 0.04, dur: 1650, startT: 0.2, endT: 0.78, rippleNode: "amber" },
        { path: "g-in-1", cls: "coral", label: "p99 spike", phase: 0.14, dur: 1650, startT: 0.2, endT: 0.78 },
        { path: "g-in-2", cls: "amber", label: "CI flake", phase: 0.24, dur: 1650, startT: 0.2, endT: 0.78 },
        { path: "g-in-3", cls: "moss", label: "#deploys", phase: 0.34, dur: 1650, startT: 0.2, endT: 0.78, rippleNode: "amber" },
        { path: "g-out-1", cls: "", label: "digest: 4 unread (1 line)", phase: 0.56, dur: 2000, startT: 0.22, endT: 0.8, rippleAgent: true },
      ],
    },
    unsub: {
      cmd: 'hyp_unsubscribe("ci-flakes") && hyp_channel_leave("#deploys")',
      ruleText: "2 streams detached · 0 wakes",
      ruleCls: "moss",
      deflectText: "Cut at connector · 0 background polling",
      delivered: "2 subscribed",
      blocked: "2 streams off",
      blockedCls: "",
      saved: "100%",
      barPct: 100,
      foot: "Zero wakes for detached streams",
      caption:
        "Call <code>hyp_unsubscribe()</code> or <code>hyp_channel_leave()</code> anytime — your <strong>Local Node</strong> cuts the strand immediately with zero wakes, zero retries, and zero polling.",
      sources: [
        { state: "pass", badge: "subscribed" },
        { state: "idle", badge: "paused" },
        { state: "detached", badge: "detached" },
        { state: "detached", badge: "left room" },
        { state: "pass", badge: "-> disk" },
      ],
      strands: {
        "g-in-0": "active",
        "g-in-1": "dim",
        "g-in-2": "detached",
        "g-in-3": "detached",
        "g-in-4": "active",
        "g-out-0": "dim",
        "g-out-1": "active",
        "g-out-2": "active",
      },
      packets: [
        { path: "g-in-0", cls: "amber", label: "PR #412", phase: 0.08, dur: 1800, startT: 0.2, endT: 0.8 },
        { path: "g-out-1", cls: "amber", label: "PR #412 approved", phase: 0.5, dur: 1850, startT: 0.2, endT: 0.8, rippleAgent: true },
        { path: "g-in-4", cls: "moss", label: "🔒 diff.patch", phase: 0.28, dur: 1800, startT: 0.2, endT: 0.8 },
        { path: "g-out-2", cls: "moss", label: "saved -> disk", phase: 0.7, dur: 1850, startT: 0.2, endT: 0.8, rippleAgent: true },
      ],
    },
  };

  // Build braided companion hyphae for every gate strand (mirrors hero organic style)
  const gateBundles = new Map();
  const gateHost = document.getElementById("gateBundles");
  document.querySelectorAll(".gate-strand").forEach((path, idx) => {
    if (!gateHost) return;
    const len = path.getTotalLength();
    const g = document.createElementNS(SVG_NS, "g");
    const cls = ["amber-muted", "amber", "coral", "olive", "moss"].find((c) => path.classList.contains(c)) || "";
    g.setAttribute("class", `gate-bundle ${cls}`.trim());

    const steps = Math.max(10, Math.min(20, Math.round(len / 18)));
    const amp = Math.min(7.5, Math.max(4, len * 0.025));
    const seed = (idx + 2) * 1.43;
    const ptsA = [];
    const ptsB = [];
    for (let i = 0; i <= steps; i++) {
      const f = i / steps;
      const d = f * len;
      const p = path.getPointAtLength(d);
      const pN = path.getPointAtLength(Math.min(len, d + 2));
      const pP = path.getPointAtLength(Math.max(0, d - 2));
      const dx = pN.x - pP.x;
      const dy = pN.y - pP.y;
      const mag = Math.hypot(dx, dy) || 1;
      const nx = -dy / mag;
      const ny = dx / mag;
      const env = Math.sin(f * Math.PI);
      const offA = env * Math.sin(f * Math.PI * 3 + seed) * amp;
      const offB = env * Math.cos(f * Math.PI * 4.1 - seed) * (amp * 0.62);
      ptsA.push(`${(p.x + nx * offA).toFixed(1)} ${(p.y + ny * offA).toFixed(1)}`);
      ptsB.push(`${(p.x + nx * offB).toFixed(1)} ${(p.y + ny * offB).toFixed(1)}`);
    }

    for (const [pts, wcls] of [[ptsA, "gb-weave"], [ptsB, "gb-weave fine"]]) {
      const w = document.createElementNS(SVG_NS, "path");
      w.setAttribute("class", wcls);
      w.setAttribute("d", `M ${pts[0]} L ${pts.slice(1).join(" L ")}`);
      g.appendChild(w);
    }

    [0.34, 0.68].forEach((f, ti) => {
      const d = f * len;
      const p = path.getPointAtLength(d);
      const pN = path.getPointAtLength(Math.min(len, d + 3));
      const dx = pN.x - p.x;
      const dy = pN.y - p.y;
      const mag = Math.hypot(dx, dy) || 1;
      const tx = dx / mag;
      const ty = dy / mag;
      const side = (ti + idx) % 2 === 0 ? 1 : -1;
      const nx = -ty * side;
      const ny = tx * side;
      const reach = 15;
      const c1x = p.x + tx * 7 + nx * 8;
      const c1y = p.y + ty * 7 + ny * 8;
      const ex = p.x + tx * 12 + nx * reach;
      const ey = p.y + ty * 12 + ny * reach;
      const twig = document.createElementNS(SVG_NS, "path");
      twig.setAttribute("class", "gb-twig");
      twig.setAttribute("d", `M ${p.x.toFixed(1)} ${p.y.toFixed(1)} Q ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${ex.toFixed(1)} ${ey.toFixed(1)}`);
      g.appendChild(twig);
    });

    gateHost.appendChild(g);
    gateBundles.set(path.id, g);
  });

  const MODE_ORDER = ["filter", "mute", "digest", "unsub"];
  const urlGate = new URLSearchParams(window.location.search).get("gate");
  let activeGate = GATE_MODES[urlGate] ? urlGate : "filter";
  let gatePlaying = !GATE_MODES[urlGate] && !reducedMotion;
  let gateCycleTimer = null;
  let gateRaf = null;

  function fireRipple(el, extraCls) {
    if (!el || reducedMotion) return;
    el.classList.remove("fire", "amber", "coral");
    if (extraCls) el.classList.add(extraCls);
    void el.offsetWidth;
    el.classList.add("fire");
  }

  function renderGateMobile(mode) {
    if (!mobileHost) return;
    mobileHost.innerHTML = `
      <div class="gm-mob-list">
        ${GATE_SOURCES.map((src, i) => {
          const st = mode.sources[i];
          return `
            <div class="gm-mob-row ${src.cls} state-${st.state}">
              <div class="gm-mob-left">
                <span class="gs-dot"></span>
                <div>
                  <strong>${esc(src.name)}</strong>
                  <small>${esc(src.sub)}</small>
                </div>
              </div>
              <span class="gs-badge">${esc(st.badge)}</span>
            </div>
          `;
        }).join("")}
      </div>
      <div class="gm-mob-stem" aria-hidden="true">
        <svg viewBox="0 0 64 22" fill="none">
          <path stroke="rgba(183,217,86,0.65)" stroke-width="1.8" d="M 32 0 C 30 8, 34 14, 32 22" />
          <path stroke="rgba(232,163,49,0.45)" stroke-width="1.2" d="M 22 0 C 24 8, 28 14, 30 22" />
          <path stroke="rgba(127,201,123,0.45)" stroke-width="1.2" d="M 42 0 C 40 8, 36 14, 34 22" />
        </svg>
      </div>
      <div class="gm-mob-node">
        <img src="./assets/node-hub.png?v=6" alt="Local Hyphae Node" />
        <div class="gm-mob-node-body">
          <strong>Your Local Node (Connector)</strong>
          <span>${esc(mode.ruleText)}</span>
          <small>${esc(mode.deflectText)} · localhost SQLite WAL</small>
        </div>
      </div>
      <div class="gm-mob-stem" aria-hidden="true">
        <svg viewBox="0 0 64 22" fill="none">
          <path stroke="rgba(183,217,86,0.75)" stroke-width="2" d="M 32 0 C 34 8, 30 14, 32 22" />
        </svg>
      </div>
      <div class="gm-mob-agent">
        <div class="gm-mob-agent-head">
          <img src="./assets/sprite-alex.jpg?v=2" alt="Your agent harness" />
          <div>
            <strong>Your Agent · Claude / Codex / Agy</strong>
            <small>${esc(mode.foot)}</small>
          </div>
        </div>
        <div class="gm-row"><span>Delivered</span><strong>${esc(mode.delivered)}</strong></div>
        <div class="gm-row"><span>At gate</span><strong class="${esc(mode.blockedCls)}">${esc(mode.blocked)}</strong></div>
        <div class="gm-bar-wrap">
          <div class="gm-bar-head"><span>Context saved</span><strong>${esc(mode.saved)}</strong></div>
          <div class="gm-bar"><span style="width:${mode.barPct}%"></span></div>
        </div>
      </div>
    `;
  }

  function startGatePackets(mode) {
    if (gateRaf) cancelAnimationFrame(gateRaf);
    if (!packetsHost) return;
    packetsHost.innerHTML = "";

    const items = mode.packets.map((spec) => {
      const path = document.getElementById(spec.path);
      if (!path) return null;
      const el = document.createElement("div");
      el.className = `gate-pkt ${spec.cls || ""}`.trim();
      el.innerHTML = `<span class="gp-dot"></span><span>${esc(spec.label)}</span>`;
      packetsHost.appendChild(el);
      return { ...spec, el, path, len: path.getTotalLength(), lastCycle: -1 };
    }).filter(Boolean);

    // Position static snapshot neatly when reduced-motion is enabled
    if (reducedMotion) {
      items.forEach((item) => {
        const pt = item.path.getPointAtLength(item.len * (0.46));
        item.el.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
        item.el.style.top = `${(pt.y / LOGICAL_H) * 100}%`;
        item.el.style.opacity = "0.95";
        item.el.style.transform = "translate(-50%, -50%) scale(1)";
      });
      return;
    }

    const CYCLE_MS = 3200;
    const t0 = performance.now();
    const agentRipple = document.getElementById("gateAgentRipple");
    const nodeRipple = document.getElementById("gateNodeRipple");

    function tick(now) {
      const elapsed = now - t0;
      for (const item of items) {
        const cyclePos = ((elapsed / CYCLE_MS) + item.phase) % 1;
        const cycleNum = Math.floor((elapsed / CYCLE_MS) + item.phase);
        const span = Math.min(0.82, item.dur / CYCLE_MS);
        const raw = cyclePos / span;

        if (raw > 1) {
          item.el.style.opacity = "0";
          continue;
        }

        const startT = item.startT ?? 0.18;
        const endT = item.endT ?? 0.8;
        const travel = startT + easeInOutQuad(raw) * (endT - startT);
        const pt = item.path.getPointAtLength(item.len * travel);
        item.el.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
        item.el.style.top = `${(pt.y / LOGICAL_H) * 100}%`;

        let opacity = 1;
        let scale = 1;
        if (raw < 0.1) {
          opacity = raw / 0.1;
          scale = 0.86 + 0.14 * (raw / 0.1);
        } else if (raw > 0.88) {
          const tail = (raw - 0.88) / 0.12;
          opacity = Math.max(0, 1 - tail);
          scale = 1 - 0.18 * tail;
        }

        if (raw >= 0.86 && item.lastCycle !== cycleNum) {
          item.lastCycle = cycleNum;
          if (item.deflect) {
            const burst = document.createElement("div");
            burst.className = `gate-deflect-burst ${item.deflect}`;
            burst.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
            burst.style.top = `${(pt.y / LOGICAL_H) * 100}%`;
            packetsHost.appendChild(burst);
            setTimeout(() => burst.remove(), 520);
          }
          if (item.rippleAgent) fireRipple(agentRipple);
          if (item.rippleNode) fireRipple(nodeRipple, item.rippleNode);
        }

        item.el.style.opacity = opacity.toFixed(2);
        item.el.style.transform = `translate(-50%, -50%) scale(${scale.toFixed(3)})`;
      }
      gateRaf = requestAnimationFrame(tick);
    }
    gateRaf = requestAnimationFrame(tick);
  }

  function renderGateMode() {
    const mode = GATE_MODES[activeGate];
    document.querySelectorAll("#gateTabs .gate-tab").forEach((b) => {
      const on = b.dataset.gate === activeGate;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });

    const cmdEl = document.getElementById("gateCmdPill");
    if (cmdEl) cmdEl.textContent = mode.cmd;

    const ruleEl = document.getElementById("gateRulePill");
    if (ruleEl) {
      ruleEl.textContent = mode.ruleText;
      ruleEl.className = `gate-rule-pill ${mode.ruleCls}`.trim();
    }

    const deflectEl = document.getElementById("gateDeflectPill");
    if (deflectEl) deflectEl.textContent = mode.deflectText;

    const valveEl = document.getElementById("gateValveRing");
    if (valveEl) valveEl.className = `gate-valve-ring mode-${activeGate}`;

    const capEl = document.getElementById("gateCaption");
    if (capEl) capEl.innerHTML = mode.caption;

    const gmDel = document.getElementById("gmDelivered");
    const gmBlk = document.getElementById("gmBlocked");
    const gmSav = document.getElementById("gmSaved");
    const gmBar = document.getElementById("gmBarFill");
    const gmFt = document.getElementById("gmFoot");
    if (gmDel) gmDel.textContent = mode.delivered;
    if (gmBlk) {
      gmBlk.textContent = mode.blocked;
      gmBlk.className = mode.blockedCls || "";
    }
    if (gmSav) gmSav.textContent = mode.saved;
    if (gmBar) gmBar.style.width = `${mode.barPct}%`;
    if (gmFt) gmFt.textContent = mode.foot;

    document.querySelectorAll("#gateSources .gate-src").forEach((el, idx) => {
      const st = mode.sources[idx];
      if (!st) return;
      el.classList.remove("state-pass", "state-blocked", "state-muted", "state-batched", "state-detached", "state-idle");
      el.classList.add(`state-${st.state}`);
      const badge = document.getElementById(`gsBadge${idx}`);
      if (badge) badge.textContent = st.badge;
    });

    Object.entries(mode.strands).forEach(([id, state]) => {
      const p = document.getElementById(id);
      if (p) {
        p.classList.toggle("dim", state === "dim");
        p.classList.toggle("blocked", state === "blocked");
        p.classList.toggle("detached", state === "detached");
        if (state === "detached") {
          const l = p.getTotalLength();
          p.style.strokeDasharray = `${(l * 0.42).toFixed(1)} ${l.toFixed(1)}`;
        } else {
          p.style.strokeDasharray = "";
        }
      }
      const b = gateBundles.get(id);
      if (b) {
        b.classList.toggle("dim", state === "dim");
        b.classList.toggle("blocked", state === "blocked");
        b.classList.toggle("detached", state === "detached");
      }
    });

    renderGateMobile(mode);
    startGatePackets(mode);
  }

  function resetGateCycle() {
    clearInterval(gateCycleTimer);
    if (!gatePlaying) return;
    gateCycleTimer = setInterval(() => {
      const i = MODE_ORDER.indexOf(activeGate);
      activeGate = MODE_ORDER[(i + 1) % MODE_ORDER.length];
      renderGateMode();
    }, 6400);
  }

  const playBtn = document.getElementById("gatePlayBtn");
  function syncPlayBtn() {
    if (playBtn) playBtn.textContent = gatePlaying ? "Pause" : "Auto";
  }

  document.querySelectorAll("#gateTabs .gate-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeGate = btn.dataset.gate;
      gatePlaying = false;
      clearInterval(gateCycleTimer);
      syncPlayBtn();
      renderGateMode();
    });
  });

  playBtn?.addEventListener("click", () => {
    gatePlaying = !gatePlaying;
    syncPlayBtn();
    if (gatePlaying) resetGateCycle();
    else clearInterval(gateCycleTimer);
  });

  syncPlayBtn();
  renderGateMode();
  resetGateCycle();
})();

// ============================================================================
// 4. DARK STREAMS, REAL CLOUDEVENTS FILTER DECK, #CHANNELS & PRIVATE BRIDGES
// ============================================================================
let activeDeck = "prometheus";
let activePromCase = "critical-firing";
let activeGhCase = "pr-approved";
let activeRoom = "#incidents";
const chatLinked = new Set(["alex@laptop/claude"]);
let chatApp = "slack";

const PROM_CASES = {
  "critical-firing": {
    label: "Critical · checkout-api (firing)",
    event: {
      specversion: "1.0",
      id: "8f3c1a9b:firing:2026-11-24T12:00:00Z",
      type: "io.prometheus.alert.firing",
      source: "prometheus/alertmanager",
      subject: "severity=critical/HighErrorRate",
      time: "2026-11-24T12:00:00Z",
      datacontenttype: "application/json",
      data: {
        status: "firing",
        alertname: "HighErrorRate",
        severity: "critical",
        service: "checkout-api",
        summary: "5xx error rate at 4.2% across 14 prod nodes",
      },
    },
  },
  "warning-firing": {
    label: "Warning · billing-db (firing)",
    event: {
      specversion: "1.0",
      id: "4d9a22e1:firing:2026-11-24T12:03:10Z",
      type: "io.prometheus.alert.firing",
      source: "prometheus/alertmanager",
      subject: "severity=warning/ReplicationLag",
      time: "2026-11-24T12:03:10Z",
      datacontenttype: "application/json",
      data: {
        status: "firing",
        alertname: "ReplicationLag",
        severity: "warning",
        service: "billing-db",
        summary: "Read replica lag 4.1s (threshold 3s)",
      },
    },
  },
  "critical-resolved": {
    label: "Critical · checkout-api (resolved)",
    event: {
      specversion: "1.0",
      id: "8f3c1a9b:resolved:2026-11-24T12:14:22Z",
      type: "io.prometheus.alert.resolved",
      source: "prometheus/alertmanager",
      subject: "severity=critical/HighErrorRate",
      time: "2026-11-24T12:14:22Z",
      datacontenttype: "application/json",
      data: {
        status: "resolved",
        alertname: "HighErrorRate",
        severity: "critical",
        service: "checkout-api",
        summary: "5xx error rate back to 0.0%",
      },
    },
  },
};

const PROM_SUBS = [
  {
    addr: "jack@prod/ops",
    harness: "T3 Code · mode: interrupt · coalesce: 10s",
    mode: "interrupt",
    filters: [
      { exact: { type: "io.prometheus.alert.firing", "data.severity": "critical" } },
      { prefix: { subject: "severity=critical/" } },
    ],
  },
  {
    addr: "alex@laptop/claude",
    harness: "Claude in Herdr · mode: queue · coalesce: 15s",
    mode: "queue",
    filters: [
      { exact: { "data.service": "checkout-api" } },
      { any: [
        { exact: { type: "io.prometheus.alert.firing" } },
        { exact: { type: "io.prometheus.alert.resolved" } },
      ]},
    ],
  },
  {
    addr: "alice@laptop/codex",
    harness: "Codex via OpenClaw · mode: queue · coalesce: 60s",
    mode: "queue",
    filters: [
      { exact: { type: "io.prometheus.alert.firing" } },
      { not: { exact: { "data.severity": "critical" } } },
    ],
  },
];

const GH_CASES = {
  "pr-approved": {
    label: "PR #412 Approved",
    event: {
      specversion: "1.0",
      id: "72d91b40-9a12-11ef-8120-0242ac120003",
      source: "github.com/acme/checkout-api",
      type: "com.github.pull_request_review.submitted",
      time: "2026-11-24T12:05:12Z",
      datacontenttype: "application/json",
      subject: "pull/412",
      repo: "acme/checkout-api",
      action: "submitted",
      actor: "alice-bot",
      data: {
        number: 412,
        pr_numbers: [412],
        title: "Bound Redis pool queueLimit",
        state: "approved",
        labels: ["release-ready"],
        author: "alice-bot",
      },
    },
  },
  "ci-failed": {
    label: "PR #412 CI Failed",
    event: {
      specversion: "1.0",
      id: "91e04c12-9a12-11ef-8120-0242ac120003",
      source: "github.com/acme/checkout-api",
      type: "com.github.workflow_run.completed",
      time: "2026-11-24T12:02:01Z",
      datacontenttype: "application/json",
      subject: "actions/runs/982144",
      repo: "acme/checkout-api",
      action: "completed",
      actor: "alex",
      data: {
        pr_numbers: [412],
        conclusion: "failure",
        workflow_path: ".github/workflows/ci.yml",
        branch: "fix/redis-pool",
      },
    },
  },
  "dependabot-pr": {
    label: "Dependabot PR #419",
    event: {
      specversion: "1.0",
      id: "11c8a9f0-9a12-11ef-8120-0242ac120003",
      source: "github.com/acme/checkout-api",
      type: "com.github.pull_request.opened",
      time: "2026-11-24T12:08:40Z",
      datacontenttype: "application/json",
      subject: "pull/419",
      repo: "acme/checkout-api",
      action: "opened",
      actor: "dependabot[bot]",
      data: {
        number: 419,
        pr_numbers: [419],
        title: "Bump eslint from 9.10 to 9.11",
        labels: ["dependencies"],
      },
    },
  },
  "strict-lint": {
    label: "Reachability Lint (strict: true)",
    lintDemo: true,
    call: {
      tool: "hyp_subscribe",
      key: "gh:broken-typo",
      topic: "github",
      strict: true,
      filters: [
        { exact: { subject: "acme/checkout-api" } },
      ],
    },
    response: {
      ok: false,
      code: "unreachable_subscription",
      rolledBack: true,
      diagnostics: [
        {
          code: "invalid_github_subject_filter",
          message: "GitHub `subject` is `pull/<n>`, `issues/<n>`, or `actions/runs/<id>` — use the `repo` extension attribute for `owner/repo`.",
          suggestedFilter: { exact: { repo: "acme/checkout-api" } },
        },
      ],
    },
  },
};

const GH_SUBS = [
  {
    addr: "jack@prod/release",
    harness: "T3 Code · mode: queue · coalesce: 15s · strict: true",
    mode: "queue",
    filters: [
      { exact: { repo: "acme/checkout-api", type: "com.github.pull_request_review.submitted" } },
      { exact: { "data.state": "approved", "data.labels": "release-ready" } },
    ],
  },
  {
    addr: "alex@laptop/claude",
    harness: "Claude in Herdr · mode: queue · array match on data.pr_numbers",
    mode: "queue",
    filters: [
      { exact: { repo: "acme/checkout-api", "data.pr_numbers": "412" } },
      { not: { exact: { actor: "dependabot[bot]" } } },
    ],
  },
  {
    addr: "alice@laptop/codex",
    harness: "Codex via OpenClaw · suffix + not bot exclusion",
    mode: "queue",
    filters: [
      { exact: { repo: "acme/checkout-api" } },
      { suffix: { type: ".opened" } },
      { not: { exact: { actor: "dependabot[bot]" } } },
    ],
  },
];

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
      "#incidents · Team Node SQLite room (2 enrolled · no sender echo)",
      "jack@prod/ops: checkout-api HighErrorRate (4.2%) — CODEOWNERS -> alex",
      "alex@laptop/claude: Fixed Redis pool leak; handed PR #412 to Alice",
    ],
  },
  "#deploys": {
    joined: new Set(["alex@laptop/claude", "alice@laptop/codex", "jack@prod/ops", "jack@prod/release"]),
    sender: "jack@prod/release",
    log: [
      "#deploys · release fan-out room (4 enrolled · no sender echo)",
      "jack@prod/release: Merged PR #412 (approved by Alice) -> v2.14.1 live ✓ · alert resolved (0.0%)",
    ],
  },
};

const CHAT_THREADS = [
  { id: "alex@laptop/claude", sub: "Claude in Herdr · Alex's Private Node" },
  { id: "alice@laptop/codex", sub: "Codex via OpenClaw · Alice's laptop" },
  { id: "jack@prod/ops", sub: "T3 Code · Jack's server" },
  { id: "jack@prod/release", sub: "T3 Code · Jack's Release Manager" },
];

const BRIDGE_SECRET_ENV = {
  slack: {
    SLACK_APP_TOKEN: { secret: "slack-app-token" },
    SLACK_BOT_TOKEN: { secret: "slack-bot-token" },
    SLACK_ALLOWED_USERS: "U01234567",
  },
  telegram: {
    TELEGRAM_BOT_TOKEN: { secret: "telegram-bot-token" },
    TELEGRAM_ALLOWED_USERS: "981234567",
  },
  whatsapp: {
    WHATSAPP_ACCESS_TOKEN: { secret: "whatsapp-access-token" },
    WHATSAPP_APP_SECRET: { secret: "whatsapp-app-secret" },
    WHATSAPP_ALLOWED_NUMBERS: "15551234567",
  },
  "byo-fd3": {
    exec: "/usr/local/bin/my-bridge.py",
    protocol: "NDJSON over fd 3 (plugins/sdk/client.{mjs,py})",
    BRIDGE_API_KEY: { secret: "my-bridge-key" },
  },
};

function renderEventEvaluator(topic, cases, activeKey, setKey, subs) {
  const current = cases[activeKey];
  const chips = Object.entries(cases)
    .map(([k, c]) => `<button class="sub-chip ${c.lintDemo ? "lint" : ""} ${activeKey === k ? "active" : ""}" data-case="${k}" type="button">${esc(c.label)}</button>`)
    .join("");

  if (current.lintDemo) {
    return `
      <div>
        <div class="deck-col-label"><span>Subscribe Call</span><code>strict: true</code></div>
        <div class="deck-subtabs">${chips}</div>
        <pre class="payload-pre">${esc(JSON.stringify(current.call, null, 2))}</pre>
      </div>
      <div>
        <div class="deck-col-label"><span>Router Reachability Lint</span><code>fail-closed rollback</code></div>
        <div class="route-item lint-warn">
          <div class="route-top">
            <div>
              <span class="ri-addr">invalid_github_subject_filter</span>
              <span class="ri-sub">Caught before saving — never silently waits forever on an unreachable filter.</span>
            </div>
            <span class="ri-pill">rejected</span>
          </div>
          <pre class="ri-filter">${esc(JSON.stringify(current.response, null, 2))}</pre>
        </div>
        <div class="route-item matched">
          <div class="route-top">
            <div>
              <span class="ri-addr">Also linted at subscribe time</span>
              <span class="ri-sub"><code>unknown_topic</code> · <code>unmonitored_repo</code> (checks <code>GITHUB_REPOS</code> / <code>GITHUB_ORGS</code>) · <code>unknown_filter_attribute</code> · <code>unprovisioned_publisher</code></span>
            </div>
            <span class="ri-pill">hyp_topics</span>
          </div>
        </div>
      </div>
    `;
  }

  const ev = current.event;
  return `
    <div>
      <div class="deck-col-label"><span>Incoming CloudEvent v1.0</span><code>topic: "${topic}"</code></div>
      <div class="deck-subtabs">${chips}</div>
      <pre class="payload-pre">${esc(JSON.stringify(ev, null, 2))}</pre>
    </div>
    <div>
      <div class="deck-col-label"><span>Live Subscriptions API v1.0 Evaluation</span><code>filter.ts</code></div>
      ${subs.map((s) => {
        const matched = ceMatchesFilters(s.filters, ev);
        const cls = matched ? (s.mode === "interrupt" ? "interrupt" : "matched") : "dim";
        const pill = matched ? (s.mode === "interrupt" ? "interrupt" : "woken") : "filtered";
        return `
          <div class="route-item ${cls}">
            <div class="route-top">
              <div>
                <span class="ri-addr">${esc(s.addr)}</span>
                <span class="ri-sub">${esc(s.harness)}</span>
              </div>
              <span class="ri-pill">${pill}</span>
            </div>
            <pre class="ri-filter">filters: ${esc(JSON.stringify(s.filters))}</pre>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderDeck() {
  document.querySelectorAll("#deckTabs .deck-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.deck === activeDeck)
  );
  const body = document.getElementById("deckBody");
  if (!body) return;

  if (activeDeck === "prometheus") {
    body.innerHTML = renderEventEvaluator("alerts", PROM_CASES, activePromCase, (k) => { activePromCase = k; }, PROM_SUBS);
    body.querySelectorAll("[data-case]").forEach((btn) => {
      btn.addEventListener("click", () => { activePromCase = btn.dataset.case; renderDeck(); });
    });
    return;
  }

  if (activeDeck === "github") {
    body.innerHTML = renderEventEvaluator("github", GH_CASES, activeGhCase, (k) => { activeGhCase = k; }, GH_SUBS);
    body.querySelectorAll("[data-case]").forEach((btn) => {
      btn.addEventListener("click", () => { activeGhCase = btn.dataset.case; renderDeck(); });
    });
    return;
  }

  if (activeDeck === "channels") {
    const room = ROOM_STATE[activeRoom];
    body.innerHTML = `
      <div>
        <div class="deck-col-label"><span>Multi-Agent Room Log</span><code>hyp_channel_post</code></div>
        <div class="deck-subtabs">
          <button class="sub-chip ${activeRoom === "#incidents" ? "active" : ""}" data-room="#incidents" type="button">#incidents</button>
          <button class="sub-chip ${activeRoom === "#deploys" ? "active" : ""}" data-room="#deploys" type="button">#deploys</button>
        </div>
        <div class="deck-log" id="deckChannelLog">
          ${room.log.map((line, i) => `<div class="${i === room.log.length - 1 ? "hl" : ""}">${esc(line)}</div>`).join("")}
        </div>
        <div class="deck-input-row">
          <input class="deck-input" id="deckChannelInput" placeholder="Post to ${esc(activeRoom)} as ${esc(room.sender)}..." />
          <button class="deck-send-btn" id="deckChannelSendBtn" type="button">Post</button>
        </div>
      </div>
      <div>
        <div class="deck-col-label"><span>Room Membership</span><code>toggle join / leave</code></div>
        ${chMembers.map((m) => {
          const on = room.joined.has(m.id);
          return `
            <div class="route-item inline ${on ? "matched" : "dim"}">
              <div>
                <span class="ri-addr">${esc(m.id)}</span>
                <span class="ri-sub">${esc(m.sub)}</span>
              </div>
              <button class="ri-pill" data-cm="${esc(m.id)}" type="button">${on ? "joined · leave" : "join room"}</button>
            </div>
          `;
        }).join("")}
      </div>
    `;
    const logEl = document.getElementById("deckChannelLog");
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
    const postMsg = () => {
      const input = document.getElementById("deckChannelInput");
      const text = (input?.value || "").trim() || (activeRoom === "#incidents"
        ? "PR #412 merged — checkout-api errors back to 0.0%."
        : "Shipping checkout-api v2.14.1 to prod.");
      if (input) input.value = "";
      const recips = [...room.joined].filter((x) => x !== room.sender);
      room.log.push(`${room.sender}: ${text}`);
      room.log.push(`-> pushed natively to [${recips.join(", ") || "nobody"}] (no self-echo)`);
      renderDeck();
    };
    body.querySelectorAll("[data-room]").forEach((btn) => {
      btn.addEventListener("click", () => { activeRoom = btn.dataset.room; renderDeck(); });
    });
    body.querySelectorAll("[data-cm]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.cm;
        if (room.joined.has(id)) {
          room.joined.delete(id);
          room.log.push(`hyp_channel_leave('${activeRoom}') -> ${id}`);
        } else {
          room.joined.add(id);
          room.log.push(`hyp_channel_join('${activeRoom}') -> ${id}`);
        }
        renderDeck();
      });
    });
    document.getElementById("deckChannelSendBtn")?.addEventListener("click", postMsg);
    document.getElementById("deckChannelInput")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") postMsg();
    });
    return;
  }

  const linkedList = [...chatLinked];
  body.innerHTML = `
    <div>
      <div class="deck-col-label"><span>Private Node Bridge Config</span><code>connector.json</code></div>
      <div class="deck-subtabs">
        ${["slack", "telegram", "whatsapp", "byo-fd3"].map((app) =>
          `<button class="sub-chip ${chatApp === app ? "active" : ""}" data-capp="${app}" type="button">${app}</button>`
        ).join("")}
      </div>
      <pre class="payload-pre">${esc(JSON.stringify({
        node: "Private Node (127.0.0.1 — never shared with Team Node)",
        plugin: chatApp,
        env: BRIDGE_SECRET_ENV[chatApp],
        target: {
          name: "dm-alex",
          coalesceSeconds: 5,
          maxWaitSeconds: 30,
          wakesPerHour: 120,
          linkedThreads: linkedList,
        },
        outboundReply: 'hyp_plugin_post({ plugin: "' + chatApp + '", target: "dm-alex", text: "..." })',
      }, null, 2))}</pre>
    </div>
    <div>
      <div class="deck-col-label"><span>Live Multi-Thread Fan-In</span><code>hyp_bridge_link / unlink</code></div>
      ${CHAT_THREADS.map((t) => {
        const on = chatLinked.has(t.id);
        return `
          <div class="route-item inline ${on ? "matched" : "dim"}">
            <div>
              <span class="ri-addr">${esc(t.id)}</span>
              <span class="ri-sub">${esc(t.sub)}</span>
            </div>
            <button class="ri-pill" data-ct="${esc(t.id)}" type="button">${on ? "linked · unlink" : "link thread"}</button>
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
  curl: `# Install hyp from GitHub and launch interactive onboarding
bash -c "$(curl -fsSL https://raw.githubusercontent.com/hyphae-to/hyp/main/install.sh)"

# Verify Node 24, daemon, live nodes, secrets, and harnesses
hyp status`,
  npm: `# Install globally via npm (Node 24+)
npm install -g @hyphae-to/hyp

# Pick Private / Public / Shared nodes, harnesses, streams & SSH hosts
hyp onboard`,
  assist: `# Install the standalone Hyphae skill across harnesses (agent starting point)
hyp skill install all

# Or let your coding agent run full onboarding end-to-end (secrets captured out-of-band via --web)
hyp onboard --assist`,
  fleet: `# Wire OpenClaw as your fleet orchestrator
hyp setup openclaw

# Share your private node on Tailscale & onboard remote Linux hosts over SSH
hyp share tailscale --service hyphae
hyp onboard --remote-ssh bogdan@solace --install-service

# Store Slack/Telegram/webhook tokens in OS Keychain / Secret Service (never enters LLM context)
hyp secret set slack-bot-token --web`,
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
