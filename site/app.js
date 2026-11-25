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
    document.documentElement.style.setProperty("--header-h", `${headerH}px`);
    const pastHero = heroBottom <= headerH + 6;
    header.classList.toggle("header-light", pastHero);
    header.classList.toggle("header-dark", !pastHero);
    header.classList.toggle("is-scrolled", !pastHero && window.scrollY > 24);
  }

  syncHeaderTheme();
  window.addEventListener("scroll", syncHeaderTheme, { passive: true });
  window.addEventListener("resize", syncHeaderTheme, { passive: true });
})();

// ============================================================================
// 1. HERO INSTALL SWITCHER (Pre-rendered in HTML; JS enhances tabs & copy)
// ============================================================================
const HERO_CMDS = {
  unix: "curl -fsSL https://hyphae.to/install.sh | sh",
  win: "irm https://hyphae.to/install.ps1 | iex",
  git: "git clone https://github.com/hyphae-to/hyp && cd hyp && cargo install --path crates/hyp-cli",
};

let activeHeroInstall = "unix";
function renderHeroInstall() {
  const cmdEl = document.getElementById("heroInstallCmd");
  if (cmdEl) cmdEl.textContent = HERO_CMDS[activeHeroInstall];
  document.querySelectorAll("#heroInstallTabs .it-btn").forEach((b) => {
    const active = b.dataset.hi === activeHeroInstall;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
  });
}
document.querySelectorAll("#heroInstallTabs .it-btn").forEach((b) => {
  b.addEventListener("click", () => {
    activeHeroInstall = b.dataset.hi;
    renderHeroInstall();
  });
});
document.getElementById("heroCopyBtn")?.addEventListener("click", (e) => {
  navigator.clipboard?.writeText(HERO_CMDS[activeHeroInstall]).catch(() => {});
  const btn = e.currentTarget;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy"; }, 1300);
});
renderHeroInstall();

// ============================================================================
// 1B. HERO SIGNAL BUS (Multi-Source -> Hyphae Wire -> Multi-Machine Agents)
// ============================================================================
(function initSignalBus() {
  const stage = document.getElementById("signalBusStage");
  if (!stage) return;

  const sources = [0, 1, 2, 3].map((i) => document.getElementById(`sbSrc${i}`));
  const inLines = [0, 1, 2, 3].map((i) => document.getElementById(`sbIn${i}`));
  const inPulses = [0, 1, 2, 3].map((i) => document.getElementById(`sbInPulse${i}`));
  const outLines = [0, 1, 2].map((i) => document.getElementById(`sbOut${i}`));
  const outPulses = [0, 1, 2].map((i) => document.getElementById(`sbOutPulse${i}`));

  const core = document.getElementById("sbCore");
  const canvasEl = document.getElementById("sbStageCanvas");
  const wireSvg = document.getElementById("sbWireSvg");
  const wireWeaves = document.getElementById("sbWireWeaves");
  const wireBg = document.getElementById("sbWireBg");
  const hubVisual = document.getElementById("sbHubVisual");
  const valveRing = document.getElementById("sbValveRing");
  const ruleEl = document.getElementById("sbRouteRule");
  const captionEl = document.getElementById("sbCaption");
  const playBtn = document.getElementById("sbPlayBtn");
  const beatBtns = Array.from(document.querySelectorAll("#sbBeats [data-sb-beat]"));
  const allTriggerBtns = Array.from(stage.querySelectorAll("[data-sb-beat]"));

  const agents = [0, 1, 2].map((i) => ({
    card: document.getElementById(`sbAgent${i}`),
    state: document.getElementById(`sbAgentState${i}`),
    msg: document.getElementById(`sbAgentMsg${i}`),
  }));

  function layoutHeroWires() {
    if (!canvasEl || !wireSvg || !hubVisual) return;
    const cRect = canvasEl.getBoundingClientRect();
    if (cRect.width < 100 || window.innerWidth <= 1040) return;

    const w = Math.round(cRect.width);
    const h = Math.round(cRect.height);
    wireSvg.setAttribute("viewBox", `0 0 ${w} ${h}`);

    const hRect = hubVisual.getBoundingClientRect();
    const hubCx = hRect.left + hRect.width / 2 - cRect.left;
    const hubCy = hRect.top + hRect.height / 2 - cRect.top;
    const r = Math.max(40, hRect.width / 2 - 4);

    const NS = "http://www.w3.org/2000/svg";
    if (wireWeaves) wireWeaves.innerHTML = "";
    if (wireBg) wireBg.innerHTML = "";

    const addPath = (parent, cls, d) => {
      if (!parent) return;
      const p = document.createElementNS(NS, "path");
      p.setAttribute("class", cls);
      p.setAttribute("d", d);
      parent.appendChild(p);
    };

    // Left sources -> brass Hyphae Node rim (tucked 6px inside glowing circle so wires never float)
    const inSpread = [-18, -6, 6, 18];
    sources.forEach((el, i) => {
      if (!el) return;
      const sr = el.getBoundingClientRect();
      const x1 = sr.right - cRect.left - 2;
      const y1 = sr.top + sr.height / 2 - cRect.top;
      const dy = inSpread[i] || 0;
      const dxRim = Math.sqrt(Math.max(1, r * r - dy * dy));
      const x2 = hubCx - dxRim + 6;
      const y2 = hubCy + dy;
      const span = Math.max(30, x2 - x1);
      const d = `M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${(x1 + span * 0.44).toFixed(1)} ${y1.toFixed(1)}, ${(x2 - span * 0.42).toFixed(1)} ${y2.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;
      const dw = `M ${x1.toFixed(1)} ${(y1 - 4).toFixed(1)} C ${(x1 + span * 0.36).toFixed(1)} ${(y1 - 10).toFixed(1)}, ${(x2 - span * 0.36).toFixed(1)} ${(y2 + 6).toFixed(1)}, ${x2.toFixed(1)} ${(y2 - 2).toFixed(1)}`;
      addPath(wireWeaves, "sb-weave", dw);
      addPath(wireBg, "sb-path-bg", d);
      if (inLines[i]) inLines[i].setAttribute("d", d);
      if (inPulses[i]) inPulses[i].setAttribute("d", d);
    });

    // Brass Hyphae Node rim -> right agent cards
    const outSpread = [-14, 0, 14];
    agents.forEach((a, i) => {
      if (!a.card) return;
      const ar = a.card.getBoundingClientRect();
      const dy = outSpread[i] || 0;
      const dxRim = Math.sqrt(Math.max(1, r * r - dy * dy));
      const x1 = hubCx + dxRim - 6;
      const y1 = hubCy + dy;
      const x2 = ar.left - cRect.left + 2;
      const y2 = ar.top + ar.height / 2 - cRect.top;
      const span = Math.max(30, x2 - x1);
      const d = `M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${(x1 + span * 0.42).toFixed(1)} ${y1.toFixed(1)}, ${(x2 - span * 0.44).toFixed(1)} ${y2.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;
      const dw = `M ${x1.toFixed(1)} ${(y1 + 2).toFixed(1)} C ${(x1 + span * 0.36).toFixed(1)} ${(y1 - 6).toFixed(1)}, ${(x2 - span * 0.38).toFixed(1)} ${(y2 + 9).toFixed(1)}, ${x2.toFixed(1)} ${(y2 + 3).toFixed(1)}`;
      addPath(wireWeaves, "sb-weave", dw);
      addPath(wireBg, "sb-path-bg", d);
      if (outLines[i]) outLines[i].setAttribute("d", d);
      if (outPulses[i]) outPulses[i].setAttribute("d", d);
    });
  }

  if (typeof ResizeObserver !== "undefined" && canvasEl) {
    new ResizeObserver(() => requestAnimationFrame(layoutHeroWires)).observe(canvasEl);
  }
  window.addEventListener("resize", () => requestAnimationFrame(layoutHeroWires), { passive: true });
  document.fonts?.ready?.then(() => requestAnimationFrame(layoutHeroWires));

  const BEATS = [
    {
      dur: 5000,
      srcIdx: 0,
      tone: "coral",
      rule: "github.ci → claude@laptop",
      caption:
        "<strong>CI event:</strong> Wakes laptop Claude; teammate gets 1-line digest.",
      out: [
        { cls: "coral", state: "lit" },
        { cls: "", state: "off" },
        { cls: "amber", state: "soft" },
      ],
      agents: [
        {
          cardCls: "is-coral",
          stateCls: "coral",
          state: "⚡ Woken",
          msg: "PR #412 failing check in auth.rs · pushed immediately",
        },
        {
          cardCls: "is-muted",
          stateCls: "slate",
          state: "0 wakes",
          msg: "Not subscribed to checkout-api · 0 tokens spent",
        },
        {
          cardCls: "is-amber",
          stateCls: "amber",
          state: "1-line digest",
          msg: "Summary queued for next turn · active work undisturbed",
        },
      ],
    },
    {
      dur: 5000,
      srcIdx: 1,
      tone: "olive",
      rule: "e2ee.dm → codex@linux-ci",
      caption:
        "<strong>Team DM:</strong> Wakes build-server Codex over E2EE.",
      out: [
        { cls: "", state: "off" },
        { cls: "olive", state: "lit" },
        { cls: "olive", state: "soft" },
      ],
      agents: [
        {
          cardCls: "is-idle",
          stateCls: "slate",
          state: "Idle · 0 polling",
          msg: "Unrelated session · untouched",
        },
        {
          cardCls: "is-olive",
          stateCls: "olive",
          state: "⚡ Woken",
          msg: "@alex: review auth.rs diff & run cargo test on linux-ci",
        },
        {
          cardCls: "is-olive-soft",
          stateCls: "olive",
          state: "Synced · E2EE",
          msg: "Patch thread relayed via blind Team Hub (ciphertext only)",
        },
      ],
    },
    {
      dur: 5000,
      srcIdx: 2,
      tone: "moss",
      rule: "passkey → OS Keychain",
      caption:
        "<strong>Passkey drop:</strong> Lands in OS Keychain — never in prompts.",
      out: [
        { cls: "moss", state: "lit" },
        { cls: "", state: "off" },
        { cls: "", state: "off" },
      ],
      agents: [
        {
          cardCls: "is-moss",
          stateCls: "moss",
          state: "✓ Keychain ready",
          msg: "STRIPE_KEY stored in OS Keychain · hyp exec redacts output",
        },
        {
          cardCls: "is-idle",
          stateCls: "slate",
          state: "Scoped",
          msg: "Pinned to laptop node only · zero relay plaintext",
        },
        {
          cardCls: "is-idle",
          stateCls: "slate",
          state: "Untouched",
          msg: "Blind relay auto-wipes ciphertext within 15 min",
        },
      ],
    },
    {
      dur: 5200,
      srcIdx: 3,
      tone: "amber",
      rule: "hyp emit → antigravity@team",
      caption:
        "<strong>Cron / alerts:</strong> Wakes subscribed agent; others stay quiet.",
      out: [
        { cls: "amber", state: "soft" },
        { cls: "", state: "off" },
        { cls: "amber", state: "lit" },
      ],
      agents: [
        {
          cardCls: "is-amber",
          stateCls: "amber",
          state: "1-line digest",
          msg: "09:00 triage digest attached to next turn",
        },
        {
          cardCls: "is-muted",
          stateCls: "slate",
          state: "0 wakes",
          msg: "Archived silently · active build uninterrupted",
        },
        {
          cardCls: "is-amber",
          stateCls: "amber",
          state: "⚡ Ready",
          msg: "Morning cron delivered · 3 open PRs ready in hyp_inbox",
        },
      ],
    },
  ];

  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  let beatIdx = 0;
  let playing = !reduced;
  let timer = null;

  function renderBeat(idx) {
    const b = BEATS[idx] || BEATS[0];

    sources.forEach((el, i) => {
      if (!el) return;
      el.classList.toggle("is-active", i === b.srcIdx);
      el.setAttribute("aria-pressed", i === b.srcIdx ? "true" : "false");
    });

    inLines.forEach((el, i) => {
      if (!el) return;
      el.classList.toggle("is-lit", i === b.srcIdx);
    });
    inPulses.forEach((el, i) => {
      if (!el) return;
      el.classList.toggle("is-lit", !reduced && i === b.srcIdx);
    });

    outLines.forEach((el, i) => {
      if (!el) return;
      const spec = b.out[i];
      el.setAttribute("class", `sb-path-live ${spec.cls} ${spec.state === "lit" ? "is-lit" : spec.state === "soft" ? "is-soft" : ""}`.trim());
    });
    outPulses.forEach((el, i) => {
      if (!el) return;
      const spec = b.out[i];
      const activeCls = !reduced && spec.state === "lit" ? "is-lit" : !reduced && spec.state === "soft" ? "is-soft" : "";
      el.setAttribute("class", `sb-pulse ${spec.cls} ${activeCls}`.trim());
    });

    if (core) core.className = `sb-hub-medallion tone-${b.tone}`;
    if (valveRing) valveRing.className = `sb-valve-ring tone-${b.tone}`;

    if (ruleEl) {
      ruleEl.textContent = b.rule;
      ruleEl.className = `sb-rule-readout ${b.tone}`;
    }

    agents.forEach((a, i) => {
      const spec = b.agents[i];
      if (!spec) return;
      if (a.card) a.card.className = `sb-agent ${spec.cardCls}`.trim();
      if (a.state) {
        a.state.textContent = spec.state;
        a.state.className = `sb-state ${spec.stateCls}`.trim();
      }
      if (a.msg) a.msg.textContent = spec.msg;
    });

    if (captionEl) captionEl.innerHTML = b.caption;

    beatBtns.forEach((btn, i) => {
      btn.classList.toggle("active", i === idx);
      btn.classList.toggle("passed", i < idx);
    });

    requestAnimationFrame(layoutHeroWires);
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    if (!playing) return;
    timer = setTimeout(() => {
      beatIdx = (beatIdx + 1) % BEATS.length;
      renderBeat(beatIdx);
      schedule();
    }, BEATS[beatIdx].dur);
  }

  allTriggerBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      beatIdx = Number(btn.dataset.sbBeat) || 0;
      renderBeat(beatIdx);
      schedule();
    });
  });

  if (playBtn) {
    playBtn.textContent = playing ? "Pause" : "Play";
    playBtn.addEventListener("click", () => {
      playing = !playing;
      playBtn.textContent = playing ? "Pause" : "Play";
      if (playing) {
        renderBeat(beatIdx);
        schedule();
      } else if (timer) {
        clearTimeout(timer);
      }
    });
  }

  layoutHeroWires();
  requestAnimationFrame(layoutHeroWires);
  renderBeat(beatIdx);
  schedule();
})();

// ============================================================================
// 1C. INTERACTIVE USE CASE SHOWCASE (#use-cases)
// ============================================================================
(function initUseCaseShowcase() {
  const root = document.getElementById("ucShowcase");
  if (!root) return;

  const tabs = Array.from(root.querySelectorAll(".uc-tab[data-uc]"));
  const card = document.getElementById("ucStageCard");
  const badgeEl = document.getElementById("ucStageBadge");
  const titleEl = document.getElementById("ucStageTitle");
  const leadEl = document.getElementById("ucStageLead");
  const fromEl = document.getElementById("ucFlowFrom");
  const midLabelEl = document.getElementById("ucFlowMidLabel");
  const toEl = document.getElementById("ucFlowTo");
  const termLabelEl = document.getElementById("ucTermLabel");
  const termCodeEl = document.getElementById("ucTermCode");
  const copyBtn = document.getElementById("ucCopyBtn");
  const chipsEl = document.getElementById("ucChips");
  const actionLinkEl = document.getElementById("ucActionLink");

  const KEY_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8.5" cy="14.5" r="4"/><path d="M11.5 11.5 20 3"/><path d="m17 6 2.5 2.5"/><path d="m14.5 8.5 2 2"/></svg>`;

  const WORKFLOWS = {
    team: {
      tone: "olive",
      badge: "Direct P2P · Team Hub (Beta)",
      title: "Coordinate agents across laptops and build servers",
      lead: "Pair machines directly over Tailscale or LAN with zero server, or run a blind Team Hub for <code>#channels</code> and shared KV.",
      from: { kind: "avatar", src: "./assets/sprite-alex.jpg?v=2", title: "alex@macbook", sub: "Claude · sends E2EE DM" },
      mid: "HPKE E2EE",
      to: { kind: "avatar", src: "./assets/sprite-alice.jpg?v=2", title: "codex@linux-ci", sub: "Wakes · audits & replies" },
      termLabel: "Pair directly or spin up a hub",
      code: `# Direct P2P pairing (zero server)\nhyp onboard\n# Or self-host a blind Team Hub:\nhyp deploy init tailscale`,
      copy: "hyp onboard",
      chips: ["Tailscale / LAN", "HPKE E2EE", "#channels & KV"],
      link: { text: "See 7-step team walkthrough ↓", href: "#walkthrough", openWalkthrough: true },
    },
    events: {
      tone: "amber",
      badge: "Standardized Event Streams",
      title: "Wake only the right agent from CI, alerts, or OS cron",
      lead: "GitHub PRs, Prometheus webhooks, and <code>hyp emit</code> schedules normalize onto one CloudEvents bus with burst caps — zero polling.",
      from: { kind: "icon", src: "./assets/icons/github.svg", title: "GitHub / Cron / Alerts", sub: "Normalized CloudEvents" },
      mid: "Filter + Tier",
      to: { kind: "icon", src: "./assets/icons/claude.svg", title: "Subscribed session", sub: "Wakes or queues 1-line digest" },
      termLabel: "Emit a scheduled wake from cron, launchd, systemd, or schtasks",
      code: `# Emit a structured event to local.schedule\nhyp emit --label morning-triage \\\n  --note "Review open PRs"\n# Wakes only matching subscribers`,
      copy: 'hyp emit --label morning-triage --note "Review open PRs"',
      chips: ["GitHub & Prometheus", "OS cron triggers", "Zero polling"],
      link: { text: "Try the live delivery simulator ↓", href: "#streams" },
    },
    drops: {
      tone: "moss",
      badge: "Passkey + Keychain + hyp exec",
      title: "Send secrets or signed approvals from your phone",
      lead: "Seal credentials or signed directives on <a class=\"card-inline-link\" href=\"./drop/\">hyphae.to/drop ↗</a> with Face ID — secrets land in Keychain and inject via <code>hyp exec</code>.",
      from: { kind: "glyph", svg: KEY_SVG, title: "Phone · Face ID", sub: "WebAuthn Passkey + PRF" },
      mid: "Blind Relay ≤15m",
      to: { kind: "icon", src: "./assets/icons/openai.svg", title: "OS Keychain → hyp exec", sub: "Child env only · stdout redacted" },
      termLabel: "Request a secret drop and inject it safely",
      code: `# Request a Passkey-sealed secret drop\nhyp drop create --kind secret --secret-name stripe-key\n# Inject into child env with live stdout redaction\nhyp exec --env STRIPE_KEY=stripe-key -- ./deploy.sh`,
      copy: "hyp drop create --kind secret --secret-name stripe-key",
      chips: ["OS Keychain", "Passkey Signed", "Live Redaction"],
      link: { text: "Open Drop Portal ↗", href: "./drop/" },
    },
    local: {
      tone: "olive",
      badge: "Zero Setup · Local Daemon",
      title: "Let Claude Code, Codex, and OpenCode work together",
      lead: "Every harness on your laptop shares one local SQLite inbox over 4 MCP tools and 2.7 ms hooks — idle sessions wake automatically.",
      from: { kind: "icon", src: "./assets/icons/claude.svg", title: "Claude Code · @builder", sub: "Asks @reviewer to check diff" },
      mid: "Local IPC",
      to: { kind: "icon", src: "./assets/icons/openai.svg", title: "Codex · @reviewer", sub: "Wakes · audits · wakes builder" },
      termLabel: "Prompt in Claude Code after install",
      code: `# In Claude Code:\n"Join the Hyphae mesh as builder, then ask codex\n to review my last commit and reply when done."\n# Idle Codex wakes, audits, and replies`,
      copy: "Join the Hyphae mesh as builder, then ask codex to review my last commit and reply when done.",
      chips: ["Claude Code", "Codex", "Antigravity", "OpenCode"],
      link: { text: "See supported harnesses ↓", href: "#how-it-works" },
    },
    bridges: {
      tone: "olive",
      badge: "Verified Bridge Plugins",
      title: "Message live sessions from Slack, Telegram, or WhatsApp",
      lead: "Install SHA-256 verified bridges on macOS, Linux, or Windows. Bot tokens stay in Keychain, allowlists fail closed, and topics stay local.",
      from: { kind: "icon", src: "./assets/icons/telegram.svg", title: "Slack · Telegram · WhatsApp", sub: "Allowlisted private chat" },
      mid: "Local Bridge",
      to: { kind: "icon", src: "./assets/icons/herdr.png", title: "Linked agent session", sub: "Replies & emoji reactions" },
      termLabel: "Install a verified bridge and store its token out-of-band",
      code: `# Install checksum-pinned bridge plugin\nhyp plugin install telegram\n# Store bot token directly into OS Keychain\nhyp secret set telegram-bot-token --web`,
      copy: "hyp plugin install telegram && hyp secret set telegram-bot-token --web",
      chips: ["macOS · Linux · Windows", "SHA-256 pinned", "Local-only topics"],
      link: { text: "Read chat bridges guide ↗", href: "https://github.com/hyphae-to/hyp/blob/main/docs/guides/chat-bridges.md", external: true },
    },
  };

  function renderNode(el, spec) {
    if (!el || !spec) return;
    let icoHtml = "";
    if (spec.kind === "glyph") {
      icoHtml = `<span class="uc-flow-ico glyph" aria-hidden="true">${spec.svg}</span>`;
    } else if (spec.kind === "avatar") {
      icoHtml = `<span class="uc-flow-ico avatar"><img src="${esc(spec.src)}" alt="" /></span>`;
    } else {
      icoHtml = `<span class="uc-flow-ico"><img src="${esc(spec.src)}" alt="" /></span>`;
    }
    el.innerHTML = `${icoHtml}<span class="uc-flow-copy"><strong>${esc(spec.title)}</strong><small>${esc(spec.sub)}</small></span>`;
  }

  function formatCode(raw) {
    return raw
      .split("\n")
      .map((line) => (line.trimStart().startsWith("#") ? `<span class="uc-c">${esc(line)}</span>` : esc(line)))
      .join("\n");
  }

  let activeKey = "team";

  function selectWorkflow(key) {
    const wf = WORKFLOWS[key] || WORKFLOWS.team;
    activeKey = key in WORKFLOWS ? key : "team";

    tabs.forEach((btn) => {
      const isAct = btn.dataset.uc === activeKey;
      btn.classList.toggle("is-active", isAct);
      btn.setAttribute("aria-selected", isAct ? "true" : "false");
    });

    if (card) card.className = `uc-stage tone-${wf.tone}`;
    if (badgeEl) badgeEl.textContent = wf.badge;
    if (titleEl) titleEl.textContent = wf.title;
    if (leadEl) leadEl.innerHTML = wf.lead;
    renderNode(fromEl, wf.from);
    if (midLabelEl) midLabelEl.textContent = wf.mid;
    renderNode(toEl, wf.to);
    if (termLabelEl) termLabelEl.textContent = wf.termLabel;
    if (termCodeEl) termCodeEl.innerHTML = formatCode(wf.code);
    if (chipsEl) chipsEl.innerHTML = wf.chips.map((c) => `<span>${esc(c)}</span>`).join("");

    if (actionLinkEl && wf.link) {
      actionLinkEl.textContent = wf.link.text;
      actionLinkEl.setAttribute("href", wf.link.href);
      if (wf.link.external) {
        actionLinkEl.setAttribute("target", "_blank");
        actionLinkEl.setAttribute("rel", "noreferrer");
      } else {
        actionLinkEl.removeAttribute("target");
        actionLinkEl.removeAttribute("rel");
      }
      actionLinkEl.dataset.openWalkthrough = wf.link.openWalkthrough ? "1" : "";
    }
  }

  tabs.forEach((btn, idx) => {
    btn.addEventListener("click", () => selectWorkflow(btn.dataset.uc));
    btn.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" || e.key === "ArrowRight") {
        e.preventDefault();
        const next = tabs[(idx + 1) % tabs.length];
        next.focus();
        selectWorkflow(next.dataset.uc);
      } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
        e.preventDefault();
        const prev = tabs[(idx - 1 + tabs.length) % tabs.length];
        prev.focus();
        selectWorkflow(prev.dataset.uc);
      }
    });
  });

  copyBtn?.addEventListener("click", () => {
    const wf = WORKFLOWS[activeKey];
    if (!wf) return;
    navigator.clipboard?.writeText(wf.copy).catch(() => {});
    copyBtn.textContent = "Copied";
    setTimeout(() => { copyBtn.textContent = "Copy"; }, 1300);
  });

  actionLinkEl?.addEventListener("click", () => {
    if (actionLinkEl.dataset.openWalkthrough === "1" && !walkthroughOpen) {
      setWalkthroughOpen(true);
    }
  });

  selectWorkflow("team");
})();

// ============================================================================
// 2. PANORAMIC 7-CHAPTER INCIDENT WALKTHROUGH (Collapsible Beta Diorama)
// ============================================================================
const CHAPTERS = [
  {
    durationMs: 5800,
    tip: "1 · Alex joins Team Node -> peers bloom one by one",
    caption: "<strong>1/7</strong> · <strong>Alex</strong> (Claude in Herdr) joins the <strong>Team Node</strong> — immediately unlocking <code>#channels</code>, streams, <strong>Alice's Codex</strong>, and <strong>Jack's ops &amp; release mgr</strong>.",
    visible: ["ent-alex", "ent-node"],
    dim: [],
    spotlight: ["ent-alex"],
    alertHit: [],
    strands: ["p-alex-node"],
    softStrands: [],
    bubbles: { "bub-alex": { text: "Calling hyp_mesh(join) on the Team Node…", alert: false } },
    caps: [],
    subs: [],
    promState: "",
    promSub: "14 servers · healthy",
    ghTitle: "GitHub · stream",
    ghSub: "ready on node",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-node", reverse: false, cls: "", label: "hyp_mesh(join)", delay: 150, dur: 900 },
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
    durationMs: 3500,
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
    durationMs: 4900,
    tip: "3 · Ops calls hyp_send -> Alex + Local Node Slack + #deploys",
    caption: "<strong>3/7</strong> · Jack's ops sends a <code>hyp_send</code> to <strong>Alex</strong>. Alex joins <code>#deploys</code> with ops and wires a <strong>Local Node · Bridge -> Slack</strong> to DM Alex.",
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
    durationMs: 5200,
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
    ccAction: "→ opened PR #412 · hyp_stream(subscribe)",
    promState: "coral",
    promSub: "HighErrorRate · 4.2%!",
    filterTag: false,
    ripples: [],
    packets: [
      { path: "p-alex-gh", reverse: false, cls: "amber", label: "open PR #412", delay: 150, dur: 900 },
      { path: "p-alex-node", reverse: false, cls: "", label: "hyp_stream(subscribe)", delay: 280, dur: 920 },
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
    durationMs: 5400,
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
    durationMs: 6600,
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
    durationMs: 6900,
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
        at: 4120,
        bubbles: {
          "bub-ops": { text: "0.0% errors across all 14 servers. Nice save, team.", alert: false },
        },
      },
      {
        at: 4720,
        bubbles: {
          "bub-alice": { text: "Glad my sub-agent caught that timeout. Coffee's on Alex.", alert: false },
        },
      },
      {
        at: 5220,
        bubbles: {
          "bub-alex": { text: "Deal. Next outage is Jack's turn.", alert: false },
          "bub-release": { text: "Please don't jinx v2.14.1.", alert: false },
        },
        showReplay: true,
      },
    ],
  },
];

const SVG_NS = "http://www.w3.org/2000/svg";
const strandLengths = new Map();
const hyphaBundleMap = new Map();
let bundlesBuilt = false;

function buildOrganicHyphaBundles() {
  if (bundlesBuilt) return;
  bundlesBuilt = true;
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

function fitWalkthroughStage() {
  const stageCenter = document.getElementById("heroStageCenter");
  const viewport = document.getElementById("storyViewport");
  const stage = document.getElementById("storyStage");
  if (!viewport || !stage) return;
  const availW = (stageCenter ? stageCenter.clientWidth : viewport.clientWidth) || 0;
  if (availW <= 0) return;

  const LOGICAL_W = 1200;
  const LOGICAL_H = 590;
  const scale = Math.min(1, availW / LOGICAL_W);
  const offsetX = Math.max(0, (availW - LOGICAL_W * scale) / 2);
  stage.style.transform = `translateX(${offsetX.toFixed(1)}px) scale(${scale.toFixed(4)})`;
  viewport.style.height = `${Math.round(LOGICAL_H * scale)}px`;
}

let vineMainLen = 1000;
let vineSubLen = 1000;
let chapterIdx = 0;
let storyPlaying = false;
let storyTimer = null;
let pktRaf = null;
let stagedTimers = [];
let walkthroughOpen = false;
let forceSettled = new URLSearchParams(window.location.search).get("settled") === "1";

function initVineLengths() {
  const vineMain = document.getElementById("tlVineMain");
  const vineSub = document.getElementById("tlVineSub");
  if (vineMain) {
    vineMainLen = vineMain.getTotalLength() || 1000;
    vineMain.style.strokeDasharray = `${vineMainLen}`;
    vineMain.style.strokeDashoffset = `${vineMainLen}`;
  }
  if (vineSub) {
    vineSubLen = vineSub.getTotalLength() || 1000;
    vineSub.style.strokeDasharray = `${vineSubLen}`;
    vineSub.style.strokeDashoffset = `${vineSubLen}`;
  }
}

function clearStagedTimers() {
  for (const t of stagedTimers) clearTimeout(t);
  stagedTimers = [];
}

function easeInOutQuad(t) {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
}

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
    if (!walkthroughOpen) return;
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
    st.addVisible.forEach((id) => document.getElementById(id)?.classList.add("visible"));
  }
  if (st.undim) {
    st.undim.forEach((id) => document.getElementById(id)?.classList.remove("dim"));
  }
  if (st.spotlight) {
    ["ent-alex", "ent-node", "ent-alice", "ent-ops", "ent-release"].forEach((id) => {
      document.getElementById(id)?.classList.toggle("spotlight", st.spotlight.includes(id));
    });
  }
  if (st.alertHit) {
    st.alertHit.forEach((id) => document.getElementById(id)?.classList.add("alert-hit"));
  }
  if (st.hideStrands) {
    st.hideStrands.forEach((id) => setStrandState(id, "hidden"));
  }
  if (st.addStrands) {
    st.addStrands.forEach((id) => setStrandState(id, "grown"));
  }
  if (st.caps) {
    ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
      document.getElementById(id)?.classList.toggle("lit", st.caps.includes(id));
    });
  }
  if (st.coralCaps) {
    ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
      document.getElementById(id)?.classList.toggle("lit-coral", st.coralCaps.includes(id));
    });
  }
  if (st.subs) {
    ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"].forEach((id) => {
      document.getElementById(id)?.classList.toggle("show", st.subs.includes(id));
    });
  }
  if (st.addSubs) {
    st.addSubs.forEach((id) => document.getElementById(id)?.classList.add("show"));
  }
  if (st.filterTag !== undefined) {
    document.getElementById("filterTag")?.classList.toggle("show", Boolean(st.filterTag));
  }
  if (st.ghActive !== undefined) {
    const ghEl = document.getElementById("ent-gh");
    if (ghEl) {
      ghEl.classList.toggle("active-amber", st.ghActive === "amber");
      ghEl.classList.toggle("active-coral", st.ghActive === "coral");
      ghEl.classList.toggle("active-green", st.ghActive === "green");
    }
  }
  if (st.ghTitle) document.getElementById("ghTitle").textContent = st.ghTitle;
  if (st.ghSub) document.getElementById("ghSub").textContent = st.ghSub;
  if (st.promState !== undefined) {
    const promEl = document.getElementById("ent-prom");
    if (promEl) {
      promEl.classList.toggle("active-coral", st.promState === "coral");
      promEl.classList.toggle("active-green", st.promState === "green");
    }
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
  const vineMain = document.getElementById("tlVineMain");
  const vineSub = document.getElementById("tlVineSub");
  const frac = CHAPTERS.length > 1 ? chapterIdx / (CHAPTERS.length - 1) : 1;
  if (vineMain) vineMain.style.strokeDashoffset = `${(vineMainLen * (1 - frac)).toFixed(1)}`;
  if (vineSub) vineSub.style.strokeDashoffset = `${(vineSubLen * (1 - frac)).toFixed(1)}`;
}

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
  if (ghEl) {
    ghEl.classList.toggle("active-amber", ch.ghActive === "amber");
    ghEl.classList.toggle("active-coral", ch.ghActive === "coral");
    ghEl.classList.toggle("active-green", ch.ghActive === "green");
  }
  document.getElementById("ghTitle").textContent = ch.ghTitle;
  document.getElementById("ghSub").textContent = ch.ghSub;
  if (ch.ccAction) document.getElementById("ccAction").textContent = ch.ccAction;

  const promEl = document.getElementById("ent-prom");
  if (promEl) {
    promEl.classList.toggle("active-coral", ch.promState === "coral");
    promEl.classList.toggle("active-green", ch.promState === "green");
  }
  document.getElementById("promSub").textContent = ch.promSub;
  document.getElementById("filterTag")?.classList.toggle("show", Boolean(ch.filterTag));

  if (ch.subagentText) document.getElementById("subagentText").textContent = ch.subagentText;
  if (ch.slackMsg) document.getElementById("slackDmMsg").innerHTML = ch.slackMsg;

  ["sub-alex-pr", "sub-alex-dep", "sub-alice-pr", "sub-alice-dep", "sub-ops-dep", "sub-rel-pr"].forEach((id) => {
    document.getElementById(id)?.classList.toggle("show", (ch.subs || []).includes(id));
  });

  ["cap-ch", "cap-dep", "cap-gh", "cap-pr"].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
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
    if (!el) return;
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
    if (!el) return;
    el.classList.remove("fire");
    if (ch.ripples.includes(id)) {
      void el.offsetWidth;
      el.classList.add("fire");
    }
  });

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
  if (!storyPlaying || !walkthroughOpen) return;
  const isLast = chapterIdx >= CHAPTERS.length - 1;
  if (isLast) {
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
  const playBtn = document.getElementById("storyPlayBtn");
  if (playBtn) playBtn.textContent = "Pause";
  renderChapter();
  resetStoryTimer();
}

function setWalkthroughOpen(open) {
  const body = document.getElementById("walkthroughBody");
  const toggle = document.getElementById("walkthroughToggle");
  const label = document.getElementById("walkthroughToggleLabel");
  if (!body || !toggle) return;

  walkthroughOpen = open;
  body.hidden = !open;
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  toggle.classList.toggle("is-open", open);
  if (label) label.textContent = open ? "Hide 7-step story" : "Expand 7-step story";

  if (open) {
    requestAnimationFrame(() => {
      fitWalkthroughStage();
      buildOrganicHyphaBundles();
      initVineLengths();
      const urlChapter = new URLSearchParams(window.location.search).get("chapter");
      const hasUrlCh = urlChapter !== null && Number.isInteger(Number(urlChapter)) && Number(urlChapter) >= 0 && Number(urlChapter) < CHAPTERS.length;
      if (hasUrlCh) {
        chapterIdx = Number(urlChapter);
        storyPlaying = false;
        const playBtn = document.getElementById("storyPlayBtn");
        if (playBtn) playBtn.textContent = "Play";
      } else {
        storyPlaying = !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
        const playBtn = document.getElementById("storyPlayBtn");
        if (playBtn) playBtn.textContent = storyPlaying ? "Pause" : "Play";
      }
      renderChapter();
      resetStoryTimer();
    });
  } else {
    storyPlaying = false;
    clearStagedTimers();
    if (storyTimer) clearTimeout(storyTimer);
    if (pktRaf) cancelAnimationFrame(pktRaf);
  }
}

document.getElementById("walkthroughToggle")?.addEventListener("click", () => {
  setWalkthroughOpen(!walkthroughOpen);
});

document.getElementById("jumpWalkthroughBtn")?.addEventListener("click", () => {
  if (!walkthroughOpen) setWalkthroughOpen(true);
});

document.getElementById("storyReplayBtn")?.addEventListener("click", replayStory);

document.getElementById("storyPlayBtn")?.addEventListener("click", (e) => {
  if (!storyPlaying && chapterIdx === CHAPTERS.length - 1) {
    replayStory();
    return;
  }
  storyPlaying = !storyPlaying;
  e.currentTarget.textContent = storyPlaying ? "Pause" : "Play";
  resetStoryTimer();
});

document.getElementById("storyPrevBtn")?.addEventListener("click", () => {
  chapterIdx = (chapterIdx - 1 + CHAPTERS.length) % CHAPTERS.length;
  renderChapter();
  resetStoryTimer();
});

document.getElementById("storyNextBtn")?.addEventListener("click", () => {
  chapterIdx = (chapterIdx + 1) % CHAPTERS.length;
  renderChapter();
  resetStoryTimer();
});

window.addEventListener("resize", () => {
  if (walkthroughOpen) fitWalkthroughStage();
}, { passive: true });

if (new URLSearchParams(window.location.search).get("chapter") !== null) {
  setWalkthroughOpen(true);
}

// Floating organic spore canvas behind hero
(function initSporeCanvas() {
  const canvas = document.getElementById("sporeCanvas");
  if (!canvas || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
  const ctx = canvas.getContext("2d");
  let w = 0, h = 0;
  const motes = Array.from({ length: 28 }, () => ({
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

// ============================================================================
// 3. INTERACTIVE LOCAL NODE DELIVERY SIMULATOR (#streams — always visible)
// ============================================================================
(function initControlGate() {
  const shell = document.getElementById("gateShell");
  const viewport = document.getElementById("gateViewport");
  const stage = document.getElementById("gateStage");
  const packetsHost = document.getElementById("gatePackets");
  const mobileHost = document.getElementById("gateMobile");
  const shieldArc = document.getElementById("gateShieldArc");
  if (!shell || !viewport || !stage) return;

  const LOGICAL_W = 1120;
  const LOGICAL_H = 488;
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  let simInView = true;
  let gateBundlesBuilt = false;

  function fitGateStage() {
    if (window.innerWidth <= 760) {
      viewport.style.height = "";
      return;
    }
    const availW = viewport.clientWidth || 0;
    if (availW <= 0) return;
    const scale = Math.min(1, availW / LOGICAL_W);
    const offsetX = Math.max(0, (availW - LOGICAL_W * scale) / 2);
    stage.style.transform = `translateX(${offsetX.toFixed(1)}px) scale(${scale.toFixed(4)})`;
    viewport.style.height = `${Math.round(LOGICAL_H * scale)}px`;
  }

  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(fitGateStage).observe(viewport);
  }
  window.addEventListener("resize", fitGateStage, { passive: true });

  const GATE_SOURCES = [
    { name: "DM @alice", sub: "direct message", cls: "peer" },
    { name: "OSS PRs", sub: "anthropics/claude-code", linkedSub: "anthropics/claude-code", cls: "amber" },
    { name: "CI Burst (×12)", sub: "flaky retries", cls: "amber-muted" },
    { name: "#deploys", sub: "build room", cls: "olive" },
    { name: "Direct P2P · bob@laptop", sub: "E2EE · diff.patch", cls: "moss" },
  ];

  const gateBundles = new Map();
  function ensureGateBundles() {
    if (gateBundlesBuilt) return;
    gateBundlesBuilt = true;
    const gateHost = document.getElementById("gateBundles");
    document.querySelectorAll(".gate-strand").forEach((path, idx) => {
      if (!gateHost) return;
      const isUnified = path.id === "g-out";
      const len = path.getTotalLength();
      const g = document.createElementNS(SVG_NS, "g");
      const cls = ["amber-muted", "amber", "coral", "olive", "moss", "peer"].find((c) => path.classList.contains(c)) || "";
      g.setAttribute("class", `gate-bundle ${cls}`.trim());

      const steps = Math.max(10, Math.min(24, Math.round(len / 18)));
      const amp = isUnified ? 2.8 : Math.min(6.4, Math.max(3.6, len * 0.022));
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
        const offA = env * Math.sin(f * Math.PI * (isUnified ? 4.2 : 3) + seed) * amp;
        const offB = env * Math.cos(f * Math.PI * (isUnified ? 5.2 : 4.1) - seed) * (amp * 0.58);
        ptsA.push(`${(p.x + nx * offA).toFixed(1)} ${(p.y + ny * offA).toFixed(1)}`);
        ptsB.push(`${(p.x + nx * offB).toFixed(1)} ${(p.y + ny * offB).toFixed(1)}`);
      }

      for (const [pts, wcls] of [[ptsA, "gb-weave"], [ptsB, "gb-weave fine"]]) {
        const w = document.createElementNS(SVG_NS, "path");
        w.setAttribute("class", wcls);
        w.setAttribute("d", `M ${pts[0]} L ${pts.slice(1).join(" L ")}`);
        g.appendChild(w);
      }

      if (!isUnified) {
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
          const reach = 14;
          const c1x = p.x + tx * 6 + nx * 7;
          const c1y = p.y + ty * 6 + ny * 7;
          const ex = p.x + tx * 11 + nx * reach;
          const ey = p.y + ty * 11 + ny * reach;
          const twig = document.createElementNS(SVG_NS, "path");
          twig.setAttribute("class", "gb-twig");
          twig.setAttribute("d", `M ${p.x.toFixed(1)} ${p.y.toFixed(1)} Q ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${ex.toFixed(1)} ${ey.toFixed(1)}`);
          g.appendChild(twig);
        });
      }

      gateHost.appendChild(g);
      gateBundles.set(path.id, g);
    });
  }

  const DEFAULT_STATE = {
    publicLinked: false,
    ciMode: "burst",
    aliceMode: "queue",
    deploysMode: "mute",
    guard: true,
    focus: false,
  };

  const params = new URLSearchParams(window.location.search);
  const urlPhaseRaw = params.get("t");
  const fixedPhase = urlPhaseRaw !== null && !Number.isNaN(Number(urlPhaseRaw)) ? Number(urlPhaseRaw) : null;

  let gateState = { ...DEFAULT_STATE };
  if (params.get("public") === "1") gateState.publicLinked = true;
  if (params.get("focus") === "1") gateState.focus = true;
  if (params.get("ci") && ["burst", "unsub", "all"].includes(params.get("ci"))) gateState.ciMode = params.get("ci");
  if (params.get("alice") && ["queue", "interrupt", "notify", "mute"].includes(params.get("alice"))) gateState.aliceMode = params.get("alice");
  if (params.get("deploys") && ["mute", "notify", "queue"].includes(params.get("deploys"))) gateState.deploysMode = params.get("deploys");
  if (params.get("guard") === "0") gateState.guard = false;

  let lastCmd = 'hyp_inbox({ mode: "queue", burst: "notify" })';
  let gatePlaying = fixedPhase === null && !reducedMotion;
  let gateRaf = null;
  let shieldTimer = null;

  function fireRipple(el, extraCls) {
    if (!el || reducedMotion) return;
    el.classList.remove("fire", "amber", "coral");
    if (extraCls) el.classList.add(extraCls);
    void el.offsetWidth;
    el.classList.add("fire");
  }

  function flashShield(kind) {
    if (!shieldArc) return;
    shieldArc.classList.remove("hit-amber", "hit-coral");
    shieldArc.classList.add(kind === "coral" ? "hit-coral" : "hit-amber");
    clearTimeout(shieldTimer);
    shieldTimer = setTimeout(() => {
      shieldArc.classList.remove("hit-amber", "hit-coral");
    }, 440);
  }

  function buildScenario(st) {
    const packets = [];
    const queuedItems = [];
    const notifyItems = [];
    const interruptItems = [];
    let droppedCount = 0;
    let burstCapped = 0;
    let unsubOrUnlinked = 0;
    let leakedInject = false;
    let noisyFlood = false;

    const aliceEff = st.aliceMode === "mute"
      ? "mute"
      : st.aliceMode === "interrupt"
      ? "interrupt"
      : st.focus
      ? "notify"
      : st.aliceMode;

    let src0;
    if (aliceEff === "mute") {
      droppedCount += 1;
      src0 = { state: "muted", badge: "muted", strand: "blocked" };
      packets.push({
        path: "g-in-0",
        cls: "coral",
        label: "DM @alice",
        phase: 0.78,
        dur: 1680,
        startT: 0.14,
        endT: 0.72,
        deflect: "coral",
        dropTag: "✕ muted · @alice",
      });
    } else if (aliceEff === "interrupt") {
      interruptItems.push("DM @alice");
      src0 = { state: "urgent", badge: "interrupt!", strand: "active" };
      packets.push({ path: "g-in-0", cls: "coral", label: "⚡ DM @alice", phase: 0.02, dur: 980, startT: 0.14, endT: 0.78, rippleNode: "coral" });
    } else if (aliceEff === "notify") {
      notifyItems.push("DM @alice");
      src0 = { state: "notify", badge: "notify", strand: "active" };
      packets.push({ path: "g-in-0", cls: "amber", label: "DM @alice", phase: 0.03, dur: 1180, startT: 0.14, endT: 0.78, rippleNode: "amber" });
    } else {
      queuedItems.push("DM");
      src0 = { state: "pass", badge: "queue", strand: "active" };
      packets.push({ path: "g-in-0", cls: "", label: "DM @alice", phase: 0.02, dur: 1160, startT: 0.14, endT: 0.78, rippleNode: "green" });
    }

    let src1;
    if (!st.publicLinked) {
      unsubOrUnlinked += 1;
      src1 = { state: "detached", badge: "unlinked", strand: "detached", sub: GATE_SOURCES[1].sub };
    } else {
      const ossEff = st.focus ? "notify" : "queue";
      if (ossEff === "notify") notifyItems.push("claude-code PR");
      else queuedItems.push("OSS PR");

      src1 = {
        state: !st.guard ? "warn" : ossEff === "notify" ? "notify" : "pass",
        badge: !st.guard ? "⚠ guard off" : ossEff,
        strand: "active",
        sub: GATE_SOURCES[1].linkedSub,
      };
      packets.push({ path: "g-in-1", cls: "amber", label: "claude-code PR", phase: 0.05, dur: 1180, startT: 0.14, endT: 0.78 });

      if (st.guard) {
        droppedCount += 1;
        packets.push({
          path: "g-in-1",
          cls: "coral",
          label: "ignore prev…",
          phase: 0.36,
          dur: 1700,
          startT: 0.14,
          endT: 0.72,
          deflect: "coral",
          dropTag: "✕ quarantined · guard",
        });
      } else {
        leakedInject = true;
        packets.push({ path: "g-in-1", cls: "coral", label: "⚠ ignore prev…", phase: 0.42, dur: 1160, startT: 0.14, endT: 0.78, rippleNode: "coral" });
      }
    }

    let src2;
    if (st.ciMode === "unsub") {
      unsubOrUnlinked += 1;
      src2 = { state: "detached", badge: "unsub · 0 wire", strand: "detached" };
    } else if (st.ciMode === "burst") {
      burstCapped = 11;
      notifyItems.push("CI ×12");
      src2 = { state: "notify", badge: "burst→notify", strand: "blocked" };
      packets.push({
        path: "g-in-2",
        cls: "blocked",
        label: "CI burst ×12",
        phase: 0.12,
        dur: 1680,
        startT: 0.14,
        endT: 0.74,
        deflect: "amber",
        dropTag: "✕ burst cap → notify",
      });
    } else {
      noisyFlood = true;
      if (st.focus) {
        notifyItems.push("CI ×12");
        src2 = { state: "notify", badge: "notify", strand: "active" };
      } else {
        queuedItems.push("CI ×12");
        src2 = { state: "warn", badge: "flood!", strand: "active" };
      }
      packets.push({ path: "g-in-2", cls: "amber", label: "CI burst ×12", phase: 0.08, dur: 1120, startT: 0.14, endT: 0.78 });
    }

    const deploysEff = st.deploysMode === "mute" ? "mute" : st.focus ? "notify" : st.deploysMode;
    let src3;
    if (deploysEff === "mute") {
      droppedCount += 1;
      src3 = { state: "muted", badge: "muted", strand: "blocked" };
      packets.push({
        path: "g-in-3",
        cls: "coral",
        label: "#deploys noise",
        phase: 0.72,
        dur: 1680,
        startT: 0.14,
        endT: 0.74,
        deflect: "coral",
        dropTag: "✕ muted · 0 tokens",
      });
    } else if (deploysEff === "notify") {
      notifyItems.push("#deploys");
      src3 = { state: "notify", badge: "notify", strand: "active" };
      packets.push({ path: "g-in-3", cls: "amber", label: "#deploys ok", phase: 0.16, dur: 1180, startT: 0.14, endT: 0.78 });
    } else {
      queuedItems.push("#deploys");
      src3 = { state: "pass", badge: "queue", strand: "active" };
      packets.push({ path: "g-in-3", cls: "moss", label: "#deploys ok", phase: 0.16, dur: 1180, startT: 0.14, endT: 0.78 });
    }

    const src4 = { state: "pass", badge: "→ disk", strand: "active" };
    if (st.focus) notifyItems.push("diff.patch");
    else queuedItems.push("P2P diff");
    packets.push({ path: "g-in-4", cls: "moss", label: "🔒 P2P diff.patch", phase: 0.04, dur: 1180, startT: 0.14, endT: 0.78 });
    packets.push({ path: "g-in-5", cls: "moss", label: "Slack · writer", phase: 0.48, dur: 1320, startT: 0.16, endT: 0.76 });

    const hasInterrupt = interruptItems.length > 0;
    const hasQueued = queuedItems.length > 0;
    const hasNotify = notifyItems.length > 0;
    const outActive = hasInterrupt || hasQueued || hasNotify || leakedInject;

    let outTone = "";
    if (hasInterrupt || leakedInject) outTone = "urgent";
    else if (st.focus || (!hasQueued && hasNotify)) outTone = "notify-mode";

    const firstPassIn = packets.find((p) => !p.deflect);
    if (firstPassIn) {
      if (st.focus && hasInterrupt) {
        firstPassIn.mergeTag = `VIP interrupt · ${notifyItems.length} in inbox`;
      } else if (st.focus) {
        firstPassIn.mergeTag = `${notifyItems.length} queued · 1-line digest`;
      } else if (hasInterrupt) {
        firstPassIn.mergeTag = "⚡ interrupt · wake now";
      } else if (queuedItems.length >= 2) {
        firstPassIn.mergeTag = `${queuedItems.length} queued · idle wake`;
      }
    }

    if (hasInterrupt) {
      packets.push({
        path: "g-out",
        cls: "coral",
        label: "⚡ interrupt: DM @alice",
        phase: 0.24,
        dur: 1240,
        startT: 0.25,
        endT: 0.78,
        rippleAgent: true,
      });
    }

    if (st.focus && hasNotify) {
      packets.push({
        path: "g-out",
        cls: leakedInject ? "coral" : "amber",
        label: leakedInject
          ? `⚠ digest (${notifyItems.length} + inject)`
          : `notify: ${notifyItems.length} in inbox (1 line)`,
        phase: hasInterrupt ? 0.64 : 0.38,
        dur: 1900,
        startT: 0.25,
        endT: 0.78,
        rippleAgent: true,
      });
    } else {
      if (hasQueued) {
        const qLabel = queuedItems.slice(0, 3).join(" + ") + (queuedItems.length > 3 ? "…" : "");
        packets.push({
          path: "g-out",
          cls: "",
          label: `queue (idle): ${qLabel}`,
          phase: hasInterrupt ? 0.6 : 0.36,
          dur: 1840,
          startT: 0.25,
          endT: 0.78,
          rippleAgent: true,
        });
      }
      if (hasNotify && !hasInterrupt) {
        packets.push({
          path: "g-out",
          cls: "amber",
          label: `notify: ${notifyItems.length} digest (inbox)`,
          phase: hasQueued ? 0.74 : 0.38,
          dur: 1860,
          startT: 0.25,
          endT: 0.78,
          rippleAgent: !hasQueued,
        });
      }
      if (leakedInject) {
        packets.push({
          path: "g-out",
          cls: "coral",
          label: "⚠ prompt inject leaked!",
          phase: 0.76,
          dur: 1460,
          startT: 0.25,
          endT: 0.78,
          rippleAgent: true,
        });
      }
    }

    const nodeSubText = st.publicLinked
      ? "acme-team + public.hyphae.to"
      : "acme-team · Keychain";

    let rulePillText = `${st.publicLinked ? "2 nodes" : "acme-team"} · ${st.guard ? "Guard ON" : "Guard OFF"} · ${st.ciMode === "burst" ? "Burst cap" : st.ciMode === "unsub" ? "CI unsub" : "CI open"}`;
    let rulePillCls = "";
    if (leakedInject) {
      rulePillText = "⚠ Injection Guard OFF";
      rulePillCls = "coral";
    } else if (st.focus && hasInterrupt) {
      rulePillText = "Focus · VIP interrupt active";
      rulePillCls = "coral";
    } else if (st.focus) {
      rulePillText = "Focus (* → notify) · local inbox";
      rulePillCls = "amber";
    } else if (hasInterrupt) {
      rulePillText = "⚡ interrupt active · wake now";
      rulePillCls = "coral";
    } else if (!st.guard) {
      rulePillCls = "amber";
    }

    // Deterministic simulation counts (no synthetic percentage)
    let deliveredLabel = "Delivery";
    let deliveredText = "quiet · 0 wakes";
    let blockedLabel = "Stopped";
    const stopParts = [];
    if (burstCapped > 0) stopParts.push(`${burstCapped} burst`);
    if (droppedCount > 0) stopParts.push(`${droppedCount} drop`);
    if (unsubOrUnlinked > 0 && stopParts.length < 2) stopParts.push(`${unsubOrUnlinked} off`);
    let blockedText = stopParts.length ? stopParts.join(" · ") : "0 stopped";
    let blockedCls = burstCapped > 0 || droppedCount > 0 ? "amber" : "";

    let savedLabel = "Simulation";
    let savedValue = "11 of 12 held back";
    let barPct = 92;
    let barDanger = false;
    let foot = "Delivers on idle · P2P → disk";

    if (leakedInject) {
      deliveredText = st.focus ? "⚠ digest + inject" : "⚠ unguarded inject";
      blockedLabel = "Guard";
      blockedText = "1 inject leaked!";
      blockedCls = "coral";
      savedLabel = "Simulation";
      savedValue = "1 inject leaked";
      barPct = 24;
      barDanger = true;
      foot = "Enable Guard to screen inbound text";
    } else if (st.focus) {
      deliveredText = hasInterrupt ? "⚡ 1 VIP + 1 digest" : `1-line digest (${notifyItems.length})`;
      blockedLabel = "Held";
      blockedText = `${notifyItems.length} notify · ${burstCapped + droppedCount} stopped`;
      const heldTotal = st.ciMode === "unsub" ? 12 : st.ciMode === "burst" ? 11 : 12;
      savedValue = `${heldTotal} of 12 held back`;
      barPct = Math.round((heldTotal / 12) * 100);
      foot = hasInterrupt
        ? "VIP @alice breaks through Focus"
        : "Held in inbox · 1-line digest";
    } else {
      if (hasInterrupt) {
        deliveredText = `⚡ interrupt + ${queuedItems.length} queue`;
      } else if (hasQueued && hasNotify) {
        deliveredText = `queue (${queuedItems.length}) + digest`;
      } else if (hasQueued) {
        deliveredText = `queue (${queuedItems.length}) on idle`;
      } else if (hasNotify) {
        deliveredText = `notify (${notifyItems.length} digest)`;
      }

      if (st.ciMode === "burst") {
        savedValue = "11 of 12 held back";
        barPct = 92;
      } else if (st.ciMode === "unsub") {
        savedValue = "12 of 12 unsubscribed";
        barPct = 100;
      } else if (noisyFlood) {
        savedValue = "0 of 12 held back";
        barPct = 18;
        barDanger = true;
      }

      foot = hasInterrupt
        ? "Urgent interrupt wakes now"
        : st.publicLinked
        ? "3 topologies · P2P → disk"
        : "Delivers on idle · P2P → disk";
    }

    return {
      sources: [src0, src1, src2, src3, src4],
      strands: {
        "g-in-0": src0.strand,
        "g-in-1": src1.strand,
        "g-in-2": src2.strand,
        "g-in-3": src3.strand,
        "g-in-4": src4.strand,
        "g-in-5": "active",
        "g-out": outActive ? "active" : "dim",
      },
      outTone,
      packets,
      nodeSubText,
      rulePillText,
      rulePillCls,
      deliveredLabel,
      deliveredText,
      blockedLabel,
      blockedText,
      blockedCls,
      savedLabel,
      savedValue,
      barPct,
      barDanger,
      foot,
      leakedInject,
      hasInterrupt,
    };
  }

  function renderGateMobile(sc) {
    if (!mobileHost) return;
    const ciFill = gateState.ciMode === "unsub" ? 34 : gateState.ciMode === "burst" ? 66 : 100;
    const ciStateTxt = gateState.ciMode === "burst" ? "Burst → notify" : gateState.ciMode === "unsub" ? "Unsub · 0 wire" : "Pass all";
    const aliceMap = {
      queue: { cls: "is-on", txt: "Queue · idle" },
      interrupt: { cls: "is-urgent", txt: "Interrupt" },
      notify: { cls: "is-amber", txt: "Notify" },
      mute: { cls: "", txt: "Muted" },
    };
    const aCur = aliceMap[gateState.aliceMode] || aliceMap.queue;
    const depMap = {
      mute: { cls: "", txt: "Muted" },
      notify: { cls: "is-amber", txt: "Notify" },
      queue: { cls: "is-on", txt: "Queue · idle" },
    };
    const dCur = depMap[gateState.deploysMode] || depMap.mute;

    const renderMobRow = (idx) => {
      const src = GATE_SOURCES[idx];
      const st = sc.sources[idx];
      const subTxt = st.sub || src.sub;
      return `
        <div class="gm-mob-row ${src.cls} state-${st.state}">
          <div class="gm-mob-left">
            <span class="gs-dot"></span>
            <div>
              <strong>${esc(src.name)}</strong>
              <small>${esc(subTxt)}</small>
            </div>
          </div>
          <span class="gs-badge">${esc(st.badge)}</span>
        </div>
      `;
    };

    const relState = gateState.publicLinked ? "notify" : "detached";
    const relBadge = gateState.publicLinked ? "notify" : "unlinked";

    mobileHost.innerHTML = `
      <div class="gm-mob-list">
        <div class="gm-mob-group team">
          <div class="gg-head">
            <span class="gg-thumb"><img src="./assets/team-node-hub.jpg?v=1" alt="" /></span>
            <strong class="gg-title">Team Node · acme-team</strong>
            <span class="gg-status paired"><i></i>paired</span>
          </div>
          ${renderMobRow(0)}
          ${renderMobRow(2)}
          ${renderMobRow(3)}
        </div>

        <div class="gm-mob-group public ${gateState.publicLinked ? "" : "is-unlinked"}" data-toggle="publicLinked" role="button" tabindex="0">
          <div class="gg-head">
            <span class="gg-dot amber" aria-hidden="true"></span>
            <strong class="gg-title">Public · public.hyphae.to</strong>
            <span class="gg-status ${gateState.publicLinked ? "linked" : ""}">${gateState.publicLinked ? "linked" : "unlinked"}</span>
          </div>
          ${renderMobRow(1)}
          <div class="gm-mob-row amber-soft state-${relState}">
            <div class="gm-mob-left">
              <span class="gs-dot"></span>
              <div>
                <strong>#hyp-releases</strong>
                <small>read-only feed</small>
              </div>
            </div>
            <span class="gs-badge">${relBadge}</span>
          </div>
        </div>

        <div class="gm-mob-group private">
          <div class="gg-head">
            <span class="gg-dot moss" aria-hidden="true"></span>
            <strong class="gg-title">Private · Keychain &amp; P2P</strong>
            <span class="gg-status moss">local</span>
          </div>
          <div class="gm-mob-row moss state-pass">
            <div class="gm-mob-left">
              <span class="gs-bridge-icos" aria-hidden="true">
                <span><img src="./assets/icons/slack.svg" alt="" /></span>
                <span><img src="./assets/icons/telegram.svg" alt="" /></span>
              </span>
              <div>
                <strong>Slack · Telegram</strong>
                <small>all read · 1 writer + handoff</small>
              </div>
            </div>
            <span class="gs-badge">bridge</span>
          </div>
          ${renderMobRow(4)}
        </div>
      </div>
      <div class="gm-mob-stem" aria-hidden="true">
        <svg viewBox="0 0 64 22" fill="none">
          <path stroke="rgba(183,217,86,0.65)" stroke-width="1.8" d="M 32 0 C 30 8, 34 14, 32 22" />
          <path stroke="rgba(232,163,49,0.45)" stroke-width="1.2" d="M 22 0 C 24 8, 28 14, 30 22" />
          <path stroke="rgba(127,201,123,0.45)" stroke-width="1.2" d="M 42 0 C 40 8, 36 14, 34 22" />
        </svg>
      </div>
      <div class="gm-mob-node" style="flex-direction:column; align-items:stretch;">
        <div style="display:flex; align-items:center; gap:11px;">
          <img class="gate-local-node-img" src="./assets/node-hub.webp?v=1" alt="Local Hyphae Node" />
          <div class="gm-mob-node-body">
            <strong>Your Local Node</strong>
            <span>${esc(sc.rulePillText)}</span>
            <small>${esc(sc.nodeSubText)}</small>
          </div>
        </div>
        <div class="gm-mob-cc">
          <div class="cc-grid">
            <button class="cc-tile ${gateState.publicLinked ? "is-amber" : ""}" data-toggle="publicLinked" type="button">
              <span class="cc-medallion" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14.5 14.5 0 0 1 0 18M12 3a14.5 14.5 0 0 0 0 18"/></svg></span>
              <span class="cc-copy"><strong>Public Node</strong><small>${gateState.publicLinked ? "Linked" : "Unlinked"}</small></span>
            </button>
            <button class="cc-tile ${gateState.guard ? "is-on" : "is-danger"}" data-toggle="guard" type="button">
              <span class="cc-medallion" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.8-3 8.8-7 10-4-1.2-7-5.2-7-10V6l7-3z"/><path d="m9.5 12 1.8 1.8 3.6-3.8"/></svg></span>
              <span class="cc-copy"><strong>Guard</strong><small>${gateState.guard ? "Active" : "Off"}</small></span>
            </button>
            <button class="cc-tile ${aCur.cls}" data-toggle="aliceMode" type="button">
              <span class="cc-medallion" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg></span>
              <span class="cc-copy"><strong>DM @alice</strong><small>${aCur.txt}</small></span>
            </button>
            <button class="cc-tile ${dCur.cls}" data-toggle="deploysMode" type="button">
              <span class="cc-medallion" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"/></svg></span>
              <span class="cc-copy"><strong>#deploys</strong><small>${dCur.txt}</small></span>
            </button>
          </div>
          <div class="cc-slider-card" data-ci-state="${gateState.ciMode}">
            <div class="cc-slider-head">
              <strong>CI Burst Cap</strong>
              <span>${ciStateTxt}</span>
            </div>
            <div class="cc-slider-track">
              <div class="cc-slider-fill" style="width:${ciFill}%;"></div>
              <button class="cc-step ${gateState.ciMode === "unsub" ? "active" : "covered"}" data-ci="unsub" type="button">Unsub</button>
              <button class="cc-step ${gateState.ciMode === "burst" ? "active" : gateState.ciMode === "all" ? "covered" : ""}" data-ci="burst" type="button">Burst→notify</button>
              <button class="cc-step ${gateState.ciMode === "all" ? "active" : ""}" data-ci="all" type="button">Pass all</button>
            </div>
          </div>
          <button class="cc-reset-pill gm-mob-reset" data-reset-gate="1" type="button">Reset Controls</button>
        </div>
      </div>
      <div class="gm-mob-stem" aria-hidden="true">
        <svg viewBox="0 0 64 22" fill="none">
          <path stroke="${sc.hasInterrupt ? "rgba(255,122,92,0.9)" : "rgba(183,217,86,0.85)"}" stroke-width="2.4" d="M 32 0 C 33 8, 31 14, 32 22" />
        </svg>
      </div>
      <div class="gm-mob-agent">
        <div class="gm-mob-agent-head">
          <img src="./assets/sprite-alex.jpg?v=2" alt="Your agent harness" />
          <div>
            <strong>Your Agent · Claude / Codex / Antigravity</strong>
            <small>${esc(sc.foot)}</small>
          </div>
        </div>
        <button class="cc-tile cc-focus-tile ${gateState.focus ? "is-on" : ""}" data-toggle="focus" type="button">
          <span class="cc-medallion" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.354 15.354A9 9 0 0 1 8.646 3.646 9.003 9.003 0 0 0 12 21a9.003 9.003 0 0 0 8.354-5.646z"/></svg></span>
          <span class="cc-copy"><strong>Focus</strong><small>${gateState.focus ? "All → notify" : "Off · normal delivery"}</small></span>
        </button>
        <div class="gm-row"><span>${esc(sc.deliveredLabel)}</span><strong class="${sc.leakedInject || sc.hasInterrupt ? "coral" : ""}">${esc(sc.deliveredText)}</strong></div>
        <div class="gm-row"><span>${esc(sc.blockedLabel)}</span><strong class="${esc(sc.blockedCls)}">${esc(sc.blockedText)}</strong></div>
        <div class="gm-bar-wrap">
          <div class="gm-bar-head"><span>${esc(sc.savedLabel)}</span><strong>${esc(sc.savedValue)}</strong></div>
          <div class="gm-bar"><span class="${sc.barDanger ? "danger" : ""}" style="width:${sc.barPct}%"></span></div>
        </div>
      </div>
    `;
  }

  let pausedElapsed = 0;
  let cycleStart = performance.now();
  let lastRenderFrame = null;

  function startGatePackets(sc) {
    if (gateRaf) cancelAnimationFrame(gateRaf);
    gateRaf = null;
    if (!packetsHost) return;
    packetsHost.innerHTML = "";
    shieldArc?.classList.remove("hit-amber", "hit-coral");

    const items = sc.packets.map((spec) => {
      const path = document.getElementById(spec.path);
      if (!path) return null;
      const el = document.createElement("div");
      el.className = `gate-pkt ${spec.cls || ""}`.trim();
      el.innerHTML = `<span class="gp-dot"></span><span class="gp-label">${esc(spec.label)}</span>`;
      packetsHost.appendChild(el);
      return { ...spec, el, path, len: path.getTotalLength(), lastCycle: -1 };
    }).filter(Boolean);

    const dropTagEl = document.createElement("div");
    dropTagEl.className = "gate-drop-tag";
    dropTagEl.style.opacity = "0";
    packetsHost.appendChild(dropTagEl);

    const mergeTagEl = document.createElement("div");
    mergeTagEl.className = "gate-merge-tag";
    mergeTagEl.style.opacity = "0";
    packetsHost.appendChild(mergeTagEl);

    const CYCLE_MS = 3400;
    cycleStart = performance.now() - pausedElapsed;
    const agentRipple = document.getElementById("gateAgentRipple");
    const nodeRipple = document.getElementById("gateNodeRipple");

    function renderFrame(elapsed) {
      let shieldHitKind = "";
      let bestDrop = null;
      let bestMerge = null;

      for (const item of items) {
        const rawPos = (elapsed / CYCLE_MS) - item.phase;
        const cyclePos = ((rawPos % 1) + 1) % 1;
        const cycleNum = Math.floor(rawPos);
        const span = Math.min(0.84, item.dur / CYCLE_MS);
        const raw = cyclePos / span;

        if (item.dropTag) {
          const hitAt = 0.62;
          const tagWindow = 0.24;
          const post = (cyclePos - span * hitAt + 1) % 1;
          if (post >= 0 && post < tagWindow && (!bestDrop || post < bestDrop.post)) {
            bestDrop = { item, post, tagWindow };
          }
        }
        if (item.mergeTag) {
          const hitAt = 0.88;
          const tagWindow = 0.4;
          const post = (cyclePos - span * hitAt + 1) % 1;
          if (post >= 0 && post < tagWindow && (!bestMerge || post < bestMerge.post)) {
            bestMerge = { item, post, tagWindow };
          }
        }

        if (raw > 1) {
          item.el.style.opacity = "0";
          item.el.classList.remove("hit-drop");
          continue;
        }

        const startT = item.startT ?? 0.14;
        const endT = item.endT ?? 0.84;

        if (item.deflect) {
          const hitFrac = 0.62;
          if (raw < hitFrac) {
            const moveFrac = raw / hitFrac;
            const travel = startT + easeInOutQuad(moveFrac) * (endT - startT);
            const pt = item.path.getPointAtLength(item.len * travel);
            const op = moveFrac < 0.12 ? moveFrac / 0.12 : 1;
            item.el.classList.remove("hit-drop");
            item.el.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
            item.el.style.top = `${(pt.y / LOGICAL_H) * 100}%`;
            item.el.style.opacity = op.toFixed(2);
            item.el.style.transform = "translate(-50%, -50%) scale(1)";
          } else {
            const dropFrac = (raw - hitFrac) / (1 - hitFrac);
            const pt = item.path.getPointAtLength(item.len * endT);
            const shakeX = Math.sin(dropFrac * Math.PI * 3) * (1 - dropFrac) * 4;
            const bounceX = -10 * dropFrac + shakeX;
            const dropY = 18 * dropFrac * dropFrac + 6 * dropFrac;
            const tilt = -6 * dropFrac;
            const op = dropFrac > 0.62 ? Math.max(0, 1 - (dropFrac - 0.62) / 0.38) : 1;

            item.el.classList.add("hit-drop");
            item.el.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
            item.el.style.top = `${(pt.y / LOGICAL_H) * 100}%`;
            item.el.style.opacity = op.toFixed(2);
            item.el.style.transform = `translate(-50%, -50%) translate(${bounceX.toFixed(1)}px, ${dropY.toFixed(1)}px) rotate(${tilt.toFixed(1)}deg) scale(${(1 - 0.08 * dropFrac).toFixed(3)})`;

            if (dropFrac < 0.55) shieldHitKind = item.deflect;

            if (item.lastCycle !== cycleNum && fixedPhase === null && gatePlaying) {
              item.lastCycle = cycleNum;
              flashShield(item.deflect);
              const burst = document.createElement("div");
              burst.className = `gate-deflect-burst ${item.deflect}`;
              burst.style.left = `${(pt.x / LOGICAL_W) * 100}%`;
              burst.style.top = `${(pt.y / LOGICAL_H) * 100}%`;
              packetsHost.appendChild(burst);
              setTimeout(() => burst.remove(), 540);
            }
          }
          continue;
        }

        const travel = startT + easeInOutQuad(raw) * (endT - startT);
        const pt = item.path.getPointAtLength(item.len * travel);
        item.el.classList.remove("hit-drop");
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

        if (raw >= 0.86 && item.lastCycle !== cycleNum && fixedPhase === null && gatePlaying) {
          item.lastCycle = cycleNum;
          if (item.rippleAgent) fireRipple(agentRipple);
          if (item.rippleNode) fireRipple(nodeRipple, item.rippleNode === "green" ? "" : item.rippleNode);
        }

        item.el.style.opacity = opacity.toFixed(2);
        item.el.style.transform = `translate(-50%, -50%) scale(${scale.toFixed(3)})`;
      }

      if (bestDrop) {
        const { item, post, tagWindow } = bestDrop;
        const pNorm = post / tagWindow;
        const anchorPt = item.path.getPointAtLength(item.len * (item.endT ?? 0.72));
        const tx = Math.min(458, Math.max(396, anchorPt.x - 42));
        const ty = Math.min(176, anchorPt.y + 30 + pNorm * 5);
        const tOp = pNorm < 0.14 ? pNorm / 0.14 : pNorm > 0.72 ? (1 - pNorm) / 0.28 : 1;
        dropTagEl.className = `gate-drop-tag ${item.deflect === "amber" ? "amber" : ""}`.trim();
        dropTagEl.textContent = item.dropTag;
        dropTagEl.style.left = `${(tx / LOGICAL_W) * 100}%`;
        dropTagEl.style.top = `${(ty / LOGICAL_H) * 100}%`;
        dropTagEl.style.opacity = Math.max(0, Math.min(1, tOp)).toFixed(2);
      } else {
        dropTagEl.style.opacity = "0";
      }

      if (bestMerge) {
        const { item, post, tagWindow } = bestMerge;
        const pNorm = post / tagWindow;
        const ty = 44 - pNorm * 4;
        const tOp = pNorm < 0.14 ? pNorm / 0.14 : pNorm > 0.74 ? (1 - pNorm) / 0.26 : 1;
        mergeTagEl.textContent = item.mergeTag;
        mergeTagEl.style.left = `${(576 / LOGICAL_W) * 100}%`;
        mergeTagEl.style.top = `${(ty / LOGICAL_H) * 100}%`;
        mergeTagEl.style.opacity = Math.max(0, Math.min(1, tOp)).toFixed(2);
      } else {
        mergeTagEl.style.opacity = "0";
      }

      if (fixedPhase !== null && shieldArc) {
        shieldArc.classList.toggle("hit-amber", shieldHitKind === "amber");
        shieldArc.classList.toggle("hit-coral", shieldHitKind === "coral");
      }
    }

    lastRenderFrame = renderFrame;
    if (fixedPhase !== null || !gatePlaying) {
      renderFrame(fixedPhase !== null ? fixedPhase * CYCLE_MS : pausedElapsed || 0.48 * CYCLE_MS);
      return;
    }

    renderFrame(pausedElapsed);
    if (!simInView) return;

    function tick(now) {
      if (!simInView) {
        gateRaf = null;
        return;
      }
      pausedElapsed = now - cycleStart;
      renderFrame(pausedElapsed);
      gateRaf = requestAnimationFrame(tick);
    }
    gateRaf = requestAnimationFrame(tick);
  }

  function renderControlCenter() {
    const sc = buildScenario(gateState);

    const nodeSubEl = document.getElementById("gateNodeSub");
    if (nodeSubEl) nodeSubEl.textContent = sc.nodeSubText;

    const valveEl = document.getElementById("gateValveRing");
    if (valveEl) {
      const modeCls = sc.leakedInject || sc.hasInterrupt ? "mode-guard" : gateState.focus ? "mode-digest" : "mode-coalesce";
      valveEl.className = `gate-valve-ring ${modeCls}`.trim();
    }

    const pubBtn = document.getElementById("ctlPublicLink");
    const pubState = document.getElementById("ctlPublicState");
    if (pubBtn) {
      pubBtn.className = `cc-tile ${gateState.publicLinked ? "is-amber" : ""}`.trim();
      pubBtn.setAttribute("aria-pressed", gateState.publicLinked ? "true" : "false");
    }
    if (pubState) pubState.textContent = gateState.publicLinked ? "Linked · OSS" : "Unlinked";

    const guardBtn = document.getElementById("ctlGuard");
    const guardState = document.getElementById("ctlGuardState");
    if (guardBtn) {
      guardBtn.className = `cc-tile ${gateState.guard ? "is-on" : "is-danger"}`.trim();
      guardBtn.setAttribute("aria-pressed", gateState.guard ? "true" : "false");
    }
    if (guardState) guardState.textContent = gateState.guard ? "Active" : "Off";

    const aliceBtn = document.getElementById("ctlAliceMode");
    const aliceState = document.getElementById("ctlAliceState");
    if (aliceBtn) {
      const aMap = {
        queue: { cls: "is-on", txt: "Queue · idle" },
        interrupt: { cls: "is-urgent", txt: "Interrupt" },
        notify: { cls: "is-amber", txt: "Notify" },
        mute: { cls: "", txt: "Muted" },
      };
      const cur = aMap[gateState.aliceMode] || aMap.queue;
      aliceBtn.className = `cc-tile ${cur.cls}`.trim();
      if (aliceState) aliceState.textContent = cur.txt;
    }

    const depBtn = document.getElementById("ctlDeploysMode");
    const depState = document.getElementById("ctlDeploysState");
    if (depBtn) {
      const dMap = {
        mute: { cls: "", txt: "Muted" },
        notify: { cls: "is-amber", txt: "Notify" },
        queue: { cls: "is-on", txt: "Queue · idle" },
      };
      const cur = dMap[gateState.deploysMode] || dMap.mute;
      depBtn.className = `cc-tile ${cur.cls}`.trim();
      if (depState) depState.textContent = cur.txt;
    }

    const ciCard = document.getElementById("ctlCiCard");
    const ciState = document.getElementById("ctlCiState");
    const ciFill = document.getElementById("ctlCiFill");
    if (ciCard) {
      ciCard.dataset.ciState = gateState.ciMode;
      const fillPct = gateState.ciMode === "unsub" ? 34 : gateState.ciMode === "burst" ? 66 : 100;
      const ciTxt = gateState.ciMode === "burst" ? "Burst → notify" : gateState.ciMode === "unsub" ? "Unsub · 0 wire" : "Pass all";
      if (ciState) ciState.textContent = ciTxt;
      if (ciFill) ciFill.style.width = `${fillPct}%`;
      ciCard.querySelectorAll(".cc-step").forEach((btn) => {
        const v = btn.dataset.ci;
        const isActive = v === gateState.ciMode;
        const isCovered =
          (gateState.ciMode === "burst" && v === "unsub") ||
          (gateState.ciMode === "all" && (v === "unsub" || v === "burst"));
        btn.classList.toggle("active", isActive);
        btn.classList.toggle("covered", !isActive && isCovered);
        btn.setAttribute("aria-pressed", isActive ? "true" : "false");
      });
    }

    const focusBtn = document.getElementById("gateFocusBtn");
    const focusState = document.getElementById("gateFocusState");
    if (focusBtn) {
      focusBtn.className = `cc-tile cc-focus-tile ${gateState.focus ? "is-on" : ""}`.trim();
      focusBtn.setAttribute("aria-pressed", gateState.focus ? "true" : "false");
    }
    if (focusState) focusState.textContent = gateState.focus ? "All → notify" : "Off · normal delivery";

    const gmDelLbl = document.getElementById("gmDeliveredLabel");
    const gmDel = document.getElementById("gmDelivered");
    const gmBlkLbl = document.getElementById("gmBlockedLabel");
    const gmBlk = document.getElementById("gmBlocked");
    const gmSavLbl = document.getElementById("gmSavedLabel");
    const gmSav = document.getElementById("gmSaved");
    const gmBar = document.getElementById("gmBarFill");
    const gmFt = document.getElementById("gmFoot");
    if (gmDelLbl) gmDelLbl.textContent = sc.deliveredLabel;
    if (gmDel) {
      gmDel.textContent = sc.deliveredText;
      gmDel.className = sc.leakedInject || sc.hasInterrupt ? "coral" : "";
    }
    if (gmBlkLbl) gmBlkLbl.textContent = sc.blockedLabel;
    if (gmBlk) {
      gmBlk.textContent = sc.blockedText;
      gmBlk.className = sc.blockedCls || "";
    }
    if (gmSavLbl) gmSavLbl.textContent = sc.savedLabel;
    if (gmSav) gmSav.textContent = sc.savedValue;
    if (gmBar) {
      gmBar.style.width = `${sc.barPct}%`;
      gmBar.classList.toggle("danger", sc.barDanger);
    }
    if (gmFt) gmFt.textContent = sc.foot;

    document.querySelectorAll("#gateSources .gate-src[data-src]").forEach((el) => {
      const idx = Number(el.dataset.src);
      const st = sc.sources[idx];
      if (!st) return;
      el.classList.remove("state-pass", "state-blocked", "state-muted", "state-batched", "state-detached", "state-idle", "state-warn", "state-urgent", "state-notify");
      el.classList.add(`state-${st.state}`);
      const badge = document.getElementById(`gsBadge${idx}`);
      if (badge) badge.textContent = st.badge;
      if (idx === 1) {
        const subEl = document.getElementById("gsSub1");
        if (subEl && st.sub) subEl.textContent = st.sub;
      }
    });

    const pubGroup = document.getElementById("gatePublicGroup");
    const pubGroupStatus = document.getElementById("ggPubStatus");
    const relRow = document.getElementById("gateRelRow");
    const relBadge = document.getElementById("gsBadgeRel");
    if (pubGroup) pubGroup.classList.toggle("is-unlinked", !gateState.publicLinked);
    if (pubGroupStatus) {
      pubGroupStatus.textContent = gateState.publicLinked ? "linked" : "unlinked";
      pubGroupStatus.className = `gg-status ${gateState.publicLinked ? "linked" : ""}`.trim();
    }
    if (relRow) {
      relRow.classList.remove("state-notify", "state-detached");
      relRow.classList.add(gateState.publicLinked ? "state-notify" : "state-detached");
    }
    if (relBadge) relBadge.textContent = gateState.publicLinked ? "notify" : "unlinked";

    Object.entries(sc.strands).forEach(([id, state]) => {
      const p = document.getElementById(id);
      if (p) {
        p.classList.toggle("dim", state === "dim");
        p.classList.toggle("blocked", state === "blocked");
        p.classList.toggle("detached", state === "detached");
        if (id === "g-out") {
          p.classList.toggle("urgent", sc.outTone === "urgent");
          p.classList.toggle("notify-mode", sc.outTone === "notify-mode");
        }
        if (state === "detached") {
          const l = p.getTotalLength();
          p.style.strokeDasharray = `${(l * 0.44).toFixed(1)} ${l.toFixed(1)}`;
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

    renderGateMobile(sc);
    startGatePackets(sc);
  }

  function handleToggle(key) {
    if (key === "ciMode") {
      const order = ["burst", "unsub", "all"];
      gateState.ciMode = order[(order.indexOf(gateState.ciMode) + 1) % order.length];
      lastCmd =
        gateState.ciMode === "burst"
          ? 'hyp_stream({ topic: "ci", burstCap: "notify" })'
          : gateState.ciMode === "unsub"
          ? 'hyp_stream({ action: "unsubscribe", key: "ci" })'
          : 'hyp_stream({ topic: "ci", burstCap: "off" })';
      renderControlCenter();
      return;
    }
    if (key === "aliceMode") {
      const order = ["queue", "interrupt", "notify", "mute"];
      gateState.aliceMode = order[(order.indexOf(gateState.aliceMode) + 1) % order.length];
      lastCmd =
        gateState.aliceMode === "mute"
          ? 'hyp_inbox({ mute: "@alice" })'
          : `hyp_inbox({ from: "@alice", mode: "${gateState.aliceMode}" })`;
      renderControlCenter();
      return;
    }
    if (key === "deploysMode") {
      const order = ["mute", "notify", "queue"];
      gateState.deploysMode = order[(order.indexOf(gateState.deploysMode) + 1) % order.length];
      lastCmd =
        gateState.deploysMode === "mute"
          ? 'hyp_inbox({ mute: "#deploys" })'
          : `hyp_inbox({ from: "#deploys", mode: "${gateState.deploysMode}" })`;
      renderControlCenter();
      return;
    }
    if (!(key in gateState)) return;
    gateState[key] = !gateState[key];
    switch (key) {
      case "publicLinked":
        lastCmd = gateState.publicLinked
          ? "hyp pair join https://public.hyphae.to"
          : "hyp pair revoke public.hyphae.to";
        break;
      case "guard":
        lastCmd = gateState.guard
          ? "hyp gate init --adapter anthropic|openai|plugin"
          : "hyp gate disable injection-guard";
        break;
      case "focus":
        lastCmd = gateState.focus
          ? 'hyp_inbox({ mode: "notify", filter: {...}, cursor })'
          : 'hyp_inbox({ mode: "queue" })';
        break;
    }
    renderControlCenter();
  }

  function resumeGateLoop() {
    if (!gatePlaying || fixedPhase !== null || gateRaf || !lastRenderFrame || !simInView) return;
    cycleStart = performance.now() - pausedElapsed;
    function tick(now) {
      if (!simInView) {
        gateRaf = null;
        return;
      }
      pausedElapsed = now - cycleStart;
      lastRenderFrame(pausedElapsed);
      gateRaf = requestAnimationFrame(tick);
    }
    gateRaf = requestAnimationFrame(tick);
  }

  shell.addEventListener("click", (e) => {
    const ciStep = e.target.closest("[data-ci]");
    if (ciStep) {
      const val = ciStep.dataset.ci;
      if (["unsub", "burst", "all"].includes(val)) {
        gateState.ciMode = val;
        lastCmd =
          val === "burst"
            ? 'hyp_stream({ topic: "ci", burstCap: "notify" })'
            : val === "unsub"
            ? 'hyp_stream({ action: "unsubscribe", key: "ci" })'
            : 'hyp_stream({ topic: "ci", burstCap: "off" })';
        renderControlCenter();
      }
      return;
    }
    const resetEl = e.target.closest("[data-reset-gate]");
    if (resetEl) {
      gateState = { ...DEFAULT_STATE };
      lastCmd = 'hyp_inbox({ mode: "queue", burst: "notify" })';
      renderControlCenter();
      return;
    }
    const btn = e.target.closest("[data-toggle]");
    if (!btn) return;
    handleToggle(btn.dataset.toggle);
  });

  shell.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const roleBtn = e.target.closest('[data-toggle][role="button"]');
    if (!roleBtn) return;
    e.preventDefault();
    handleToggle(roleBtn.dataset.toggle);
  });

  document.getElementById("gateResetBtn")?.addEventListener("click", () => {
    gateState = { ...DEFAULT_STATE };
    lastCmd = 'hyp_inbox({ mode: "queue", burst: "notify" })';
    renderControlCenter();
  });

  if (typeof IntersectionObserver !== "undefined") {
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.some((entry) => entry.isIntersecting);
        simInView = visible;
        if (visible) {
          fitGateStage();
          resumeGateLoop();
        } else if (gateRaf) {
          cancelAnimationFrame(gateRaf);
          gateRaf = null;
        }
      },
      { rootMargin: "160px 0px" }
    );
    io.observe(shell);
  }

  ensureGateBundles();
  fitGateStage();
  renderControlCenter();
})();

// ============================================================================
// 4. TOPOLOGY CARD COPY BUTTONS (#topologies)
// ============================================================================
const TOPO_SNIPPETS = {
  p2p: "hyp onboard",
  team: "hyp deploy init tailscale",
  public: "hyp pair join https://public.hyphae.to",
};

document.querySelectorAll("[data-copy-topo]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const text = TOPO_SNIPPETS[btn.dataset.copyTopo];
    if (!text) return;
    navigator.clipboard?.writeText(text).catch(() => {});
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = "Copy"; }, 1300);
  });
});

// ============================================================================
// 4B. COMPARISON TABLE ACCESSIBLE (i) INFO POPOVERS (#why)
// ============================================================================
(() => {
  const pop = document.getElementById("cmpPopover");
  const popTitle = document.getElementById("cmpPopTitle");
  const popBody = document.getElementById("cmpPopBody");
  if (!pop || !popTitle || !popBody) return;

  let activeBtn = null;
  let pinnedBtn = null;
  let hideTimer = null;

  function positionPopover(btn) {
    const r = btn.getBoundingClientRect();
    const pw = pop.offsetWidth || 292;
    const ph = pop.offsetHeight || 96;
    const margin = 12;

    let leftVp = r.left + r.width / 2 - pw / 2;
    leftVp = Math.max(margin, Math.min(window.innerWidth - pw - margin, leftVp));

    const placeBelow = r.top < ph + 24;
    const topDoc = placeBelow
      ? r.bottom + window.scrollY + 10
      : r.top + window.scrollY - ph - 10;
    const leftDoc = leftVp + window.scrollX;
    const arrowX = Math.max(18, Math.min(pw - 18, r.left + r.width / 2 - leftVp));

    pop.style.left = `${Math.round(leftDoc)}px`;
    pop.style.top = `${Math.round(topDoc)}px`;
    pop.style.setProperty("--pop-arrow-x", `${Math.round(arrowX)}px`);
    pop.classList.toggle("below", placeBelow);
  }

  function showPopover(btn, pin = false) {
    clearTimeout(hideTimer);
    if (activeBtn && activeBtn !== btn) {
      activeBtn.setAttribute("aria-expanded", "false");
      activeBtn.classList.remove("is-open");
    }
    activeBtn = btn;
    if (pin) pinnedBtn = btn;
    popTitle.textContent = btn.dataset.infoTitle || "";
    popBody.textContent = btn.dataset.infoBody || "";
    pop.hidden = false;
    pop.classList.add("show");
    btn.setAttribute("aria-expanded", "true");
    btn.classList.add("is-open");
    positionPopover(btn);
  }

  function hidePopover(force = false) {
    if (!force && pinnedBtn) return;
    clearTimeout(hideTimer);
    if (activeBtn) {
      activeBtn.setAttribute("aria-expanded", "false");
      activeBtn.classList.remove("is-open");
    }
    activeBtn = null;
    pinnedBtn = null;
    pop.classList.remove("show");
    pop.hidden = true;
  }

  document.querySelectorAll(".cmp-info-btn").forEach((btn) => {
    btn.setAttribute("aria-expanded", "false");
    btn.addEventListener("mouseenter", () => {
      if (!pinnedBtn || pinnedBtn === btn) showPopover(btn, false);
    });
    btn.addEventListener("mouseleave", () => {
      if (pinnedBtn === btn) return;
      hideTimer = setTimeout(() => hidePopover(false), 110);
    });
    btn.addEventListener("focus", () => showPopover(btn, false));
    btn.addEventListener("blur", () => {
      if (pinnedBtn === btn) return;
      hideTimer = setTimeout(() => hidePopover(false), 80);
    });
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (pinnedBtn === btn) hidePopover(true);
      else showPopover(btn, true);
    });
  });

  pop.addEventListener("mouseenter", () => clearTimeout(hideTimer));
  pop.addEventListener("mouseleave", () => {
    if (!pinnedBtn) hideTimer = setTimeout(() => hidePopover(false), 110);
  });

  document.addEventListener("click", (e) => {
    if (!activeBtn) return;
    if (e.target.closest(".cmp-info-btn") || e.target.closest("#cmpPopover")) return;
    hidePopover(true);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && activeBtn) hidePopover(true);
  });
  window.addEventListener("resize", () => { if (activeBtn) positionPopover(activeBtn); });
  document.querySelector(".compare-scroll")?.addEventListener("scroll", () => {
    if (activeBtn) positionPopover(activeBtn);
  }, { passive: true });
})();

// ============================================================================
// 5. INSTALL TABS (OS-only: macOS / Linux and Windows)
// ============================================================================
const QS = {
  unix: {
    code: `# Checksum-verified install — launches hyp onboard automatically
curl -fsSL https://hyphae.to/install.sh | sh`,
    copy: "curl -fsSL https://hyphae.to/install.sh | sh",
    note: "macOS & Linux: native daemon, OS Keychain / Secret Service, and optional chat bridges. Pass --no-onboard to skip the interactive wizard.",
  },
  win: {
    code: `# Checksum-verified PowerShell install — launches hyp onboard automatically
irm https://hyphae.to/install.ps1 | iex`,
    copy: "irm https://hyphae.to/install.ps1 | iex",
    note: "Windows: native MCP, hooks, schtasks service, uninstall.ps1, and optional chat bridges over authenticated loopback TCP.",
  },
};

function formatQsHtml(raw) {
  return raw
    .split("\n")
    .map((line) => {
      if (line.trimStart().startsWith("#")) {
        return `<span class="qs-comment">${esc(line)}</span>`;
      }
      const inlineIdx = line.indexOf("  # ");
      if (inlineIdx !== -1) {
        return `${esc(line.slice(0, inlineIdx))}<span class="qs-comment">${esc(line.slice(inlineIdx))}</span>`;
      }
      return esc(line);
    })
    .join("\n");
}

let activeQs = "unix";
function renderQs() {
  const item = QS[activeQs] || QS.unix;
  const pre = document.getElementById("qsPre");
  const note = document.getElementById("qsOsNote");
  if (pre) pre.innerHTML = formatQsHtml(item.code);
  if (note) note.textContent = item.note;
  document.querySelectorAll("#qsTabs .it-btn").forEach((b) => {
    const active = b.dataset.qs === activeQs;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
  });
}
document.querySelectorAll("#qsTabs .it-btn").forEach((b) => {
  b.addEventListener("click", () => {
    activeQs = b.dataset.qs;
    renderQs();
  });
});
document.getElementById("qsCopyBtn")?.addEventListener("click", (e) => {
  const item = QS[activeQs] || QS.unix;
  navigator.clipboard?.writeText(item.copy).catch(() => {});
  const btn = e.currentTarget;
  btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = "Copy"; }, 1300);
});
renderQs();
