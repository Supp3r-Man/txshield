"use strict";

const $ = (s) => document.querySelector(s);
let CSRF = "";

// Builds DOM with textContent only, so nothing from a pasted transaction is ever parsed as HTML.
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) n.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return n;
}

async function api(path, method = "GET", body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-CSRF-Token"] = CSRF;
  }
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && document.body.dataset.page !== "login") {
    location.href = "/login.html";
    throw new Error("Signed out.");
  }
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "That input was rejected.");
  return data;
}

const usd = (n) => (n < 0 ? "-$" : "$") + Math.abs(n).toLocaleString(undefined, { maximumFractionDigits: 0 });
const VERDICT = {
  green: { cls: "ok", icon: "✔", title: "Looks OK", sub: "Nothing on your policy tripped. That is not a guarantee." },
  amber: { cls: "warn", icon: "▲", title: "Slow down", sub: "Something here deserves a second look before you sign." },
  red: { cls: "block", icon: "✖", title: "Don't sign this", sub: "Your policy says no." },
};
const CHIP = { green: "allow", amber: "warn", red: "block" };

function table(heads, rows) {
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, heads.map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c)))))));
}

function renderResult(res) {
  const v = VERDICT[res.verdict];
  const d = res.diff;
  const out = [
    el("div", { class: `verdict ${v.cls}`, role: "status" },
      el("span", { class: "icon", "aria-hidden": "true" }, v.icon),
      el("div", {}, el("strong", {}, v.title),
        el("div", { class: "sub" }, res.escalated ? "Several warnings piled up, so your policy escalated this to a block." : v.sub))),
    el("h3", {}, "What this does"),
    el("ul", { class: "lines" }, res.summary.map((s) => el("li", {}, s))),
    el("h3", {}, "What changes in your wallet"),
    el("p", {}, d.headline),
  ];
  if (d.balances.length) {
    out.push(table(["Asset", "Before", "After", "Change", "About (USD)"],
      d.balances.map((b) => [b.symbol, b.before, b.after, b.change, usd(b.usd)])));
  }
  if (d.approvals.length) {
    out.push(table(["Permission", "Who", "Before", "After", "At risk now"],
      d.approvals.map((a) => [a.label, a.who, a.before, a.after, usd(a.exposure_usd)])));
  }
  d.notes.forEach((n) => out.push(el("p", { class: "note" }, n)));
  out.push(el("h3", {}, "Why"));
  out.push(res.reasons.length
    ? el("ul", { class: "reasons" }, res.reasons.map((r) => el("li", {},
      el("span", { class: `chip ${r.action}` }, r.action.toUpperCase()), " ", el("strong", {}, r.title),
      el("div", { class: "msg" }, r.message))))
    : el("p", { class: "muted" }, "No rule fired."));
  return out;
}

async function logout() {
  await api("/api/logout", "POST");
  location.href = "/login.html";
}

function header(page, user) {
  const link = (href, name, text) => el("a", { href, "aria-current": page === name ? "page" : false }, text);
  $("#top").replaceChildren(
    el("a", { class: "brand", href: "/" }, "🧯 txshield"),
    el("nav", { "aria-label": "Main" }, link("/", "check", "Check"), link("/history.html", "history", "History"), link("/policy.html", "policy", "Policy")),
    el("span", { class: "who" }, el("span", {}, user), el("button", { class: "ghost", type: "button", onclick: logout }, "Log out")));
}

// ---------- pages ----------

function initLogin() {
  const go = async (path) => {
    try {
      await api(path, "POST", { username: $("#user").value, password: $("#pass").value });
      location.href = "/";
    } catch (e) {
      $("#msg").textContent = e.message;
    }
  };
  $("#login-form").addEventListener("submit", (e) => { e.preventDefault(); go("/api/login"); });
  $("#register").addEventListener("click", () => go("/api/register"));
}

async function initCheck() {
  const fixtures = await api("/api/fixtures");
  const sel = $("#sample");
  fixtures.forEach((f) => sel.append(el("option", { value: f.id }, `${f.id} · ${f.label} · ${f.title}`)));
  sel.addEventListener("change", () => {
    const f = fixtures.find((x) => x.id === sel.value);
    if (f) $("#tx").value = JSON.stringify(f.payload, null, 2);
  });
  $("#go").addEventListener("click", async () => {
    $("#msg").textContent = "";
    try {
      const res = await api("/api/analyze", "POST", { text: $("#tx").value });
      $("#out").replaceChildren(el("h2", {}, "Verdict"), ...renderResult(res));
    } catch (e) {
      $("#msg").textContent = e.message;
    }
  });
}

async function initHistory() {
  const rows = $("#rows");
  const detail = $("#detail");
  const load = async () => {
    const items = await api("/api/history");
    rows.replaceChildren(...(items.length ? items.map((i) => el("tr", {},
      el("td", {}, new Date(i.created_at * 1000).toLocaleString()),
      el("td", {}, el("span", { class: `chip ${CHIP[i.verdict]}` }, i.verdict.toUpperCase())),
      el("td", {}, i.title),
      el("td", {}, el("button", {
        class: "ghost", type: "button",
        onclick: async () => detail.replaceChildren(el("h2", {}, "Details"), ...renderResult(await api(`/api/history/${i.id}`))),
      }, "View"))))
      : [el("tr", {}, el("td", { colspan: 4, class: "muted" }, "Nothing here yet. Check a transaction first."))]));
  };
  $("#clear").addEventListener("click", async () => {
    await api("/api/history", "DELETE");
    detail.replaceChildren(el("h2", {}, "Details"), el("p", { class: "muted" }, "History cleared."));
    load();
  });
  load();
}

async function initPolicy() {
  const { policy, meta } = await api("/api/policy");
  let state = policy;
  const msg = $("#msg");

  const actionSelect = (id, cur, onchange) => el("select", { id, onchange: (e) => onchange(e.target.value) },
    meta.actions.map((a) => el("option", { value: a, selected: a === cur }, a)));

  const draw = () => {
    $("#def").replaceChildren(...meta.actions.map((a) => el("option", { value: a, selected: a === state.default_action }, a)));
    $("#esc").value = state.escalate_warns_at;

    $("#rules").replaceChildren(...Object.entries(meta.rules).map(([id, m]) => el("fieldset", { class: "rule" },
      el("legend", {}, m.title),
      el("label", { for: `a-${id}` }, "Action"),
      actionSelect(`a-${id}`, state.rules[id].action, (v) => { state.rules[id].action = v; }),
      Object.entries(m.params).map(([name, [lo, hi]]) => el("label", {}, name.replaceAll("_", " "),
        el("input", {
          type: "number", min: lo, max: hi, step: "any", value: state.rules[id].params[name],
          onchange: (e) => { state.rules[id].params[name] = Number(e.target.value); },
        }))))));

    $("#overrides").replaceChildren(...state.overrides.map((o, i) => el("div", { class: "override" },
      el("label", {}, "Rule", el("select", { onchange: (e) => { o.rule = e.target.value; } },
        Object.entries(meta.rules).map(([id, m]) => el("option", { value: id, selected: id === o.rule }, m.title)))),
      el("label", {}, "Address (optional)", el("input", {
        value: o.address || "", maxlength: 42, placeholder: "0x...",
        onchange: (e) => { o.address = e.target.value.trim(); },
      })),
      el("label", {}, "Action", el("select", { onchange: (e) => { o.action = e.target.value; } },
        meta.actions.map((a) => el("option", { value: a, selected: a === o.action }, a)))),
      el("button", { class: "ghost", type: "button", onclick: () => { state.overrides.splice(i, 1); draw(); } }, "Remove"))));
  };

  $("#def").addEventListener("change", (e) => { state.default_action = e.target.value; });
  $("#esc").addEventListener("change", (e) => { state.escalate_warns_at = Number(e.target.value); });
  $("#add").addEventListener("click", () => {
    state.overrides.push({ rule: Object.keys(meta.rules)[0], address: "", action: "allow" });
    draw();
  });
  $("#save").addEventListener("click", async () => {
    msg.className = "";
    try {
      state = (await api("/api/policy", "PUT", state)).policy;
      draw();
      msg.className = "ok-msg";
      msg.textContent = "Saved.";
    } catch (e) {
      msg.className = "err";
      msg.textContent = e.message;
    }
  });
  $("#reset").addEventListener("click", async () => {
    state = (await api("/api/policy/reset", "POST")).policy;
    draw();
    msg.className = "ok-msg";
    msg.textContent = "Back to defaults.";
  });
  draw();
}

async function boot() {
  const page = document.body.dataset.page;
  if (page === "login") return initLogin();
  const me = await api("/api/me");
  CSRF = me.csrf;
  header(page, me.username);
  return { check: initCheck, history: initHistory, policy: initPolicy }[page]();
}

boot().catch((e) => {
  const m = $("#msg");
  if (m) m.textContent = e.message;
});
