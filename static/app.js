/* dachboard SPA. vanilla JS, no build. */
let CSRF = "", ME = null;
const $ = (s) => document.querySelector(s);
let view = $("#view");
/* works both at / and under a subpath like /dash/ */
const BASE = (() => {
  const m = location.pathname.match(/^(\/dash)(?=\/|$)/);
  return m ? m[1] : "";
})();
const u = (p) => BASE + p;

/* stroke icons (feather-style, inline) */
const P = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
  box: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/>',
  term: '<path d="M4 17l6-6-6-6M12 19h8"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  file: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M13 2v7h7"/>',
  zap: '<path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  refresh: '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
  play: '<path d="M6 4l14 8-14 8z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  trash: '<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  up: '<path d="M12 19V5M5 12l7-7 7 7"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  out: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M11 12l10-10M15 6l3 3M18 3l3 3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
};
const ic = (n) => `<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">${P[n] || ""}</svg>`;
$("#logout").innerHTML = ic("out");

async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (CSRF && opts.method && opts.method !== "GET")
    opts.headers["X-CSRF-Token"] = CSRF;
  const r = await fetch(u(path), opts);
  if (r.status === 401) { showLogin(); throw new Error("auth"); }
  if (!r.ok) { const t = await r.text(); throw new Error(t.slice(0, 200)); }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

function showLogin() {
  $("#login").classList.remove("hidden");
  $("#setup").classList.add("hidden");
  $("#app").classList.add("hidden");
}

async function boot() {
  try {
    const need = await (await fetch(u("/api/setup-needed"))).json();
    if (need.needed) {
      $("#setup").classList.remove("hidden");
      $("#login").classList.add("hidden");
      $("#app").classList.add("hidden");
      return;
    }
  } catch { /* fall through to login */ }
  try {
    ME = await api("/api/me");
    $("#login").classList.add("hidden");
    $("#setup").classList.add("hidden");
    $("#app").classList.remove("hidden");
    $("#me").textContent = ME.login + (ME.is_admin ? " · admin" : "");
    buildTabs();
  } catch { showLogin(); }
}

$("#li-go").onclick = async () => {
  $("#li-err").textContent = "";
  $("#li-first").classList.add("hidden");
  try {
    const r = await fetch(u("/api/login"), { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: $("#li-login").value, password: $("#li-pass").value }) });
    if (r.status === 401) {
      let must = false;
      try { must = (await r.json()).detail.must_change === true; } catch { /* plain 401 */ }
      if (must) { $("#li-first").classList.remove("hidden"); throw new Error("Set your password to continue."); }
      throw new Error("Wrong login or password.");
    }
    if (!r.ok) throw new Error("Login failed.");
    const j = await r.json();
    CSRF = j.csrf;
    $("#li-pass").value = "";
    boot();
  } catch (e) { $("#li-err").textContent = e.message; }
};
$("#li-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#li-go").click(); });
$("#li-set").onclick = async () => {
  $("#li-err").textContent = "";
  const r = await fetch(u("/api/first-password"), { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login: $("#li-login").value,
      old_password: $("#li-pass").value, new_password: $("#li-new").value }) });
  if (!r.ok) { $("#li-err").textContent = "Rejected — check the passwords."; return; }
  $("#li-pass").value = $("#li-new").value; $("#li-new").value = "";
  $("#li-go").click();
};
$("#su-go").onclick = async () => {
  $("#su-err").textContent = "";
  const r = await fetch(u("/api/setup"), { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: $("#su-token").value.trim(),
      login: $("#su-login").value.trim(), password: $("#su-pass").value }) });
  if (!r.ok) { $("#su-err").textContent = "Rejected — check the token."; return; }
  $("#li-login").value = $("#su-login").value;
  $("#li-pass").value = $("#su-pass").value;
  boot();
};
$("#logout").onclick = async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  CSRF = ""; ME = null; showLogin();
};

const has = (r) => ME && (ME.is_admin || (ME.rights || {})[r]);
const TABS = [
  ["overview", "overview", "grid"], ["containers", "containers_view", "box"],
  ["terminal", "terminal", "term"], ["files", "files", "folder"],
  ["commands", "commands_run", "zap"], ["tunnel", "tunnel_view", "link"],
  ["users", "users_manage", "users"],
];
function buildTabs() {
  const nav = $("#tabs"); nav.innerHTML = "";
  TABS.forEach(([name, right, icon]) => {
    if (!has(right)) return;
    const b = document.createElement("button");
    b.innerHTML = ic(icon) + "<span>" + name + "</span>";
    b.dataset.tab = name;
    b.onclick = () => showTab(name);
    nav.appendChild(b);
  });
  showTab("overview");
}
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) =>
    b.classList.toggle("on", b.dataset.tab === name));
  const meta = {
    overview: ["Overview", "Live vitals of this host — CPU, memory, disk, temperature and failed units."],
    containers: ["Containers", "Docker containers on this host. Anyone with view rights reads logs; control actions need approval."],
    terminal: ["Terminal", "A shell inside your own slot, fenced by your CPU and RAM limits."],
    files: ["Files", "Your home directory. Admins can hop between slots."],
    commands: ["Commands", "Reviewed one-shot commands. Everything runs without a shell, as your user."],
    tunnel: ["Tunnel", "The current public URL of this panel. Share it with credentials, never alone."],
    users: ["Users", "Accounts, per-user rights, disk / CPU / RAM limits and API tokens for bots."],
  }[name];
  $("#view").innerHTML = `<div class="pagehead"><h2>${meta[0]}</h2><p>${meta[1]}</p></div><div id="vbody"></div>`;
  view = $("#vbody");
  ({ overview: vOverview, containers: vContainers, terminal: vTerminal,
     files: vFiles, commands: vCommands, tunnel: vTunnel, users: vUsers })[name]();
}
const fmtGB = (b) => (b / 1073741824).toFixed(1) + " G";
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const dot = (on) => `<span class="dot${on ? " on" : ""}"></span>`;

/* ---- overview ---- */
async function vOverview() {
  view.innerHTML = "<p class=dim>Loading…</p>";
  try {
    const m = await api("/api/metrics");
    const svcs = await api("/api/services").catch(() => []);
    const bad = svcs.filter((s) => s.active === "failed");
    const temps = Object.entries(m.temps || {}).map(([k, v]) => `${esc(k)} ${v}°`).join(" · ");
    view.innerHTML = `
      <div class="grid">
        <div class="box"><h3>CPU</h3><div class="big">${m.cpu}%</div><div class="sub">load ${m.load.map((x) => x.toFixed(2)).join(" ")}</div></div>
        <div class="box"><h3>Memory</h3><div class="big">${fmtGB(m.mem.used)}<span class="dim"> / ${fmtGB(m.mem.total)}</span></div></div>
        <div class="box"><h3>Disk /</h3><div class="big">${fmtGB(m.disk.used)}<span class="dim"> / ${fmtGB(m.disk.total)}</span></div></div>
        <div class="box"><h3>Uptime</h3><div class="big">${(m.uptime / 3600).toFixed(1)}<span class="dim"> h</span></div></div>
        <div class="box"><h3>Temp</h3><div class="sub" style="white-space:normal">${temps || "—"}</div></div>
        <div class="box"><h3>Failed units</h3><div class="big ${bad.length ? "bad" : "ok"}">${bad.length}</div>
          <div class="sub">${bad.map((s) => esc(s.unit)).join(", ")}</div></div>
      </div>
      <div class="row"><button id="ov-ref">${ic("refresh")}Refresh</button></div>`;
    $("#ov-ref").onclick = vOverview;
  } catch (e) { view.innerHTML = `<p class=bad>${esc(e.message)}</p>`; }
}

/* ---- containers ---- */
function stateDot(s) {
  const on = /run|up/i.test(s || "");
  return dot(on) + esc(s || "—");
}
async function vContainers() {
  view.innerHTML = "<p class=dim>Loading…</p>";
  const list = await api("/api/containers");
  view.innerHTML = `<table><thead><tr><th>Name</th><th>Image</th><th>State</th><th>Status</th><th></th></tr></thead><tbody>` +
    list.map((c) => `<tr><td class="mono"><b>${esc(c.Names)}</b></td><td class="dim mono">${esc(c.Image)}</td>
      <td>${stateDot(c.State)}</td><td class="dim">${esc(c.Status || "")}</td>
      <td style="white-space:nowrap"><button data-log="${esc(c.Names)}" title="Logs">Logs</button>
      ${has("containers_control") ? `
        <button data-act="restart:${esc(c.Names)}" title="Restart">${ic("refresh")}</button>
        <button data-act="stop:${esc(c.Names)}" title="Stop">${ic("stop")}</button>
        <button data-act="start:${esc(c.Names)}" title="Start">${ic("play")}</button>` : ""}</td></tr>`).join("") +
    `</tbody></table><pre id="clog" class="hidden"></pre>`;
  view.querySelectorAll("[data-log]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/containers/${b.dataset.log}/logs?tail=200`);
    const p = $("#clog"); p.classList.remove("hidden"); p.textContent = l.logs;
    p.scrollTop = p.scrollHeight;
  });
  view.querySelectorAll("[data-act]").forEach((b) => b.onclick = async () => {
    const [act, name] = b.dataset.act.split(/:(.+)/);
    if (!confirm(`${act} ${name}?`)) return;
    const r = await api(`/api/containers/${name}/${act}`, { method: "POST" });
    alert("exit " + r.code + "\n" + r.output.slice(-500));
    vContainers();
  });
}

/* ---- terminal ---- */
async function vTerminal() {
  view.innerHTML = "<p class=dim>Starting terminal…</p>";
  try {
    const r = await api("/api/terminal/ensure", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: "{}" });
    view.innerHTML = `<p class="dim">slot <span class="mono">${esc(r.slot)}</span> · 127.0.0.1:${r.port}</p>
      <iframe class="term" src="/term/${esc(r.slot)}/" title="terminal"></iframe>`;
  } catch (e) { view.innerHTML = `<p class=bad>${esc(e.message)}</p>`; }
}

/* ---- files ---- */
let fPath = "", fSlot = "";
async function vFiles() {
  view.innerHTML = "<p class=dim>Loading…</p>";
  await fRender();
}
async function fRender() {
  const q = `?path=${encodeURIComponent(fPath)}${fSlot ? `&slot=${fSlot}` : ""}`;
  const list = await api("/api/files" + q);
  const quota = await api("/api/quota" + (fSlot ? `?slot=${fSlot}` : "")).catch(() => null);
  view.innerHTML = `
    ${ME.is_admin ? `<div class="row"><input id="f-slot" value="${esc(fSlot)}" placeholder="slot, e.g. u-c1" style="max-width:160px">
      <button id="f-go">Open</button></div>` : ""}
    <div class="row"><span class="path">/${esc(fPath)}</span>
      ${quota ? `<span class="dim">${(quota.used / 1048576).toFixed(0)} MiB used${quota.limit ? " · limit " + esc(quota.limit) : ""}</span>` : ""}
    </div>
    <table><tbody>
    ${fPath ? `<tr><td colspan="3"><button id="f-up" class="ghost">${ic("up")}Up</button></td></tr>` : ""}
    ${list.map((e) => `<tr><td><a href="#" data-p="${esc(fPath ? fPath + "/" + e.name : e.name)}" data-d="${e.dir ? 1 : 0}">${ic(e.dir ? "folder" : "file")} ${esc(e.name)}</a></td>
      <td class="dim mono">${e.dir ? "" : (e.size / 1024).toFixed(0) + " KiB"}</td>
      <td style="text-align:right"><button data-del="${esc(e.name)}" class="danger ghost" title="Delete">${ic("trash")}</button></td></tr>`).join("")}
    </tbody></table>
    <div class="row"><input id="f-new" placeholder="New file or folder" style="max-width:220px">
      <button id="f-mkf">${ic("plus")}File</button><button id="f-mkd">${ic("plus")}Folder</button></div>
    <div id="f-edit" class="hidden"><textarea id="f-text" spellcheck="false"></textarea>
      <div class="row"><button id="f-save" class="primary">${ic("check")}Save</button></div></div>`;
  if (ME.is_admin) $("#f-go").onclick = () => { fSlot = $("#f-slot").value.trim(); fPath = ""; fRender(); };
  view.querySelectorAll("[data-p]").forEach((a) => a.onclick = async (ev) => {
    ev.preventDefault();
    if (a.dataset.d === "1") { fPath = a.dataset.p; fRender(); }
    else {
      const r = await api(`/api/files/read?path=${encodeURIComponent(a.dataset.p)}${fSlot ? `&slot=${fSlot}` : ""}`);
      $("#f-edit").classList.remove("hidden");
      $("#f-text").value = r.content; $("#f-text").dataset.p = a.dataset.p;
      $("#f-text").focus();
    }
  });
  const up = $("#f-up"); if (up) up.onclick = () => {
    fPath = fPath.split("/").slice(0, -1).join("/"); fRender();
  };
  view.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => {
    if (!confirm("Delete " + b.dataset.del + "?")) return;
    await api("/api/files/delete", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: fPath ? fPath + "/" + b.dataset.del : b.dataset.del, slot: fSlot }) });
    fRender();
  });
  $("#f-mkf").onclick = async () => {
    const n = $("#f-new").value.trim(); if (!n) return;
    await api("/api/files/write", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: fPath ? fPath + "/" + n : n, content: "", slot: fSlot }) });
    fRender();
  };
  $("#f-mkd").onclick = async () => {
    const n = $("#f-new").value.trim(); if (!n) return;
    await api("/api/files/mkdir", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: fPath ? fPath + "/" + n : n, slot: fSlot }) });
    fRender();
  };
  $("#f-save").onclick = async () => {
    await api("/api/files/write", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: $("#f-text").dataset.p, content: $("#f-text").value, slot: fSlot }) });
    $("#f-save").innerHTML = ic("check") + "Saved";
    setTimeout(() => { const b = $("#f-save"); if (b) b.innerHTML = ic("check") + "Save"; }, 1500);
  };
}

/* ---- commands ---- */
async function vCommands() {
  const list = await api("/api/commands");
  const runs = await api("/api/runs");
  view.innerHTML = `<h3>${ic("zap")}Run</h3><table><tbody>` +
    list.map((c) => `<tr><td><b>${esc(c.name)}</b><div class="dim mono">${esc(c.argv.join(" "))}</div></td>
      <td style="text-align:right"><button data-run="${c.id}">${ic("play")}Run</button></td></tr>`).join("") +
    `</tbody></table>
    <h3>${ic("clock")}History</h3><pre>${esc(runs.map((r) => `#${r.id} cmd=${r.cmd_id} exit=${r.exit_code}\n${(r.output || "").slice(-500)}`).join("\n---\n")) || "empty"}</pre>
    ${has("commands_edit") ? `<h3>${ic("plus")}Command constructor</h3>
    <div class="row"><input id="c-name" placeholder="Name" style="max-width:180px">
    <input id="c-run" placeholder="run_as: owner / self / user" style="max-width:200px">
    <input id="c-allow" placeholder="Allowed user ids (* = all)" style="max-width:200px"></div>
    <textarea id="c-argv" placeholder="One argument per line. No shell, ever." spellcheck="false"></textarea>
    <div class="row"><button id="c-add" class="primary">${ic("plus")}Add command</button></div>
    <div id="c-list"></div>` : ""}`;
  view.querySelectorAll("[data-run]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try {
      const r = await api(`/api/commands/${b.dataset.run}/run`, { method: "POST" });
      alert("exit " + r.code + "\n" + r.output.slice(-2000));
      vCommands();
    } finally { b.disabled = false; }
  });
  if (has("commands_edit")) {
    $("#c-add").onclick = async () => {
      const argv = $("#c-argv").value.split("\n").map((s) => s.trim()).filter(Boolean);
      await api("/api/commands", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: $("#c-name").value.trim(),
          argv, run_as: $("#c-run").value.trim() || "owner",
          allowed: $("#c-allow").value.split(",").map((s) => s.trim()).filter(Boolean).map((s) => s === "*" ? "*" : +s) }) });
      vCommands();
    };
    $("#c-list").innerHTML = list.map((c) => `<div class="row"><span class="mono">#${c.id} ${esc(c.name)}</span>
      <button data-cdel="${c.id}" class="danger ghost">${ic("trash")}</button></div>`).join("");
    view.querySelectorAll("[data-cdel]").forEach((b) => b.onclick = async () => {
      if (!confirm("Delete command?")) return;
      await api(`/api/commands/${b.dataset.cdel}`, { method: "DELETE" });
      vCommands();
    });
  }
}

/* ---- tunnel ---- */
async function vTunnel() {
  view.innerHTML = "<p class=dim>Loading…</p>";
  const t = await api("/api/tunnel");
  view.innerHTML = `<div class="box"><h3>${ic("link")}Public URL</h3>
    <div class="url-big">${esc(t.url || "— none —")}</div>
    <div class="row"><button id="t-ref">${ic("refresh")}Refresh</button></div></div>`;
  $("#t-ref").onclick = async () => {
    await api("/api/tunnel/refresh", { method: "POST" });
    vTunnel();
  };
}

/* ---- users (admin) ---- */
async function vUsers() {
  const users = await api("/api/users");
  const info = await api("/api/rights");
  const ck = (r, u) => `<label class="ck"><input type="checkbox" data-r="${r}" data-u="${u.id}" ${u.rights[r] ? "checked" : ""}>${r}</label>`;
  view.innerHTML = `<h3>${ic("users")}Users</h3><table>
    <thead><tr><th>Login</th><th>Slot</th><th>Rights</th><th>Limits (JSON)</th><th></th></tr></thead><tbody>` +
    users.map((u) => `<tr><td><b>${esc(u.login)}</b>${u.is_admin ? ' <span class="dim">admin</span>' : ""}${u.must_change_pw ? ' <span class="dim">· must change pw</span>' : ""}</td>
      <td><input data-slot="${u.id}" value="${esc(u.slot || "")}" size="6"></td>
      <td>${info.rights.filter((r) => !info.admin_only.includes(r)).map((r) => ck(r, u)).join("")}</td>
      <td><input data-lim="${u.id}" value='${esc(JSON.stringify(u.limits))}' size="18" class="mono"></td>
      <td style="white-space:nowrap"><button data-save="${u.id}" title="Save">${ic("check")}</button>
        <button data-pw="${u.id}" title="Reset password">${ic("key")}</button>
        <button data-u-del="${u.id}" class="danger ghost" title="Delete">${ic("trash")}</button></td></tr>`).join("") +
    `</tbody></table>
    <h3>New user</h3><div class="row"><input id="nu-login" placeholder="Login" style="max-width:150px">
    <input id="nu-pass" type="password" placeholder="Temp password, 8+" style="max-width:170px">
    <input id="nu-slot" placeholder="Slot, e.g. u-c1" style="max-width:140px">
    <label class="ck"><input type="checkbox" id="nu-admin">admin</label>
    <button id="nu-add" class="primary">${ic("plus")}Add</button></div>
    <p class="dim">New users get a temp password and must set their own on first login.</p>`;
  view.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
    const id = b.dataset.save;
    const rights = {};
    view.querySelectorAll(`[data-u="${id}"]`).forEach((c) => rights[c.dataset.r] = c.checked);
    let limits = {};
    try { limits = JSON.parse(view.querySelector(`[data-lim="${id}"]`).value || "{}"); }
    catch { alert("Bad limits JSON."); return; }
    const r = await api(`/api/users/${id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rights, limits, slot: view.querySelector(`[data-slot="${id}"]`).value.trim() || null }) });
    alert(r.quota_applied ? "Saved · disk quota applied." : "Saved." + (r.quota_msg ? " Quota: " + r.quota_msg : ""));
  });
  view.querySelectorAll("[data-pw]").forEach((b) => b.onclick = async () => {
    const p = prompt("New temp password (8+). User must change it on first login:"); if (!p) return;
    await api(`/api/users/${b.dataset.pw}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: p, must_change_pw: true }) });
    alert("Password reset.");
  });
  view.querySelectorAll("[data-u-del]").forEach((b) => b.onclick = async () => {
    if (!confirm("Delete user?")) return;
    await api(`/api/users/${b.dataset.uDel}`, { method: "DELETE" });
    vUsers();
  });
  $("#nu-add").onclick = async () => {
    await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: $("#nu-login").value.trim(), password: $("#nu-pass").value,
        slot: $("#nu-slot").value.trim() || null, is_admin: $("#nu-admin").checked, rights: {}, limits: {} }) });
    vUsers();
  };
  view.insertAdjacentHTML("beforeend", `<h3>${ic("key")}API tokens</h3>
    <p class="dim">For bots, sites, any code: <span class="mono">curl -H "Authorization: Bearer TOKEN" /api/tunnel</span></p>
    <div id="t-list"></div>
    <div class="row"><input id="nt-name" placeholder="Token name" style="max-width:170px">
    <label class="ck"><input type="checkbox" id="nt-tun" checked>tunnel_view</label>
    <button id="nt-add" class="primary">${ic("plus")}New token</button></div>
    <pre id="nt-once" class="hidden"></pre>`);
  const reloadTokens = async () => {
    const toks = await api("/api/tokens");
    $("#t-list").innerHTML = toks.map((t) => `<div class="row"><span class="mono">#${t.id} <b>${esc(t.name)}</b></span>
      <span class="dim">${esc(Object.keys(t.rights).filter((k) => t.rights[k]).join(", ") || "—")}
      · last used ${t.last_used_at ? new Date(t.last_used_at * 1000).toLocaleString() : "never"}</span>
      <button data-tdel="${t.id}" class="danger ghost">Revoke</button></div>`).join("") || "<p class=dim>No tokens.</p>";
    view.querySelectorAll("[data-tdel]").forEach((b) => b.onclick = async () => {
      if (!confirm("Revoke token?")) return;
      await api(`/api/tokens/${b.dataset.tdel}`, { method: "DELETE" });
      reloadTokens();
    });
  };
  $("#nt-add").onclick = async () => {
    const r = await api("/api/tokens", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("#nt-name").value.trim() || "bot",
        rights: { tunnel_view: $("#nt-tun").checked } }) });
    const p = $("#nt-once"); p.classList.remove("hidden");
    p.textContent = "Copy now — shown once:\n" + r.token;
    reloadTokens();
  };
  reloadTokens();
}

boot();
