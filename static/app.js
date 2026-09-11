/* dachboard SPA. vanilla JS, no build. */
let CSRF = "", ME = null, RIGHTS = [];
const $ = (s) => document.querySelector(s);
const view = $("#view");

async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (CSRF && opts.method && opts.method !== "GET")
    opts.headers["X-CSRF-Token"] = CSRF;
  const r = await fetch(path, opts);
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
    const need = await (await fetch("/api/setup-needed")).json();
    if (need.needed) {
      $("#setup").classList.remove("hidden");
      $("#login").classList.add("hidden");
      $("#app").classList.add("hidden");
      return;
    }
  } catch { /* fall through to login */ }
  try {
    ME = await api("/api/me");
    RIGHTS = Object.keys(ME.rights || {}).filter((k) => ME.rights[k]);
    if (ME.is_admin) RIGHTS = ["*"];
    $("#login").classList.add("hidden");
    $("#app").classList.remove("hidden");
    $("#me").textContent = ME.login + (ME.is_admin ? " (admin)" : "");
    buildTabs();
  } catch { showLogin(); }
}

$("#li-go").onclick = async () => {
  $("#li-err").textContent = "";
  $("#li-first").classList.add("hidden");
  try {
    const r = await fetch("/api/login", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: $("#li-login").value, password: $("#li-pass").value }) });
    if (r.status === 401) {
      let must = false;
      try { must = (await r.json()).detail.must_change === true; } catch { /* plain 401 */ }
      if (must) { $("#li-first").classList.remove("hidden"); throw new Error("set your password"); }
      throw new Error("bad credentials");
    }
    if (!r.ok) throw new Error("login failed");
    const j = await r.json();
    CSRF = j.csrf;
    $("#li-pass").value = "";
    boot();
  } catch (e) { $("#li-err").textContent = e.message; }
};
$("#li-set").onclick = async () => {
  $("#li-err").textContent = "";
  const r = await fetch("/api/first-password", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login: $("#li-login").value,
      old_password: $("#li-pass").value, new_password: $("#li-new").value }) });
  if (!r.ok) { $("#li-err").textContent = "rejected"; return; }
  $("#li-pass").value = $("#li-new").value; $("#li-new").value = "";
  $("#li-go").click();
};
$("#su-go").onclick = async () => {
  $("#su-err").textContent = "";
  const r = await fetch("/api/setup", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: $("#su-token").value.trim(),
      login: $("#su-login").value.trim(), password: $("#su-pass").value }) });
  if (!r.ok) { $("#su-err").textContent = "rejected"; return; }
  $("#li-login").value = $("#su-login").value;
  $("#li-pass").value = $("#su-pass").value;
  boot();
};
$("#li-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#li-go").click(); });
$("#logout").onclick = async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  CSRF = ""; ME = null; showLogin();
};

const has = (r) => ME && (ME.is_admin || (ME.rights || {})[r]);
const TABS = [
  ["overview", "overview"], ["containers", "containers_view"], ["terminal", "terminal"],
  ["files", "files"], ["commands", "commands_run"], ["tunnel", "tunnel_view"],
  ["users", "users_manage"],
];
function buildTabs() {
  const nav = $("#tabs"); nav.innerHTML = "";
  TABS.forEach(([name, right]) => {
    if (!has(right)) return;
    const b = document.createElement("button");
    b.textContent = name; b.dataset.tab = name;
    b.onclick = () => showTab(name);
    nav.appendChild(b);
  });
  showTab("overview");
}
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) =>
    b.classList.toggle("on", b.dataset.tab === name));
  ({ overview: vOverview, containers: vContainers, terminal: vTerminal,
     files: vFiles, commands: vCommands, tunnel: vTunnel, users: vUsers })[name]();
}
const fmtGB = (b) => (b / 1073741824).toFixed(1) + "G";
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

/* ---- overview ---- */
async function vOverview() {
  view.innerHTML = "<p class=dim>loading…</p>";
  try {
    const m = await api("/api/metrics");
    const svcs = await api("/api/services").catch(() => []);
    const bad = svcs.filter((s) => s.active === "failed");
    const temps = Object.entries(m.temps || {}).map(([k, v]) => `${esc(k)} ${v}°`).join(" · ");
    view.innerHTML = `
      <div class="grid">
        <div class="box"><h3>cpu</h3><div class="big">${m.cpu}%</div><div class=dim>load ${m.load.map((x) => x.toFixed(2)).join(" ")}</div></div>
        <div class="box"><h3>mem</h3><div class="big">${fmtGB(m.mem.used)} / ${fmtGB(m.mem.total)}</div></div>
        <div class="box"><h3>disk /</h3><div class="big">${fmtGB(m.disk.used)} / ${fmtGB(m.disk.total)}</div></div>
        <div class="box"><h3>uptime</h3><div class="big">${(m.uptime / 3600).toFixed(1)}h</div></div>
        <div class="box"><h3>temps</h3><div>${temps || "—"}</div></div>
        <div class="box"><h3>services failed</h3><div class="big ${bad.length ? "bad" : "ok"}">${bad.length}</div>
          <div class=dim>${bad.map((s) => esc(s.unit)).join(", ")}</div></div>
      </div>
      <p><button id="ov-ref">refresh</button></p>`;
    $("#ov-ref").onclick = vOverview;
  } catch (e) { view.innerHTML = `<p class=bad>${esc(e.message)}</p>`; }
}

/* ---- containers ---- */
async function vContainers() {
  view.innerHTML = "<p class=dim>loading…</p>";
  const list = await api("/api/containers");
  view.innerHTML = `<table><tr><th>name</th><th>image</th><th>state</th><th>status</th><th></th></tr>` +
    list.map((c) => `<tr><td>${esc(c.Names)}</td><td class=dim>${esc(c.Image)}</td>
      <td>${esc(c.State)}</td><td class=dim>${esc(c.Status || "")}</td>
      <td><button data-log="${esc(c.Names)}">logs</button>
      ${has("containers_control") ? ` <button data-act="restart:${esc(c.Names)}">restart</button>
      <button data-act="stop:${esc(c.Names)}">stop</button>
      <button data-act="start:${esc(c.Names)}">start</button>` : ""}</td></tr>`).join("") +
    `</table><pre id="clog" class=hidden></pre>`;
  view.querySelectorAll("[data-log]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/containers/${b.dataset.log}/logs?tail=200`);
    const p = $("#clog"); p.classList.remove("hidden"); p.textContent = l.logs;
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
  view.innerHTML = "<p class=dim>starting ttyd…</p>";
  try {
    const r = await api("/api/terminal/ensure", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: "{}" });
    view.innerHTML = `<p class=dim>slot ${esc(r.slot)} → 127.0.0.1:${r.port} (via nginx /term/)</p>
      <iframe class="term" src="/term/${esc(r.slot)}/"></iframe>`;
  } catch (e) { view.innerHTML = `<p class=bad>${esc(e.message)}</p>`; }
}

/* ---- files ---- */
let fPath = "", fSlot = "";
async function vFiles() {
  view.innerHTML = "<p class=dim>loading…</p>";
  await fRender();
}
async function fRender() {
  const q = `?path=${encodeURIComponent(fPath)}${fSlot ? `&slot=${fSlot}` : ""}`;
  const list = await api("/api/files" + q);
  const quota = await api("/api/quota" + (fSlot ? `?slot=${fSlot}` : "")).catch(() => null);
  view.innerHTML = `
    ${ME.is_admin ? `<div class=row>slot: <input id="f-slot" value="${esc(fSlot)}" placeholder="u-c1">
      <button id="f-go">go</button></div>` : ""}
    <div class=row><b>/${esc(fPath)}</b>
      ${quota ? `<span class=dim>used ${(quota.used / 1048576).toFixed(0)}M${quota.limit ? " / limit " + esc(quota.limit) : ""}</span>` : ""}
    </div>
    <table>${fPath ? `<tr><td colspan=4><button id="f-up">.. up</button></td></tr>` : ""}
    ${list.map((e) => `<tr><td>${e.dir ? "📁" : "📄"} <a href="#" data-p="${esc(fPath ? fPath + "/" + e.name : e.name)}" data-d="${e.dir ? 1 : 0}">${esc(e.name)}</a></td>
      <td class=dim>${e.dir ? "" : (e.size / 1024).toFixed(0) + "K"}</td>
      <td><button data-del="${esc(e.name)}">del</button></td></tr>`).join("")}</table>
    <div class=row><input id="f-new" placeholder="new file/dir">
      <button id="f-mkf">+file</button><button id="f-mkd">+dir</button></div>
    <div id="f-edit" class=hidden><textarea id="f-text"></textarea>
      <button id="f-save" class=primary>save</button></div>`;
  if (ME.is_admin) $("#f-go").onclick = () => { fSlot = $("#f-slot").value.trim(); fPath = ""; fRender(); };
  view.querySelectorAll("[data-p]").forEach((a) => a.onclick = async (ev) => {
    ev.preventDefault();
    if (a.dataset.d === "1") { fPath = a.dataset.p; fRender(); }
    else {
      const r = await api(`/api/files/read?path=${encodeURIComponent(a.dataset.p)}${fSlot ? `&slot=${fSlot}` : ""}`);
      $("#f-edit").classList.remove("hidden");
      $("#f-text").value = r.content; $("#f-text").dataset.p = a.dataset.p;
    }
  });
  const up = $("#f-up"); if (up) up.onclick = () => {
    fPath = fPath.split("/").slice(0, -1).join("/"); fRender();
  };
  view.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => {
    if (!confirm("delete " + b.dataset.del + "?")) return;
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
    alert("saved");
  };
}

/* ---- commands ---- */
async function vCommands() {
  const list = await api("/api/commands");
  const runs = await api("/api/runs");
  view.innerHTML = `<h3>run</h3><table>` +
    list.map((c) => `<tr><td><b>${esc(c.name)}</b><div class=dim>${esc(c.argv.join(" "))}</div></td>
      <td><button data-run="${c.id}">run</button></td></tr>`).join("") + `</table>
    <h3>history</h3><pre>${esc(runs.map((r) => `#${r.id} cmd=${r.cmd_id} exit=${r.exit_code}\n${(r.output || "").slice(-500)}`).join("\n---\n"))}</pre>
    ${has("commands_edit") ? `<h3>constructor</h3>
    <input id="c-name" placeholder="name"> <input id="c-run" placeholder="run_as (owner/self/user)">
    <input id="c-allow" placeholder="allowed user ids, comma, * = all">
    <textarea id="c-argv" placeholder="one arg per line (no shell!)"></textarea>
    <button id="c-add" class=primary>add command</button><div id="c-list"></div>` : ""}`;
  view.querySelectorAll("[data-run]").forEach((b) => b.onclick = async () => {
    const r = await api(`/api/commands/${b.dataset.run}/run`, { method: "POST" });
    alert("exit " + r.code + "\n" + r.output.slice(-2000));
    vCommands();
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
    const all = await api("/api/commands");
    $("#c-list").innerHTML = all.map((c) => `<div class=row>#${c.id} ${esc(c.name)}
      <button data-cdel="${c.id}">del</button></div>`).join("");
    view.querySelectorAll("[data-cdel]").forEach((b) => b.onclick = async () => {
      if (!confirm("delete?")) return;
      await api(`/api/commands/${b.dataset.cdel}`, { method: "DELETE" });
      vCommands();
    });
  }
}

/* ---- tunnel ---- */
async function vTunnel() {
  view.innerHTML = "<p class=dim>loading…</p>";
  const t = await api("/api/tunnel");
  view.innerHTML = `<div class=box><h3>public url</h3><div class=big>${esc(t.url || "— none —")}</div>
    <p><button id="t-ref">refresh</button></p></div>`;
  $("#t-ref").onclick = async () => {
    await api("/api/tunnel/refresh", { method: "POST" });
    vTunnel();
  };
}

/* ---- users (admin) ---- */
async function vUsers() {
  const users = await api("/api/users");
  const info = await api("/api/rights");
  const ck = (r, u) => `<label class=ck><input type=checkbox data-r="${r}" data-u="${u.id}" ${u.rights[r] ? "checked" : ""}>${r}</label>`;
  view.innerHTML = `<h3>users</h3><table><tr><th>login</th><th>slot</th><th>rights</th><th>limits</th><th></th></tr>` +
    users.map((u) => `<tr><td><b>${esc(u.login)}</b>${u.is_admin ? " ★" : ""}</td>
      <td><input data-slot="${u.id}" value="${esc(u.slot || "")}" size=6></td>
      <td>${info.rights.filter((r) => !info.admin_only.includes(r)).map((r) => ck(r, u)).join("")}</td>
      <td><input data-lim="${u.id}" value='${esc(JSON.stringify(u.limits))}' size=20></td>
      <td><button data-save="${u.id}">save</button>
        <button data-pw="${u.id}">pass</button>
        <button data-u-del="${u.id}">del</button></td></tr>`).join("") + `</table>
    <h3>new user</h3><div class=row><input id="nu-login" placeholder="login">
    <input id="nu-pass" type=password placeholder="password 8+">
    <input id="nu-slot" placeholder="slot u-c1.."> <label class=ck><input type=checkbox id="nu-admin">admin</label>
    <button id="nu-add" class=primary>add</button></div>`;
  view.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
    const id = b.dataset.save;
    const rights = {};
    view.querySelectorAll(`[data-u="${id}"]`).forEach((c) => rights[c.dataset.r] = c.checked);
    let limits = {};
    try { limits = JSON.parse(view.querySelector(`[data-lim="${id}"]`).value || "{}"); }
    catch { alert("bad limits json"); return; }
    await api(`/api/users/${id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rights, limits, slot: view.querySelector(`[data-slot="${id}"]`).value.trim() || null }) });
    alert("saved");
  });
  view.querySelectorAll("[data-pw]").forEach((b) => b.onclick = async () => {
    const p = prompt("new password (8+), user must change it on first login:"); if (!p) return;
    await api(`/api/users/${b.dataset.pw}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: p, must_change_pw: true }) });
    alert("changed");
  });
  view.querySelectorAll("[data-u-del]").forEach((b) => b.onclick = async () => {
    if (!confirm("delete user?")) return;
    await api(`/api/users/${b.dataset.uDel}`, { method: "DELETE" });
    vUsers();
  });
  $("#nu-add").onclick = async () => {
    await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login: $("#nu-login").value.trim(), password: $("#nu-pass").value,
        slot: $("#nu-slot").value.trim() || null, is_admin: $("#nu-admin").checked, rights: {}, limits: {} }) });
    vUsers();
  };
}

boot();
