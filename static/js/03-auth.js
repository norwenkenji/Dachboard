/* dachboard SPA: 03-auth. vanilla JS, no build. Loaded in order, shared globals. */

function applyLang() {
  const b = $("#lang");
  if (b) b.textContent = LANG === "en" ? "RU" : "EN";
  document.documentElement.lang = LANG;
  const set = (id, key, attr) => {
    const el = document.getElementById(id);
    if (el) el[attr || "textContent"] = t(key);
  };
  set("li-login", "login_ph", "placeholder"); set("li-pass", "pass_ph", "placeholder");
  set("li-go", "sign_in"); set("li-new", "new_pass_ph", "placeholder");
  set("li-set", "set_signin"); set("su-h", "first_setup"); set("su-sub", "setup_hint");
  set("su-token", "setup_token_ph", "placeholder"); set("su-login", "admin_login_ph", "placeholder");
  set("su-pass", "admin_pass_ph", "placeholder"); set("su-go", "create_admin");
  set("li-sub", "first_login"); set("logout", null);
  const lo = $("#logout"); if (lo) lo.title = t("sign_in");
}
$("#lang").onclick = () => {
  LANG = LANG === "en" ? "ru" : "en";
  localStorage.setItem("dach-lang", LANG);
  location.reload(); // safe: boot() restores CSRF via /api/csrf
};

async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (CSRF && opts.method && opts.method !== "GET")
    opts.headers["X-CSRF-Token"] = CSRF;
  const r = await fetch(u(path), opts);
  if (r.status === 401) { showLogin(); throw new Error("auth"); }
  if (!r.ok) { const txt = await r.text(); throw new Error(txt.slice(0, 200)); }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

function showLogin() {
  applyLang();
  $("#login").classList.remove("hidden");
  $("#setup").classList.add("hidden");
  $("#app").classList.add("hidden");
}

async function boot() {
  applyLang();
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
    try { CSRF = (await api("/api/csrf")).csrf; } catch { /* keep sick */ }
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
      if (must) { $("#li-first").classList.remove("hidden"); throw new Error(t("first_login")); }
      throw new Error(t("bad_creds"));
    }
    if (!r.ok) throw new Error(t("login_failed"));
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
  if (!r.ok) { $("#li-err").textContent = t("rejected_pw"); return; }
  $("#li-pass").value = $("#li-new").value; $("#li-new").value = "";
  $("#li-go").click();
};
$("#su-go").onclick = async () => {
  $("#su-err").textContent = "";
  const r = await fetch(u("/api/setup"), { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: $("#su-token").value.trim(),
      login: $("#su-login").value.trim(), password: $("#su-pass").value }) });
  if (!r.ok) { $("#su-err").textContent = t("setup_rejected"); return; }
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
  ["overview", null, "grid"], ["services", null, "box"], ["console", null, "term"],
  ["files", "files", "folder"], ["users", "users_manage", "users"],
];
const TABVIS = {
  overview: () => has("overview"),
  services: () => has("containers_view"),
  console: () => has("commands_run") || has("terminal"),
  files: () => has("files"),
  users: () => has("users_manage"),
};
const TABNAME = {
  overview: "nav_overview", services: "nav_services", console: "nav_console",
  files: "nav_files", users: "nav_users",
};
function buildTabs() {
  const nav = $("#tabs"); nav.innerHTML = "";
  TABS.forEach(([name, , icon]) => {
    if (!TABVIS[name]()) return;
    const b = document.createElement("button");
    b.innerHTML = ic(icon) + "<span>" + t(TABNAME[name]) + "</span>";
    b.dataset.tab = name;
    b.onclick = () => showTab(name);
    nav.appendChild(b);
  });
  const first = document.querySelector("#tabs button");
  if (!first) { view.innerHTML = `<p class="dim">—</p>`; return; }
  showTab(has("overview") ? "overview" : first.dataset.tab);
}
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) =>
    b.classList.toggle("on", b.dataset.tab === name));
  const meta = {
    overview: ["pg_overview_t", "pg_overview_d"], services: ["pg_services_t", "pg_services_d"],
    console: ["pg_console_t", "pg_console_d"], files: ["pg_files_t", "pg_files_d"],
    users: ["pg_users_t", "pg_users_d"],
  }[name];
  $("#view").innerHTML = `<div class="pagehead"><h2>${t(meta[0])}</h2><p>${t(meta[1])}</p></div><div id="vbody"></div>`;
  view = $("#vbody");
  ({ overview: vOverview, services: vServices, console: vConsole,
     files: vFiles, users: vUsers })[name]();
}
const fmtGB = (b) => (b / 1073741824).toFixed(1);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const dot = (on) => `<span class="dot${on ? " on" : ""}"></span>`;
