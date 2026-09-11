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

/* ---- i18n (default en) ---- */
const STR = {
en: {
  nav_overview: "overview", nav_services: "services", nav_console: "console",
  nav_files: "files", nav_tunnel: "tunnel", nav_users: "users",
  pg_overview_t: "Overview", pg_overview_d: "Live vitals of this host — CPU, memory, disk, temperature and failed units.",
  pg_services_t: "Services", pg_services_d: "Docker containers and systemd units. Logs are readable with the view right; control actions need approval.",
  pg_console_t: "Console", pg_console_d: "Reviewed one-shot commands and a live shell in your own slot.",
  pg_files_t: "Files", pg_files_d: "Your home directory. Admins can hop between slots.",
  pg_tunnel_t: "Tunnel", pg_tunnel_d: "The current public URL of this panel. Share it with credentials, never alone.",
  pg_users_t: "Users", pg_users_d: "Accounts, per-user rights, disk / CPU / RAM limits and API tokens for bots.",
  cpu: "CPU", memory: "Memory", disk: "Disk", uptime: "Uptime", temp: "Temp",
  failed: "Failed units", refresh: "Refresh", load: "load", hours: "h",
  docker_t: "Docker containers", systemd_t: "Systemd units", filter_ph: "Filter…",
  th_name: "Name", th_image: "Image", th_state: "State", th_status: "Status",
  th_unit: "Unit", th_active: "Active", th_desc: "Description",
  logs: "Logs", restart: "Restart", stop: "Stop", start: "Start",
  run_t: "Presets", history_t: "History", history_empty: "empty",
  term_t: "Shell", term_starting: "Starting shell…",
  ctor_t: "Command constructor", ph_name: "Name", ph_runas: "run_as: owner / self / user",
  ph_allow: "Allowed user ids (* = all)", ph_argv: "One argument per line. No shell, ever.",
  add_cmd: "Add command", del_cmd_q: "Delete command?",
  slot_ph: "slot, e.g. u-c1", open: "Open", pick_slot: "Pick a slot to browse its files.",
  used: "used", limit: "limit", up: "Up", del_q: "Delete", new_ph: "New file or folder",
  file_btn: "File", folder_btn: "Folder", save: "Save", saved: "Saved",
  tunnel_url: "Public URL", tunnel_none: "— none —",
  users_t: "Users", new_user_t: "New user", add: "Add",
  temp_note: "New users get a temp password and must set their own on first login.",
  save_btn: "Save", reset_pw: "Reset password", del_user_q: "Delete user?",
  pass_prompt: "New temp password (8+). User must change it on first login:",
  pass_changed: "Password reset.", user_deleted: "Deleted.",
  saved_q: "Saved.", quota_on: "Saved · disk quota applied.", bad_json: "Bad limits JSON.",
  tokens_t: "API tokens", tokens_hint: 'For bots, sites, any code:',
  revoke_q: "Revoke token?", token_name_ph: "Token name", new_token_btn: "New token",
  shown_once: "Copy now — shown once:", never: "never", last_used: "last used",
  no_tokens: "No tokens.",
  sign_in: "Sign in", login_ph: "Login", pass_ph: "Password",
  bad_creds: "Wrong login or password.", login_failed: "Login failed.",
  first_login: "First login — set your own password.", new_pass_ph: "New password, 8+ chars",
  set_signin: "Set & sign in", rejected_pw: "Rejected — check the passwords.",
  first_setup: "First setup", setup_hint: "One-time token from the server log.",
  setup_token_ph: "Setup token", admin_login_ph: "Admin login", admin_pass_ph: "Password, 12+ chars",
  create_admin: "Create admin", setup_rejected: "Rejected — check the token.",
  loading: "Loading…", confirm_q: "Confirm?",
},
ru: {
  nav_overview: "обзор", nav_services: "службы", nav_console: "консоль",
  nav_files: "файлы", nav_tunnel: "туннель", nav_users: "пользователи",
  pg_overview_t: "Обзор", pg_overview_d: "Живые показатели хоста — CPU, память, диск, температуры и упавшие юниты.",
  pg_services_t: "Службы", pg_services_d: "Docker-контейнеры и systemd-юниты. Логи видно с правом просмотра, управление — только с допуском.",
  pg_console_t: "Консоль", pg_console_d: "Проверенные разовые команды и живой шелл в твоем слоте.",
  pg_files_t: "Файлы", pg_files_d: "Твоя домашняя папка. Админ может прыгать между слотами.",
  pg_tunnel_t: "Туннель", pg_tunnel_d: "Текущий публичный URL панели. Раздавай вместе с доступами, не один.",
  pg_users_t: "Пользователи", pg_users_d: "Аккаунты, права, лимиты диска / CPU / RAM и API-токены для ботов.",
  cpu: "CPU", memory: "Память", disk: "Диск", uptime: "Аптайм", temp: "Темп.",
  failed: "Упавшие юниты", refresh: "Обновить", load: "нагрузка", hours: "ч",
  docker_t: "Docker-контейнеры", systemd_t: "Systemd-юниты", filter_ph: "Фильтр…",
  th_name: "Имя", th_image: "Образ", th_state: "Состояние", th_status: "Статус",
  th_unit: "Юнит", th_active: "Активен", th_desc: "Описание",
  logs: "Логи", restart: "Рестарт", stop: "Стоп", start: "Старт",
  run_t: "Пресеты", history_t: "История", history_empty: "пусто",
  term_t: "Шелл", term_starting: "Запускаю шелл…",
  ctor_t: "Конструктор команд", ph_name: "Название", ph_runas: "run_as: owner / self / user",
  ph_allow: "ID допущенных (* = все)", ph_argv: "По одному аргументу на строку. Шелла нет и не будет.",
  add_cmd: "Добавить", del_cmd_q: "Удалить команду?",
  slot_ph: "слот, напр. u-c1", open: "Открыть", pick_slot: "Выбери слот, чтобы смотреть файлы.",
  used: "занято", limit: "лимит", up: "Вверх", del_q: "Удалить",
  new_ph: "Новый файл или папка", file_btn: "Файл", folder_btn: "Папка",
  save: "Сохранить", saved: "Сохранено",
  tunnel_url: "Публичный URL", tunnel_none: "— нет —",
  users_t: "Пользователи", new_user_t: "Новый пользователь", add: "Добавить",
  temp_note: "Новичок получает временный пароль и обязан задать свой при первом входе.",
  save_btn: "Сохранить", reset_pw: "Сбросить пароль", del_user_q: "Удалить пользователя?",
  pass_prompt: "Новый временный пароль (8+). Пользователь сменит при первом входе:",
  pass_changed: "Пароль сброшен.", user_deleted: "Удален.",
  saved_q: "Сохранено.", quota_on: "Сохранено · квота применена.", bad_json: "Кривой JSON лимитов.",
  tokens_t: "API-токены", tokens_hint: "Для ботов, сайтов, любого кода:",
  revoke_q: "Отозвать токен?", token_name_ph: "Имя токена", new_token_btn: "Новый токен",
  shown_once: "Скопируй сейчас — больше не покажу:", never: "никогда", last_used: "использовался",
  no_tokens: "Токенов нет.",
  sign_in: "Войти", login_ph: "Логин", pass_ph: "Пароль",
  bad_creds: "Неверный логин или пароль.", login_failed: "Не вошел.",
  first_login: "Первый вход — задай свой пароль.", new_pass_ph: "Новый пароль, 8+ символов",
  set_signin: "Задать и войти", rejected_pw: "Отклонено — проверь пароли.",
  first_setup: "Первый запуск", setup_hint: "Одноразовый токен из лога сервера.",
  setup_token_ph: "Setup-токен", admin_login_ph: "Логин админа", admin_pass_ph: "Пароль, 12+ символов",
  create_admin: "Создать админа", setup_rejected: "Отклонено — проверь токен.",
  loading: "Загрузка…", confirm_q: "Точно?",
}};
let LANG = localStorage.getItem("dach-lang") || "en";
if (!STR[LANG]) LANG = "en";
const t = (k) => (STR[LANG] && STR[LANG][k]) || STR.en[k] || k;

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
  ["files", "files", "folder"], ["tunnel", "tunnel_view", "link"], ["users", "users_manage", "users"],
];
const TABVIS = {
  overview: () => has("overview"),
  services: () => has("containers_view"),
  console: () => has("commands_run") || has("terminal"),
  files: () => has("files"),
  tunnel: () => has("tunnel_view"),
  users: () => has("users_manage"),
};
const TABNAME = {
  overview: "nav_overview", services: "nav_services", console: "nav_console",
  files: "nav_files", tunnel: "nav_tunnel", users: "nav_users",
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
    tunnel: ["pg_tunnel_t", "pg_tunnel_d"], users: ["pg_users_t", "pg_users_d"],
  }[name];
  $("#view").innerHTML = `<div class="pagehead"><h2>${t(meta[0])}</h2><p>${t(meta[1])}</p></div><div id="vbody"></div>`;
  view = $("#vbody");
  ({ overview: vOverview, services: vServices, console: vConsole,
     files: vFiles, tunnel: vTunnel, users: vUsers })[name]();
}
const fmtGB = (b) => (b / 1073741824).toFixed(1);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const dot = (on) => `<span class="dot${on ? " on" : ""}"></span>`;

/* ---- overview: rows, not tiles ---- */
async function vOverview() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  try {
    const m = await api("/api/metrics");
    const svcs = await api("/api/services").catch(() => []);
    const bad = svcs.filter((s) => s.active === "failed");
    const pct = (a, b) => (b ? Math.min(100, (a / b) * 100) : 0).toFixed(0);
    const temps = Object.entries(m.temps || {})
      .map(([k, v]) => `<div class="trow"><span>${esc(k)}</span><b>${v}°</b></div>`).join("");
    view.innerHTML = `
      <div class="panel">
        <div class="vrow"><span class="vk">${t("cpu")}</span>
          <div class="meter"><i style="width:${m.cpu}%"></i></div>
          <span class="vv mono">${m.cpu}% · ${t("load")} ${m.load.map((x) => x.toFixed(2)).join(" ")}</span></div>
        <div class="vrow"><span class="vk">${t("memory")}</span>
          <div class="meter"><i style="width:${pct(m.mem.used, m.mem.total)}%"></i></div>
          <span class="vv mono">${fmtGB(m.mem.used)} / ${fmtGB(m.mem.total)} G</span></div>
        <div class="vrow"><span class="vk">${t("disk")} /</span>
          <div class="meter"><i style="width:${pct(m.disk.used, m.disk.total)}%"></i></div>
          <span class="vv mono">${fmtGB(m.disk.used)} / ${fmtGB(m.disk.total)} G</span></div>
        <div class="vrow"><span class="vk">${t("uptime")}</span>
          <span class="vv mono">${(m.uptime / 3600).toFixed(1)} ${t("hours")}</span></div>
        <div class="vrow"><span class="vk">${t("temp")}</span>
          <div class="tgrid">${temps || "—"}</div></div>
        <div class="vrow"><span class="vk">${t("failed")}</span>
          <span class="vv ${bad.length ? "bad" : "ok"}">${bad.length ? bad.map((s) => esc(s.unit)).join(", ") : "0"}</span></div>
      </div>
      <div class="row"><button id="ov-ref">${ic("refresh")}${t("refresh")}</button></div>`;
    $("#ov-ref").onclick = vOverview;
  } catch (e) { view.innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
}

/* ---- services: docker + systemd ---- */
function stateDot(s) {
  const on = /run|up/i.test(s || "") || /active/i.test(s || "");
  return dot(on) + esc(s || "—");
}
async function vServices() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  const list = await api("/api/containers");
  const units = await api("/api/services");
  const show = units.filter((s) => !/^(sys|systemd|dbus|user@|getty)/.test(s.unit));
  const ctrl = has("containers_control");
  const btns = (kind, name) => ctrl
    ? `<button data-sact="restart:${kind}:${esc(name)}" title="${t("restart")}">${ic("refresh")}</button>
       <button data-sact="stop:${kind}:${esc(name)}" title="${t("stop")}">${ic("stop")}</button>
       <button data-sact="start:${kind}:${esc(name)}" title="${t("start")}">${ic("play")}</button>` : "";
  view.innerHTML = `
    <h3>${ic("box")}${t("docker_t")}</h3>
    <table><thead><tr><th>${t("th_name")}</th><th>${t("th_image")}</th><th>${t("th_state")}</th><th>${t("th_status")}</th><th></th></tr></thead><tbody>
    ${list.map((c) => `<tr><td class="mono"><b>${esc(c.Names)}</b></td><td class="dim mono">${esc(c.Image)}</td>
      <td>${stateDot(c.State)}</td><td class="dim">${esc(c.Status || "")}</td>
      <td style="white-space:nowrap"><button data-clog="${esc(c.Names)}">${t("logs")}</button>${btns("docker", c.Names)}</td></tr>`).join("")}
    </tbody></table>
    <h3>${ic("grid")}${t("systemd_t")}</h3>
    <div class="row"><input id="s-filter" placeholder="${t("filter_ph")}" style="max-width:220px"></div>
    <table><thead><tr><th>${t("th_unit")}</th><th>${t("th_active")}</th><th>${t("th_desc")}</th><th></th></tr></thead><tbody id="s-rows">
    ${show.map((s) => `<tr data-u="${esc(s.unit)}"><td class="mono"><b>${esc(s.unit)}</b></td>
      <td>${stateDot(s.active)}</td><td class="dim">${esc(s.desc)}</td>
      <td style="white-space:nowrap"><button data-slog="${esc(s.unit)}">${t("logs")}</button>${btns("unit", s.unit)}</td></tr>`).join("")}
    </tbody></table>
    <pre id="slog" class="hidden"></pre>`;
  const showLog = async (text) => {
    const p = $("#slog"); p.classList.remove("hidden"); p.textContent = text;
    p.scrollTop = p.scrollHeight;
  };
  view.querySelectorAll("[data-clog]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/containers/${b.dataset.clog}/logs?tail=200`);
    showLog(l.logs);
  });
  view.querySelectorAll("[data-slog]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/services/${b.dataset.slog}/logs?tail=200`);
    showLog(l.logs);
  });
  view.querySelectorAll("[data-sact]").forEach((b) => b.onclick = async () => {
    const m = b.dataset.sact.match(/^(restart|stop|start):(docker|unit):(.+)$/);
    if (!m) return;
    const [, act, kind, name] = m;
    if (!confirm(`${act} ${name}?`)) return;
    const url = kind === "docker" ? `/api/containers/${name}/${act}` : `/api/services/${name}/${act}`;
    const r = await api(url, { method: "POST" });
    alert("exit " + r.code + "\n" + (r.output || "").slice(-500));
    vServices();
  });
  $("#s-filter").oninput = (e) => {
    const q = e.target.value.toLowerCase();
    view.querySelectorAll("#s-rows tr").forEach((tr) =>
      tr.style.display = tr.dataset.u.toLowerCase().includes(q) ? "" : "none");
  };
}

/* ---- console: presets + shell in one place ---- */
async function vConsole() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  const canRun = has("commands_run"), canTerm = has("terminal");
  let html = "";
  if (canRun) {
    const list = await api("/api/commands");
    const runs = await api("/api/runs");
    html += `<h3>${ic("zap")}${t("run_t")}</h3><table><tbody>` +
      (list.map((c) => `<tr><td><b>${esc(c.name)}</b><div class="dim mono">${esc(c.argv.join(" "))}</div></td>
        <td style="text-align:right"><button data-run="${c.id}">${ic("play")}${t("run_t")}</button></td></tr>`).join("") ||
       `<tr><td class="dim">${t("history_empty")}</td></tr>`) + `</tbody></table>
      <h3>${ic("clock")}${t("history_t")}</h3>
      <pre>${esc(runs.map((r) => `#${r.id} cmd=${r.cmd_id} exit=${r.exit_code}\n${(r.output || "").slice(-500)}`).join("\n---\n")) || t("history_empty")}</pre>`;
    if (has("commands_edit")) {
      html += `<h3>${ic("plus")}${t("ctor_t")}</h3>
      <div class="row"><input id="c-name" placeholder="${t("ph_name")}" style="max-width:180px">
      <input id="c-run" placeholder="${t("ph_runas")}" style="max-width:200px">
      <input id="c-allow" placeholder="${t("ph_allow")}" style="max-width:200px"></div>
      <textarea id="c-argv" placeholder="${t("ph_argv")}" spellcheck="false"></textarea>
      <div class="row"><button id="c-add" class="primary">${ic("plus")}${t("add_cmd")}</button></div>
      <div id="c-list"></div>`;
    }
  }
  if (canTerm) {
    html += `<h3>${ic("term")}${t("term_t")}</h3><div id="term-slot"><p class="dim">${t("term_starting")}</p></div>`;
  }
  view.innerHTML = html || `<p class="dim">—</p>`;
  if (canRun) {
    view.querySelectorAll("[data-run]").forEach((b) => b.onclick = async () => {
      b.disabled = true;
      try {
        const r = await api(`/api/commands/${b.dataset.run}/run`, { method: "POST" });
        alert("exit " + r.code + "\n" + r.output.slice(-2000));
        vConsole();
      } finally { b.disabled = false; }
    });
    if (has("commands_edit")) {
      $("#c-add").onclick = async () => {
        const argv = $("#c-argv").value.split("\n").map((s) => s.trim()).filter(Boolean);
        await api("/api/commands", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: $("#c-name").value.trim(),
            argv, run_as: $("#c-run").value.trim() || "owner",
            allowed: $("#c-allow").value.split(",").map((s) => s.trim()).filter(Boolean).map((s) => s === "*" ? "*" : +s) }) });
        vConsole();
      };
      const list = await api("/api/commands");
      $("#c-list").innerHTML = list.map((c) => `<div class="row"><span class="mono">#${c.id} ${esc(c.name)}</span>
        <button data-cdel="${c.id}" class="danger ghost">${ic("trash")}</button></div>`).join("");
      view.querySelectorAll("[data-cdel]").forEach((b) => b.onclick = async () => {
        if (!confirm(t("del_cmd_q"))) return;
        await api(`/api/commands/${b.dataset.cdel}`, { method: "DELETE" });
        vConsole();
      });
    }
  }
  if (canTerm) {
    try {
      const r = await api("/api/terminal/ensure", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      $("#term-slot").innerHTML =
        `<p class="dim"><span class="mono">${esc(r.slot)}</span> · 127.0.0.1:${r.port}</p>
         <iframe class="term" src="/term/${esc(r.slot)}/" title="terminal"></iframe>`;
    } catch (e) {
      $("#term-slot").innerHTML = `<p class="bad">${esc(e.message)}</p>`;
    }
  }
}

/* ---- files ---- */
let fPath = "", fSlot = "";
async function vFiles() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  await fRender();
}
async function fRender() {
  if (ME.is_admin && !fSlot) {
    view.innerHTML = `<div class="row"><input id="f-slot" placeholder="${t("slot_ph")}" style="max-width:180px">
      <button id="f-go" class="primary">${t("open")}</button></div>
      <p class="dim">${t("pick_slot")}</p>`;
    $("#f-go").onclick = () => { fSlot = $("#f-slot").value.trim(); fPath = ""; fRender(); };
    return;
  }
  const q = `?path=${encodeURIComponent(fPath)}${fSlot ? `&slot=${fSlot}` : ""}`;
  let list;
  try {
    list = await api("/api/files" + q);
  } catch (e) {
    view.innerHTML = `<p class="bad">${esc(e.message)}</p>`;
    return;
  }
  const quota = await api("/api/quota" + (fSlot ? `?slot=${fSlot}` : "")).catch(() => null);
  view.innerHTML = `
    ${ME.is_admin ? `<div class="row"><input id="f-slot" value="${esc(fSlot)}" placeholder="${t("slot_ph")}" style="max-width:160px">
      <button id="f-go">${t("open")}</button></div>` : ""}
    <div class="row"><span class="path">/${esc(fPath)}</span>
      ${quota ? `<span class="dim">${(quota.used / 1048576).toFixed(0)} MiB ${t("used")}${quota.limit ? " · " + t("limit") + " " + esc(quota.limit) : ""}</span>` : ""}
    </div>
    <table><tbody>
    ${fPath ? `<tr><td colspan="3"><button id="f-up" class="ghost">${ic("up")}${t("up")}</button></td></tr>` : ""}
    ${list.map((e) => `<tr><td><a href="#" data-p="${esc(fPath ? fPath + "/" + e.name : e.name)}" data-d="${e.dir ? 1 : 0}">${ic(e.dir ? "folder" : "file")} ${esc(e.name)}</a></td>
      <td class="dim mono">${e.dir ? "" : (e.size / 1024).toFixed(0) + " KiB"}</td>
      <td style="text-align:right"><button data-del="${esc(e.name)}" class="danger ghost" title="${t("del_q")}">${ic("trash")}</button></td></tr>`).join("")}
    </tbody></table>
    <div class="row"><input id="f-new" placeholder="${t("new_ph")}" style="max-width:220px">
      <button id="f-mkf">${ic("plus")}${t("file_btn")}</button><button id="f-mkd">${ic("plus")}${t("folder_btn")}</button></div>
    <div id="f-edit" class="hidden"><textarea id="f-text" spellcheck="false"></textarea>
      <div class="row"><button id="f-save" class="primary">${ic("check")}${t("save")}</button></div></div>`;
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
    if (!confirm(t("del_q") + " " + b.dataset.del + "?")) return;
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
    $("#f-save").innerHTML = ic("check") + t("saved");
    setTimeout(() => { const b = $("#f-save"); if (b) b.innerHTML = ic("check") + t("save"); }, 1500);
  };
}

/* ---- tunnel ---- */
async function vTunnel() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  const tun = await api("/api/tunnel");
  view.innerHTML = `<div class="box"><h3>${ic("link")}${t("tunnel_url")}</h3>
    <div class="url-big">${esc(tun.url || t("tunnel_none"))}</div>
    <div class="row"><button id="t-ref">${ic("refresh")}${t("refresh")}</button></div></div>`;
  $("#t-ref").onclick = async () => {
    await api("/api/tunnel/refresh", { method: "POST" });
    vTunnel();
  };
}

/* ---- users (admin) ---- */
async function vUsers() {
  const users = await api("/api/users");
  const info = await api("/api/rights");
  const ck = (r, usr) => `<label class="ck"><input type="checkbox" data-r="${r}" data-usr="${usr.id}" ${usr.rights[r] ? "checked" : ""}>${r}</label>`;
  view.innerHTML = `<h3>${ic("users")}${t("users_t")}</h3><table>
    <thead><tr><th>Login</th><th>Slot</th><th>Rights</th><th>Limits (JSON)</th><th></th></tr></thead><tbody>` +
    users.map((usr) => `<tr><td><b>${esc(usr.login)}</b>${usr.is_admin ? ' <span class="dim">admin</span>' : ""}${usr.must_change_pw ? ' <span class="dim">· must change pw</span>' : ""}</td>
      <td><input data-slot="${usr.id}" value="${esc(usr.slot || "")}" size="6"></td>
      <td>${info.rights.filter((r) => !info.admin_only.includes(r)).map((r) => ck(r, usr)).join("")}</td>
      <td><input data-lim="${usr.id}" value='${esc(JSON.stringify(usr.limits))}' size="18" class="mono"></td>
      <td style="white-space:nowrap"><button data-save="${usr.id}" title="${t("save_btn")}">${ic("check")}</button>
        <button data-pw="${usr.id}" title="${t("reset_pw")}">${ic("key")}</button>
        <button data-u-del="${usr.id}" class="danger ghost" title="${t("del_user_q")}">${ic("trash")}</button></td></tr>`).join("") +
    `</tbody></table>
    <h3>${t("new_user_t")}</h3><div class="row"><input id="nu-login" placeholder="Login" style="max-width:150px">
    <input id="nu-pass" type="password" placeholder="Temp password, 8+" style="max-width:170px">
    <input id="nu-slot" placeholder="Slot, e.g. u-c1" style="max-width:140px">
    <label class="ck"><input type="checkbox" id="nu-admin">admin</label>
    <button id="nu-add" class="primary">${ic("plus")}${t("add")}</button></div>
    <p class="dim">${t("temp_note")}</p>`;
  view.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
    const id = b.dataset.save;
    const rights = {};
    view.querySelectorAll(`[data-usr="${id}"]`).forEach((c) => rights[c.dataset.r] = c.checked);
    let limits = {};
    try { limits = JSON.parse(view.querySelector(`[data-lim="${id}"]`).value || "{}"); }
    catch { alert(t("bad_json")); return; }
    const r = await api(`/api/users/${id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rights, limits, slot: view.querySelector(`[data-slot="${id}"]`).value.trim() || null }) });
    alert(r.quota_applied ? t("quota_on") : t("saved_q") + (r.quota_msg ? " Quota: " + r.quota_msg : ""));
  });
  view.querySelectorAll("[data-pw]").forEach((b) => b.onclick = async () => {
    const p = prompt(t("pass_prompt")); if (!p) return;
    await api(`/api/users/${b.dataset.pw}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: p, must_change_pw: true }) });
    alert(t("pass_changed"));
  });
  view.querySelectorAll("[data-u-del]").forEach((b) => b.onclick = async () => {
    if (!confirm(t("del_user_q"))) return;
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
    <p class="dim">${t("tokens_hint")} <span class="mono">curl -H "Authorization: Bearer TOKEN" /api/tunnel</span></p>
    <div id="t-list"></div>
    <div class="row"><input id="nt-name" placeholder="${t("token_name_ph")}" style="max-width:170px">
    <label class="ck"><input type="checkbox" id="nt-tun" checked>tunnel_view</label>
    <button id="nt-add" class="primary">${ic("plus")}${t("new_token_btn")}</button></div>
    <pre id="nt-once" class="hidden"></pre>`);
  const reloadTokens = async () => {
    const toks = await api("/api/tokens");
    $("#t-list").innerHTML = toks.map((tk) => `<div class="row"><span class="mono">#${tk.id} <b>${esc(tk.name)}</b></span>
      <span class="dim">${esc(Object.keys(tk.rights).filter((k) => tk.rights[k]).join(", ") || "—")}
      · ${t("last_used")} ${tk.last_used_at ? new Date(tk.last_used_at * 1000).toLocaleString() : t("never")}</span>
      <button data-tdel="${tk.id}" class="danger ghost">${t("revoke_q").replace("?", "")}</button></div>`).join("") || `<p class="dim">${t("no_tokens")}</p>`;
    view.querySelectorAll("[data-tdel]").forEach((b) => b.onclick = async () => {
      if (!confirm(t("revoke_q"))) return;
      await api(`/api/tokens/${b.dataset.tdel}`, { method: "DELETE" });
      reloadTokens();
    });
  };
  $("#nt-add").onclick = async () => {
    const r = await api("/api/tokens", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("#nt-name").value.trim() || "bot",
        rights: { tunnel_view: $("#nt-tun").checked } }) });
    const p = $("#nt-once"); p.classList.remove("hidden");
    p.textContent = t("shown_once") + "\n" + r.token;
    reloadTokens();
  };
  reloadTokens();
}

boot();
