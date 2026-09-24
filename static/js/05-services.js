/* dachboard SPA: 05-services. vanilla JS, no build. Loaded in order, shared globals. */

/* ---- services: docker + systemd ---- */
function stateDot(s) {
  const on = /run|up/i.test(s || "") || /active/i.test(s || "");
  return dot(on) + esc(s || "—");
}
async function vServices() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  /* docker and systemd are separate rights: containers_* delegates, services_*
     is host-wide root systemctl and stays admin-only (see rbac.ADMIN_ONLY).
     Fetch only what this user may see, or the tab would die on a 403. */
  const canDocker = has("containers_view"), canUnits = has("services_view");
  const dockerCtrl = has("containers_control"), unitCtrl = has("services_control");
  const [list, units] = await Promise.all([
    canDocker ? api("/api/containers").catch(() => []) : Promise.resolve([]),
    canUnits ? api("/api/services").catch(() => []) : Promise.resolve([]),
  ]);
  const SYS = /^(systemd-|sys-|dev-|proc-|serial-getty|console-getty|getty@|user@|user-runtime|dbus|avahi|bluetooth|cups|ModemManager|polkit|udisks2|upower|accounts-daemon|rsyslog|unattended-upgrades|apport|whoopsie|thermald|irqbalance|lvm2-|dm-event|grub-|apt-|man-db|logrotate|e2scrub|fstrim|motd-news|update-notifier|packagekit|snapd|salt-|mdmonitor)/;
  // ghosts like dead connman.service come from --all with load=not-found
  const isSys = (s) => s.load === "not-found" || SYS.test(s.unit);
  const btns = (kind, name, allowed) => allowed
    ? `<button data-sact="restart:${kind}:${esc(name)}" title="${t("restart")}">${ic("refresh")}</button>
       <button data-sact="stop:${kind}:${esc(name)}" title="${t("stop")}">${ic("stop")}</button>
       <button data-sact="start:${kind}:${esc(name)}" title="${t("start")}">${ic("play")}</button>` : "";
  const dockerHtml = !canDocker ? "" : `
    <h3>${ic("box")}${t("docker_t")}</h3>
    <div class="row"><input id="c-filter" placeholder="${t("search_ph")}" style="max-width:220px"></div>
    <table><thead><tr><th>${t("th_name")}</th><th>${t("th_image")}</th><th>${t("th_state")}</th><th>${t("th_status")}</th><th></th></tr></thead><tbody id="c-rows">
    ${list.map((c) => `<tr data-n="${esc((c.Names || "").toLowerCase())}"><td class="mono"><b>${esc(c.Names)}</b></td><td class="dim mono">${esc(c.Image)}</td>
      <td>${stateDot(c.State)}</td><td class="dim">${esc(c.Status || "")}</td>
      <td style="white-space:nowrap"><button data-clog="${esc(c.Names)}">${t("logs")}</button>${btns("docker", c.Names, dockerCtrl)}</td></tr>`).join("")}
    </tbody></table>`;
  const unitsHtml = !canUnits ? "" : `
    <h3>${ic("grid")}${t("systemd_t")}</h3>
    <div class="row"><input id="s-filter" placeholder="${t("search_ph")}" style="max-width:220px">
    <label class="ck"><input type="checkbox" id="s-sys">${t("show_system")}</label>
    <span class="dim" id="s-count"></span></div>
    <table><thead><tr><th>${t("th_unit")}</th><th>${t("th_active")}</th><th>${t("th_desc")}</th><th></th></tr></thead><tbody id="s-rows">
    ${units.map((s) => `<tr data-n="${esc(s.unit.toLowerCase())}" data-sys="${isSys(s) ? 1 : 0}"><td class="mono"><b>${esc(s.unit)}</b></td>
      <td>${stateDot(s.active)}</td><td class="dim">${esc(s.desc)}</td>
      <td style="white-space:nowrap"><button data-slog="${esc(s.unit)}">${t("logs")}</button>${btns("unit", s.unit, unitCtrl)}</td></tr>`).join("")}
    </tbody></table>`;
  view.innerHTML = `${dockerHtml}${unitsHtml}
    ${dockerHtml || unitsHtml ? "" : `<p class="dim">—</p>`}
    <pre id="slog" class="hidden"></pre>`;
  const showLog = async (text) => {
    const p = $("#slog"); p.classList.remove("hidden"); p.textContent = text;
    p.scrollTop = p.scrollHeight;
  };
  view.querySelectorAll("[data-clog]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/containers/${encodeURIComponent(b.dataset.clog)}/logs?tail=200`);
    showLog(l.logs);
  });
  view.querySelectorAll("[data-slog]").forEach((b) => b.onclick = async () => {
    const l = await api(`/api/services/${encodeURIComponent(b.dataset.slog)}/logs?tail=200`);
    showLog(l.logs);
  });
  view.querySelectorAll("[data-sact]").forEach((b) => b.onclick = async () => {
    const m = b.dataset.sact.match(/^(restart|stop|start):(docker|unit):(.+)$/);
    if (!m) return;
    const [, act, kind, name] = m;
    if (!confirm(`${act} ${name}?`)) return;
    const url = kind === "docker"
      ? `/api/containers/${encodeURIComponent(name)}/${act}`
      : `/api/services/${encodeURIComponent(name)}/${act}`;
    const r = await api(url, { method: "POST" });
    alert("exit " + r.code + "\n" + (r.output || "").slice(-500));
    vServices();
  });
  const applyFilters = () => {
    const cf = $("#c-filter");
    if (cf) {
      const cq = (cf.value || "").toLowerCase();
      view.querySelectorAll("#c-rows tr").forEach((tr) =>
        tr.style.display = tr.dataset.n.includes(cq) ? "" : "none");
    }
    const sf = $("#s-filter"), ssys = $("#s-sys");
    if (!sf || !ssys) return;
    const q = (sf.value || "").toLowerCase();
    const showSys = ssys.checked;
    let n = 0, hidden = 0;
    view.querySelectorAll("#s-rows tr").forEach((tr) => {
      const sys = tr.dataset.sys === "1";
      const ok = tr.dataset.n.includes(q) && (showSys || !sys);
      tr.style.display = ok ? "" : "none";
      if (ok) n++; else if (sys && tr.dataset.n.includes(q)) hidden++;
    });
    $("#s-count").textContent = hidden && !showSys
      ? `${n} · ${hidden} ${t("sys_hidden")}` : `${n}`;
  };
  const cf = $("#c-filter"); if (cf) cf.oninput = applyFilters;
  const sf = $("#s-filter"); if (sf) sf.oninput = applyFilters;
  const ssys = $("#s-sys"); if (ssys) ssys.onchange = applyFilters;
  applyFilters();
}
