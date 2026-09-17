/* dachboard SPA: 08-users. vanilla JS, no build. Loaded in order, shared globals. */
/* ---- users (admin) ---- */
async function vUsers() {
  const users = await api("/api/users");
  const info = await api("/api/rights");
  const rname = (r) => t("right_" + r);
  const rdesc = (r) => t("right_" + r + "_d");
  const ck = (r, usr) => `<label class="ck ck-stack"><input type="checkbox" data-r="${r}" data-usr="${usr.id}" ${usr.rights[r] ? "checked" : ""}><span><b>${esc(rname(r))}</b><small class="dim">${esc(rdesc(r))}</small></span></label>`;
  view.innerHTML = `<h3>${ic("users")}${t("users_t")}</h3><table class="users-table">
    <thead><tr><th>${t("th_login")}</th><th>${t("th_rights")}</th><th></th></tr></thead><tbody>` +
    users.map((usr) => `<tr><td><span class="who${usr.is_admin ? " adm" : ""}" title="${usr.is_admin ? "admin" : "user"}">${ic(usr.is_admin ? "shield" : "user")}<b>${esc(usr.login)}</b></span>${usr.must_change_pw ? ' <span class="dim">· must change pw</span>' : ""}</td>
      <td><span class="rights-list">${info.rights.filter((r) => !info.admin_only.includes(r)).map((r) => ck(r, usr)).join("")}</span>
      <div class="lim-row"><label>${t("cpu")}<input data-lim-cpu="${usr.id}" value="${esc(((usr.limits) || {}).cpu_quota || "")}" placeholder="50%"></label><label>${t("memory")}<input data-lim-mem="${usr.id}" value="${esc(((usr.limits) || {}).mem_max || "")}" placeholder="1G"></label><label>${t("disk")}<input data-lim-disk="${usr.id}" value="${esc(((usr.limits) || {}).disk_quota || "")}" placeholder="2G"></label></div></td>
      <td style="white-space:nowrap"><button data-save="${usr.id}" title="${t("save_btn")}">${ic("check")}</button>
        <button data-pw="${usr.id}" title="${t("reset_pw")}">${ic("key")}</button>
        <button data-u-del="${usr.id}" class="danger ghost" title="${t("del_user_q")}">${ic("trash")}</button></td></tr>`).join("") +
    `</tbody></table>
    <h3>${t("new_user_t")}</h3><div class="row"><input id="nu-login" placeholder="Login" style="max-width:150px">
    <input id="nu-pass" type="password" placeholder="Temp password, 8+" style="max-width:170px">
    <input id="nu-slot" placeholder="${t("slot_ph")}" style="max-width:140px" title="${esc(t("slot_hint"))}">
    <label class="ck"><input type="checkbox" id="nu-admin">admin</label>
    <button id="nu-add" class="primary">${ic("plus")}${t("add")}</button></div>
    <p class="dim">${t("temp_note")}</p>`;
  view.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
    const id = b.dataset.save;
    const rights = {};
    view.querySelectorAll(`[data-usr="${id}"]`).forEach((c) => rights[c.dataset.r] = c.checked);
    const lv = (k) => { const el = view.querySelector(`[data-lim-${k}="${id}"]`); return el ? el.value.trim() : ""; };
    const limits = { cpu_quota: lv("cpu"), mem_max: lv("mem"), disk_quota: lv("disk") };
    const r = await api(`/api/users/${id}`, { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rights, limits }) });
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
    <input id="nt-slot" placeholder="${t("token_slot_ph")}" style="max-width:140px">
    <label class="ck"><input type="checkbox" id="nt-tun" checked>${esc(t("right_tunnel_view"))}</label>
    <label class="ck"><input type="checkbox" id="nt-admin">${esc(t("token_admin"))}</label>
    <button id="nt-add" class="primary">${ic("plus")}${t("new_token_btn")}</button></div>
    <p class="dim">${t("token_admin_d")}</p>
    <pre id="nt-once" class="hidden"></pre>`);
  const reloadTokens = async () => {
    const toks = await api("/api/tokens");
    const host = $("#t-list");
    if (!host || !host.isConnected) return; // user switched tabs mid-flight
    host.innerHTML = toks.map((tk) => `<div class="row"><span class="mono">#${tk.id} <b>${esc(tk.name)}</b>${tk.is_admin ? ` ${ic("star")}` : ""}${tk.slot ? ` <span class="dim">${esc(tk.slot)}</span>` : ""}</span>
      <span class="dim">${esc(Object.keys(tk.rights).filter((k) => tk.rights[k]).map(rname).join(", ") || "—")}
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
        slot: $("#nt-slot").value.trim() || null,
        is_admin: $("#nt-admin").checked,
        rights: { tunnel_view: $("#nt-tun").checked } }) });
    const p = $("#nt-once"); p.classList.remove("hidden");
    p.textContent = t("shown_once") + "\n" + r.token;
    reloadTokens();
  };
  reloadTokens();
}
