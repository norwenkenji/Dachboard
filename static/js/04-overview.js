/* dachboard SPA: 04-overview. vanilla JS, no build. Loaded in order, shared globals. */

/* ---- overview: rows, not tiles ---- */
async function vOverview() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  try {
    const m = await api("/api/metrics");
    const svcs = await api("/api/services").catch(() => []);
    const tun = await api("/api/tunnel").catch(() => ({ url: null }));
    const bad = svcs.filter((s) => s.active === "failed");
    const pct = (a, b) => (b ? Math.min(100, (a / b) * 100) : 0).toFixed(0);
    const temps = Object.entries(m.temps || {})
      .map(([k, v]) => `<div class="trow"><span>${esc(k)}</span><b>${v}°</b></div>`).join("");
    const h = m.host || {};
    view.innerHTML = `
      <div class="panel">
        <div class="vrow"><span class="vk">${t("host")}</span>
          <span class="vv mono">${esc(h.hostname || "—")}</span></div>
        <div class="vrow"><span class="vk">${t("hw_cpu")}</span>
          <span class="vv">${esc(h.cpu_model || "—")}${h.cpu_cores ? ` · ${h.cpu_cores} ${t("cores")}` : ""}</span></div>
        <div class="vrow"><span class="vk">${t("hw_ram")}</span>
          <span class="vv mono">${fmtGB(m.mem.total)} G</span></div>
        <div class="vrow"><span class="vk">${t("hw_disk")}</span>
          <span class="vv mono">${fmtGB(m.disk.total)} G</span></div>
        <div class="vrow"><span class="vk">${t("hw_sys")}</span>
          <span class="vv">${esc([h.os, h.kernel, h.arch].filter(Boolean).join(" · ") || "—")}</span></div>
      </div>
      <div class="panel" style="margin-top:10px">
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
        ${has("tunnel_view") ? `<div class="vrow"><span class="vk">${t("tunnel_url")}</span>
          <span class="vv mono" style="overflow:hidden;text-overflow:ellipsis">${esc(tun.url || t("tunnel_none"))}</span></div>` : ""}
      </div>
      <div class="row"><button id="ov-ref">${ic("refresh")}${t("refresh")}</button></div>`;
    $("#ov-ref").onclick = vOverview;
  } catch (e) { view.innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
}
