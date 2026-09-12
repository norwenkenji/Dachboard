/* dachboard SPA: 06-console. vanilla JS, no build. Loaded in order, shared globals. */

/* ---- console: presets + shell in one place ---- */
async function vConsole() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  const canRun = has("commands_run"), canTerm = has("terminal");
  let html = "";
  if (canTerm) {
    html += `<h3>${ic("term")}${t("term_t")}</h3><div id="term-slot"><p class="dim">${t("term_starting")}</p></div>`;
  }
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
    const paintTerm = (slot, port) => {
      const host = $("#term-slot");
      if (!host) return; // user switched tabs mid-flight
      const label = slot === "root" ? "system · root" : slot;
      host.innerHTML =
        `<div class="termbar"><span class="mono">${esc(label)} · 127.0.0.1:${port}</span>
         <span class="sp"></span>
         <button id="t-recon" class="ghost" title="${t("reconnect")}">${ic("refresh")}${t("reconnect")}</button>
         <button id="t-new" class="ghost danger" title="${t("new_shell")}">${ic("plus")}${t("new_shell")}</button></div>
         <iframe id="term-frame" class="term" src="/term/${esc(slot)}/" title="terminal"></iframe>`;
      styleTermFrame();
      $("#t-recon").onclick = () => {
        // reattach to the SAME shell session (tab switches never kill it)
        $("#term-frame").src = "/term/" + encodeURIComponent(slot) + "/";
        styleTermFrame();
      };
      $("#t-new").onclick = async () => {
        if (!confirm(t("new_shell_q"))) return;
        await api("/api/terminal/restart", { method: "POST",
          headers: { "Content-Type": "application/json" }, body: "{}" });
        $("#term-frame").src = "/term/" + encodeURIComponent(slot) + "/";
        styleTermFrame();
      };
    };
    const styleTermFrame = () => {
      const f = $("#term-frame");
      if (!f) return;
      const inject = () => {
        try {
          const d = f.contentDocument;
          if (!d || d.querySelector("#dach-term-css")) return;
          const s = d.createElement("style");
          s.id = "dach-term-css";
          s.textContent = ".xterm-viewport{scrollbar-width:thin;scrollbar-color:#2e3238 transparent}"
            + ".xterm-viewport::-webkit-scrollbar{width:10px;height:10px}"
            + ".xterm-viewport::-webkit-scrollbar-track{background:transparent}"
            + ".xterm-viewport::-webkit-scrollbar-thumb{background:#2e3238;border-radius:6px;border:2px solid #000}"
            + ".xterm-viewport::-webkit-scrollbar-thumb:hover{background:#3d434b}"
            + ".xterm-screen,.xterm-viewport{background-color:#0b0e0c !important}";
          d.head.appendChild(s);
        } catch (e) { /* cross-origin: leave default */ }
      };
      f.onload = inject;
      // cached iframe may already be complete before onload attaches
      try {
        if (f.contentDocument && f.contentDocument.readyState === "complete") inject();
      } catch (e) { /* not ready yet, onload will fire */ }
    };
    try {
      const r = await api("/api/terminal/ensure", { method: "POST",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      paintTerm(r.slot, r.port);
    } catch (e) {
      const host = $("#term-slot");
      if (host) host.innerHTML = `<p class="bad">${esc(e.message)}</p>`;
    }
  }
}
