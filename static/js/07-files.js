/* dachboard SPA: 07-files. vanilla JS, no build. Loaded in order, shared globals. */

/* ---- files: explorer ---- */
let fPath = "";
let fClip = null; // {mode:"cut"|"copy", src}
let fSel = null;
const fCache = new Map(); // path -> {ts, list, quota}; busted on every mutation
const fBust = () => fCache.clear();

const EXT_ICON = (() => {
  const groups = {
    code: "js,ts,tsx,jsx,mjs,cjs,py,sh,bash,zsh,json,yml,yaml,xml,html,htm,css,scss,c,h,cpp,hpp,go,rs,java,rb,php,sql,toml,ini,cfg,conf,env,service,timer,socket,unit,pl",
    ftext: "txt,md,markdown,log,nfo,pdf",
    img: "png,jpg,jpeg,gif,webp,svg,bmp,ico",
    video: "mp4,mkv,webm,avi,mov",
    music: "mp3,wav,ogg,flac,m4a",
    box: "zip,tar,gz,tgz,bz2,xz,rar,7z",
    doc: "doc,docx,odt,rtf",
    sheet: "xls,xlsx,csv,ods",
    db: "sqlite3,sqlite,db",
  };
  const map = {};
  for (const k in groups) groups[k].split(",").forEach((e) => (map[e] = k));
  return map;
})();
const TEXT_EXTS = new Set(
  "txt,md,markdown,log,json,yml,yaml,xml,html,htm,css,scss,js,ts,tsx,jsx,mjs,cjs,py,sh,bash,zsh,toml,ini,cfg,conf,env,c,h,cpp,hpp,go,rs,java,rb,php,sql,pl,service,timer,socket,unit,nfo".split(","));
function ficon(name, dir) {
  if (dir) return "folder";
  const e = (name.split(".").pop() || "").toLowerCase();
  return EXT_ICON[e] || "file";
}
function mediaKind(name) {
  const e = (name.split(".").pop() || "").toLowerCase();
  const k = EXT_ICON[e];
  if (k === "img") return "image";
  if (k === "video") return "video";
  if (k === "music") return "audio";
  if (e === "pdf") return "pdf";
  if (TEXT_EXTS.has(e)) return "text";
  return "bin";
}
const fmtSize = (b) => (b > 1048576 ? (b / 1048576).toFixed(1) + " MiB" : Math.max(1, Math.round(b / 1024)) + " KiB");
const fmtDate = (ts) => { try { return new Date(ts * 1000).toLocaleString(); } catch { return ""; } };
const relOf = (name) => (fPath ? fPath + "/" + name : name);

function closeMenu() { document.querySelector(".ctxmenu")?.remove(); }
if (!window.__dachMenuInit) {
  window.__dachMenuInit = true;
  document.addEventListener("click", closeMenu);
  document.addEventListener("scroll", closeMenu, true);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeMenu(); closeModal(); }
  });
}
function openMenu(x, y, items) {
  closeMenu();
  const m = document.createElement("div");
  m.className = "ctxmenu";
  items.forEach(([label, icon, fn, dis, danger]) => {
    if (label === "-") {
      const s = document.createElement("div");
      s.className = "ctxsep";
      m.appendChild(s);
      return;
    }
    const b = document.createElement("button");
    b.innerHTML = ic(icon) + "<span>" + esc(label) + "</span>";
    b.disabled = !!dis;
    if (danger) b.classList.add("danger");
    b.onclick = (ev) => { ev.stopPropagation(); closeMenu(); if (fn) fn(); };
    m.appendChild(b);
  });
  document.body.appendChild(m);
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(8, Math.min(x, innerWidth - r.width - 8)) + "px";
  m.style.top = Math.max(8, Math.min(y, innerHeight - r.height - 8)) + "px";
}

function closeModal() { document.getElementById("modal-root").innerHTML = ""; }
function modal(html) {
  const root = document.getElementById("modal-root");
  root.innerHTML = `<div class="overlay" id="m-ov"><div class="modal">
    <div class="row" style="justify-content:flex-end;margin:0 0 8px"><button id="m-x" class="ghost">${ic("x")}${t("fm_close")}</button></div>
    <div id="m-body">${html}</div></div></div>`;
  $("#m-x").onclick = closeModal;
  $("#m-ov").addEventListener("mousedown", (e) => { if (e.target.id === "m-ov") closeModal(); });
}

async function previewFile(name) {
  const rel = relOf(name);
  const kind = mediaKind(name);
  const url = u("/api/files/download?path=" + encodeURIComponent(rel));
  if (kind === "image") { modal(`<img src="${url}" alt="">`); return; }
  if (kind === "video") { modal(`<video src="${url}" controls></video>`); return; }
  if (kind === "audio") { modal(`<audio src="${url}" controls style="width:100%"></audio>`); return; }
  if (kind === "pdf") {
    modal(`<iframe src="${url}" style="width:80vw;height:75vh;border:0;border-radius:8px;background:#fff"></iframe>`);
    return;
  }
  if (kind === "text") {
    let content = "";
    try {
      content = (await api(`/api/files/read?path=${encodeURIComponent(rel)}`)).content;
    } catch (e) { modal(`<p class="bad">${esc(e.message)}</p>`); return; }
    modal(`<div class="dim mono" style="margin-bottom:8px">${esc(rel)}</div>
      <textarea id="m-text" spellcheck="false"></textarea>
      <div class="row"><button id="m-save" class="primary">${ic("check")}${t("save")}</button>
      <a class="btn ghost" href="${url}">${ic("trash")}${t("fm_download")}</a></div>`);
    $("#m-text").value = content;
    $("#m-save").onclick = async () => {
      await api("/api/files/write", { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: rel, content: $("#m-text").value }) });
      $("#m-save").innerHTML = ic("check") + t("saved");
      setTimeout(closeModal, 600);
      fRender();
    };
    return;
  }
  modal(`<p>${esc(rel)}</p><p class="dim">${t("fm_binary")}</p>
    <div class="row"><a class="btn primary" href="${url}">${ic("trash")}${t("fm_download")}</a></div>`);
}

async function vFiles() {
  view.innerHTML = `<p class="dim">${t("loading")}</p>`;
  await fRender();
}

async function fRender() {
  const q = `?path=${encodeURIComponent(fPath)}`;
  let list, quota;
  const hit = fCache.get(fPath);
  if (hit && Date.now() - hit.ts < 5000) {
    list = hit.list;
    quota = hit.quota;
  } else {
    try {
      const r = await api("/api/files" + q);
      list = r.entries;
      quota = r.quota;
      fCache.set(fPath, { ts: Date.now(), list, quota });
      if (fCache.size > 40) fCache.delete(fCache.keys().next().value);
    } catch (e) {
      view.innerHTML = `<p class="bad">${esc(e.message)}</p>`;
      return;
    }
  }
  const parts = fPath ? fPath.split("/") : [];
  let crumbs = `<button data-crumb="" title="/">${ic("folder")}</button>`;
  crumbs += parts.map((p, i) =>
    `<span class="dim">/</span><button data-crumb="${esc(parts.slice(0, i + 1).join("/"))}">${esc(p)}</button>`).join("");
  view.innerHTML = `
    <div class="crumbs">${crumbs}</div>
    <div class="row">
      <button id="f-up" class="ghost" title="${t("up")}">${ic("up")}</button>
      <button id="f-ref" class="ghost" title="${t("refresh")}">${ic("refresh")}</button>
      <button id="f-mkf">${ic("plus")}${t("fm_new_file")}</button>
      <button id="f-mkd">${ic("plus")}${t("fm_new_folder")}</button>
      <button id="f-upl">${ic("up")}${t("fm_upload")}</button>
      <button id="f-paste" ${fClip ? "" : "disabled"}>${ic("check")}${t("fm_paste")}</button>
      ${quota ? `<span class="dim">${(quota.used / 1048576).toFixed(0)} MiB ${t("used")}${quota.limit ? " · " + t("limit") + " " + esc(quota.limit) : ""}</span>` : ""}
      <input type="file" id="f-upfile" class="hidden" multiple>
      <input type="file" id="f-updir" class="hidden" webkitdirectory>
    </div>
    <div id="f-drop" class="dropzone">${t("fm_drop_hint")}</div>
    <table id="f-table"><thead><tr><th>${t("th_name")}</th><th></th><th></th></tr></thead><tbody>
    ${list.length ? list.map((e) => `<tr data-name="${esc(e.name)}" data-dir="${e.dir ? 1 : 0}">
      <td><span class="fname">${ic(ficon(e.name, e.dir))} ${esc(e.name)}</span></td>
      <td class="dim mono">${e.dir ? "" : fmtSize(e.size)}</td>
      <td class="dim">${fmtDate(e.mtime)}</td></tr>`).join("")
      : `<tr><td colspan="3" class="dim">${t("fm_empty")}</td></tr>`}
    </tbody></table>`;
  view.querySelectorAll("[data-crumb]").forEach((b) => (b.onclick = () => {
    fPath = b.dataset.crumb; fSel = null; fRender();
  }));
  const up = $("#f-up"); if (up) up.onclick = () => {
    fPath = fPath.split("/").slice(0, -1).join("/"); fSel = null; fRender();
  };
  $("#f-ref").onclick = fRender;
  $("#f-mkf").onclick = () => inlineCreate(false);
  $("#f-mkd").onclick = () => inlineCreate(true);
  $("#f-upl").onclick = () => $("#f-upfile").click();

  /* upload queue: multiple files, folders (webkitRelativePath), drag&drop */
  const upQueue = async (fileList, basePath = "") => {
    const files = [...fileList];
    if (!files.length) return;
    const dz = $("#f-drop");
    const dzText = () => dz ? dz.textContent : "";
    let done = 0;
    const upd = () => { if (dz) dz.textContent = `${t("fm_uploading")} ${done}/${files.length}`; };
    upd();
    for (const f of files) {
      const rel = f.webkitRelativePath || f.name;
      const relDir = (basePath + "/" + rel).replace(/^\/+/, "").split("/").slice(0, -1).join("/");
      const fd = new FormData();
      fd.append("file", f, rel.split("/").pop());
      const q = relDir ? "?path=" + encodeURIComponent(relDir) : "?path=" + encodeURIComponent(fPath);
      try {
        const r = await fetch(u("/api/files/upload" + q), {
          method: "POST", headers: CSRF ? { "X-CSRF-Token": CSRF } : {}, body: fd });
        if (!r.ok) alert(`${rel}: ${(await r.text()).slice(0, 200)}`);
      } catch (e) { alert(`${rel}: ${e.message}`); }
      done++;
      upd();
    }
    if (dz) { dz.textContent = t("fm_done"); setTimeout(() => fRender(), 400); }
  };
  $("#f-upfile").onchange = async (ev) => {
    await upQueue(ev.target.files);
    ev.target.value = "";
  };
  const dirInput = $("#f-updir");
  if (dirInput) dirInput.onchange = async (ev) => {
    await upQueue(ev.target.files);
    ev.target.value = "";
  };
  const dz = $("#f-drop");
  if (dz) {
    ["dragenter", "dragover"].forEach((n) => dz.addEventListener(n, (e) => {
      e.preventDefault(); dz.classList.add("over");
    }));
    ["dragleave", "drop"].forEach((n) => dz.addEventListener(n, (e) => {
      e.preventDefault(); dz.classList.remove("over");
    }));
    dz.addEventListener("drop", async (e) => {
      const items = [...(e.dataTransfer?.items || [])];
      const files = [...(e.dataTransfer?.files || [])];
      // directories first: walk them via webkitGetAsEntry
      const entries = items.map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
      if (entries.length && entries.every((en) => en.isDirectory || en.isFile)) {
        const all = [];
        const walk = (entry, prefix) => new Promise((res) => {
          if (entry.isFile) {
            entry.file((f) => { f.webkitRelativePath = prefix + entry.name; all.push(f); res(); });
          } else {
            const reader = entry.createReader();
            const read = () => reader.readEntries(async (batch) => {
              if (!batch.length) return res();
              for (const en of batch) await walk(en, prefix + entry.name + "/");
              read();
            });
            read();
          }
        });
        for (const en of entries) await walk(en, "");
        await upQueue(all);
      } else if (files.length) {
        await upQueue(files);
      }
    });
  }
  $("#f-paste").onclick = doPaste;
  const rows = view.querySelectorAll("#f-table tbody tr[data-name]");
  rows.forEach((tr) => {
    const name = tr.dataset.name, isDir = tr.dataset.dir === "1";
    if (name === fSel) tr.classList.add("sel");
    tr.onclick = () => {
      fSel = name;
      view.querySelectorAll("#f-table tr").forEach((x) => x.classList.remove("sel"));
      tr.classList.add("sel");
    };
    tr.ondblclick = () => {
      if (isDir) { fPath = relOf(name); fSel = null; fRender(); }
      else previewFile(name);
    };
    tr.oncontextmenu = (e) => {
      e.preventDefault();
      fSel = name;
      rowMenu(e.clientX, e.clientY, name, isDir);
    };
  });
  view.querySelector("#f-table").oncontextmenu = (e) => {
    if (e.target.closest("tr[data-name]")) return;
    e.preventDefault();
    freshMenu(e.clientX, e.clientY);
  };
}

function rowMenu(x, y, name, isDir) {
  openMenu(x, y, [
    [t("fm_open"), isDir ? "folder" : "file", () => {
      if (isDir) { fPath = relOf(name); fSel = null; fRender(); }
      else previewFile(name);
    }],
    [t("fm_rename"), "edit", () => inlineRename(name)],
    [t("fm_download"), "download", () => {
      if (isDir) return;
      const a = document.createElement("a");
      a.href = u("/api/files/download?path=" + encodeURIComponent(relOf(name)));
      a.download = name;
      a.click();
    }, isDir],
    [t("fm_unzip"), "box", () => doUnzip(name), isDir || !/\.zip$/i.test(name)],
    ["-", null, null],
    [t("fm_copy"), "copy", () => { fClip = { mode: "copy", src: relOf(name) }; fRender(); }],
    [t("fm_cut"), "cut", () => { fClip = { mode: "cut", src: relOf(name) }; fRender(); }],
    [t("fm_paste"), "clipboard", doPaste, !fClip],
    ["-", null, null],
    [t("del_q"), "trash", () => doDelete(name), false, true],
  ]);
}

function freshMenu(x, y) {
  openMenu(x, y, [
    [t("fm_new_file"), "file", () => inlineCreate(false)],
    [t("fm_new_folder"), "folder", () => inlineCreate(true)],
    [t("fm_upload"), "download", () => document.getElementById("f-upfile")?.click()],
    [t("fm_upload_dir"), "folder", () => document.getElementById("f-updir")?.click()],
    [t("fm_paste"), "clipboard", doPaste, !fClip],
  ]);
}

async function doUnzip(name) {
  if (!/\.zip$/i.test(name)) return;
  const into = prompt(t("fm_unzip_into"), relOf(name).replace(/\.zip$/i, ""));
  if (into === null) return;
  try {
    const r = await api("/api/files/unzip", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: relOf(name), into: into.trim() }) });
    alert(t("fm_unzipped").replace("%n", r.files));
  } catch (e) { alert(e.message); }
  fBust();
  fRender();
}

async function doDelete(name) {
  const target = name || fSel;
  if (!target) return;
  if (!confirm(t("del_q") + " " + target + "?")) return;
  await api("/api/files/delete", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: relOf(target) }) });
  if (fSel === target) fSel = null;
  fBust();
  fRender();
}

async function doPaste() {
  if (!fClip) return;
  const base = fClip.src.split("/").pop();
  const dst = fPath ? fPath + "/" + base : base;
  if (dst === fClip.src) { fClip = null; fRender(); return; }
  const ep = fClip.mode === "cut" ? "move" : "copy";
  await api("/api/files/" + ep, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: fClip.src, to: dst }) });
  fClip = null;
  fBust();
  fRender();
}

function inlineRename(name) {
  const tr = view.querySelector(`#f-table tr[data-name="${CSS.escape(name)}"] .fname`);
  if (!tr) return;
  tr.innerHTML = `<input id="f-ren" value="${esc(name)}" spellcheck="false">`;
  const inp = document.getElementById("f-ren");
  inp.focus();
  inp.setSelectionRange(0, name.lastIndexOf(".") > 0 ? name.lastIndexOf(".") : name.length);
  const commit = async () => {
    const nn = inp.value.trim();
    if (nn && nn !== name && !nn.includes("/")) {
      await api("/api/files/move", { method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: relOf(name), to: fPath ? fPath + "/" + nn : nn }) });
      if (fSel === name) fSel = nn;
    }
    fBust();
    fRender();
  };
  inp.onkeydown = (e) => {
    if (e.key === "Enter") commit();
    if (e.key === "Escape") fRender();
    e.stopPropagation();
  };
  inp.onblur = () => fRender();
}

function inlineCreate(isDir) {
  const tb = view.querySelector("#f-table tbody");
  if (!tb || document.getElementById("f-new-inp")) return;
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${ic(isDir ? "folder" : "file")} <input id="f-new-inp" placeholder="${t("fm_name_ph")}" spellcheck="false"></td><td></td><td></td>`;
  tb.prepend(tr);
  const inp = document.getElementById("f-new-inp");
  inp.focus();
  const commit = async () => {
    const nn = inp.value.trim();
    if (nn && !nn.includes("/")) {
      const rel = fPath ? fPath + "/" + nn : nn;
      if (isDir) {
        await api("/api/files/mkdir", { method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: rel }) });
      } else {
        await api("/api/files/write", { method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: rel, content: "" }) });
      }
      fSel = nn;
    }
    fBust();
    fRender();
  };
  inp.onkeydown = (e) => {
    if (e.key === "Enter") commit();
    if (e.key === "Escape") fRender();
    e.stopPropagation();
  };
  inp.onblur = () => { if (document.getElementById("f-new-inp")) fRender(); };
}
