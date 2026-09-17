/* dachboard SPA: 10-api. API + MCP instructions tab (admin). */
const API_ENDPOINTS = [
  ["GET", "/api/metrics", "overview", "CPU/RAM/disk/temp/load snapshot"],
  ["GET", "/api/metrics/history", "overview", "last 24h of metrics"],
  ["GET", "/api/services", "overview", "systemd units list"],
  ["GET", "/api/services/{name}/logs", "containers_view", "journal of a unit"],
  ["POST", "/api/services/{name}/{action}", "containers_control", "start/stop/restart a unit"],
  ["GET", "/api/containers", "containers_view", "docker ps"],
  ["GET", "/api/containers/{name}/logs", "containers_view", "container logs"],
  ["POST", "/api/containers/{name}/{action}", "containers_control", "start/stop/restart container"],
  ["GET", "/api/files?path=&slot=", "files", "list directory"],
  ["GET", "/api/files/read?path=", "files", "read text file"],
  ["GET", "/api/files/download?path=", "files", "download file"],
  ["POST", "/api/files/write", "files", "write text file {path, content}"],
  ["POST", "/api/files/mkdir", "files", "create directory {path}"],
  ["POST", "/api/files/delete", "files", "delete file/dir {path}"],
  ["POST", "/api/files/move", "files", "rename/move {path, to}"],
  ["POST", "/api/files/copy", "files", "copy {path, to}"],
  ["POST", "/api/files/upload?path=", "files", "multipart upload (field 'file')"],
  ["POST", "/api/files/unzip", "files", "unpack zip {path, into?}"],
  ["GET", "/api/commands", "commands_run", "preset commands list"],
  ["POST", "/api/commands", "commands_edit", "create {name, argv, run_as, allowed, timeout_sec}"],
  ["PUT", "/api/commands/{id}", "commands_edit", "update command"],
  ["DELETE", "/api/commands/{id}", "commands_edit", "delete command"],
  ["POST", "/api/commands/{id}/run", "commands_run", "run preset, returns {code, output}"],
  ["GET", "/api/runs", "commands_run", "recent runs"],
  ["GET", "/api/tunnel", "tunnel_view", "public tunnel URL"],
  ["POST", "/api/tunnel/refresh", "tunnel_view", "drop tunnel URL cache"],
  ["GET", "/api/me", "—", "current user or token info"],
  ["GET", "/api/users", "users_manage", "users list (admin)"],
  ["POST", "/api/users", "users_manage", "create user {login, password, slot?, is_admin?} — a new slot name is provisioned"],
  ["PUT", "/api/users/{id}", "users_manage", "update rights/limits/slot"],
  ["DELETE", "/api/users/{id}", "users_manage", "delete user + sessions"],
  ["GET", "/api/rights", "users_manage", "rights matrix"],
  ["GET", "/api/slots", "users_manage", "registered slots + their ports"],
  ["POST", "/api/slots", "users_manage", "provision a slot {slot} — linux user, home, quota, ttyd, nginx gate"],
  ["DELETE", "/api/slots/{slot}", "users_manage", "remove slot, {wipe?} deletes user + home"],
  ["POST", "/api/terminal/ensure", "terminal", "start the slot's ttyd, returns {slot, port}"],
  ["POST", "/api/terminal/restart", "terminal", "fresh shell in the slot"],
  ["POST", "/api/tokens", "users_manage", "mint API token {name, slot?, is_admin?}"],
];

const API_DOC = {
en: {
  rest_t: "REST API",
  rest_d: "Everything the UI does is an API call. Machines authenticate with an API token from the Users tab:",
  rest_curl: "curl example",
  mcp_t: "MCP — let an LLM drive this server",
  mcp_d1: "Download the stdio MCP server (python 3.10+, no dependencies) and point your MCP client at it. The token's rights are the hard ceiling for the model.",
  mcp_step1: "1. Create a token in the Users tab (tick admin for full access — a token still cannot manage users).",
  mcp_step2: "2. Download the script:",
  mcp_step3: "3. Add to your MCP client config:",
  mcp_step4: "4. Verify:",
  dl_btn: "Download dachboard_mcp.py",
  tools_t: "Tools the model gets",
  ep_method: "Method", ep_path: "Endpoint", ep_right: "Right needed", ep_what: "What it does",
},
ru: {
  rest_t: "REST API",
  rest_d: "Всё, что делает интерфейс — вызовы API. Машины авторизуются токеном из вкладки «Пользователи»:",
  rest_curl: "пример curl",
  mcp_t: "MCP — нейронка рулит сервером",
  mcp_d1: "Скачай stdio MCP-сервер (python 3.10+, без зависимостей) и пропиши в MCP-клиенте. Права токена — жесткий потолок для модели.",
  mcp_step1: "1. Создай токен во вкладке «Пользователи» (галка «админ» = полный доступ — но юзеров токен не управляет).",
  mcp_step2: "2. Скачай скрипт:",
  mcp_step3: "3. Добавь в конфиг MCP-клиента:",
  mcp_step4: "4. Проверка:",
  dl_btn: "Скачать dachboard_mcp.py",
  tools_t: "Инструменты модели",
  ep_method: "Метод", ep_path: "Эндпоинт", ep_right: "Нужное право", ep_what: "Что делает",
}};

const MCP_TOOLS = [
  ["dach_overview", "dach_services", "dach_service_logs", "dach_service_action"],
  ["dach_containers", "dach_container_logs", "dach_container_action"],
  ["dach_files_list", "dach_files_read", "dach_files_write", "dach_files_mkdir",
   "dach_files_delete", "dach_files_move", "dach_files_upload", "dach_files_unzip"],
  ["dach_commands", "dach_command_create", "dach_command_run", "dach_command_delete", "dach_runs"],
  ["dach_tunnel", "dach_whoami"],
];

async function vApi() {
  const d = API_DOC[LANG] || API_DOC.en;
  const base = location.origin + u("");
  const mcpUrl = base + "/mcp/dachboard_mcp.py";
  const cfg = JSON.stringify({ mcpServers: { dachboard: {
    command: "python3", args: ["/path/to/dachboard_mcp.py"],
    env: { DACH_URL: base, DACH_TOKEN: "dach_..." } } } }, null, 2);
  view.innerHTML = `
    <h3>${ic("code")}${d.rest_t}</h3>
    <p class="dim">${d.rest_d}</p>
    <pre>curl -H "Authorization: Bearer dach_..." ${base}/api/metrics</pre>
    <table><thead><tr><th>${d.ep_method}</th><th>${d.ep_path}</th><th>${d.ep_right}</th><th>${d.ep_what}</th></tr></thead>
    <tbody>${API_ENDPOINTS.map((e) => `<tr><td class="mono">${e[0]}</td><td class="mono">${esc(e[1])}</td><td class="mono dim">${e[2]}</td><td class="dim">${esc(e[3])}</td></tr>`).join("")}</tbody></table>

    <h3>${ic("zap")}${d.mcp_t}</h3>
    <p class="dim">${d.mcp_d1}</p>
    <p>${d.mcp_step1}</p>
    <p>${d.mcp_step2} <a class="btn primary" href="${mcpUrl}" download>${ic("download")}${d.dl_btn}</a>
       <span class="mono dim">curl -O ${mcpUrl}</span></p>
    <p>${d.mcp_step3}</p>
    <pre>${esc(cfg)}</pre>
    <p>${d.mcp_step4}</p>
    <pre>DACH_URL=${base} DACH_TOKEN=dach_... python3 dachboard_mcp.py</pre>
    <h3>${ic("term")}${d.tools_t}</h3>
    ${MCP_TOOLS.map((g) => `<p class="mono dim">${g.map(esc).join(" · ")}</p>`).join("")}`;
}
