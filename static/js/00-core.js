/* dachboard SPA: 00-core. vanilla JS, no build. Loaded in order, shared globals. */
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

