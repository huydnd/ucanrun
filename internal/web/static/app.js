"use strict";
// All dynamic text goes through textContent, so agent-supplied values cannot
// become markup.
const app = document.getElementById("app");
let state = {tab: "requests", status: null, timer: null};

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c);
  return e;
}

function fill(el, ...kids) { el.replaceChildren(...kids.flat().filter(c => c != null)); }

async function api(method, path, body) {
  const r = await fetch(path, {method, headers: {"Content-Type": "application/json", "X-Ucanrun": "1"},
    body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin"});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.error || ("HTTP " + r.status)); e.data = data; e.status = r.status; throw e; }
  return data;
}

function field(label, attrs) {
  const input = h("input", attrs);
  return {input, el: h("label", null, h("span", null, label), input)};
}

function form(title, fields, submit, onsubmit, extra) {
  const err = h("div", {class: "err", role: "alert"});
  const btn = h("button", {class: "primary", type: "button", onclick: async () => {
    err.textContent = ""; btn.disabled = true;
    try { await onsubmit(); } catch (e) { err.textContent = e.message; } finally { btn.disabled = false; }
  }}, submit);
  fields.forEach(f => f.input.addEventListener("keydown", e => { if (e.key === "Enter") btn.click(); }));
  return h("div", {class: "card"}, h("h2", null, title), extra, fields.map(f => f.el), h("div", {class: "row"}, btn), err);
}

async function boot() {
  clearInterval(state.timer);
  state.status = await api("GET", "/api/status");
  const s = state.status;
  if (!s.initialized) return renderSetup();
  if (!s.authed) return renderLogin(s.locked);
  renderShell();
}

function renderSetup() {
  const tok = field("Setup token (trong log của container)", {type: "password", autocomplete: "off"});
  const p1 = field("Mật khẩu chính, ít nhất 12 ký tự", {type: "password", autocomplete: "new-password"});
  const p2 = field("Nhập lại mật khẩu chính", {type: "password", autocomplete: "new-password"});
  app.replaceChildren(h("div", {class: "narrow"}, form("Khởi tạo ucanrun", [tok, p1, p2], "Khởi tạo", async () => {
    if (p1.input.value !== p2.input.value) throw new Error("Hai mật khẩu không khớp");
    await api("POST", "/api/setup", {setup_token: tok.input.value, passphrase: p1.input.value});
    boot();
  }, h("p", {class: "note"}, "Không có cách khôi phục nếu mất mật khẩu chính. Hãy lưu vào Bitwarden."))));
}

function renderLogin(locked) {
  const p = field("Mật khẩu chính", {type: "password", autocomplete: "current-password"});
  const t = field("Mã TOTP (nếu đã bật)", {inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6});
  app.replaceChildren(h("div", {class: "narrow"}, form(locked ? "Mở khoá ucanrun" : "Đăng nhập", [p, t], "Tiếp tục", async () => {
    await api("POST", "/api/login", {passphrase: p.input.value, totp: t.input.value});
    boot();
  }, locked ? h("p", {class: "muted"}, "Kho đang khoá, agent chưa chạy được lệnh nào.") : null)));
}

const tabs = {requests: "Yêu cầu", secrets: "Secret", profiles: "Profile", tokens: "Token agent", settings: "Cài đặt", audit: "Nhật ký"};

function renderShell() {
  const body = h("main");
  const nav = h("nav", null, Object.entries(tabs).map(([k, v]) =>
    h("button", {class: state.tab === k ? "on" : "", onclick: () => { state.tab = k; renderShell(); }}, v)));
  app.replaceChildren(h("header", null, h("b", null, "ucanrun"), nav,
    h("button", {onclick: async () => { await api("POST", "/api/lock"); boot(); }}, "Khoá kho")), body);
  clearInterval(state.timer);
  const views = {requests: viewRequests, secrets: viewSecrets, profiles: viewProfiles, tokens: viewTokens, settings: viewSettings, audit: viewAudit};
  const draw = () => views[state.tab](body).catch(e => { if (e.status === 401) boot(); else fill(body, h("div", {class: "err"}, e.message)); });
  draw();
  if (state.tab === "requests") state.timer = setInterval(() => { if (!body.querySelector("input:focus, select:focus")) draw(); }, 3000);
}

async function viewRequests(body) {
  const list = await api("GET", "/api/requests");
  const pending = list.filter(r => r.state === "pending");
  const rest = list.filter(r => r.state !== "pending");
  const card = r => {
    const code = h("input", {placeholder: "Mã TOTP", inputmode: "numeric", maxlength: 6});
    const err = h("div", {class: "err"});
    state.picks = state.picks || {};
    // The list redraws every 3 seconds, so the choice must outlive the element.
    const pick = r.choices && r.choices.length ? select(state.picks[r.id] || r.choices[0], r.choices.map(n => [n, n]), v => { state.picks[r.id] = v; }, "Chọn secret") : null;
    const act = approve => async () => {
      try { await api("POST", `/api/requests/${r.id}/decide`, {approve, hash: r.hash, totp: code.value, secret: pick ? pick.value : ""}); viewRequests(body); }
      catch (e) { err.textContent = e.message; }
    };
    return h("div", {class: "card"},
      h("h3", null, r.profile, " ", h("span", {class: "badge " + (r.risk === "high" ? "high" : "")}, r.risk === "high" ? "rủi ro cao" : "rủi ro thấp")),
      h("div", {class: "muted"}, `Agent: ${r.caller} · Mã: ${r.hash.slice(0, 8)} · ${new Date(r.created).toLocaleTimeString()}`),
      h("pre", null, r.display),
      r.reason ? h("div", {class: "muted"}, "Lý do (agent tự khai, chưa kiểm chứng): " + r.reason) : null,
      r.state === "pending" ? h("div", null, pick ? h("label", null, h("span", null, "Secret dùng cho lần này"), pick) : null, r.risk === "high" ? code : null,
        h("div", {class: "row"}, h("button", {class: "primary", onclick: act(true)}, "Duyệt"), h("button", {class: "danger", onclick: act(false)}, "Từ chối")), err) : null,
      r.state !== "pending" ? h("div", {class: "muted"}, `Kết quả: ${r.state}` + (r.decided_by ? ` · ${r.decided_by}` : "") + (r.secret ? ` · secret ${r.secret}` : "")) : null,
      r.result ? h("pre", null, r.result.output) : null);
  };
  fill(body, h("h2", null, `Đang chờ duyệt (${pending.length})`),
    pending.length ? pending.map(card) : h("p", {class: "muted"}, "Không có yêu cầu nào đang chờ."),
    rest.length ? h("h2", null, "Gần đây") : null, rest.slice(0, 30).map(card));
}

async function viewSecrets(body) {
  const list = await api("GET", "/api/secrets");
  const n = field("Tên", {autocomplete: "off"});
  const v = field("Giá trị", {type: "password", autocomplete: "off"});
  const multi = h("textarea", {class: "short", spellcheck: "false", "aria-label": "Giá trị nhiều dòng", hidden: true});
  const toggle = h("input", {type: "checkbox", onchange: e => { multi.hidden = !e.target.checked; v.el.hidden = e.target.checked; }});
  fill(body,
    form("Thêm hoặc thay secret", [n, v], "Lưu", async () => {
      await api("PUT", "/api/secrets/" + encodeURIComponent(n.input.value), {value: toggle.checked ? multi.value : v.input.value});
      viewSecrets(body);
    }, h("div", null, h("p", {class: "muted"}, "Giá trị chỉ ghi, không có cách xem lại trên giao diện. Nhập trùng tên để thay."),
      h("label", {class: "check"}, toggle, h("span", null, "Nhiều dòng, như khoá SSH")), multi)),
    h("div", {class: "card"}, h("h2", null, `Secret (${list.length})`),
      list.length ? list.map(s => h("div", {class: "spread"}, h("span", null, h("code", null, s.name), h("div", {class: "muted"}, new Date(s.updated).toLocaleString())),
        h("button", {class: "danger", onclick: async () => {
          if (confirm(`Xoá secret ${s.name}?`)) { await api("DELETE", "/api/secrets/" + encodeURIComponent(s.name)); viewSecrets(body); }
        }}, "Xoá"))) : h("p", {class: "muted"}, "Chưa có secret.")));
}

// --- Profile builder ---
// The form edits a plain draft; toProfile() is the only place that produces the
// stored shape, so people never need to know it.
const paramTypes = {
  slug: {label: "Tên ngắn (chữ thường, số, . _ -)", pattern: "[a-z0-9._-]{1,64}", sample: "vi-du"},
  text: {label: "Văn bản ngắn", pattern: "[\\p{L}\\p{N} ._,:@/-]{1,200}", sample: "Nội dung mẫu"},
  number: {label: "Số", pattern: "[0-9]{1,18}", sample: "123"},
  email: {label: "Email", pattern: "[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}", sample: "ten@example.com"},
  uuid: {label: "UUID", pattern: "[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", sample: "123e4567-e89b-12d3-a456-426614174000"},
  choice: {label: "Chọn trong danh sách", pattern: "", sample: ""},
  custom: {label: "Tự viết regex (nâng cao)", pattern: "", sample: "abc"},
};
const reEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const slugify = s => s.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d").replace(/Đ/g, "D")
  .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);

const errorText = [
  [/profile name/, "Tên profile chỉ gồm chữ thường, số, dấu gạch."],
  [/url must start/, "Địa chỉ phải bắt đầu bằng http:// hoặc https:// và có tên máy cố định."],
  [/template is not allowed in the url host/, "Tên máy phải cố định, agent không được chọn nơi gửi."],
  [/secrets are not allowed in the url/, "Không đặt secret trong địa chỉ."],
  [/undeclared param "(.+)"/, m => `Chưa khai báo giá trị "${m[1]}" ở mục 4.`],
  [/param "(.+)" is declared but never used/, m => `Giá trị "${m[1]}" chưa được dùng ở đâu. Hãy chèn vào địa chỉ hoặc nội dung, hoặc xoá đi.`],
  [/param "(.+)" needs a pattern/, m => `Giá trị "${m[1]}" cần một kiểu dữ liệu.`],
  [/param "(.+)" does not match/, m => `Giá trị mẫu của "${m[1]}" không đúng kiểu đã chọn.`],
  [/missing param "(.+)"/, m => `Giá trị mẫu của "${m[1]}" đang trống.`],
  [/bad param name/, "Tên giá trị chỉ gồm chữ thường, số, gạch dưới, bắt đầu bằng chữ."],
  [/argv\[0\]/, "Dòng đầu phải là đường dẫn đầy đủ tới chương trình, ví dụ /usr/bin/git."],
  [/interpreters/, "Không chạy được shell hay trình thông dịch, vì giá trị agent điền sẽ thành code."],
  [/env "(.+)" is not allowed/, m => `Không dùng được biến ${m[1]}, vì nó đổi cách chương trình chạy.`],
  [/high risk profile cannot auto/, "Mức cần TOTP không thể tự chạy."],
  [/a param may not/, "Giá trị mẫu không hợp lệ ở vị trí này."],
  [/secret_choices is required/, "Hãy tích ít nhất một secret được phép chọn."],
  [/secret choice needs a human/, "Chọn secret khi duyệt thì không thể tự chạy."],
];
function viErr(msg) {
  for (const [re, t] of errorText) { const m = msg.match(re); if (m) return typeof t === "function" ? t(m) : t; }
  return msg;
}

const templates = {
  blank: {label: "Trống", d: {}},
  bearer: {label: "API có Bearer token", d: {description: "Đọc dữ liệu từ API", method: "GET", url: "https://api.example.com/v1/items/{{item_id}}", auth: "bearer",
    params: [{name: "item_id", type: "slug", required: true}]}},
  gitea: {label: "Gitea: tạo repo", d: {description: "Tạo repo private trên Gitea", method: "POST", url: "http://gitea:3000/api/v1/user/repos", auth: "token",
    bodyMode: "json", jsonRows: [{key: "name", value: "{{repo}}"}, {key: "private", value: "true"}], params: [{name: "repo", type: "slug", required: true}]}},
  webhook: {label: "Gọi webhook", d: {description: "Kích hoạt webhook", method: "POST", url: "https://hooks.example.com/run", auth: "header", authHeader: "X-Api-Key",
    bodyMode: "json", jsonRows: [{key: "event", value: "{{event}}"}], params: [{name: "event", type: "choice", choices: "deploy, restart", required: true}]}},
};

function newDraft(over) {
  const d = Object.assign({description: "", name: "", nameTouched: false, kind: "http", method: "GET", url: "", auth: "none", authHeader: "", secret: "",
    choices: [], stdinSecret: "", stdin: "", fileRows: [], bodyMode: "none", jsonRows: [], raw: "", rawType: "text/plain", params: [], approval: "ask", argv: "", envRows: [], extraHeaders: {}, timeout: 0}, JSON.parse(JSON.stringify(over || {})));
  d.params = d.params.map(p => Object.assign({name: "", type: "slug", pattern: "", choices: "", required: true, description: "", sample: ""}, p));
  return d;
}

function patternOf(p) {
  if (p.type === "choice") return p.choices.split(",").map(s => s.trim()).filter(Boolean).map(reEscape).join("|");
  if (p.type === "custom") return p.pattern;
  return paramTypes[p.type].pattern;
}
function sampleOf(p) {
  if (p.sample) return p.sample;
  if (p.type === "choice") return p.choices.split(",")[0].trim();
  return paramTypes[p.type].sample;
}

function jsonBody(rows) {
  const lit = /^(true|false|null|-?\d+(\.\d+)?)$/;
  const body = rows.filter(r => r.key).map(r => JSON.stringify(r.key) + ":" + (lit.test(r.value) ? r.value : JSON.stringify(r.value))).join(",");
  return "{" + body + "}";
}

function toProfile(d) {
  const p = {name: d.name, description: d.description, risk: d.approval === "totp" ? "high" : "low"};
  if (d.approval === "auto") p.auto_approve = true;
  if (d.timeout) p.timeout_sec = Number(d.timeout);
  const params = d.params.map(q => { const o = {name: q.name, pattern: patternOf(q), required: q.required}; if (q.description) o.description = q.description; return o; });
  if (params.length) p.params = params;
  if (d.kind === "exec") {
    p.exec = {argv: d.argv.split("\n").map(s => s.trim()).filter(Boolean)};
    const rows = d.envRows.filter(r => r.key && r.secret);
    if (rows.length) p.exec.env = Object.fromEntries(rows.map(r => [r.key, `{{secret:${r.secret}}}`]));
    if (d.stdinSecret) p.exec.stdin = `{{secret:${d.stdinSecret}}}`;
    else if (d.stdin) p.exec.stdin = d.stdin;
    const files = d.fileRows.filter(r => r.key && r.secret);
    if (files.length) p.exec.files = Object.fromEntries(files.map(r => [r.key, `{{secret:${r.secret}}}`]));
    return p;
  }
  const headers = Object.assign({}, d.extraHeaders);
  const picking = d.secret === "choice";
  if (picking) p.secret_choices = d.choices;
  if (d.secret) {
    const ref = `{{secret:${d.secret}}}`;
    if (d.auth === "bearer") headers.Authorization = "Bearer " + ref;
    if (d.auth === "token") headers.Authorization = "token " + ref;
    if (d.auth === "header" && d.authHeader) headers[d.authHeader] = ref;
  }
  p.http = {method: d.method, url: d.url};
  if (d.bodyMode === "json") { headers["Content-Type"] = "application/json"; p.http.body = jsonBody(d.jsonRows); }
  if (d.bodyMode === "raw") { headers["Content-Type"] = d.rawType; p.http.body = d.raw; }
  if (Object.keys(headers).length) p.http.headers = headers;
  return p;
}

function fromProfile(p) {
  const d = newDraft({name: p.name, nameTouched: true, description: p.description || "", timeout: p.timeout_sec || 0,
    approval: p.risk === "high" ? "totp" : p.auto_approve ? "auto" : "ask"});
  d.params = (p.params || []).map(q => {
    const known = Object.entries(paramTypes).find(([k, t]) => t.pattern && t.pattern === q.pattern);
    const base = {name: q.name, required: !!q.required, description: q.description || "", sample: "", choices: "", pattern: q.pattern, type: "custom"};
    if (known) base.type = known[0];
    else if (/^[\w .-]+(\|[\w .-]+)*$/.test(q.pattern)) { base.type = "choice"; base.choices = q.pattern.split("|").join(", "); }
    return base;
  });
  d.choices = p.secret_choices || [];
  if (p.exec) {
    const m = (p.exec.stdin || "").match(/^\{\{secret:(.+?)\}\}$/);
    if (m) d.stdinSecret = m[1]; else d.stdin = p.exec.stdin;
    d.fileRows = Object.entries(p.exec.files || {}).map(([key, v]) => ({key, secret: (v.match(/\{\{secret:(.+?)\}\}/) || [])[1] || ""}));
  }
  if (p.exec) {
    d.kind = "exec"; d.argv = p.exec.argv.join("\n");
    d.envRows = Object.entries(p.exec.env || {}).map(([key, v]) => ({key, secret: (v.match(/\{\{secret:(.+?)\}\}/) || [])[1] || ""}));
    return d;
  }
  const h = p.http; d.method = h.method; d.url = h.url;
  const headers = Object.assign({}, h.headers);
  const auth = headers.Authorization || "";
  let m;
  if ((m = auth.match(/^Bearer \{\{secret:(.+?)\}\}$/))) { d.auth = "bearer"; d.secret = m[1]; delete headers.Authorization; }
  else if ((m = auth.match(/^token \{\{secret:(.+?)\}\}$/))) { d.auth = "token"; d.secret = m[1]; delete headers.Authorization; }
  else for (const [k, v] of Object.entries(headers)) {
    if ((m = v.match(/^\{\{secret:(.+?)\}\}$/))) { d.auth = "header"; d.authHeader = k; d.secret = m[1]; delete headers[k]; break; }
  }
  if (h.body) {
    let obj = null;
    try { obj = JSON.parse(h.body); } catch (_) {}
    if (obj && typeof obj === "object" && !Array.isArray(obj) && Object.values(obj).every(v => typeof v !== "object" || v === null)) {
      d.bodyMode = "json"; d.jsonRows = Object.entries(obj).map(([key, v]) => ({key, value: String(v)})); delete headers["Content-Type"];
    } else { d.bodyMode = "raw"; d.raw = h.body; d.rawType = headers["Content-Type"] || "text/plain"; delete headers["Content-Type"]; }
  }
  d.extraHeaders = headers;
  return d;
}

function choiceGroup(name, value, options, onchange) {
  return h("div", {class: "choices", role: "radiogroup"}, options.map(o => {
    const input = h("input", {type: "radio", name, value: o.value, checked: o.value === value, onchange: () => onchange(o.value)});
    return h("label", {class: "choice"}, input, h("span", null, h("b", null, o.title), o.help ? h("small", null, o.help) : null));
  }));
}

function select(value, options, onchange, label) {
  const s = h("select", {"aria-label": label, onchange: e => onchange(e.target.value)},
    options.map(([v, t]) => h("option", {value: v, selected: v === value}, t)));
  return s;
}

async function viewProfiles(body) {
  const [list, secrets] = await Promise.all([api("GET", "/api/profiles"), api("GET", "/api/secrets")]);
  const openBuilder = d => renderBuilder(body, d, secrets);
  const catalog = await fetch("catalog.json").then(r => r.json()).catch(() => []);
  const haveSecret = n => secrets.some(s => s.name === n);
  const haveProfile = n => list.some(p => p.name === n);
  const catalogCard = c => {
    const missing = c.secrets.filter(n => !haveSecret(n));
    const inputs = c.custom ? [] : missing.map(n => h("input", {type: "password", autocomplete: "off", placeholder: "Dán " + n, "aria-label": n}));
    const err = h("div", {class: "err"});
    const added = haveProfile(c.profile.name);
    const direct = !c.custom && !(c.profile.secret_choices || []).length;
    return h("div", {class: "tile"}, h("b", null, c.title), h("small", {class: "muted"}, c.hint),
      added ? h("span", {class: "badge"}, "đã thêm") : h("div", null, inputs,
        h("div", {class: "row"}, direct ? h("button", {class: "primary", onclick: async () => {
          err.textContent = "";
          try {
            for (const [i, n] of missing.entries()) {
              if (!inputs[i].value) throw new Error("Hãy dán giá trị " + n);
              await api("PUT", "/api/secrets/" + encodeURIComponent(n), {value: inputs[i].value.trim()});
            }
            await api("PUT", "/api/profiles", c.profile);
            viewProfiles(body);
          } catch (e) { err.textContent = viErr(e.message); }
        }}, "Thêm") : null, h("button", {onclick: () => openBuilder(fromProfile(c.profile))}, "Tuỳ chỉnh")), err));
  };
  const groups = [...new Set(catalog.map(c => c.group))];
  fill(body, h("div", {class: "card"}, h("h2", null, "Thêm nhanh"),
    h("p", {class: "muted"}, "Dán token của dịch vụ rồi bấm Thêm, không cần cấu hình gì khác."),
    groups.map(g => h("div", null, h("h3", null, g), h("div", {class: "tiles"}, catalog.filter(c => c.group === g).map(catalogCard))))),
  h("div", {class: "card"}, h("h2", null, "Tự tạo profile"),
    h("p", {class: "muted"}, "Profile là một việc cụ thể bạn cho phép agent xin làm."),
    h("div", {class: "row"}, Object.values(templates).map(t => h("button", {onclick: () => openBuilder(newDraft(t.d))}, t.label)))),
  h("div", {class: "card"}, h("h2", null, `Profile (${list.length})`),
    list.length ? list.map(p => h("div", {class: "spread"}, h("span", null, h("b", null, p.description || p.name), " ",
      h("span", {class: "badge " + (p.risk === "high" ? "high" : "")}, p.risk === "high" ? "cần TOTP" : p.auto_approve ? "tự chạy" : "hỏi duyệt"),
      h("div", {class: "muted"}, h("code", null, "ucr run " + p.name + (p.params || []).map(q => ` ${q.name}=…`).join("")))),
    h("span", null, h("button", {onclick: () => openBuilder(fromProfile(p))}, "Sửa"), " ",
      h("button", {class: "danger", onclick: async () => { if (confirm(`Xoá profile ${p.name}?`)) { await api("DELETE", "/api/profiles/" + encodeURIComponent(p.name)); viewProfiles(body); } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có profile.")));
}

function renderBuilder(body, d, secrets) {
  let lastField = null, timer = null, valid = false;
  if (!d.name && d.description) d.name = slugify(d.description);
  const refresh = () => { clearTimeout(timer); timer = setTimeout(runPreview, 250); };
  const track = el => { el.addEventListener("focus", () => { lastField = el; }); return el; };
  const text = (label, get, set, attrs, help) => {
    const i = h("input", Object.assign({autocomplete: "off", spellcheck: "false"}, attrs));
    i.value = get();
    i.addEventListener("input", () => { set(i.value); refresh(); });
    return h("label", null, h("span", null, label), i, help ? h("small", {class: "muted"}, help) : null);
  };

  // 1. What
  const nameInput = h("input", {autocomplete: "off", spellcheck: "false"});
  nameInput.value = d.name;
  nameInput.addEventListener("input", () => { d.name = nameInput.value; d.nameTouched = true; refresh(); });
  const desc = text("Việc này làm gì?", () => d.description, v => {
    d.description = v;
    if (!d.nameTouched) { d.name = slugify(v); nameInput.value = d.name; }
  }, {placeholder: "Ví dụ: Tạo repo private trên Gitea"}, "Câu này hiện cho bạn và cho agent.");
  const step1 = h("section", {class: "card"}, h("h3", null, "1. Việc cần làm"), desc,
    h("label", null, h("span", null, "Tên lệnh"), nameInput, h("small", {class: "muted"}, "Tự sinh từ mô tả. Agent gọi bằng tên này.")));

  // 2. Where
  const where = h("div");
  const drawWhere = () => {
    if (d.kind === "exec") {
      const ta = h("textarea", {class: "short", spellcheck: "false", placeholder: "/usr/bin/git\nls-remote\n{{url}}", "aria-label": "Lệnh"});
      ta.value = d.argv; track(ta);
      ta.addEventListener("input", () => { d.argv = ta.value; refresh(); });
      fill(where, h("label", null, h("span", null, "Lệnh, mỗi đối số một dòng"), ta,
        h("small", {class: "muted"}, "Dòng đầu là đường dẫn đầy đủ. Không qua shell, nên không dùng được dấu | hay >.")));
      return;
    }
    const url = h("input", {type: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1/items/{{item_id}}", "aria-label": "Địa chỉ"});
    url.value = d.url; track(url);
    url.addEventListener("input", () => { d.url = url.value; refresh(); });
    fill(where, h("div", {class: "url-row"}, select(d.method, ["GET", "POST", "PUT", "PATCH", "DELETE"].map(m => [m, m]), v => { d.method = v; if (v !== "GET" && d.approval === "auto") { d.approval = "ask"; drawApproval(); } refresh(); }, "Phương thức"), url),
      h("small", {class: "muted"}, "Tên máy luôn cố định, agent chỉ điền được các giá trị ở mục 4."));
  };
  const step2 = h("section", {class: "card"}, h("h3", null, "2. Gọi tới đâu"),
    choiceGroup("kind", d.kind, [{value: "http", title: "Gọi API", help: "An toàn hơn, nên dùng"}, {value: "exec", title: "Chạy lệnh", help: "Nâng cao, chạy trong container"}],
      v => { d.kind = v; drawWhere(); drawAuth(); refresh(); }), where);

  // 3. Credentials
  const authBox = h("div");
  const secretSelect = (value, on, withChoice) => secrets.length
    ? select(value, [["", "Chọn secret…"]].concat(withChoice ? [["choice", "Chọn khi duyệt trên Telegram"]] : [], secrets.map(s => [s.name, s.name])), on, "Secret")
    : h("p", {class: "note"}, "Kho chưa có secret. Hãy thêm ở tab Secret trước.");
  const drawAuth = () => {
    if (d.kind === "exec") {
      const rows = d.envRows.map((r, i) => {
        const k = h("input", {placeholder: "TEN_BIEN", "aria-label": "Tên biến", autocomplete: "off"}); k.value = r.key;
        k.addEventListener("input", () => { r.key = k.value; refresh(); });
        return h("div", {class: "kv"}, k, secretSelect(r.secret, v => { r.secret = v; refresh(); }),
          h("button", {"aria-label": "Xoá", onclick: () => { d.envRows.splice(i, 1); drawAuth(); refresh(); }}, "×"));
      });
      const fileRows = d.fileRows.map((r, i) => {
        const k = h("input", {placeholder: "id_key", "aria-label": "Tên file", autocomplete: "off"}); k.value = r.key;
        k.addEventListener("input", () => { r.key = k.value; refresh(); });
        return h("div", {class: "kv"}, k, secretSelect(r.secret, v => { r.secret = v; refresh(); }),
          h("button", {"aria-label": "Xoá file", onclick: () => { d.fileRows.splice(i, 1); drawAuth(); refresh(); }}, "×"));
      });
      fill(authBox,
        h("h3", null, "Mật khẩu đưa vào chương trình"),
        h("small", {class: "muted"}, "Dùng cho sudo -S và các lệnh đọc mật khẩu từ đầu vào."),
        select(d.stdinSecret, [["", "Không dùng"]].concat(secrets.map(s => [s.name, s.name])), v => { d.stdinSecret = v; refresh(); }, "Mật khẩu stdin"),
        h("h3", {class: "gap"}, "File tạm từ secret"),
        h("small", {class: "muted"}, "Như khoá SSH. Tạo trong thư mục chạy, xoá ngay sau khi xong."),
        fileRows, h("button", {onclick: () => { d.fileRows.push({key: "", secret: ""}); drawAuth(); }}, "+ Thêm file"),
        h("h3", {class: "gap"}, "Biến môi trường"),
        rows, h("button", {onclick: () => { d.envRows.push({key: "", secret: ""}); drawAuth(); }}, "+ Thêm biến"));
      return;
    }
    const kids = [select(d.auth, [["none", "Không cần đăng nhập"], ["bearer", "Bearer token (phổ biến nhất)"], ["token", "Token kiểu Gitea, GitHub"], ["header", "Header riêng, như X-Api-Key"]],
      v => { d.auth = v; drawAuth(); refresh(); }, "Cách đăng nhập")];
    if (d.auth === "header") kids.push(text("Tên header", () => d.authHeader, v => { d.authHeader = v; }, {placeholder: "X-Api-Key"}));
    if (d.auth !== "none") kids.push(h("label", null, h("span", null, "Secret dùng"), secretSelect(d.secret, v => { d.secret = v; if (v === "choice" && d.approval === "auto") { d.approval = "ask"; drawApproval(); } drawAuth(); refresh(); }, true)));
    if (d.secret === "choice") kids.push(h("div", {class: "picklist"}, h("span", {class: "muted"}, "Các secret được phép chọn:"), secrets.map(s => h("label", {class: "check"},
      h("input", {type: "checkbox", checked: d.choices.includes(s.name), onchange: e => { d.choices = e.target.checked ? d.choices.concat(s.name) : d.choices.filter(n => n !== s.name); refresh(); }}), h("span", null, s.name)))));
    fill(authBox, ...kids);
  };
  const step3 = h("section", {class: "card"}, h("h3", null, "3. Đăng nhập bằng gì"), authBox,
    h("small", {class: "muted"}, "Agent không bao giờ thấy giá trị secret."));

  // 4. Values the agent fills
  const paramBox = h("div"), chips = h("div", {class: "chips"});
  const insert = name => {
    const el = lastField;
    if (!el) return;
    const tag = `{{${name}}}`, s = el.selectionStart ?? el.value.length;
    el.value = el.value.slice(0, s) + tag + el.value.slice(el.selectionEnd ?? s);
    el.dispatchEvent(new Event("input"));
    el.focus(); el.setSelectionRange(s + tag.length, s + tag.length);
  };
  const drawChips = () => fill(chips, d.params.filter(p => p.name).length ? h("span", {class: "muted"}, "Chèn vào ô đang chọn:") : null,
    d.params.filter(p => p.name).map(p => h("button", {class: "chip", onmousedown: e => e.preventDefault(), onclick: () => insert(p.name)}, p.name)));
  const drawParams = () => {
    fill(paramBox, d.params.map((p, i) => {
      const nameEl = h("input", {placeholder: "ten_gia_tri", "aria-label": "Tên giá trị", autocomplete: "off", spellcheck: "false"}); nameEl.value = p.name;
      nameEl.addEventListener("input", () => { p.name = nameEl.value; drawChips(); refresh(); });
      const extra = h("div");
      const drawExtra = () => {
        const kids = [];
        if (p.type === "choice") kids.push(text("Các lựa chọn, cách nhau bằng dấu phẩy", () => p.choices, v => { p.choices = v; }, {placeholder: "deploy, restart"}));
        if (p.type === "custom") kids.push(text("Regex", () => p.pattern, v => { p.pattern = v; }, {placeholder: "[a-z]+"}));
        kids.push(text("Giá trị mẫu để xem trước", () => p.sample, v => { p.sample = v; }, {placeholder: sampleOf(p)}));
        fill(extra, ...kids);
      };
      drawExtra();
      const req = h("input", {type: "checkbox", checked: p.required, onchange: e => { p.required = e.target.checked; refresh(); }});
      return h("div", {class: "param"}, h("div", {class: "kv"}, nameEl,
        select(p.type, Object.entries(paramTypes).map(([k, t]) => [k, t.label]), v => { p.type = v; drawExtra(); refresh(); }, "Kiểu"),
        h("button", {"aria-label": `Xoá ${p.name}`, onclick: () => { d.params.splice(i, 1); drawParams(); drawChips(); refresh(); }}, "×")),
      extra, h("label", {class: "check"}, req, h("span", null, "Bắt buộc")));
    }), h("button", {onclick: () => { d.params.push(newDraft({params: [{}]}).params[0]); drawParams(); }}, "+ Thêm giá trị"));
  };
  const step4 = h("section", {class: "card"}, h("h3", null, "4. Agent được điền gì"),
    h("p", {class: "muted"}, "Mọi thứ khác là cố định. Giá trị sai kiểu sẽ bị từ chối trước khi tới tay bạn."), paramBox, chips);

  // 5. Request body
  const bodyBox = h("div");
  const drawBody = () => {
    if (d.bodyMode === "json") {
      fill(bodyBox, d.jsonRows.map((r, i) => {
        const k = h("input", {placeholder: "tên trường", "aria-label": "Tên trường", autocomplete: "off"}); k.value = r.key;
        const v = h("input", {placeholder: "giá trị hoặc {{ten_gia_tri}}", "aria-label": "Giá trị", autocomplete: "off", spellcheck: "false"}); v.value = r.value; track(v);
        k.addEventListener("input", () => { r.key = k.value; refresh(); });
        v.addEventListener("input", () => { r.value = v.value; refresh(); });
        return h("div", {class: "kv"}, k, v, h("button", {"aria-label": "Xoá", onclick: () => { d.jsonRows.splice(i, 1); drawBody(); refresh(); }}, "×"));
      }), h("button", {onclick: () => { d.jsonRows.push({key: "", value: ""}); drawBody(); }}, "+ Thêm trường"));
    } else if (d.bodyMode === "raw") {
      const ta = h("textarea", {class: "short", spellcheck: "false", "aria-label": "Nội dung"}); ta.value = d.raw; track(ta);
      ta.addEventListener("input", () => { d.raw = ta.value; refresh(); });
      fill(bodyBox, ta);
    } else fill(bodyBox);
  };
  const step5 = h("details", {class: "card", open: d.bodyMode !== "none"}, h("summary", null, h("b", null, "Nội dung gửi đi (nếu có)")),
    choiceGroup("bodyMode", d.bodyMode, [{value: "none", title: "Không có"}, {value: "json", title: "Các trường JSON"}, {value: "raw", title: "Tự viết"}], v => { d.bodyMode = v; drawBody(); refresh(); }), bodyBox);

  // 6. Approval
  const approvalBox = h("div");
  const drawApproval = () => fill(approvalBox, choiceGroup("approval", d.approval, [
    {value: "ask", title: "Luôn hỏi tôi", help: "Bấm Duyệt trên Telegram"},
    {value: "totp", title: "Hỏi và cần mã TOTP", help: "Cho việc xoá, thay đổi quan trọng"},
    {value: "auto", title: "Tự chạy, không hỏi", help: "Chỉ dùng cho việc đọc vô hại"},
  ], v => { d.approval = v; refresh(); }));
  const step6 = h("section", {class: "card"}, h("h3", null, "5. Ai duyệt"), approvalBox);

  // Advanced JSON
  const jsonArea = h("textarea", {spellcheck: "false", "aria-label": "Profile JSON"});
  const jsonErr = h("div", {class: "err"});
  const adv = h("details", {class: "card", ontoggle: () => { jsonArea.value = JSON.stringify(toProfile(d), null, 2); }}, h("summary", null, h("b", null, "Nâng cao: xem hoặc dán JSON")), jsonArea,
    h("div", {class: "row"}, h("button", {onclick: () => {
      try { renderBuilder(body, fromProfile(JSON.parse(jsonArea.value)), secrets); } catch (e) { jsonErr.textContent = "JSON không hợp lệ: " + e.message; }
    }}, "Áp dụng vào form")), jsonErr);

  // Preview
  const pvText = h("pre", {class: "tg"}), pvMsgs = h("div"), saveErr = h("div", {class: "err"});
  const saveBtn = h("button", {class: "primary", disabled: true, onclick: async () => {
    saveErr.textContent = "";
    try { await api("PUT", "/api/profiles", toProfile(d)); viewProfiles(body); } catch (e) { saveErr.textContent = viErr(e.message); }
  }}, "Lưu profile");
  async function runPreview() {
    const sample = Object.fromEntries(d.params.filter(p => p.name).map(p => [p.name, sampleOf(p)]));
    let r;
    try { r = await api("POST", "/api/profiles/preview", {profile: toProfile(d), sample}); } catch (e) { r = {error: e.message, warnings: []}; }
    valid = !r.error;
    saveBtn.disabled = !valid;
    const head = d.approval === "totp" ? "⚠️ RỦI RO CAO, cần TOTP\n\n" : "";
    pvText.textContent = r.display ? head + `Agent xin chạy: ${d.description || d.name}\n\nLệnh sẽ chạy:\n${r.display}` : "Điền đủ thông tin để xem trước.";
    fill(pvMsgs, r.error ? h("p", {class: "err"}, viErr(r.error)) : null, (r.warnings || []).map(w => h("p", {class: "note"}, w)));
  }

  const side = h("aside", {class: "side"}, h("div", {class: "card"}, h("h3", null, "Telegram sẽ hiện"), pvText, pvMsgs,
    h("p", {class: "muted"}, d.approval === "auto" ? "Mức này chạy ngay, không gửi tin nhắn." : "Có nút Duyệt và Từ chối."),
    h("div", {class: "row"}, saveBtn, h("button", {onclick: () => viewProfiles(body)}, "Huỷ")), saveErr));
  fill(body, h("div", {class: "builder"}, h("div", null, step1, step2, step3, step4, step5, step6, adv), side));
  drawWhere(); drawAuth(); drawParams(); drawChips(); drawBody(); drawApproval();
  runPreview();
}

async function viewTokens(body) {
  const list = await api("GET", "/api/tokens");
  const n = field("Tên agent", {autocomplete: "off"});
  const p = field("Giới hạn profile, cách nhau bằng dấu phẩy (trống là tất cả)", {autocomplete: "off"});
  const shown = h("div");
  fill(body, form("Tạo token cho agent", [n, p], "Tạo", async () => {
    const profiles = p.input.value.split(",").map(s => s.trim()).filter(Boolean);
    const r = await api("POST", "/api/tokens", {name: n.input.value, profiles});
    await viewTokens(body);
    body.prepend(h("div", {class: "note"}, "Token chỉ hiện một lần, lưu vào ~/.config/ucanrun/token:", h("pre", null, r.token)));
  }), shown, h("div", {class: "card"}, h("h2", null, `Token (${list.length})`),
    list.length ? list.map(t => h("div", {class: "spread"}, h("span", null, h("code", null, t.name), h("div", {class: "muted"}, (t.profiles && t.profiles.length ? t.profiles.join(", ") : "mọi profile") + " · " + new Date(t.created).toLocaleString())),
      h("button", {class: "danger", onclick: async () => { if (confirm(`Thu hồi token ${t.name}?`)) { await api("DELETE", "/api/tokens/" + t.id); viewTokens(body); } }}, "Thu hồi"))) : h("p", {class: "muted"}, "Chưa có token.")));
}

async function viewSettings(body) {
  const s = await api("GET", "/api/status");
  const tg = field("Token bot từ @BotFather", {type: "password", autocomplete: "off"});
  const out = h("div");
  const pairHint = (bot, code) => out.replaceChildren(h("div", {class: "note"}, `Mở chat riêng với ${bot ? "@" + bot : "bot"} và gửi trong 3 phút:`, h("pre", null, "/pair " + code)));
  const tgCard = form("Telegram", [tg], "Lưu token", async () => {
    const r = await api("PUT", "/api/telegram", {token: tg.input.value});
    tg.input.value = ""; pairHint(r.bot, r.code);
  }, h("p", {class: "muted"}, s.telegram && s.telegram.paired ? `Đã ghép nối với user ${s.telegram.user_id}.` : (s.telegram && s.telegram.configured ? "Đã có bot, chưa ghép nối." : "Chưa cấu hình. Dùng bot riêng, không dùng chung bot khác.")));
  if (s.telegram && s.telegram.configured) tgCard.append(h("div", {class: "row"}, h("button", {onclick: async () => pairHint("", (await api("POST", "/api/telegram/pair")).code)}, "Tạo mã ghép nối mới")));
  tgCard.append(out);
  const box = h("div");
  const totpCard = h("div", {class: "card"}, h("h2", null, "TOTP"), s.totp ? h("p", {class: "muted"}, "Đã bật. Cần khi đăng nhập và duyệt yêu cầu rủi ro cao. Hãy lưu mã bí mật TOTP vào Bitwarden, mất nó thì không đăng nhập được.") :
    h("div", null, h("p", {class: "muted"}, "Yêu cầu rủi ro cao không duyệt được cho đến khi bật TOTP."), h("button", {onclick: async () => {
      const r = await api("POST", "/api/totp/start");
      const c = field("Nhập mã 6 số để xác nhận", {inputmode: "numeric", maxlength: 6});
      box.replaceChildren(h("img", {class: "qr", src: r.qr, alt: "Mã QR TOTP"}), h("pre", null, r.secret), form("Xác nhận", [c], "Bật TOTP", async () => {
        await api("POST", "/api/totp/confirm", {code: c.input.value}); viewSettings(body);
      }));
    }}, "Bật TOTP"), box));
  const o = field("Mật khẩu hiện tại", {type: "password", autocomplete: "current-password"});
  const n = field("Mật khẩu mới", {type: "password", autocomplete: "new-password"});
  fill(body, tgCard, totpCard, form("Đổi mật khẩu chính", [o, n], "Đổi", async () => {
    await api("POST", "/api/passphrase", {old: o.input.value, new: n.input.value}); o.input.value = n.input.value = "";
  }));
}

async function viewAudit(body) {
  const a = await api("GET", "/api/audit");
  fill(body, h("div", {class: "card"}, h("h2", null, "Nhật ký"),
    h("p", {class: a.chain_ok ? "muted" : "note"}, a.chain_ok ? `Chuỗi băm hợp lệ, ${a.valid_entries} mục.` : `Chuỗi băm bị hỏng sau mục ${a.valid_entries}.`),
    a.entries.map(e => h("div", {class: "spread"}, h("span", null, h("code", null, e.event), " ", e.actor || "", h("div", {class: "muted"}, e.fields ? JSON.stringify(e.fields) : "")), h("span", {class: "muted"}, new Date(e.time).toLocaleString())))));
}

boot().catch(e => app.replaceChildren(h("div", {class: "narrow err"}, e.message)));
