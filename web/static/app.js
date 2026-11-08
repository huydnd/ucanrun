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
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : ["placeholder", "aria-label", "alt"].includes(k) ? tr(v) : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(typeof c === "string" ? tr(c) : c);
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
    try { await onsubmit(); } catch (e) { err.textContent = tr(e.message); } finally { btn.disabled = false; }
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
  const {steps} = await loadSteps();
  state.incomplete = steps.some(x => !x.done);
  if (state.incomplete && !state.opened && !steps.every(x => x.done || skipped().includes(x.key))) state.tab = "start";
  state.opened = true;
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
  }, h("p", {class: "note"}, "Không có cách khôi phục nếu mất mật khẩu chính. Hãy lưu vào trình quản lý mật khẩu."))));
}

function renderLogin(locked) {
  const p = field("Mật khẩu chính", {type: "password", autocomplete: "current-password"});
  const t = field("Mã TOTP hoặc mã khôi phục (nếu đã bật)", {autocomplete: "one-time-code", maxlength: 12});
  app.replaceChildren(h("div", {class: "narrow"}, form(locked ? "Mở khoá ucanrun" : "Đăng nhập", [p, t], "Tiếp tục", async () => {
    await api("POST", "/api/login", {passphrase: p.input.value, totp: t.input.value});
    boot();
  }, locked ? h("p", {class: "muted"}, "Kho đang khoá, agent chưa chạy được lệnh nào.") : null)));
}

const tabs = {start: "Bắt đầu", requests: "Yêu cầu", secrets: "Secret", tokens: "Token agent", profiles: "Nâng cao", settings: "Cài đặt", audit: "Nhật ký"};

function renderShell() {
  const body = h("main");
  const nav = h("nav", null, Object.entries(tabs).filter(([k]) => k !== "start" || state.incomplete).map(([k, v]) =>
    h("button", {class: state.tab === k ? "on" : "", "data-req": k === "requests" ? "1" : null, onclick: () => { state.tab = k; renderShell(); }}, v)));
  const waiting = h("span", {class: "count"});
  api("GET", "/api/requests").then(l => { const n = l.filter(r => r.state === "pending").length; if (n) { waiting.textContent = n; nav.querySelector("[data-req]").append(" ", waiting); } }).catch(() => {});
  app.replaceChildren(h("header", null, h("img", {class: "brand", src: "logo.svg", alt: "", width: 28, height: 28}), h("b", null, "ucanrun"), nav,
    h("button", {onclick: async () => { await api("POST", "/api/lock"); boot(); }}, "Khoá kho")), body);
  clearInterval(state.timer);
  const views = {start: viewStart, requests: viewRequests, secrets: viewSecrets, profiles: viewProfiles, tokens: viewTokens, settings: viewSettings, audit: viewAudit};
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
      catch (e) { err.textContent = tr(e.message); }
    };
    return h("div", {class: "card"},
      h("h3", null, r.profile === "agent-call" ? tr("Agent tự soạn") : r.profile, " ", h("span", {class: "badge " + (r.risk === "high" ? "high" : "")}, r.risk === "high" ? "rủi ro cao" : "rủi ro thấp")),
      h("div", {class: "muted"}, `Agent: ${r.caller}${r.app ? " (" + r.app + ")" : ""}${r.device ? " · " + tr("Thiết bị") + ": " + r.device : ""} · Mã: ${r.hash.slice(0, 8)} · ${new Date(r.created).toLocaleTimeString()}`),
      h("pre", null, r.display),
      r.reason ? h("div", {class: "muted"}, "Lý do (agent tự khai, chưa kiểm chứng): " + r.reason) : null,
      r.state === "pending" ? h("div", null, pick ? h("label", null, h("span", null, "Secret dùng cho lần này"), pick) : null, r.totp ? code : null,
        h("div", {class: "row"}, h("button", {class: "primary", onclick: act(true)}, "Duyệt"), h("button", {class: "danger", onclick: act(false)}, "Từ chối")), err) : null,
      r.state !== "pending" ? h("div", {class: "muted"}, `Kết quả: ${r.state}` + (r.decided_by ? ` · ${r.decided_by}` : "") + (r.secret ? ` · secret ${r.secret}` : "")) : null,
      r.result ? h("pre", null, r.result.output) : null);
  };
  // History is one line per request; open a row to see the command and output.
  const tone = {done: "ok", failed: "high", denied: "", expired: ""};
  const row = r => h("details", {class: "hist"},
    h("summary", null, h("span", {class: "badge " + (tone[r.state] || "")}, {done: "xong", failed: "lỗi", denied: "đã từ chối", expired: "hết hạn", running: "đang chạy"}[r.state] || r.state), " ",
      h("b", null, r.profile === "agent-call" ? tr("Agent tự soạn") : r.profile), " ",
      h("span", {class: "muted"}, `${r.caller} · ${new Date(r.created).toLocaleTimeString()}`)),
    h("pre", null, r.display), r.reason ? h("div", {class: "muted"}, "Lý do (agent tự khai, chưa kiểm chứng): " + r.reason) : null,
    h("div", {class: "muted"}, (r.decided_by ? r.decided_by : "") + (r.secret ? ` · secret ${r.secret}` : "")),
    r.result ? h("pre", null, r.result.output) : null);
  fill(body, h("h2", null, `Đang chờ duyệt (${pending.length})`),
    pending.length ? pending.map(card) : h("div", {class: "card empty"}, h("p", {class: "muted"}, "Không có yêu cầu nào đang chờ.")),
    rest.length ? h("div", {class: "card"}, h("h2", null, "Gần đây"), rest.slice(0, 30).map(row)) : null);
}

// Picks the English variant of a data field when the UI is in English.
const L = (o, k) => lang === "en" && o[k + "_en"] || o[k];

// Workspaces group secrets; "" is the default one, shown as "Chung".
const wsLabel = w => w || tr("Chung");
const workspacesOf = list => [...new Set(list.map(s => s.workspace || ""))].sort((a, b) => a === "" ? -1 : b === "" ? 1 : a.localeCompare(b));

async function secretTemplates() {
  if (!state.templates) state.templates = await fetch("secret-templates.json").then(r => r.ok ? r.json() : []).catch(() => []);
  return state.templates;
}

async function viewSecrets(body, editing, tpl) {
  if (!editing && !tpl && state.pendingTpl) { tpl = state.pendingTpl; state.pendingTpl = null; }
  const [list, builtin, mine] = await Promise.all([api("GET", "/api/secrets"), secretTemplates(), api("GET", "/api/templates").catch(() => [])]);
  // The owner's own templates come first.
  const templates = mine.map(t => Object.assign({}, t, {custom: true})).concat(builtin);
  const cur = editing ? list.find(x => x.name === editing) : null;
  const n = field("Tên", {autocomplete: "off", spellcheck: "false", placeholder: "github_token"});
  const v = field(cur ? "Giá trị mới (để trống nếu giữ nguyên)" : "Giá trị", {type: "password", autocomplete: "off"});
  const desc = h("textarea", {class: "short", "aria-label": "Dùng để làm gì", placeholder: "Ví dụ: Token GitHub cá nhân, đọc repo và tạo issue"});
  const hosts = field("Máy chủ được phép gửi tới", {autocomplete: "off", spellcheck: "false", placeholder: "api.github.com"});
  const multi = h("textarea", {class: "short", spellcheck: "false", "aria-label": "Giá trị nhiều dòng", hidden: true});
  const toggle = h("input", {type: "checkbox", onchange: e => { multi.hidden = !e.target.checked; v.el.hidden = e.target.checked; }});
  const cmd = h("input", {type: "checkbox"});
  // A secret is one value, or several named fields such as a database login.
  let multiMode = !!(cur && cur.fields && cur.fields.length || tpl && tpl.fields);
  const rows = cur ? (cur.fields || []).map(f => ({name: f.name, public: !!f.public, value: "", had: true}))
    : tpl && tpl.fields ? tpl.fields.map(f => ({name: f.name, public: !!f.public, value: tpl.custom && f.public ? f.value || "" : "", hint: f.value})) : [];
  if (!rows.length) rows.push({name: "host", public: true, value: ""}, {name: "user", public: true, value: ""}, {name: "password", public: false, value: ""});
  const fieldBox = h("div", {hidden: !multiMode});
  const drawFields = () => fill(fieldBox, h("small", {class: "muted"}, "Trường công khai (máy chủ, cổng, user, tên database) agent thấy được giá trị và dùng ở mọi vị trí. Trường kín như password chỉ đi vào header hoặc biến môi trường."),
    rows.map((r, i) => {
      const nm = h("input", {"aria-label": "Tên trường", autocomplete: "off", spellcheck: "false", placeholder: "password"}); nm.value = r.name;
      const val = h("input", {"aria-label": "Giá trị trường", autocomplete: "off", type: r.public ? "text" : "password", placeholder: r.had ? tr("giữ nguyên") : r.hint || ""}); val.value = r.value;
      const pub = h("input", {type: "checkbox", checked: r.public, onchange: e => { r.public = e.target.checked; val.type = r.public ? "text" : "password"; }});
      nm.addEventListener("input", () => { r.name = nm.value.trim(); });
      val.addEventListener("input", () => { r.value = val.value; });
      return h("div", {class: "field-row"}, nm, val, h("label", {class: "check"}, pub, h("span", null, "Công khai")),
        h("button", {"aria-label": "Xoá trường", onclick: () => { rows.splice(i, 1); drawFields(); }}, "×"));
    }), h("button", {onclick: () => { rows.push({name: "", public: false, value: ""}); drawFields(); }}, "+ Thêm trường"));
  drawFields();
  const modeSel = choiceGroup("secretkind", multiMode ? "multi" : "one", [{value: "one", title: "Một giá trị", help: "Token, API key"}, {value: "multi", title: "Nhiều trường", help: "Đăng nhập database, máy chủ"}],
    v => { multiMode = v === "multi"; fieldBox.hidden = !multiMode; v_wrap.hidden = multiMode; });
  const execOn = !!(state.status && state.status.exec);
  const known = workspacesOf(list).filter(Boolean);
  const ws = field("Workspace", {autocomplete: "off", spellcheck: "false", placeholder: tr("Chung"), list: "ws-names", maxlength: 32});
  ws.input.value = cur ? (cur.workspace || "") : state.secretWs && state.secretWs !== "*" ? state.secretWs : "";
  const wsBox = h("div", null, ws.el, h("datalist", {id: "ws-names"}, known.map(w => h("option", {value: w}))),
    h("small", {class: "muted"}, "Nhóm secret theo việc, ví dụ Công việc, Cá nhân. Để trống là Chung. Token của agent có thể chỉ được dùng một số workspace."));
  if (cur) {
    n.input.value = cur.name; n.input.readOnly = true;
    desc.value = cur.description || ""; hosts.input.value = (cur.hosts || []).join(", "); cmd.checked = !!cur.allow_commands;
  } else if (tpl) {
    // A template fills everything except the value.
    n.input.value = tpl.name || ""; desc.value = L(tpl, "description") || ""; hosts.input.value = (tpl.hosts || []).join(", ");
    if (tpl.workspace) ws.input.value = tpl.workspace;
    cmd.checked = !!tpl.allow_commands && execOn;
    if (tpl.placeholder) v.input.placeholder = tpl.placeholder;
    if (tpl.multiline) { toggle.checked = true; multi.hidden = false; v.el.hidden = true; }
  }
  // TOTP when approving requests that use this secret.
  const totpWas = cur ? (cur.totp || "") : "";
  let totpMode = cur ? totpWas : tpl && tpl.totp || "";
  const totpCode = field("Mã TOTP hiện tại, để xác nhận tắt", {inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code"});
  const showCode = () => { totpCode.el.hidden = !(totpMode === "never" && totpWas !== "never" && state.status && state.status.totp); };
  const totpBox = h("div", null, h("h3", null, "TOTP khi duyệt"),
    choiceGroup("secrettotp", totpMode, [
      {value: "", title: "Theo mức rủi ro", help: "Cần TOTP khi việc rủi ro cao hoặc lệnh agent tự soạn. Mặc định."},
      {value: "always", title: "Luôn cần TOTP", help: "Mọi lần dùng secret này, kể cả việc rủi ro thấp hay tự duyệt."},
      {value: "never", title: "Không cần TOTP", help: "Chỉ một lần bấm Duyệt. Dùng cho secret ít quan trọng."}],
      v => { totpMode = v; showCode(); }),
    totpCode.el);
  showCode();
  const v_wrap = h("div", {hidden: multiMode}, v.el, h("label", {class: "check"}, toggle, h("span", null, "Nhiều dòng, như khoá SSH")), multi);
  const save = form(cur ? "Sửa secret" : "Lưu secret mới", [n], "Lưu", async () => {
    const hs = hosts.input.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
    const req = {description: desc.value.trim(), hosts: hs, allow_commands: cmd.checked, totp: totpMode, code: totpCode.input.value, workspace: ws.input.value.trim()};
    if (multiMode) req.fields = rows.filter(r => r.name).map(r => ({name: r.name, public: r.public, value: r.value}));
    else req.value = toggle.checked ? multi.value : v.input.value;
    await api("PUT", "/api/secrets/" + encodeURIComponent(n.input.value.trim()), req);
    viewSecrets(body);
  }, h("div", null, v_wrap, fieldBox,
    h("label", null, h("span", null, "Dùng để làm gì"), desc, h("small", {class: "muted"}, "Agent đọc dòng này để biết khi nào dùng secret. Không ghi giá trị vào đây.")),
    hosts.el, h("small", {class: "muted"}, "Agent chỉ gửi được secret tới các máy chủ này, cách nhau bằng dấu phẩy. Dùng *.example.com cho mọi tên miền con. Để trống thì agent không dùng được."),
    execOn ? h("label", {class: "check"}, cmd, h("span", null, "Cho dùng trong lệnh agent tự soạn")) : null,
    totpBox,
    h("p", {class: "muted"}, "Giá trị chỉ ghi, không có cách xem lại trên giao diện.")));
  // Read top to bottom: name, kind, value, notes, hosts, TOTP.
  save.querySelector("h2").after(n.el, wsBox, modeSel);
  // Keep this setup as a template: everything except the value.
  const tTitle = field("Tên mẫu", {autocomplete: "off", maxlength: 60});
  const tHint = field("Gợi ý (tuỳ chọn)", {autocomplete: "off", maxlength: 200});
  const tOut = h("div", {class: "err", role: "alert"});
  tTitle.input.value = cur ? cur.name : tpl ? L(tpl, "title") : "";
  save.append(h("details", {class: "save-tpl"}, h("summary", null, "Lưu thành mẫu"),
    h("p", {class: "muted"}, "Mẫu giữ tên, workspace, mô tả, máy chủ, các trường và mức TOTP. Giá trị secret và giá trị của trường riêng không được lưu."),
    tTitle.el, tHint.el,
    h("div", {class: "row"}, h("button", {type: "button", onclick: async () => {
      tOut.className = "err"; tOut.textContent = "";
      const hs = hosts.input.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
      const t = {title: tTitle.input.value.trim(), hint: tHint.input.value.trim(), name: n.input.value.trim(), description: desc.value.trim(), hosts: hs,
        fields: multiMode ? rows.filter(r => r.name).map(r => ({name: r.name, public: r.public, value: r.public ? r.value : ""})) : [],
        multiline: !multiMode && toggle.checked, allow_commands: cmd.checked, totp: totpMode, workspace: ws.input.value.trim()};
      try { await api("PUT", "/api/templates", t); tOut.className = "muted"; tOut.textContent = tr("Đã lưu mẫu."); }
      catch (e) { tOut.textContent = tr(e.message); }
    }}, "Lưu mẫu")), tOut));
  if (cur) save.append(h("div", {class: "row"}, h("button", {onclick: () => viewSecrets(body)}, "Huỷ")));
  // Templates fill the form for common services; the value is the only thing left to type.
  const tile = t => {
    const have = list.some(x => x.name === t.name);
    return h("button", {class: "tile pick" + (tpl && tpl.id === t.id ? " on" : ""), type: "button", onclick: () => {
      if (have) viewSecrets(body, t.name);
      else viewSecrets(body, null, t).then(() => { const f = body.querySelector("details.add"); if (f) { f.scrollIntoView({block: "start"}); const i = f.querySelector(t.name ? "input[type=password], textarea:not([hidden])" : "input"); if (i) i.focus(); } });
    }}, h("b", null, L(t, "title"), t.custom ? [" ", h("span", {class: "badge"}, "của bạn")] : null), h("small", {class: "muted"}, L(t, "hint") || (t.name ? t.name : "")),
      have ? h("span", {class: "badge"}, "đã có, bấm để sửa") : t.exec && !execOn ? h("span", {class: "badge"}, "cần image exec") : null);
  };
  const addBox = cur ? save : h("details", {class: "card add", open: !list.length || !!tpl},
    h("summary", null, tpl ? tr("Thêm secret") + ": " + L(tpl, "title") : tr("Thêm secret")),
    h("h3", null, "Bắt đầu từ mẫu"), h("p", {class: "muted"}, "Chọn dịch vụ để điền sẵn tên, mô tả cho agent, máy chủ và mức TOTP. Bạn chỉ cần dán giá trị."),
    h("div", {class: "tiles compact"}, templates.map(tile)),
    h("h3", null, tpl ? "Điền giá trị" : "Hoặc tự điền"), save);
  if (!cur) { save.classList.remove("card"); save.querySelector("h2").remove(); }
  // One row per secret: what it is for, where it may go, and how it is approved.
  const row = s => h("div", {class: "spread secret"}, h("span", null, h("code", null, s.name),
      s.description ? h("div", null, s.description) : h("div", {class: "note"}, "Chưa có mô tả, agent sẽ không biết dùng vào việc gì."),
      s.fields && s.fields.length ? h("div", {class: "muted"}, s.fields.map(f => f.public ? `${f.name}=${f.value || ""}` : `${f.name}=•••`).join("  ")) : null,
      h("div", {class: "chips"},
        s.hosts && s.hosts.length ? s.hosts.map(x => h("span", {class: "chip"}, "→ " + x)) : h("span", {class: "chip dim"}, "agent không dùng trực tiếp"),
        s.allow_commands ? h("span", {class: "chip"}, "dùng trong lệnh") : null,
        s.totp === "always" ? h("span", {class: "chip high"}, "luôn cần TOTP") : s.totp === "never" ? h("span", {class: "chip warn"}, "không cần TOTP") : null)),
    h("span", {class: "acts"}, h("button", {onclick: () => { viewSecrets(body, s.name); window.scrollTo(0, 0); }}, "Sửa"),
      h("button", {class: "danger", onclick: async () => {
        if (confirm(tr(`Xoá secret ${s.name}?`))) { await api("DELETE", "/api/secrets/" + encodeURIComponent(s.name)); viewSecrets(body); }
      }}, "Xoá")));
  const groups = workspacesOf(list);
  if (state.secretWs && state.secretWs !== "*" && !groups.includes(state.secretWs)) state.secretWs = "*";
  const pick = state.secretWs || "*";
  const q = h("input", {type: "search", placeholder: "Tìm theo tên hoặc mô tả", "aria-label": "Tìm secret"});
  q.value = state.secretQ || "";
  const listBox = h("div");
  const drawList = () => {
    state.secretQ = q.value;
    const t = q.value.trim().toLowerCase();
    const shown = list.filter(x => (pick === "*" || (x.workspace || "") === pick) && (!t || (x.name + " " + (x.description || "")).toLowerCase().includes(t)));
    if (!list.length) return fill(listBox, h("p", {class: "muted"}, "Chưa có secret. Chọn một mẫu ở trên để bắt đầu."));
    if (!shown.length) return fill(listBox, h("p", {class: "muted"}, "Không có secret nào khớp."));
    const by = workspacesOf(shown);
    fill(listBox, by.map(w => {
      const items = shown.filter(x => (x.workspace || "") === w);
      return h("div", {class: "group"}, groups.length > 1 && pick === "*" ? h("h3", null, wsLabel(w), h("span", {class: "count"}, String(items.length))) : null, items.map(row));
    }));
  };
  q.addEventListener("input", drawList);
  const chip = (v, label, count) => h("button", {class: "chip-btn" + (pick === v ? " on" : ""), type: "button", "aria-pressed": pick === v ? "true" : "false",
    onclick: () => { state.secretWs = v; viewSecrets(body); }}, label, h("span", {class: "count"}, String(count)));
  const bar = groups.length > 1 || list.length > 6 ? h("div", {class: "toolbar"},
    groups.length > 1 ? h("div", {class: "chips"}, chip("*", tr("Tất cả"), list.length), groups.map(w => chip(w, wsLabel(w), list.filter(x => (x.workspace || "") === w).length))) : null,
    q) : null;
  drawList();
  fill(body, cur ? save : addBox,
    h("div", {class: "card"}, h("h2", null, `Secret (${list.length})`), bar, listBox));
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
  [/bad host "(.+?)"/, m => `Máy chủ "${m[1]}" không hợp lệ, hãy ghi dạng api.example.com.`],
  [/value is required for a new secret/, "Secret mới cần có giá trị."],
  [/description is limited/, "Mô tả tối đa 300 ký tự."],
  [/with a connection the url is a path/, "Với kết nối, chỉ ghi đường dẫn bắt đầu bằng /."],
  [/is set by the connection/, "Header này do kết nối đặt, profile không ghi đè được."],
  [/base url must/, "Địa chỉ gốc phải có dạng https://api.example.com, không có ? hay #."],
  [/the base url of a connection is fixed/, "Địa chỉ gốc phải cố định, không chứa giá trị của agent."],
  [/auth needs either one secret or a list/, "Chọn một secret, hoặc tích các secret được chọn khi duyệt."],
  [/connection name must/, "Tên kết nối chỉ gồm chữ thường, số, dấu gạch."],
  [/connection is used by: (.+)/, m => `Kết nối đang được dùng bởi: ${m[1]}. Xoá các hành động đó trước.`],
  // Name the action and say why, so the fix is obvious.
  [/profile "(.+?)" would break: (.+)/, m => `Thay đổi này làm hỏng hành động "${m[1]}": ${viErr(m[2])}`],
  [/unknown connection/, "Kết nối không tồn tại."],
  [/secret_choices is required/, "Hãy tích ít nhất một secret được phép chọn."],
  [/secret choice needs a human/, "Chọn secret khi duyệt thì phải có người duyệt. Đổi hành động đó sang \"Luôn hỏi tôi\" trước."],
];
function viErr(msg) {
  for (const [re, t] of errorText) { const m = msg.match(re); if (m) return tr(typeof t === "function" ? t(m) : t); }
  return tr(msg);
}

const templates = {
  blank: {label: "Trống", d: {}},
  bearer: {label: "API có Bearer token", d: {description: "Đọc dữ liệu từ API", method: "GET", url: "https://api.example.com/v1/items/{{item_id}}", auth: "bearer",
    params: [{name: "item_id", type: "slug", required: true}]}},
  webhook: {label: "Gọi webhook", d: {description: "Kích hoạt webhook", method: "POST", url: "https://hooks.example.com/run", auth: "header", authHeader: "X-Api-Key",
    bodyMode: "json", jsonRows: [{key: "event", value: "{{event}}"}], params: [{name: "event", type: "choice", choices: "deploy, restart", required: true}]}},
};

function newDraft(over) {
  const d = Object.assign({description: "", name: "", nameTouched: false, kind: "http", connection: "", method: "GET", url: "", auth: "none", authHeader: "", secret: "",
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
  if (d.kind === "conn") {
    // The connection supplies host and sign-in; the profile is only the request.
    p.connection = d.connection;
    p.http = {method: d.method, url: d.url};
    const hs = Object.assign({}, d.extraHeaders);
    if (d.bodyMode === "json") { hs["Content-Type"] = "application/json"; p.http.body = jsonBody(d.jsonRows); }
    if (d.bodyMode === "raw") { hs["Content-Type"] = d.rawType; p.http.body = d.raw; }
    if (Object.keys(hs).length) p.http.headers = hs;
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
  if (p.connection) { d.kind = "conn"; d.connection = p.connection; }
  const auth = p.connection ? "" : headers.Authorization || "";
  let m;
  if ((m = auth.match(/^Bearer \{\{secret:(.+?)\}\}$/))) { d.auth = "bearer"; d.secret = m[1]; delete headers.Authorization; }
  else if ((m = auth.match(/^token \{\{secret:(.+?)\}\}$/))) { d.auth = "token"; d.secret = m[1]; delete headers.Authorization; }
  else if (!p.connection) for (const [k, v] of Object.entries(headers)) {
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

async function viewProfiles(body, keptImport) {
  const [list, secrets, conns] = await Promise.all([api("GET", "/api/profiles"), api("GET", "/api/secrets"), api("GET", "/api/connections")]);
  const openBuilder = d => renderBuilder(body, d, secrets, conns);
  const openConn = c => { fill(body, connForm(c, secrets, () => viewProfiles(body))); window.scrollTo(0, 0); };
  // Run now as the owner, to check a profile before an agent relies on it.
  const openTest = p => {
    const inputs = (p.params || []).map(q => { const f = field(q.name, {autocomplete: "off", spellcheck: "false"}); return [q.name, f]; });
    const pick = (p.secret_choices || []).length ? select(p.secret_choices[0], p.secret_choices.map(n => [n, n]), () => {}, "Chọn secret") : null;
    // Whether TOTP is needed depends on the secrets too, so offer the field.
    const code = field(p.risk === "high" ? "Mã TOTP" : "Mã TOTP (nếu secret yêu cầu)", {inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code"});
    const out = h("div");
    const card = form("Chạy thử: " + (p.description || p.name), inputs.map(x => x[1]).concat(code ? [code] : []), "Chạy ngay", async () => {
      out.replaceChildren(h("p", {class: "muted"}, tr("Đang chạy…")));
      const params = Object.fromEntries(inputs.filter(([, f]) => f.input.value !== "").map(([n, f]) => [n, f.input.value]));
      const r = await api("POST", `/api/profiles/${encodeURIComponent(p.name)}/test`, {params, totp: code ? code.input.value : "", secret: pick ? pick.value : ""});
      const res = r.result || {};
      out.replaceChildren(h("p", {class: res.ok ? "muted" : "note"}, tr(`Kết quả: ${r.state}`) + (res.exit ? ` · exit ${res.exit}` : "")), h("pre", null, res.output || ""));
    }, h("div", null, h("p", {class: "muted"}, "Chạy ngay với quyền của bạn, không gửi Telegram. Có ghi vào nhật ký."), pick ? h("label", null, h("span", null, "Secret dùng cho lần này"), pick) : null));
    card.append(out, h("div", {class: "row"}, h("button", {onclick: () => viewProfiles(body)}, "Đóng")));
    fill(body, card);
    window.scrollTo(0, 0);
  };
  const haveProfile = n => list.some(p => p.name === n);
  const ioErr = h("div", {class: "err", role: "alert"});
  const importBox = keptImport || h("div");
  const fileInput = h("input", {type: "file", accept: "application/json", hidden: true, onchange: () => {
    ioErr.textContent = "";
    fill(importBox);
    const f = fileInput.files && fileInput.files[0];
    if (!f) return;
    if (f.size > 1048576) {
      ioErr.textContent = tr("File quá lớn (tối đa 1 MiB).");
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => { ioErr.textContent = tr("Không đọc được file."); };
    reader.onload = () => {
      let data;
      try { data = JSON.parse(String(reader.result)); } catch (_) {
        ioErr.textContent = tr("JSON không hợp lệ");
        return;
      }
      if (!data || data.ucanrun_profiles !== 1 || !Array.isArray(data.profiles)) {
        ioErr.textContent = tr("File profile không đúng định dạng.");
        return;
      }
      const rows = data.profiles.map(p => {
        const item = p && typeof p === "object" ? p : {};
        const name = typeof item.name === "string" ? item.name : "";
        const desc = typeof item.description === "string" ? item.description : "";
        const cb = h("input", {type: "checkbox", checked: true});
        const res = h("span", {class: "muted"});
        const el = h("div", {class: "spread"},
          h("label", {class: "check"}, cb,
            h("span", null, desc ? h("b", null, desc) : null, desc ? " " : null, h("code", null, name),
              haveProfile(name) ? " " : null, haveProfile(name) ? h("span", {class: "badge"}, "ghi đè") : null)),
          res);
        return {profile: item, cb, res, el};
      });
      const importBtn = h("button", {class: "primary", type: "button", onclick: async () => {
        importBtn.disabled = true;
        // Connections first, because profiles refer to them.
        for (const c of Array.isArray(data.connections) ? data.connections : []) {
          try { await api("PUT", "/api/connections", c); } catch (e) { ioErr.textContent = viErr(e.message); }
        }
        for (const r of rows) {
          if (!r.cb.checked) continue;
          try {
            await api("PUT", "/api/profiles", r.profile);
            r.res.className = "muted";
            r.res.textContent = "ok";
          } catch (e) {
            r.res.className = "err";
            r.res.textContent = viErr(e.message);
          }
        }
        importBtn.disabled = false;
        await viewProfiles(body, importBox);
      }}, "Nhập các profile đã chọn");
      fill(importBox, h("div", {class: "card"}, h("h3", null, "Nhập profile"), rows.map(r => r.el), h("div", {class: "row"}, importBtn)));
    };
    reader.readAsText(f);
  }});
  const exportBtn = h("button", {type: "button", onclick: async () => {
    ioErr.textContent = "";
    try {
      const profiles = await api("GET", "/api/profiles");
      const connections = await api("GET", "/api/connections");
      const blob = new Blob([JSON.stringify({ucanrun_profiles: 1, connections, profiles}, null, 2)], {type: "application/json"});
      const url = URL.createObjectURL(blob);
      const a = h("a", {href: url, download: "ucanrun-profiles.json"});
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { ioErr.textContent = viErr(e.message); }
  }}, "Xuất profile");
  const importOpenBtn = h("button", {type: "button", onclick: () => { fileInput.value = ""; fileInput.click(); }}, "Nhập profile");
  fill(body, h("p", {class: "note"}, "Không bắt buộc. Thông thường chỉ cần lưu secret kèm mô tả ở tab Secret, agent tự soạn lệnh và bạn duyệt. Phần này để giới hạn chặt hơn: agent chỉ chạy đúng các hành động bạn định sẵn."),
  h("div", {class: "card"}, h("h2", null, `Kết nối (${conns.length})`),
    h("p", {class: "muted"}, "Một kết nối là một dịch vụ: nơi gọi tới và cách đăng nhập. Mọi hành động dùng chung, agent không đổi được máy chủ."),
    h("div", {class: "row"}, h("button", {class: "primary", onclick: () => openConn({_new: true, name: "", base_url: "https://", auth: {type: "bearer", secret: ""}})}, "Thêm kết nối")),
    conns.length ? conns.map(c => h("div", {class: "spread"}, h("span", null, h("b", null, c.title || c.name), " ", h("code", null, c.name),
      h("div", {class: "muted"}, c.base_url + " · " + c.auth.type + (c.auth.secret ? " · " + c.auth.secret : c.auth.choices && c.auth.choices.length ? " · " + c.auth.choices.join(" / ") : ""))),
      h("span", null, h("button", {onclick: () => openBuilder(newDraft({kind: "conn", connection: c.name, url: "/"}))}, "Hành động mới"), " ",
        h("button", {onclick: () => openConn(c)}, "Sửa"), " ",
        h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Xoá kết nối ${c.name}?`))) { try { await api("DELETE", "/api/connections/" + encodeURIComponent(c.name)); viewProfiles(body); } catch (e) { alert(viErr(e.message)); } } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có kết nối.")),
  h("div", {class: "card"}, h("h2", null, "Tự tạo profile"),
    h("p", {class: "muted"}, "Profile là một việc cụ thể bạn cho phép agent xin làm."),
    h("div", {class: "row"}, Object.values(templates).map(t => h("button", {onclick: () => openBuilder(newDraft(t.d))}, t.label)))),
  h("div", {class: "card"}, h("h2", null, `Profile (${list.length})`),
    list.length ? list.map(p => h("div", {class: "spread"}, h("span", null, h("b", null, p.description || p.name), " ",
      h("span", {class: "badge " + (p.risk === "high" ? "high" : "")}, p.risk === "high" ? "rủi ro cao" : p.auto_approve ? "tự chạy" : "hỏi duyệt"),
      h("div", {class: "muted"}, h("code", null, "ucr run " + p.name + (p.params || []).map(q => ` ${q.name}=…`).join("")))),
    h("span", null, h("button", {onclick: () => openTest(p)}, "Chạy thử"), " ", h("button", {onclick: () => openBuilder(fromProfile(p))}, "Sửa"), " ",
      h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Xoá profile ${p.name}?`))) { await api("DELETE", "/api/profiles/" + encodeURIComponent(p.name)); viewProfiles(body); } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có profile."),
    h("div", {class: "row"}, exportBtn, importOpenBtn, fileInput),
    h("p", {class: "muted"}, "File chỉ có tên secret, không có giá trị."),
    ioErr),
  importBox);
}

function connForm(c, secrets, done) {
  const x = JSON.parse(JSON.stringify(c)); x.auth = x.auth || {type: "bearer"}; x.headers = x.headers || {};
  let mode = x.auth.choices && x.auth.choices.length ? "pick" : "one";
  const name = field("Tên kết nối", {autocomplete: "off", spellcheck: "false"}); name.input.value = x.name || "";
  if (!x._new) name.input.readOnly = true;
  const title = field("Tên hiển thị", {autocomplete: "off"}); title.input.value = x.title || "";
  const base = field("Địa chỉ gốc", {autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1"}); base.input.value = x.base_url || "";
  const authBox = h("div"), headBox = h("div");
  const drawAuthC = () => {
    const kids = [select(x.auth.type, [["bearer", "Bearer token (phổ biến nhất)"], ["token", "Token kiểu Gitea, GitHub"], ["header", "Header riêng, như X-Api-Key"], ["none", "Không cần đăng nhập"]], v => { x.auth.type = v; drawAuthC(); }, "Cách đăng nhập")];
    if (x.auth.type === "header") { const hn = field("Tên header", {placeholder: "X-Api-Key", autocomplete: "off"}); hn.input.value = x.auth.header || ""; hn.input.addEventListener("input", () => { x.auth.header = hn.input.value; }); kids.push(hn.el); }
    if (x.auth.type !== "none") {
      kids.push(choiceGroup("secretmode", mode, [{value: "one", title: "Một secret"}, {value: "pick", title: "Chọn khi duyệt", help: "Nhiều tài khoản cho cùng dịch vụ"}], v => { mode = v; drawAuthC(); }));
      if (mode === "one") {
        const sn = field("Tên secret", {autocomplete: "off", spellcheck: "false", list: "secret-names"}); sn.input.value = x.auth.secret || "";
        sn.input.addEventListener("input", () => { x.auth.secret = sn.input.value.trim(); });
        kids.push(sn.el, h("datalist", {id: "secret-names"}, secrets.map(s => h("option", {value: s.name}))), h("small", {class: "muted"}, "Chưa có secret này thì thêm ở tab Secret, có sẵn mẫu cho dịch vụ phổ biến."));
      } else {
        x.auth.choices = x.auth.choices || [];
        kids.push(secrets.length ? h("div", {class: "picklist"}, secrets.map(s => h("label", {class: "check"}, h("input", {type: "checkbox", checked: x.auth.choices.includes(s.name), onchange: e => { x.auth.choices = e.target.checked ? x.auth.choices.concat(s.name) : x.auth.choices.filter(n => n !== s.name); }}), h("span", null, s.name))))
          : h("p", {class: "note"}, "Kho chưa có secret. Hãy thêm ở tab Secret trước."));
      }
    }
    fill(authBox, kids);
  };
  const drawHead = () => fill(headBox, Object.entries(x.headers).map(([k, v]) => {
    const kk = h("input", {"aria-label": "Tên header", autocomplete: "off"}); kk.value = k;
    const vv = h("input", {"aria-label": "Giá trị", autocomplete: "off"}); vv.value = v;
    const sync = () => { delete x.headers[k]; if (kk.value) x.headers[kk.value] = vv.value; k = kk.value; };
    kk.addEventListener("change", sync); vv.addEventListener("input", sync);
    return h("div", {class: "kv"}, kk, vv, h("button", {"aria-label": "Xoá", onclick: () => { delete x.headers[k]; drawHead(); }}, "×"));
  }), h("button", {onclick: () => { x.headers["X-Header-" + (Object.keys(x.headers).length + 1)] = ""; drawHead(); }}, "+ Thêm header"));
  drawAuthC(); drawHead();
  const card = form(x._new ? "Thêm kết nối" : "Sửa kết nối", [name, title, base], "Lưu kết nối", async () => {
    const out = {name: name.input.value.trim() || slugify(title.input.value), title: title.input.value.trim(), base_url: base.input.value.trim(), auth: {type: x.auth.type}};
    if (x.auth.type === "header") out.auth.header = x.auth.header;
    if (x.auth.type !== "none") { if (mode === "one") out.auth.secret = x.auth.secret; else out.auth.choices = x.auth.choices; }
    const hs = Object.fromEntries(Object.entries(x.headers).filter(([k, v]) => k && v));
    if (Object.keys(hs).length) out.headers = hs;
    try { await api("PUT", "/api/connections", out); } catch (e) { throw new Error(viErr(e.message)); }
    if (x._new && c.service_actions) for (const p of c.service_actions) await api("PUT", "/api/profiles", p).catch(() => {});
    done();
  }, h("p", {class: "muted"}, "Một kết nối là một dịch vụ: nơi gọi tới và cách đăng nhập. Mọi hành động dùng chung, agent không đổi được máy chủ."));
  card.append(h("h3", {class: "gap"}, "Đăng nhập"), authBox, h("h3", {class: "gap"}, "Header chung (tuỳ chọn)"), headBox, h("div", {class: "row"}, h("button", {onclick: done}, "Huỷ")));
  return card;
}

function renderBuilder(body, d, secrets, conns = []) {
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
    const methodSel = () => select(d.method, ["GET", "POST", "PUT", "PATCH", "DELETE"].map(m => [m, m]), v => { d.method = v; if (v !== "GET" && d.approval === "auto") { d.approval = "ask"; drawApproval(); } refresh(); }, "Phương thức");
    if (d.kind === "conn") {
      if (!d.connection && conns.length) d.connection = conns[0].name;
      const c = conns.find(x => x.name === d.connection);
      const path = h("input", {autocomplete: "off", spellcheck: "false", placeholder: "/items/{{item_id}}", "aria-label": "Đường dẫn"});
      path.value = d.url; track(path);
      path.addEventListener("input", () => { d.url = path.value; refresh(); });
      fill(where, h("label", null, h("span", null, "Kết nối"), select(d.connection, conns.map(x => [x.name, (x.title || x.name) + " · " + x.base_url]), v => { d.connection = v; drawWhere(); drawAuth(); refresh(); }, "Kết nối")),
        h("div", {class: "url-row"}, methodSel(), path),
        h("small", {class: "muted"}, c ? c.base_url.replace(/\/$/, "") + (d.url || "/…") : ""),
        h("small", {class: "muted"}, "Chỉ ghi đường dẫn bắt đầu bằng /. Máy chủ và đăng nhập lấy từ kết nối."));
      return;
    }
    const url = h("input", {type: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1/items/{{item_id}}", "aria-label": "Địa chỉ"});
    url.value = d.url; track(url);
    url.addEventListener("input", () => { d.url = url.value; refresh(); });
    fill(where, h("div", {class: "url-row"}, select(d.method, ["GET", "POST", "PUT", "PATCH", "DELETE"].map(m => [m, m]), v => { d.method = v; if (v !== "GET" && d.approval === "auto") { d.approval = "ask"; drawApproval(); } refresh(); }, "Phương thức"), url),
      h("small", {class: "muted"}, "Tên máy luôn cố định, agent chỉ điền được các giá trị ở mục 4."));
  };
  const step2 = h("section", {class: "card"}, h("h3", null, "2. Gọi tới đâu"),
    choiceGroup("kind", d.kind, [].concat(conns.length ? [{value: "conn", title: "Dùng kết nối", help: "Máy chủ và đăng nhập đã khai báo sẵn"}] : [],
      [{value: "http", title: "Địa chỉ đầy đủ", help: "Tự ghi URL và cách đăng nhập"}],
      state.status && state.status.exec ? [{value: "exec", title: "Chạy lệnh", help: "Nâng cao, chạy trong container"}] : []),
      v => { d.kind = v; drawWhere(); drawAuth(); refresh(); }), where);

  // 3. Credentials
  const authBox = h("div");
  const secretSelect = (value, on, withChoice) => secrets.length
    ? select(value, [["", "Chọn secret…"]].concat(withChoice ? [["choice", "Chọn khi duyệt trên Telegram"]] : [], secrets.map(s => [s.name, s.name])), on, "Secret")
    : h("p", {class: "note"}, "Kho chưa có secret. Hãy thêm ở tab Secret trước.");
  const drawAuth = () => {
    if (d.kind === "conn") {
      const c = conns.find(x => x.name === d.connection);
      fill(authBox, h("p", {class: "muted"}, tr("Đăng nhập theo kết nối") + " " + (c ? (c.title || c.name) : "") + (c && c.auth.choices && c.auth.choices.length ? " · " + tr("chọn secret khi duyệt") : c && c.auth.secret ? " · " + c.auth.secret : "")));
      return;
    }
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
    {value: "totp", title: "Hỏi và cần mã TOTP", help: "Cho việc xoá, thay đổi quan trọng. Bỏ qua TOTP nếu mọi secret dùng đều đặt Không cần TOTP."},
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
    const en = lang === "en";
    const head = d.approval === "totp" ? (en ? "⚠️ HIGH RISK, needs TOTP\n\n" : "⚠️ RỦI RO CAO, cần TOTP\n\n") : "";
    pvText.textContent = r.display ? head + (en ? `Agent requests: ${d.description || d.name}\n\nCommand to run:\n${r.display}` : `Agent xin chạy: ${d.description || d.name}\n\nLệnh sẽ chạy:\n${r.display}`) : tr("Điền đủ thông tin để xem trước.");
    fill(pvMsgs, r.error ? h("p", {class: "err"}, viErr(r.error)) : null, (r.warnings || []).map(w => h("p", {class: "note"}, w)));
  }

  const side = h("aside", {class: "side"}, h("div", {class: "card"}, h("h3", null, "Telegram sẽ hiện"), pvText, pvMsgs,
    h("p", {class: "muted"}, d.approval === "auto" ? "Mức này chạy ngay, không gửi tin nhắn." : "Có nút Duyệt và Từ chối."),
    h("div", {class: "row"}, saveBtn, h("button", {onclick: () => viewProfiles(body)}, "Huỷ")), saveErr));
  fill(body, h("div", {class: "builder"}, h("div", null, step1, step2, step3, step4, step5, step6, adv), side));
  drawWhere(); drawAuth(); drawParams(); drawChips(); drawBody(); drawApproval();
  runPreview();
}

// Each agent keeps MCP servers in its own settings, so the token goes there
// instead of a separate file.
const jsonCfg = (u, t, key = "mcpServers", extra = {}) => JSON.stringify({[key]: {ucanrun: Object.assign(extra, {command: "ucr", args: ["mcp"], env: {UCANRUN_URL: u, UCANRUN_TOKEN: t}})}}, null, 2);
const agents = [
  {id: "claude", name: "Claude Code", how: "Chạy trong terminal", make: (u, t) => `claude mcp add ucanrun -s user -e UCANRUN_URL=${u} -e UCANRUN_TOKEN=${t} -- ucr mcp`},
  {id: "antigravity", name: "Antigravity CLI", how: "Thêm vào file", file: "~/.gemini/config/mcp_config.json", make: jsonCfg},
  {id: "cursor", name: "Cursor", how: "Thêm vào file", file: "~/.cursor/mcp.json", make: jsonCfg},
  {id: "claude-desktop", name: "Claude Desktop", how: "Thêm vào file", file: "claude_desktop_config.json", make: jsonCfg},
  {id: "codex", name: "Codex CLI", how: "Thêm vào file", file: "~/.codex/config.toml", make: (u, t) => `[mcp_servers.ucanrun]\ncommand = "ucr"\nargs = ["mcp"]\nenv = { UCANRUN_URL = "${u}", UCANRUN_TOKEN = "${t}" }`},
  {id: "gemini", name: "Gemini CLI", how: "Thêm vào file", file: "~/.gemini/settings.json", make: jsonCfg},
  {id: "vscode", name: "VS Code", how: "Thêm vào file", file: "MCP: Open User Configuration", make: (u, t) => jsonCfg(u, t, "servers", {type: "stdio"})},
  {id: "windsurf", name: "Windsurf", how: "Thêm vào file", file: "~/.codeium/windsurf/mcp_config.json", make: jsonCfg},
  {id: "other", name: "Khác", how: "Đặt biến môi trường rồi chạy", make: (u, t) => `export UCANRUN_URL=${u}\nexport UCANRUN_TOKEN=${t}\nucr mcp`},
];

function agentPicker(cur, on) {
  return h("div", {class: "choices", role: "radiogroup", "aria-label": "Agent bạn dùng"}, agents.map(a =>
    h("label", {class: "choice"}, h("input", {type: "radio", name: "agent", value: a.id, checked: a.id === cur, onchange: () => on(a.id)}), h("span", null, h("b", null, a.name)))));
}

function agentGuide(id, token, done) {
  const box = h("div");
  let url = "http://127.0.0.1:8781";
  const draw = () => {
    const a = agents.find(x => x.id === id);
    const text = a.make(url, token), copied = h("span", {class: "muted"});
    const u = h("input", {autocomplete: "off", spellcheck: "false", "aria-label": "Địa chỉ agent API"}); u.value = url;
    u.addEventListener("change", () => { url = u.value.trim(); draw(); });
    fill(box, h("div", {class: "card"}, h("h2", null, "Nối agent"),
      agentPicker(id, v => { id = v; draw(); }),
      h("label", null, h("span", null, "Địa chỉ agent API"), u),
      h("h3", {class: "gap"}, a.how), a.file ? h("p", null, h("code", null, a.file)) : null,
      h("pre", {class: "cfg"}, text),
      h("div", {class: "row"}, h("button", {onclick: async () => {
        try { await navigator.clipboard.writeText(text); copied.textContent = tr("Đã sao chép"); } catch (_) { copied.textContent = tr("Không sao chép được, hãy chép tay."); }
      }}, "Sao chép"), copied),
      h("p", {class: "note"}, "Token chỉ hiện một lần. ", "Token nằm trong cài đặt của agent. Không commit file này và không dán token vào chat với AI."),
      h("p", {class: "muted"}, "Máy chạy agent cần lệnh ucr:"), h("pre", null, "docker cp ucanrun:/usr/local/bin/ucr ~/.local/bin/ucr"),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: done}, "Xong, về danh sách"))));
  };
  draw();
  return box;
}

function agentTokenForm(profiles, onCreated) {
  let id = "claude", touched = false, mode = "all", picked = [], wsMode = "all", wsPicked = [], wsKnown = [];
  const name = h("input", {autocomplete: "off", spellcheck: "false", "aria-label": "Tên agent"}); name.value = id;
  name.addEventListener("input", () => { touched = true; });
  const scope = h("div"), err = h("div", {class: "err", role: "alert"});
  const drawScope = () => {
    if (!profiles.length) { fill(scope, h("p", {class: "muted"}, "Chưa có profile. Token này sẽ dùng được mọi profile thêm sau.")); return; }
    fill(scope, choiceGroup("scope", mode, [{value: "all", title: "Mọi profile, kể cả profile thêm sau"}, {value: "some", title: "Chỉ các profile đã chọn"}], v => { mode = v; drawScope(); }),
      mode === "some" ? h("div", {class: "picklist"}, profiles.map(p => h("label", {class: "check"},
        h("input", {type: "checkbox", checked: picked.includes(p.name), onchange: e => { picked = e.target.checked ? picked.concat(p.name) : picked.filter(n => n !== p.name); }}),
        h("span", null, h("span", null, p.description || p.name), " ", h("code", null, p.name))))) : null);
  };
  drawScope();
  // Limit which secrets the agent can see and use, by workspace.
  const wsScope = h("div");
  const drawWs = () => fill(wsScope, h("h3", {class: "gap"}, "Giới hạn workspace"),
    choiceGroup("wsscope", wsMode, [{value: "all", title: "Mọi workspace", help: "Agent thấy mọi secret được phép"}, {value: "some", title: "Chỉ các workspace đã chọn", help: "Secret ở workspace khác coi như không tồn tại"}], v => { wsMode = v; drawWs(); }),
    wsMode === "some" ? h("div", {class: "picklist"}, wsKnown.map(w => h("label", {class: "check"},
      h("input", {type: "checkbox", checked: wsPicked.includes(w), onchange: e => { wsPicked = e.target.checked ? wsPicked.concat(w) : wsPicked.filter(x => x !== w); }}),
      h("span", null, wsLabel(w))))) : null);
  api("GET", "/api/secrets").then(l => { wsKnown = workspacesOf(l); if (wsKnown.length > 1) drawWs(); }).catch(() => {});
  return h("div", {class: "card"}, h("h2", null, "Tạo token cho agent"),
    h("h3", null, "Agent bạn dùng"), agentPicker(id, v => { id = v; if (!touched) name.value = v; }),
    h("label", null, h("span", null, "Tên agent"), name),
    h("h3", {class: "gap"}, "Giới hạn profile"), scope, wsScope,
    h("div", {class: "row"}, h("button", {class: "primary", onclick: async () => {
      err.textContent = "";
      if (mode === "some" && !picked.length) { err.textContent = tr("Hãy chọn ít nhất một profile."); return; }
      if (wsMode === "some" && !wsPicked.length) { err.textContent = tr("Hãy chọn ít nhất một workspace."); return; }
      try {
        const r = await api("POST", "/api/tokens", {name: name.value, profiles: mode === "some" ? picked : [], workspaces: wsMode === "some" ? wsPicked : []});
        onCreated(id, r.token);
      } catch (e) { err.textContent = tr(e.message); }
    }}, "Tạo")), err);
}

async function viewTokens(body) {
  const [list, profiles] = await Promise.all([api("GET", "/api/tokens"), api("GET", "/api/profiles")]);
  const tf = agentTokenForm(profiles, (id, token) => { fill(body, agentGuide(id, token, () => viewTokens(body))); window.scrollTo(0, 0); });
  tf.classList.remove("card"); tf.querySelector("h2").remove();
  const addTok = h("details", {class: "card add", open: !list.length}, h("summary", null, tr("Tạo token cho agent")), tf);
  fill(body,
    h("div", {class: "card"}, h("h2", null, `Token (${list.length})`),
    list.length ? list.map(t => h("div", {class: "spread"}, h("span", null, h("code", null, t.name), h("div", {class: "muted"}, (t.profiles && t.profiles.length ? t.profiles.join(", ") : tr("mọi profile")) + " · " + (t.workspaces && t.workspaces.length ? "workspace " + t.workspaces.map(wsLabel).join(", ") : tr("mọi workspace")) + " · " + new Date(t.created).toLocaleString())),
      h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Thu hồi token ${t.name}?`))) { await api("DELETE", "/api/tokens/" + t.id); viewTokens(body); } }}, "Thu hồi"))) : h("p", {class: "muted"}, "Chưa có token.")), addTok);
}

function showRecovery(box, codes, done) {
  // Leaving now would lose the codes for good.
  document.querySelectorAll(".skip-row").forEach(e => { e.hidden = true; });
  const go = h("button", {class: "primary", disabled: true, onclick: done}, "Tiếp tục");
  const seen = h("input", {type: "checkbox", onchange: e => { go.disabled = !e.target.checked; }});
  const list = h("pre", {class: "codes"}, codes.join("\n"));
  const copied = h("span", {class: "muted"});
  box.replaceChildren(h("div", {class: "note"}, h("b", null, "Lưu các mã khôi phục này ngay."),
    h("div", null, "Mỗi mã dùng được một lần khi mất điện thoại, và chỉ hiện lần này."), list,
    h("div", {class: "row"}, h("button", {onclick: async () => {
      try { await navigator.clipboard.writeText(codes.join("\n")); copied.textContent = tr("Đã sao chép"); }
      catch (_) { copied.textContent = tr("Không sao chép được, hãy chép tay."); }
    }}, "Sao chép"), copied),
    h("label", {class: "check"}, seen, h("span", null, "Tôi đã lưu các mã này")), h("div", {class: "row"}, go)));
}

function telegramCard(s, after) {
  const tg = field("Token bot từ @BotFather", {type: "password", autocomplete: "off"});
  const out = h("div");
  const pairHint = (bot, code) => out.replaceChildren(h("div", {class: "note"}, `Mở chat riêng với ${bot ? "@" + bot : "bot"} và gửi trong 3 phút:`, h("pre", null, "/pair " + code),
    h("div", {class: "muted"}, "Sai 3 lần thì mã bị huỷ, khi đó tạo mã mới.")));
  const paired = s.telegram && s.telegram.paired, configured = s.telegram && s.telegram.configured;
  const card = form("Telegram", [tg], "Lưu token", async () => {
    const r = await api("PUT", "/api/telegram", {token: tg.input.value});
    tg.input.value = ""; pairHint(r.bot, r.code); after && after();
  }, h("p", {class: "muted"}, paired ? `Đã ghép nối với user ${s.telegram.user_id}.` : configured ? "Đã có bot, chưa ghép nối." :
    "Tạo bot bằng @BotFather trên Telegram, rồi dán token vào đây. Dùng bot riêng, không dùng chung bot khác."));
  if (configured) card.append(h("div", {class: "row"}, h("button", {onclick: async () => pairHint("", (await api("POST", "/api/telegram/pair")).code)}, "Tạo mã ghép nối mới")));
  card.append(out);
  return card;
}

function totpCard(s, after) {
  const box = h("div");
  const card = h("div", {class: "card"}, h("h2", null, "TOTP"), box);
  if (!s.totp) {
    box.append(h("p", {class: "muted"}, "Mã 6 số từ ứng dụng xác thực như Aegis, Google Authenticator. Yêu cầu rủi ro cao không duyệt được cho đến khi bật TOTP."),
      h("button", {class: "primary", onclick: async () => {
        const r = await api("POST", "/api/totp/start");
        const c = field("Nhập mã 6 số để xác nhận", {inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code"});
        box.replaceChildren(h("img", {class: "qr", src: r.qr, alt: "Mã QR TOTP"}), h("p", {class: "muted"}, "Không quét được thì nhập mã này:"), h("pre", null, r.secret),
          form("Xác nhận", [c], "Bật TOTP", async () => {
            const d = await api("POST", "/api/totp/confirm", {code: c.input.value});
            showRecovery(box, d.recovery_codes, after);
          }));
      }}, "Bật TOTP"));
    return card;
  }
  const code = field("Mã TOTP hiện tại", {inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code"});
  const err = h("div", {class: "err"});
  box.append(h("p", {class: s.recovery_left ? "muted" : "note"}, s.recovery_left ? `Đã bật. Còn ${s.recovery_left} mã khôi phục.` : "Đã bật nhưng chưa có mã khôi phục. Mất điện thoại sẽ không đăng nhập được."),
    code.el, h("div", {class: "row"}, h("button", {class: s.recovery_left ? "" : "primary", onclick: async () => {
      err.textContent = "";
      try { const d = await api("POST", "/api/totp/recovery", {code: code.input.value}); showRecovery(box, d.recovery_codes, after); }
      catch (e) { err.textContent = tr(e.message); }
    }}, s.recovery_left ? "Tạo bộ mã mới" : "Tạo mã khôi phục")), err);
  if (after) return card;
  const p = field("Mật khẩu chính", {type: "password", autocomplete: "current-password"});
  const c2 = field("Mã TOTP hoặc mã khôi phục", {autocomplete: "one-time-code", maxlength: 12});
  card.append(h("details", null, h("summary", null, "Đổi điện thoại"),
    h("p", {class: "muted"}, "Tắt TOTP hiện tại để quét lại trên điện thoại mới."),
    form("Tắt TOTP", [p, c2], "Tắt để đăng ký lại", async () => {
      await api("POST", "/api/totp/reset", {passphrase: p.input.value, code: c2.input.value}); boot();
    })));
  return card;
}

// The vault locks itself after this long without any activity.
function autoLockCard(s) {
  const err = h("div", {class: "err", role: "alert"});
  const cur = s.auto_lock_min || 0;
  const opts = [[0, "Không tự khoá", ""], [15, "15 phút", ""], [60, "1 giờ", ""], [240, "4 giờ", ""], [1440, "24 giờ", ""]];
  if (!opts.some(o => o[0] === cur)) opts.push([cur, `${cur} phút`, ""]);
  return h("div", {class: "card"}, h("h2", null, "Tự khoá kho"),
    h("p", {class: "muted"}, "Khoá kho khi không có hoạt động nào: không mở web, không duyệt, không có yêu cầu từ agent. Khi khoá, agent nhận lỗi 423 cho tới khi bạn đăng nhập. Nếu chọn Không tự khoá, kho chỉ khoá khi bạn bấm Khoá kho hoặc server khởi động lại."),
    choiceGroup("autolock", String(cur), opts.map(([v, t, help]) => ({value: String(v), title: t, help})), async v => {
      err.textContent = "";
      try { await api("PUT", "/api/settings", {auto_lock_min: Number(v)}); state.status = await api("GET", "/api/status"); }
      catch (e) { err.textContent = tr(e.message); }
    }), err);
}

// Templates the owner saved from the secret form.
async function myTemplatesCard() {
  const box = h("div");
  const card = h("div", {class: "card"}, h("h2", null, "Mẫu secret của bạn"),
    h("p", {class: "muted"}, "Mở form ở tab Secret, điền như mong muốn rồi bấm Lưu thành mẫu. Mẫu hiện trước các mẫu có sẵn."), box);
  const draw = async () => {
    const list = await api("GET", "/api/templates").catch(() => []);
    fill(box, list.length ? list.map(t => h("div", {class: "spread"}, h("span", null, h("b", null, t.title), " ", t.name ? h("code", null, t.name) : null,
        h("div", {class: "muted"}, [t.workspace ? wsLabel(t.workspace) : tr("Chung"), t.hint].filter(Boolean).join(" · "))),
      h("span", {class: "acts"}, h("button", {onclick: () => { state.pendingTpl = Object.assign({}, t, {custom: true}); state.tab = "secrets"; renderShell(); window.scrollTo(0, 0); }}, "Dùng"),
        h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Xoá mẫu ${t.title}?`))) { await api("DELETE", "/api/templates/" + encodeURIComponent(t.id)); draw(); } }}, "Xoá"))))
      : h("p", {class: "muted"}, "Chưa có mẫu nào."));
  };
  await draw();
  return card;
}

function healthCard(items) {
  const bad = items.filter(i => i.level === "bad").length, warn = items.filter(i => i.level === "warn").length;
  const parts = [bad ? `${bad} lỗi` : "", warn ? `${warn} cảnh báo` : ""].filter(Boolean);
  const title = "Sức khoẻ bảo mật" + (parts.length ? ` (${parts.join(", ")})` : " (ổn)");
  return h("div", {class: "card"}, h("h2", null, title),
    h("ul", {class: "health"}, items.map(i => h("li", null, h("span", {class: "dot " + i.level, "aria-hidden": "true"}), h("span", null, i.message,
      (i.names || []).flatMap(n => [" ", h("code", null, n)]))))));
}

async function viewSettings(body) {
  const [s, health] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/health")]);
  const o = field("Mật khẩu hiện tại", {type: "password", autocomplete: "current-password"});
  const n = field("Mật khẩu mới", {type: "password", autocomplete: "new-password"});
  const langSel = select(lang, [["vi", "Tiếng Việt"], ["en", "English"]], v => { try { localStorage.setItem("ucr_lang", v); } catch (_) {} location.reload(); }, "Ngôn ngữ");
  const tplCard = await myTemplatesCard();
  fill(body, healthCard(health), h("div", {class: "card"}, h("h2", null, "Ngôn ngữ"), langSel), autoLockCard(s), tplCard, telegramCard(s), totpCard(s), form("Đổi mật khẩu chính", [o, n], "Đổi", async () => {
    await api("POST", "/api/passphrase", {old: o.input.value, new: n.input.value}); o.input.value = n.input.value = "";
  }));
}

function skipped() { try { return JSON.parse(localStorage.getItem("ucr_skip") || "[]"); } catch (_) { return []; } }
function unskip(k) { try { localStorage.setItem("ucr_skip", JSON.stringify(skipped().filter(x => x !== k))); } catch (_) {} }
function skip(k) { try { localStorage.setItem("ucr_skip", JSON.stringify([...new Set(skipped().concat(k))])); } catch (_) {} }

async function loadSteps() {
  const [s, profiles, tokens] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/profiles"), api("GET", "/api/tokens")]);
  const steps = [
    {key: "telegram", title: "Nối Telegram", why: "Để nhận yêu cầu duyệt trên điện thoại.", done: !!(s.telegram && s.telegram.paired)},
    {key: "totp", title: "Bật TOTP và lưu mã khôi phục", why: "Lớp bảo vệ thứ hai khi đăng nhập và duyệt việc rủi ro cao.", done: !!s.totp && s.recovery_left > 0},
    {key: "service", title: "Lưu secret đầu tiên", why: "Kèm một dòng mô tả và máy chủ được phép gửi tới.", done: (await api("GET", "/api/secrets")).some(x => (x.hosts || []).length) || profiles.length > 0},
    {key: "agent", title: "Tạo token cho agent", why: "Để agent gửi được yêu cầu tới ucanrun.", done: tokens.length > 0},
  ];
  return {s, steps};
}

async function viewStart(body) {
  const {s, steps} = await loadSteps();
  const redraw = () => viewStart(body);
  const skips = skipped();
  const cur = steps.find(x => !x.done && x.key === state.startStep) || steps.find(x => !x.done && !skips.includes(x.key));
  const open = k => { state.startStep = k; unskip(k); redraw(); };
  const list = h("ol", {class: "steps"}, steps.map(x => h("li", {class: x.done ? "ok" : x === cur ? "on" : ""}, h("b", null, x.title), h("small", {class: "muted"}, x.done ? "Xong" : x.why),
    !x.done && x !== cur ? h("button", {class: "stepgo", onclick: () => open(x.key)}, "Làm bước này") : null)));
  const head = h("div", {class: "card"}, h("h2", null, "Bắt đầu"), list);
  clearInterval(state.timer);
  if (!cur) {
    head.append(h("p", null, tr(steps.every(x => x.done) ? "Đã thiết lập xong." : "Các bước còn lại có thể làm sau trong Cài đặt.")),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: () => { state.tab = "requests"; renderShell(); }}, "Vào trang yêu cầu")));
    fill(body, head); window.scrollTo(0, 0); return;
  }
  const skipBtn = h("div", {class: "row skip-row"}, h("button", {onclick: () => { skip(cur.key); state.startStep = null; redraw(); }}, "Bỏ qua, làm sau"));
  const watchPairing = () => { clearInterval(state.timer); state.timer = setInterval(async () => {
    const n = await api("GET", "/api/status").catch(() => null);
    if (n && n.telegram && n.telegram.paired) { clearInterval(state.timer); state.startStep = null; redraw(); }
  }, 3000); };
  let panel;
  if (cur.key === "telegram") {
    panel = telegramCard(s, watchPairing);
    if (s.telegram && s.telegram.configured) watchPairing();
  } else if (cur.key === "totp") {
    panel = totpCard(s, () => { state.startStep = null; redraw(); });
  } else if (cur.key === "service") {
    panel = h("div", {class: "card"}, h("h2", null, "Lưu secret"), h("p", {class: "muted"}, "Mở tab Secret, dán token, viết một dòng nó dùng làm gì và máy chủ nhận nó, ví dụ api.github.com. Agent sẽ thấy tên và mô tả, không bao giờ thấy giá trị."),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: () => { state.tab = "secrets"; renderShell(); }}, "Mở tab Secret")));
  } else {
    const profiles = await api("GET", "/api/profiles");
    panel = agentTokenForm(profiles, (id, token) => { fill(body, head, agentGuide(id, token, () => { state.startStep = null; redraw(); })); window.scrollTo(0, 0); });
  }
  fill(body, head, panel, skipBtn);
  window.scrollTo(0, 0);
}

// One line per finished run; open it for the command and details.
function runRow(r) {
  const secs = r.duration_ms != null ? (r.duration_ms < 1000 ? `${r.duration_ms} ms` : `${(r.duration_ms / 1000).toFixed(1)} s`) : "";
  const who = [r.agent, r.app ? `(${r.app})` : "", r.device ? "· " + r.device : ""].filter(Boolean).join(" ");
  return h("details", {class: "hist"},
    h("summary", null, h("span", {class: "badge " + (r.ok === true ? "ok" : r.ok === false ? "high" : "")}, r.ok === true ? "xong" : r.ok === false ? "lỗi" : "—"), " ",
      h("b", null, r.profile === "agent-call" ? tr("Agent tự soạn") : (r.profile || "?")), " ",
      h("span", {class: "muted"}, `${who || "?"} · ${new Date(r.time).toLocaleString()}${secs ? " · " + secs : ""}`)),
    r.command ? h("pre", null, r.command) : null,
    h("div", {class: "muted"}, [tr("Secret") + ": " + ((r.secrets || []).join(", ") || "—"),
      tr("Duyệt bởi") + ": " + (r.approved_by || "—"),
      `exit ${r.exit} · ${r.bytes} bytes`].join(" · ")));
}

async function viewAudit(body) {
  const [a, runs] = await Promise.all([api("GET", "/api/audit"), api("GET", "/api/runs")]);
  const list = runs.runs || [];
  const q = h("input", {type: "search", placeholder: "Lọc theo agent, thiết bị, secret, lệnh", "aria-label": "Lọc lần chạy"});
  const box = h("div");
  const draw = () => {
    const t = q.value.trim().toLowerCase();
    const shown = t ? list.filter(r => JSON.stringify(r).toLowerCase().includes(t)) : list;
    box.replaceChildren(...(shown.length ? shown.map(runRow) : [h("p", {class: "muted"}, "Chưa có lần chạy nào.")]));
  };
  q.addEventListener("input", draw);
  draw();
  fill(body, h("div", {class: "card"}, h("h2", null, `Lần chạy (${list.length})`),
      h("p", {class: "muted"}, "Mỗi lần chạy: agent, thiết bị (do máy agent tự khai), secret đã dùng, lệnh, kết quả và thời gian xử lý. Lấy từ nhật ký có chuỗi băm."),
      q, box),
    h("div", {class: "card"}, h("h2", null, "Nhật ký"),
    h("p", {class: a.chain_ok ? "muted" : "note"}, a.chain_ok ? `Chuỗi băm hợp lệ, ${a.valid_entries} mục.` : `Chuỗi băm bị hỏng sau mục ${a.valid_entries}.`),
    a.truncated ? h("p", {class: "note"}, "Nhật ký đã bị cắt bớt so với lần lưu trước.") : null,
    a.entries.map(e => h("div", {class: "spread"}, h("span", null, h("code", null, e.event), " ", e.actor || "", h("div", {class: "muted"}, e.fields ? JSON.stringify(e.fields) : "")), h("span", {class: "muted"}, new Date(e.time).toLocaleString())))));
}

boot().catch(e => app.replaceChildren(h("div", {class: "narrow err"}, e.message)));
