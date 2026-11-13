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
  state.overview = steps.every(x => x.done || skipped().includes(x.key));
  if (!state.opened) state.tab = "start";
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

// Setup tabs come in the order they are needed, then the daily ones.
const tabs = {start: "Bắt đầu", secrets: "Secret", runners: "Runner", tokens: "Token agent", profiles: "Hành động", requests: "Yêu cầu", audit: "Nhật ký", settings: "Cài đặt"};
const flow = [
  {tab: "secrets", text: "Lưu token, mật khẩu, khoá SSH mà agent cần. Mỗi secret ghi rõ dùng để làm gì và được gửi tới máy chủ nào. Agent thấy tên và mô tả, không bao giờ thấy giá trị."},
  {tab: "runners", optional: true, text: "Cần khi agent phải chạy lệnh trên một máy (PC, laptop, server, Raspberry Pi). Runner là ucr chạy trên máy đó, tự kết nối về đây lấy việc đã duyệt; máy không cần mở cổng. Chỉ gọi API qua HTTP thì bỏ qua bước này."},
  {tab: "tokens", text: "Mỗi agent (Claude Code, Antigravity…) cần một token để gửi yêu cầu tới ucanrun. Có thể giới hạn token theo workspace hoặc theo hành động."},
  {tab: "profiles", optional: true, text: "Để siết chặt hơn: định sẵn từng việc agent được làm, và dịch vụ API nó được gọi tới. Thường không cần: agent tự soạn yêu cầu, bạn xem và duyệt."},
];

function flowIntro(tab) {
  const i = flow.findIndex(f => f.tab === tab);
  if (i < 0) return null;
  const f = flow[i];
  return h("div", {class: "intro"}, h("span", {class: "stepno"}, `${tr("Bước")} ${i + 1}/${flow.length}${f.optional ? " · " + tr("tuỳ chọn") : ""}`), h("p", null, tr(f.text)));
}

function flowNext(tab) {
  const i = flow.findIndex(f => f.tab === tab);
  if (i < 0) return null;
  const go = t => () => { state.tab = t; renderShell(); window.scrollTo(0, 0); };
  const nx = flow[i + 1];
  return h("div", {class: "row flow-next"}, i > 0 ? h("button", {onclick: go(flow[i - 1].tab)}, `← ${tr(tabs[flow[i - 1].tab])}`) : null,
    nx ? h("button", {class: "primary", onclick: go(nx.tab)}, `${tr("Tiếp")}: ${tr(tabs[nx.tab])} →`) : h("button", {class: "primary", onclick: go("start")}, tr("Xong, về Tổng quan")));
}

function renderShell() {
  // Views fill `body`; the step intro and the next button stay around it.
  const body = h("div", {class: "view"});
  const main = h("main", null, flowIntro(state.tab), body, flowNext(state.tab));
  // Once setup is done, the first tab becomes an overview.
  const label = (k, v) => k === "start" && state.overview ? "Tổng quan" : v;
  const nav = h("nav", null, Object.entries(tabs).flatMap(([k, v]) => [k === "requests" ? h("span", {class: "sep", "aria-hidden": "true"}) : null,
    h("button", {class: state.tab === k ? "on" : "", "data-req": k === "requests" ? "1" : null, onclick: () => { state.tab = k; renderShell(); }}, label(k, v))]));
  const waiting = h("span", {class: "count"});
  api("GET", "/api/requests").then(l => { const n = l.filter(r => r.state === "pending").length; if (n) { waiting.textContent = n; nav.querySelector("[data-req]").append(" ", waiting); } }).catch(() => {});
  app.replaceChildren(h("header", null, h("img", {class: "brand", src: "logo.svg", alt: "", width: 28, height: 28}), h("b", null, "ucanrun"), nav,
    h("button", {onclick: async () => { await api("POST", "/api/lock"); boot(); }}, "Khoá kho")), main);
  clearInterval(state.timer);
  const views = {start: viewStart, requests: viewRequests, secrets: viewSecrets, runners: viewRunners, profiles: viewProfiles, tokens: viewTokens, settings: viewSettings, audit: viewAudit};
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
  const execOn = !!(state.status && state.status.exec);
  const n = field("Tên", {autocomplete: "off", spellcheck: "false", placeholder: "github_token"});
  const known = workspacesOf(list).filter(Boolean);
  const ws = field("Workspace", {autocomplete: "off", spellcheck: "false", placeholder: tr("Chung"), list: "ws-names", maxlength: 32});
  ws.input.value = cur ? (cur.workspace || "") : state.secretWs != null && state.secretWs !== "*" ? state.secretWs : "";
  // Existing workspaces as buttons, Shared first; typing a new name makes one.
  const wsPicks = h("div", {class: "ws-picks", role: "group", "aria-label": tr("Workspace có sẵn")});
  const drawPicks = () => fill(wsPicks, [""].concat(known).map(w => h("button", {type: "button", class: "chip-btn small" + (ws.input.value.trim() === w ? " on" : ""),
    "aria-pressed": String(ws.input.value.trim() === w), onclick: () => { ws.input.value = w; drawPicks(); }}, wsLabel(w))));
  ws.input.addEventListener("input", drawPicks);
  drawPicks();
  const v = field(cur ? "Giá trị mới (để trống nếu giữ nguyên)" : "Giá trị", {type: "password", autocomplete: "off"});
  const desc = h("textarea", {class: "short desc", rows: 2, "aria-label": "Dùng để làm gì", placeholder: "Ví dụ: Token GitHub cá nhân, đọc repo và tạo issue"});
  const hosts = field("Máy chủ được phép gửi tới", {autocomplete: "off", spellcheck: "false", placeholder: "api.github.com, *.example.com"});
  const multi = h("textarea", {class: "short", spellcheck: "false", "aria-label": "Giá trị nhiều dòng", hidden: true});
  const toggle = h("input", {type: "checkbox", onchange: e => { multi.hidden = !e.target.checked; v.el.hidden = e.target.checked; }});
  const cmd = h("input", {type: "checkbox", onchange: () => { hostWarn(); drawSummary(); }});
  // Empty hosts mean agents cannot use the secret in calls they write.
  const noHosts = h("small", {class: "warn-line", hidden: true}, "Agent chưa tự gọi được secret này vì chưa có máy chủ nào. Thêm máy chủ, ví dụ api.github.com, để agent gửi được yêu cầu. Hành động cố định ở tab Hành động vẫn dùng được.");
  const hostWarn = () => { noHosts.hidden = !!hosts.input.value.trim() || (cmd.checked && execOn); };
  hosts.input.addEventListener("input", hostWarn);
  // A secret is one value, or several named fields such as a database login.
  let multiMode = !!(cur && cur.fields && cur.fields.length || tpl && tpl.fields);
  const rows = cur ? (cur.fields || []).map(f => ({name: f.name, public: !!f.public, value: "", had: true}))
    : tpl && tpl.fields ? tpl.fields.map(f => ({name: f.name, public: !!f.public, value: tpl.custom && f.public ? f.value || "" : "", hint: f.value})) : [];
  if (!rows.length) rows.push({name: "host", public: true, value: ""}, {name: "user", public: true, value: ""}, {name: "password", public: false, value: ""});
  const fieldBox = h("div", {class: "fields", hidden: !multiMode});
  const drawFields = () => fill(fieldBox,
    rows.map((r, i) => {
      const nm = h("input", {"aria-label": "Tên trường", autocomplete: "off", spellcheck: "false", placeholder: "password"}); nm.value = r.name;
      const val = h("input", {"aria-label": "Giá trị trường", autocomplete: "off", type: r.public ? "text" : "password", placeholder: r.had ? tr("giữ nguyên") : r.hint || ""}); val.value = r.value;
      const pub = h("input", {type: "checkbox", checked: r.public, onchange: e => { r.public = e.target.checked; val.type = r.public ? "text" : "password"; }});
      nm.addEventListener("input", () => { r.name = nm.value.trim(); });
      val.addEventListener("input", () => { r.value = val.value; });
      return h("div", {class: "field-row"}, nm, val, h("label", {class: "check", title: tr("Trường công khai (máy chủ, cổng, user, tên database) agent thấy được giá trị và dùng ở mọi vị trí. Trường kín như password chỉ đi vào header hoặc biến môi trường.")}, pub, h("span", null, "Công khai")),
        h("button", {class: "icon", "aria-label": "Xoá trường", onclick: () => { rows.splice(i, 1); drawFields(); }}, "×"));
    }), h("button", {class: "small", onclick: () => { rows.push({name: "", public: false, value: ""}); drawFields(); }}, "+ Thêm trường"));
  drawFields();
  const v_wrap = h("div", {hidden: multiMode}, v.el, multi);
  const lines = h("label", {class: "check inline", hidden: multiMode}, toggle, h("span", null, "Nhiều dòng"));
  // A compact switch instead of two big cards.
  const seg = h("div", {class: "seg", role: "radiogroup", "aria-label": "Kiểu secret"});
  const drawSeg = () => fill(seg, [["one", "Một giá trị"], ["multi", "Nhiều trường"]].map(([k, t]) =>
    h("button", {type: "button", role: "radio", "aria-checked": String((k === "multi") === multiMode), class: (k === "multi") === multiMode ? "on" : "",
      onclick: () => { multiMode = k === "multi"; fieldBox.hidden = !multiMode; v_wrap.hidden = multiMode; lines.hidden = multiMode; drawSeg(); }}, t)));
  drawSeg();
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
  // Options that weaken approvals need a current TOTP code.
  const totpWas = cur ? (cur.totp || "") : "";
  let totpMode = cur ? totpWas : tpl && tpl.totp || "";
  const approveWas = cur ? (cur.approve || "") : "";
  let approveMode = cur ? approveWas : tpl && tpl.approve || "";
  const totpCode = field("Mã TOTP hiện tại, để xác nhận thay đổi", {inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code"});
  const weaker = () => (totpMode === "never" && totpWas !== "never") || (approveMode === "auto" && approveWas !== "auto");
  const showCode = () => { totpCode.el.hidden = !(weaker() && state.status && state.status.totp); };
  const totpSel = select(totpMode, [["", tr("Theo mức rủi ro")], ["always", tr("Luôn cần TOTP")], ["never", tr("Không cần TOTP")]], x => { totpMode = x; showCode(); drawSummary(); }, "TOTP khi duyệt");
  const approveSel = select(approveMode, [["", tr("Hỏi tôi mỗi lần")], ["auto", tr("Tự chạy, không hỏi")]], x => { approveMode = x; showCode(); drawSummary(); }, "Duyệt khi agent dùng");
  const optSum = h("span", {class: "muted"});
  const drawSummary = () => {
    const on = [cmd.checked && execOn ? tr("dùng trong lệnh") : "", totpMode === "always" ? tr("luôn cần TOTP") : totpMode === "never" ? tr("không cần TOTP") : "", approveMode === "auto" ? tr("tự chạy, không hỏi") : ""].filter(Boolean);
    optSum.textContent = on.length ? " · " + on.join(", ") : " · " + tr("mặc định");
  };
  const opts = h("details", {class: "opts", open: !!(cur && (cur.totp || cur.approve))},
    h("summary", null, tr("Tuỳ chọn"), optSum),
    execOn ? h("label", {class: "check"}, cmd, h("span", null, "Cho dùng trong lệnh agent tự soạn")) : null,
    h("div", {class: "grid2"},
      h("label", null, h("span", null, "TOTP khi duyệt"), totpSel),
      h("label", null, h("span", null, "Duyệt khi agent dùng"), approveSel)),
    h("small", {class: "muted"}, "Theo mức rủi ro: cần TOTP khi việc rủi ro cao hoặc lệnh agent tự soạn. Tự chạy: không gửi tin duyệt, vẫn ghi vào nhật ký."),
    totpCode.el);
  showCode(); hostWarn(); drawSummary();
  const save = form(cur ? "Sửa secret" : "Lưu secret mới", [], "Lưu", async () => {
    const hs = hosts.input.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
    const req = {description: desc.value.trim(), hosts: hs, allow_commands: cmd.checked, totp: totpMode, approve: approveMode, code: totpCode.input.value, workspace: ws.input.value.trim()};
    if (multiMode) req.fields = rows.filter(r => r.name).map(r => ({name: r.name, public: r.public, value: r.value}));
    else req.value = toggle.checked ? multi.value : v.input.value;
    await api("PUT", "/api/secrets/" + encodeURIComponent(n.input.value.trim()), req);
    viewSecrets(body);
  }, h("div", {class: "secret-form"},
    h("div", {class: "grid2"}, n.el, h("div", null, ws.el, h("datalist", {id: "ws-names"}, known.map(w => h("option", {value: w}))), wsPicks)),
    h("div", {class: "row tight"}, seg, lines),
    v_wrap, fieldBox,
    h("label", null, h("span", null, "Dùng để làm gì"), desc),
    h("small", {class: "muted"}, "Agent đọc dòng này để biết khi nào dùng secret. Không ghi giá trị vào đây."),
    hosts.el, noHosts,
    opts));
  // Keep this setup as a template: everything except the value.
  const tTitle = field("Tên mẫu", {autocomplete: "off", maxlength: 60});
  const tHint = field("Gợi ý (tuỳ chọn)", {autocomplete: "off", maxlength: 200});
  const tOut = h("div", {class: "err", role: "alert"});
  tTitle.input.value = cur ? cur.name : tpl ? L(tpl, "title") : "";
  const tplBox = h("div", {class: "save-tpl", hidden: true}, h("div", {class: "grid2"}, tTitle.el, tHint.el),
    h("small", {class: "muted"}, "Mẫu không lưu giá trị secret hay giá trị trường riêng."),
    h("div", {class: "row"}, h("button", {type: "button", onclick: async () => {
      tOut.className = "err"; tOut.textContent = "";
      const hs = hosts.input.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
      const t = {title: tTitle.input.value.trim(), hint: tHint.input.value.trim(), name: n.input.value.trim(), description: desc.value.trim(), hosts: hs,
        fields: multiMode ? rows.filter(r => r.name).map(r => ({name: r.name, public: r.public, value: r.public ? r.value : ""})) : [],
        multiline: !multiMode && toggle.checked, allow_commands: cmd.checked, totp: totpMode, workspace: ws.input.value.trim()};
      try { await api("PUT", "/api/templates", t); tOut.className = "muted"; tOut.textContent = tr("Đã lưu mẫu."); }
      catch (e) { tOut.textContent = tr(e.message); }
    }}, "Lưu mẫu")), tOut);
  const btnRow = save.querySelector(":scope > .row");
  btnRow.append(...(cur ? [h("button", {type: "button", onclick: () => viewSecrets(body)}, "Huỷ")] : []),
    h("button", {type: "button", class: "link", onclick: () => { tplBox.hidden = !tplBox.hidden; }}, "Lưu thành mẫu"));
  btnRow.after(tplBox);
  save.append(h("small", {class: "muted foot"}, "Giá trị chỉ ghi, không có cách xem lại trên giao diện."));
  // Templates fill the form for common services; the value is the only thing left to type.
  const pill = t => {
    const have = list.some(x => x.name === t.name);
    const hint = [L(t, "hint"), have ? tr("đã có, bấm để sửa") : t.exec && !execOn ? tr("cần image exec") : ""].filter(Boolean).join(" · ");
    return h("button", {class: "pill" + (tpl && tpl.id === t.id ? " on" : "") + (have ? " have" : "") + (t.custom ? " mine" : ""), type: "button", title: hint, onclick: () => {
      if (have) viewSecrets(body, t.name);
      else viewSecrets(body, null, t).then(() => { const f = body.querySelector("details.add"); if (f) { const i = f.querySelector(t.name ? "input[type=password], textarea:not([hidden])" : "input"); if (i) i.focus(); } });
    }}, L(t, "title"), have ? " ✓" : "");
  };
  const addBox = cur ? save : h("details", {class: "card add", open: !list.length || !!tpl},
    h("summary", null, tpl ? tr("Thêm secret") + ": " + L(tpl, "title") : tr("Thêm secret")),
    h("div", {class: "pills", "aria-label": tr("Bắt đầu từ mẫu")}, h("span", {class: "muted"}, tr("Mẫu") + ":"), templates.map(pill)),
    tpl && L(tpl, "hint") ? h("small", {class: "muted"}, L(tpl, "hint")) : null,
    save);
  if (!cur) { save.classList.remove("card"); save.querySelector("h2").remove(); }
  // One row per secret: what it is for, where it may go, and how it is approved.
  const row = s => h("div", {class: "spread secret"}, h("span", null, h("code", null, s.name),
      s.description ? h("div", null, s.description) : h("div", {class: "note"}, "Chưa có mô tả, agent sẽ không biết dùng vào việc gì."),
      s.fields && s.fields.length ? h("div", {class: "muted"}, s.fields.map(f => f.public ? `${f.name}=${f.value || ""}` : `${f.name}=•••`).join("  ")) : null,
      h("div", {class: "chips"},
        s.hosts && s.hosts.length ? s.hosts.map(x => h("span", {class: "chip"}, "→ " + x)) : h("span", {class: "chip dim"}, "agent không dùng trực tiếp"),
        s.allow_commands ? h("span", {class: "chip"}, "dùng trong lệnh") : null,
        s.totp === "always" ? h("span", {class: "chip high"}, "luôn cần TOTP") : s.totp === "never" ? h("span", {class: "chip warn"}, "không cần TOTP") : null,
        s.approve === "auto" ? h("span", {class: "chip warn"}, "tự chạy, không hỏi") : null)),
    h("span", {class: "acts"}, h("button", {onclick: () => { viewSecrets(body, s.name); window.scrollTo(0, 0); }}, "Sửa"),
      h("button", {class: "danger", onclick: async () => {
        if (confirm(tr(`Xoá secret ${s.name}?`))) { await api("DELETE", "/api/secrets/" + encodeURIComponent(s.name)); viewSecrets(body); }
      }}, "Xoá")));
  const groups = workspacesOf(list);
  if (state.secretWs != null && state.secretWs !== "*" && !groups.includes(state.secretWs)) state.secretWs = "*";
  // "" is the shared workspace, so it must not fall back to all.
  const pick = state.secretWs ?? "*";
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
  [/profile name/, "Tên hành động chỉ gồm chữ thường, số, dấu gạch."],
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
  [/with a connection the url is a path/, "Với dịch vụ API, chỉ ghi đường dẫn bắt đầu bằng /."],
  [/is set by the connection/, "Header này do dịch vụ API đặt, hành động không ghi đè được."],
  [/base url must/, "Địa chỉ gốc phải có dạng https://api.example.com, không có ? hay #."],
  [/the base url of a connection is fixed/, "Địa chỉ gốc phải cố định, không chứa giá trị của agent."],
  [/auth needs either one secret or a list/, "Chọn một secret, hoặc tích các secret được chọn khi duyệt."],
  [/connection name must/, "Tên dịch vụ chỉ gồm chữ thường, số, dấu gạch."],
  [/connection is used by: (.+)/, m => `Dịch vụ đang được dùng bởi: ${m[1]}. Xoá các hành động đó trước.`],
  // Name the action and say why, so the fix is obvious.
  [/profile "(.+?)" would break: (.+)/, m => `Thay đổi này làm hỏng hành động "${m[1]}": ${viErr(m[2])}`],
  [/unknown connection/, "Dịch vụ API không tồn tại."],
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
        ioErr.textContent = tr("File không đúng định dạng.");
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
      }}, "Nhập các mục đã chọn");
      fill(importBox, h("div", {class: "card"}, h("h3", null, "Nhập từ file"), rows.map(r => r.el), h("div", {class: "row"}, importBtn)));
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
  }}, "Xuất file");
  const importOpenBtn = h("button", {type: "button", onclick: () => { fileInput.value = ""; fileInput.click(); }}, "Nhập file");
  const addConn = () => openConn({_new: true, name: "", base_url: "https://", auth: {type: "bearer", secret: ""}});
  fill(body,
    h("div", {class: "card"}, h("h2", null, `Hành động cố định (${list.length})`),
      h("p", {class: "muted"}, "Một hành động là một việc cụ thể agent được xin làm, chỉ điền tham số. Agent chạy bằng ucr run hoặc công cụ run."),
      list.length ? list.map(p => h("div", {class: "spread"}, h("span", null, h("b", null, p.description || p.name), " ",
        h("span", {class: "badge " + (p.risk === "high" ? "high" : "")}, p.risk === "high" ? "rủi ro cao" : p.auto_approve ? "tự chạy" : "hỏi duyệt"),
        p.runner ? h("span", {class: "chip"}, "runner " + p.runner) : null,
        h("div", {class: "muted"}, h("code", null, "ucr run " + p.name + (p.params || []).map(q => ` ${q.name}=…`).join("")))),
      h("span", {class: "acts"}, h("button", {onclick: () => openTest(p)}, "Chạy thử"), h("button", {onclick: () => openBuilder(fromProfile(p))}, "Sửa"),
        h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Xoá hành động ${p.name}?`))) { await api("DELETE", "/api/profiles/" + encodeURIComponent(p.name)); viewProfiles(body); } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có hành động nào."),
      h("h3", {class: "gap"}, "Tạo hành động mới"),
      h("div", {class: "row"}, Object.values(templates).map(t => h("button", {onclick: () => openBuilder(newDraft(t.d))}, t.label)))),
    h("div", {class: "card"}, h("div", {class: "spread"}, h("h2", null, `Dịch vụ API (${conns.length})`), h("button", {onclick: addConn}, "+ Thêm dịch vụ")),
      h("p", {class: "muted"}, "Địa chỉ gốc và cách đăng nhập của một dịch vụ HTTP như GitHub, Gitea. Hành động gọi tới dịch vụ chỉ ghi đường dẫn, nên agent không đổi được máy chủ. Khác runner: dịch vụ API là nơi nhận request HTTP, runner là máy chạy lệnh."),
      conns.length ? conns.map(c => h("div", {class: "spread"}, h("span", null, h("b", null, c.title || c.name), " ", h("code", null, c.name),
        h("div", {class: "muted"}, c.base_url + " · " + c.auth.type + (c.auth.secret ? " · " + c.auth.secret : c.auth.choices && c.auth.choices.length ? " · " + c.auth.choices.join(" / ") : ""))),
        h("span", {class: "acts"}, h("button", {onclick: () => openBuilder(newDraft({kind: "conn", connection: c.name, url: "/"}))}, "Hành động mới"),
          h("button", {onclick: () => openConn(c)}, "Sửa"),
          h("button", {class: "danger", onclick: async () => { if (confirm(tr(`Xoá dịch vụ ${c.name}?`))) { try { await api("DELETE", "/api/connections/" + encodeURIComponent(c.name)); viewProfiles(body); } catch (e) { alert(viErr(e.message)); } } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có dịch vụ API nào.")),
    h("details", {class: "card"}, h("summary", null, tr("Sao lưu và chép sang máy khác")),
      h("p", {class: "muted"}, "Xuất hoặc nhập hành động và dịch vụ API dưới dạng JSON. File chỉ có tên secret, không có giá trị."),
      h("div", {class: "row"}, exportBtn, importOpenBtn, fileInput), ioErr),
    importBox);
}

function connForm(c, secrets, done) {
  const x = JSON.parse(JSON.stringify(c)); x.auth = x.auth || {type: "bearer"}; x.headers = x.headers || {};
  let mode = x.auth.choices && x.auth.choices.length ? "pick" : "one";
  const name = field("Tên dịch vụ", {autocomplete: "off", spellcheck: "false"}); name.input.value = x.name || "";
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
  const card = form(x._new ? "Thêm dịch vụ API" : "Sửa dịch vụ API", [name, title, base], "Lưu", async () => {
    const out = {name: name.input.value.trim() || slugify(title.input.value), title: title.input.value.trim(), base_url: base.input.value.trim(), auth: {type: x.auth.type}};
    if (x.auth.type === "header") out.auth.header = x.auth.header;
    if (x.auth.type !== "none") { if (mode === "one") out.auth.secret = x.auth.secret; else out.auth.choices = x.auth.choices; }
    const hs = Object.fromEntries(Object.entries(x.headers).filter(([k, v]) => k && v));
    if (Object.keys(hs).length) out.headers = hs;
    try { await api("PUT", "/api/connections", out); } catch (e) { throw new Error(viErr(e.message)); }
    if (x._new && c.service_actions) for (const p of c.service_actions) await api("PUT", "/api/profiles", p).catch(() => {});
    done();
  }, h("p", {class: "muted"}, "Địa chỉ gốc và cách đăng nhập. Mọi hành động gọi tới dịch vụ này dùng chung, agent không đổi được máy chủ."));
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
      fill(where, h("label", null, h("span", null, "Dịch vụ API"), select(d.connection, conns.map(x => [x.name, (x.title || x.name) + " · " + x.base_url]), v => { d.connection = v; drawWhere(); drawAuth(); refresh(); }, "Dịch vụ API")),
        h("div", {class: "url-row"}, methodSel(), path),
        h("small", {class: "muted"}, c ? c.base_url.replace(/\/$/, "") + (d.url || "/…") : ""),
        h("small", {class: "muted"}, "Chỉ ghi đường dẫn bắt đầu bằng /. Máy chủ và đăng nhập lấy từ dịch vụ API."));
      return;
    }
    const url = h("input", {type: "url", autocomplete: "off", spellcheck: "false", placeholder: "https://api.example.com/v1/items/{{item_id}}", "aria-label": "Địa chỉ"});
    url.value = d.url; track(url);
    url.addEventListener("input", () => { d.url = url.value; refresh(); });
    fill(where, h("div", {class: "url-row"}, select(d.method, ["GET", "POST", "PUT", "PATCH", "DELETE"].map(m => [m, m]), v => { d.method = v; if (v !== "GET" && d.approval === "auto") { d.approval = "ask"; drawApproval(); } refresh(); }, "Phương thức"), url),
      h("small", {class: "muted"}, "Tên máy luôn cố định, agent chỉ điền được các giá trị ở mục 4."));
  };
  const step2 = h("section", {class: "card"}, h("h3", null, "2. Gọi tới đâu"),
    choiceGroup("kind", d.kind, [].concat(conns.length ? [{value: "conn", title: "Dùng dịch vụ API", help: "Máy chủ và đăng nhập đã khai báo sẵn"}] : [],
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
      fill(authBox, h("p", {class: "muted"}, tr("Đăng nhập theo dịch vụ API") + " " + (c ? (c.title || c.name) : "") + (c && c.auth.choices && c.auth.choices.length ? " · " + tr("chọn secret khi duyệt") : c && c.auth.secret ? " · " + c.auth.secret : "")));
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
  }}, "Lưu hành động");
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
// MCP settings for each agent. With `ucr login` the token stays in the
// machine's credential store, so the settings carry no token.
const jsonCfg = (cmd, key = "mcpServers", extra = {}) => JSON.stringify({[key]: {ucanrun: Object.assign(extra, {command: cmd, args: ["mcp"]})}}, null, 2);
const agents = [
  {id: "claude", name: "Claude Code", how: "Chạy trong terminal", make: cmd => `claude mcp add ucanrun -s user -- ${cmd} mcp`},
  {id: "antigravity", name: "Antigravity CLI", how: "Thêm vào file", file: "~/.gemini/config/mcp_config.json", make: cmd => jsonCfg(cmd)},
  {id: "cursor", name: "Cursor", how: "Thêm vào file", file: "~/.cursor/mcp.json", make: cmd => jsonCfg(cmd)},
  {id: "claude-desktop", name: "Claude Desktop", how: "Thêm vào file", file: "claude_desktop_config.json", make: cmd => jsonCfg(cmd)},
  {id: "codex", name: "Codex CLI", how: "Thêm vào file", file: "~/.codex/config.toml", make: cmd => `[mcp_servers.ucanrun]\ncommand = "${cmd.replace(/\\/g, "\\\\")}"\nargs = ["mcp"]`},
  {id: "gemini", name: "Gemini CLI", how: "Thêm vào file", file: "~/.gemini/settings.json", make: cmd => jsonCfg(cmd)},
  {id: "vscode", name: "VS Code", how: "Thêm vào file", file: "MCP: Open User Configuration", make: cmd => jsonCfg(cmd, "servers", {type: "stdio"})},
  {id: "windsurf", name: "Windsurf", how: "Thêm vào file", file: "~/.codeium/windsurf/mcp_config.json", make: cmd => jsonCfg(cmd)},
  {id: "other", name: "Khác", how: "Lệnh MCP qua stdio", make: cmd => `${cmd} mcp`},
];

function agentPicker(cur, on) {
  return h("div", {class: "choices", role: "radiogroup", "aria-label": "Agent bạn dùng"}, agents.map(a =>
    h("label", {class: "choice"}, h("input", {type: "radio", name: "agent", value: a.id, checked: a.id === cur, onchange: () => on(a.id)}), h("span", null, h("b", null, a.name)))));
}

// After a token is made: install ucr where the agent runs, save the token
// there, then point the agent at `ucr mcp`.
function agentGuide(id, token, done) {
  const box = h("div");
  let url = "http://127.0.0.1:8781", dl = "", os = guessOs();
  const step = (n, title, ...kids) => h("li", null, h("b", null, `${n}. ${tr(title)}`), ...kids.map(c => typeof c === "string" ? copyLine(c) : c));
  const draw = () => {
    const a = agents.find(x => x.id === id);
    const win = os === "windows";
    const bin = win ? WIN_UCR : "~/.local/bin/ucr";
    const cfg = a.make(win ? "C:\\Users\\<bạn>\\.local\\bin\\ucr.exe" : "ucr");
    const u = h("input", {autocomplete: "off", spellcheck: "false", "aria-label": "Địa chỉ Agent API"}); u.value = url;
    u.addEventListener("change", () => { url = u.value.trim(); draw(); });
    fill(box, h("div", {class: "card"}, h("h2", null, "Nối agent với ucanrun"),
      h("p", {class: "note"}, "Token chỉ hiện lần này. Sau bước 2 nó nằm trong kho khoá của máy đó (Windows Credential Manager, hoặc ~/.config/ucanrun với quyền 0600), không nằm trong file cấu hình agent. Đừng dán token vào chat với AI."),
      h("label", null, h("span", null, "Địa chỉ Agent API"), u),
      h("h3", {class: "gap"}, "Máy chạy agent"), osSwitch(os, k => { os = k; draw(); }),
      h("ol", {class: "steps-list"},
        step(1, "Cài ucr", installCmd(dl, os)),
        step(2, "Lưu token trên máy đó", `${win ? "& " : ""}${bin} login ${url}`, h("small", {class: "muted"}, tr("Dán token này khi được hỏi:")), token),
        step(3, "Thêm ucanrun vào agent", agentPicker(id, v => { id = v; draw(); }),
          h("small", {class: "muted"}, tr(a.how) + (a.file ? ": " : ""), a.file ? h("code", null, a.file) : null), h("pre", {class: "cfg"}, cfg),
          h("div", {class: "row"}, h("button", {class: "small", onclick: () => navigator.clipboard && navigator.clipboard.writeText(cfg)}, "Sao chép"))),
        step(4, "Kiểm tra", `${win ? "& " : ""}${bin} doctor`)),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: done}, "Xong, về danh sách"))));
  };
  api("GET", "/api/runners").then(r => { url = r.agent_url || url; dl = r.download_url || ""; draw(); }).catch(() => draw());
  draw();
  return box;
}

function agentTokenForm(profiles, onCreated) {
  let id = "claude", touched = false, mode = "all", picked = [], wsMode = "all", wsPicked = [], wsKnown = [];
  const name = h("input", {autocomplete: "off", spellcheck: "false", "aria-label": "Tên agent"}); name.value = id;
  name.addEventListener("input", () => { touched = true; });
  const scope = h("div"), err = h("div", {class: "err", role: "alert"});
  const drawScope = () => {
    if (!profiles.length) { fill(scope, h("p", {class: "muted"}, "Chưa có hành động cố định. Token này dùng được mọi hành động thêm sau.")); return; }
    fill(scope, choiceGroup("scope", mode, [{value: "all", title: "Mọi hành động, kể cả hành động thêm sau", help: "Agent cũng tự soạn được yêu cầu"}, {value: "some", title: "Chỉ các hành động đã chọn", help: "Agent không tự soạn được yêu cầu"}], v => { mode = v; drawScope(); }),
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
    h("h3", {class: "gap"}, "Giới hạn hành động"), scope, wsScope,
    h("div", {class: "row"}, h("button", {class: "primary", onclick: async () => {
      err.textContent = "";
      if (mode === "some" && !picked.length) { err.textContent = tr("Hãy chọn ít nhất một hành động."); return; }
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
    list.length ? list.map(t => h("div", {class: "spread"}, h("span", null, h("code", null, t.name), h("div", {class: "muted"}, (t.profiles && t.profiles.length ? tr("chỉ hành động") + " " + t.profiles.join(", ") : tr("tự soạn yêu cầu và mọi hành động")) + " · " + (t.workspaces && t.workspaces.length ? "workspace " + t.workspaces.map(wsLabel).join(", ") : tr("mọi workspace")) + " · " + new Date(t.created).toLocaleString())),
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
  const opts = [[0, "Không tự khoá"], [5, "5 phút"], [10, "10 phút"], [15, "15 phút"], [30, "30 phút"], [45, "45 phút"], [60, "1 giờ"], [120, "2 giờ"],
    [240, "4 giờ"], [480, "8 giờ"], [720, "12 giờ"], [1440, "24 giờ"], [4320, "3 ngày"], [10080, "7 ngày"]];
  if (!opts.some(o => o[0] === cur)) opts.push([cur, `${cur} phút`]);
  const saved = h("span", {class: "muted"});
  const sel = select(String(cur), opts.map(([v, t]) => [String(v), tr(t)]), async v => {
    err.textContent = ""; saved.textContent = "";
    try { await api("PUT", "/api/settings", {auto_lock_min: Number(v)}); state.status = await api("GET", "/api/status"); saved.textContent = tr("Đã lưu"); }
    catch (e) { err.textContent = tr(e.message); }
  }, "Tự khoá sau");
  return h("div", {class: "card"}, h("h2", null, "Tự khoá kho"),
    h("p", {class: "muted"}, "Khoá kho khi không có hoạt động nào: không mở web, không duyệt, không có yêu cầu từ agent. Khi khoá, agent nhận lỗi 423 cho tới khi bạn đăng nhập. Nếu chọn Không tự khoá, kho chỉ khoá khi bạn bấm Khoá kho hoặc server khởi động lại."),
    h("label", null, h("span", null, "Tự khoá sau"), sel), saved, err);
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

// Approval channels: what each needs, and how to finish setup on its side.
const CHANNELS = [
  {kind: "telegram", name: "Telegram", fields: [["token", "Token bot từ @BotFather", "password"]],
    guide: ["Mở @BotFather trên Telegram, gửi /newbot và làm theo hướng dẫn.", "Dán token bot vào đây rồi bấm Lưu.", "Mở chat riêng với bot và gửi /pair kèm mã ghép nối."],
    pair: c => `/pair ${c}`},
  {kind: "discord", name: "Discord", fields: [["token", "Bot token", "password"]],
    guide: ["Vào discord.com/developers/applications, tạo ứng dụng mới, mục Bot bấm Reset Token và dán token vào đây.",
      "Sau khi lưu, dán Webhook URL bên dưới vào General Information → Interactions Endpoint URL.",
      "Mục Installation bật User Install (hoặc mời bot vào một server bạn đang ở) để nhắn riêng được với bot.",
      "Nhắn riêng với bot lệnh /pair và nhập mã ghép nối."],
    pair: c => `/pair code:${c}`},
  {kind: "line", name: "LINE", fields: [["token", "Channel access token", "password"], ["secret", "Channel secret", "password"]],
    guide: ["Vào developers.line.biz, tạo kênh Messaging API.", "Dán Channel access token (long-lived) và Channel secret vào đây.",
      "Sau khi lưu, dán Webhook URL bên dưới vào Messaging API → Webhook settings, bật Use webhook, tắt Auto-reply.",
      "Kết bạn với bot và gửi /pair kèm mã ghép nối."],
    pair: c => `/pair ${c}`},
  {kind: "whatsapp", name: "WhatsApp", fields: [["token", "Access token (System User, không hết hạn)", "password"], ["phone_id", "Phone number ID", "text"], ["secret", "App secret", "password"]],
    guide: ["Vào developers.facebook.com, tạo app có sản phẩm WhatsApp.", "Dán Access token, Phone number ID và App secret (App settings → Basic) vào đây.",
      "Sau khi lưu, dán Webhook URL và Verify token bên dưới vào WhatsApp → Configuration, đăng ký trường messages.",
      "Từ số điện thoại của bạn, gửi /pair kèm mã ghép nối tới số WhatsApp Business."],
    note: "WhatsApp chỉ gửi được tin trong 24 giờ kể từ tin nhắn cuối bạn gửi cho bot. Ngoài khoảng đó yêu cầu vẫn chờ trên web.",
    pair: c => `/pair ${c}`},
];

// One tile per channel; the chosen one opens its setup below.
function channelsCard(s, chats, sys, after) {
  const box = h("div", {class: "chan-panel"});
  const pub = (sys && sys.public_url) || "";
  const stateOf = c => c.kind === "telegram" ? {configured: !!(s.telegram && s.telegram.configured), paired: !!(s.telegram && s.telegram.paired)}
    : (chats.find(x => x.kind === c.kind) || {});
  const pill = st => st.paired ? h("span", {class: "pill ok"}, tr("Đã ghép nối")) : st.configured ? h("span", {class: "pill warn"}, tr("Chưa ghép nối")) : h("span", {class: "pill"}, tr("Chưa cài"));
  const tiles = h("div", {class: "chan-tiles"});
  let open = state.chan || null;
  const reload = async () => { const [n, c] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/chats").catch(() => [])]); s = n; chats = c; draw(); after && after(); };
  const showCode = (c, code, extra) => h("div", {class: "note pair"},
    h("div", null, tr("Mã ghép nối, dùng một lần trong 3 phút:")), copyLine(c.pair(code)), extra || null,
    h("small", {class: "muted"}, tr("Sai 3 lần thì mã bị huỷ, khi đó tạo mã mới.")));
  const panel = c => {
    const st = stateOf(c);
    const err = h("div", {class: "err", role: "alert"});
    const out = h("div");
    const inputs = c.fields.map(([k, label, type]) => [k, field(label, {type, autocomplete: "off", spellcheck: "false"})]);
    const editing = !st.configured || state.chanEdit === c.kind;
    const save = h("button", {class: "primary", onclick: async () => {
      err.textContent = ""; save.disabled = true;
      try {
        const body = Object.fromEntries(inputs.map(([k, f]) => [k, f.input.value.trim()]));
        const r = c.kind === "telegram" ? await api("PUT", "/api/telegram", body) : await api("PUT", "/api/chats/" + c.kind, body);
        state.chanEdit = null;
        await reload();
        fill(out, showCode(c, r.code));
        box.append(out);
      } catch (e) { err.textContent = tr(e.message); } finally { save.disabled = false; }
    }}, "Lưu");
    const hook = st.webhook ? (pub ? pub.replace(/\/$/, "") : "https://<địa-chỉ-public>") + st.webhook : "";
    return h("div", {class: "chan-detail"},
      h("div", {class: "spread"}, h("h3", null, c.name, " ", pill(st)),
        st.configured ? h("span", {class: "acts"},
          h("button", {class: "small", onclick: async () => { const r = await api("POST", "/api/telegram/pair"); fill(out, showCode(c, r.code)); }}, "Mã ghép nối mới"),
          h("button", {class: "small", onclick: () => { state.chanEdit = state.chanEdit === c.kind ? null : c.kind; draw(); }}, editing ? "Đóng" : "Đổi cấu hình"),
          c.kind !== "telegram" ? h("button", {class: "small danger", onclick: async () => {
            if (!confirm(tr(`Gỡ ${c.name}? Yêu cầu sẽ không gửi tới đó nữa.`))) return;
            await api("DELETE", "/api/chats/" + c.kind); await reload(); }}, "Gỡ") : null) : null),
      st.error ? h("div", {class: "warn-line"}, `${tr("Lỗi gần nhất")}: ${st.error}`) : null,
      hook ? h("div", {class: "kv-line"}, h("span", {class: "muted"}, "Webhook URL"), copyLine(hook)) : null,
      st.verify ? h("div", {class: "kv-line"}, h("span", {class: "muted"}, "Verify token"), copyLine(st.verify)) : null,
      hook && !pub ? h("small", {class: "warn-line"}, tr("Server chưa đặt UCANRUN_PUBLIC_URL. Nền tảng phải gọi được tới địa chỉ HTTPS public của ucanrun.")) : null,
      st.last_hook ? h("small", {class: "muted"}, `${tr("Nền tảng gọi tới lần cuối")}: ${new Date(st.last_hook).toLocaleString()}`) : null,
      editing ? h("div", {class: "chan-setup"},
        h("ol", {class: "plain"}, c.guide.map(g => h("li", null, tr(g)))),
        c.note ? h("small", {class: "warn-line"}, tr(c.note)) : null,
        h("div", {class: "grid2"}, inputs.map(([, f]) => f.el)),
        h("div", {class: "row"}, save), err) : null,
      out);
  };
  const draw = () => {
    fill(tiles, CHANNELS.map(c => {
      const st = stateOf(c);
      return h("button", {type: "button", class: "chan-tile" + (open === c.kind ? " on" : ""), "aria-expanded": String(open === c.kind),
        onclick: () => { open = state.chan = open === c.kind ? null : c.kind; draw(); }},
        h("span", {class: "chan-logo " + c.kind, "aria-hidden": "true"}, c.name[0]), h("b", null, c.name), pill(st));
    }));
    const c = CHANNELS.find(x => x.kind === open);
    fill(box, c ? panel(c) : null);
  };
  draw();
  return h("div", {class: "card channels"}, h("h2", null, "Kênh duyệt"),
    h("p", {class: "muted"}, "Nơi bạn nhận và bấm duyệt yêu cầu. Nối một hoặc nhiều kênh; mỗi yêu cầu được gửi tới mọi kênh đã ghép nối, duyệt ở đâu cũng được."),
    tiles, box);
}

// A settings line: what it is on the left, the control on the right.
function setRow(title, desc, control) {
  return h("div", {class: "set-row"}, h("div", {class: "set-text"}, h("b", null, tr(title)), desc ? h("small", {class: "muted"}, desc) : null), control);
}

async function viewSettings(body) {
  const [s, health, chats, sys] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/health"),
    api("GET", "/api/chats").catch(() => []), api("GET", "/api/system").catch(() => null)]);
  const o = field("Mật khẩu hiện tại", {type: "password", autocomplete: "current-password"});
  const n = field("Mật khẩu mới", {type: "password", autocomplete: "new-password"});
  const langSel = select(lang, [["vi", "Tiếng Việt"], ["en", "English"]], v => { try { localStorage.setItem("ucr_lang", v); } catch (_) {} location.reload(); }, "Ngôn ngữ");
  const bad = health.filter(i => i.level === "bad").length, warn = health.filter(i => i.level === "warn").length;
  const healthBox = h("details", {class: "card health-card", open: bad > 0},
    h("summary", null, h("span", {class: "dot " + (bad ? "bad" : warn ? "warn" : "ok"), "aria-hidden": "true"}), " ",
      h("b", null, tr("Sức khoẻ bảo mật")), " ", h("span", {class: "muted"}, bad || warn ? `${bad} ${tr("lỗi")}, ${warn} ${tr("cảnh báo")}` : tr("ổn"))),
    h("ul", {class: "health"}, health.filter(i => i.level !== "ok").concat(health.filter(i => i.level === "ok")).map(i =>
      h("li", null, h("span", {class: "dot " + i.level, "aria-hidden": "true"}), h("span", null, i.message, (i.names || []).flatMap(x => [" ", h("code", null, x)]))))));
  // TOTP keeps its own flow (QR, recovery codes); here it opens in place.
  const totp = totpCard(s);
  totp.classList.remove("card");
  const th = totp.querySelector("h2"); if (th) th.remove();
  const lockOpts = [[0, "Không tự khoá"], [5, "5 phút"], [10, "10 phút"], [15, "15 phút"], [30, "30 phút"], [45, "45 phút"], [60, "1 giờ"], [120, "2 giờ"],
    [240, "4 giờ"], [480, "8 giờ"], [720, "12 giờ"], [1440, "24 giờ"], [4320, "3 ngày"], [10080, "7 ngày"]];
  const cur = s.auto_lock_min || 0;
  if (!lockOpts.some(x => x[0] === cur)) lockOpts.push([cur, `${cur} phút`]);
  const lockMsg = h("small", {class: "muted"});
  const lockSel = select(String(cur), lockOpts.map(([v, t]) => [String(v), tr(t)]), async v => {
    lockMsg.textContent = "";
    try { await api("PUT", "/api/settings", {auto_lock_min: Number(v)}); lockMsg.textContent = tr("Đã lưu"); } catch (e) { lockMsg.textContent = tr(e.message); }
  }, "Tự khoá sau");
  const pass = form("", [o, n], "Đổi mật khẩu", async () => {
    await api("POST", "/api/passphrase", {old: o.input.value, new: n.input.value}); o.input.value = n.input.value = "";
  });
  pass.classList.remove("card"); const ph = pass.querySelector("h2"); if (ph) ph.remove();
  const tpl = await myTemplatesCard();
  tpl.classList.remove("card"); const tph = tpl.querySelector("h2"); if (tph) tph.remove();
  fill(body,
    healthBox,
    channelsCard(s, chats, sys),
    h("div", {class: "card set-list"}, h("h2", null, "Đăng nhập và khoá kho"),
      h("details", {class: "set-row-d", open: !s.totp},
        h("summary", null, h("div", {class: "set-text"}, h("b", null, "TOTP"),
          h("small", {class: "muted"}, s.totp ? `${tr("Đang bật")} · ${s.recovery_left} ${tr("mã khôi phục")}` : tr("Đang tắt: yêu cầu rủi ro cao chưa duyệt được.")))), totp),
      setRow("Tự khoá kho", tr("Khi không có hoạt động nào. Kho khoá thì agent nhận lỗi 423 tới khi bạn đăng nhập."), h("div", {class: "inline"}, lockSel, lockMsg)),
      h("details", {class: "set-row-d"}, h("summary", null, h("div", {class: "set-text"}, h("b", null, tr("Mật khẩu chính")),
        h("small", {class: "muted"}, tr("Dùng để mở kho. Không có cách khôi phục nếu quên.")))), pass)),
    h("div", {class: "card set-list"}, h("h2", null, "Khác"),
      setRow("Ngôn ngữ", "", langSel),
      h("details", {class: "set-row-d"}, h("summary", null, h("div", {class: "set-text"}, h("b", null, tr("Mẫu secret của bạn")),
        h("small", {class: "muted"}, tr("Lưu từ form ở tab Secret bằng Lưu thành mẫu.")))), tpl)));
}

function skipped() { try { return JSON.parse(localStorage.getItem("ucr_skip") || "[]"); } catch (_) { return []; } }
function unskip(k) { try { localStorage.setItem("ucr_skip", JSON.stringify(skipped().filter(x => x !== k))); } catch (_) {} }
function skip(k) { try { localStorage.setItem("ucr_skip", JSON.stringify([...new Set(skipped().concat(k))])); } catch (_) {} }

async function loadSteps() {
  const [s, profiles, tokens, secrets, rinfo] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/profiles"), api("GET", "/api/tokens"),
    api("GET", "/api/secrets"), api("GET", "/api/runners").catch(() => ({runners: []}))]);
  // In the order they are needed. Optional steps are listed but never hold
  // back the overview.
  const steps = [
    {key: "telegram", title: "Nối kênh duyệt", why: "Telegram, Discord, LINE hoặc WhatsApp, để nhận yêu cầu duyệt trên điện thoại.", done: !!s.any_channel},
    {key: "totp", title: "Bật TOTP và lưu mã khôi phục", why: "Lớp bảo vệ thứ hai khi đăng nhập và duyệt việc rủi ro cao.", done: !!s.totp && s.recovery_left > 0},
    {key: "service", title: "Lưu secret đầu tiên", why: "Kèm một dòng mô tả và máy chủ được phép gửi tới.", done: secrets.some(x => (x.hosts || []).length) || profiles.length > 0},
    {key: "runner", tab: "runners", optional: true, title: "Thêm runner", why: "Khi agent cần chạy lệnh trên một máy.", done: (rinfo.runners || []).length > 0},
    {key: "agent", title: "Tạo token cho agent", why: "Để agent gửi được yêu cầu tới ucanrun.", done: tokens.length > 0},
    {key: "actions", tab: "profiles", optional: true, title: "Định sẵn hành động", why: "Khi muốn agent chỉ làm đúng các việc bạn cho phép.", done: profiles.length > 0},
  ];
  return {s, steps};
}

async function viewStart(body) {
  const {s, steps} = await loadSteps();
  const redraw = () => viewStart(body);
  const skips = skipped();
  const need = steps.filter(x => !x.optional);
  const cur = need.find(x => !x.done && x.key === state.startStep) || need.find(x => !x.done && !skips.includes(x.key));
  const open = x => { if (x.tab) { state.tab = x.tab; renderShell(); return; } state.startStep = x.key; unskip(x.key); redraw(); };
  const list = h("ol", {class: "steps"}, steps.map(x => h("li", {class: x.done ? "ok" : x === cur ? "on" : x.optional ? "opt" : ""},
    h("b", null, tr(x.title), x.optional ? h("span", {class: "muted"}, ` · ${tr("tuỳ chọn")}`) : null), h("small", {class: "muted"}, x.done ? "Xong" : x.why),
    !x.done && x !== cur ? h("button", {class: "stepgo", onclick: () => open(x)}, x.tab ? "Mở" : "Làm bước này") : null)));
  const head = h("div", {class: "card"}, h("h2", null, "Bắt đầu"), list);
  clearInterval(state.timer);
  // Keep the tab name in step with what the page shows.
  const overview = !cur;
  if (overview !== !!state.overview) {
    state.overview = overview;
    const b = document.querySelector('nav button');
    if (b) b.textContent = tr(overview ? "Tổng quan" : tabs.start);
  }
  if (overview) return viewOverview(body, s, steps, list);
  const skipBtn = h("div", {class: "row skip-row"}, h("button", {onclick: () => { skip(cur.key); state.startStep = null; redraw(); }}, "Bỏ qua, làm sau"));
  const watchPairing = () => { clearInterval(state.timer); state.timer = setInterval(async () => {
    const n = await api("GET", "/api/status").catch(() => null);
    if (n && n.any_channel) { clearInterval(state.timer); state.startStep = null; redraw(); }
  }, 3000); };
  let panel;
  if (cur.key === "telegram") {
    const [chats, sys] = await Promise.all([api("GET", "/api/chats").catch(() => []), api("GET", "/api/system").catch(() => null)]);
    panel = channelsCard(s, chats, sys, watchPairing);
    if ((s.telegram && s.telegram.configured) || chats.some(c => c.configured)) watchPairing();
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

// The landing page once setup is done: what is stored, what waits, what ran.
async function viewOverview(body, s, steps, stepList) {
  const need = steps.filter(x => !x.optional);
  const done = need.filter(x => x.done).length, all = done === need.length;
  const [secrets, tokens, profiles, reqs, runs, health] = await Promise.all([api("GET", "/api/secrets"), api("GET", "/api/tokens"), api("GET", "/api/profiles"),
    api("GET", "/api/requests"), api("GET", "/api/runs").catch(() => ({runs: []})), api("GET", "/api/health").catch(() => [])]);
  const [devs, rinfo, sys] = await Promise.all([api("GET", "/api/devices").catch(() => null), api("GET", "/api/runners").catch(() => null),
    api("GET", "/api/system").catch(() => null)]);
  const go = tab => () => { state.tab = tab; renderShell(); };
  const pending = reqs.filter(r => r.state === "pending");
  const ws = workspacesOf(secrets);
  const idle = secrets.filter(x => !(x.hosts || []).length && !(x.allow_commands && s.exec));
  const recent = (runs.runs || []).slice(0, 5);
  const day = Date.now() - 864e5;
  const today = (runs.runs || []).filter(r => new Date(r.time).getTime() > day);
  const failed = today.filter(r => r.ok === false).length;
  const bad = health.filter(i => i.level === "bad").length, warn = health.filter(i => i.level === "warn").length;
  const stat = (n, label, sub, tab, tone) => h("button", {class: "stat" + (tone ? " " + tone : ""), type: "button", onclick: go(tab)},
    h("span", {class: "num"}, String(n)), h("span", {class: "lbl"}, label), sub ? h("small", {class: "muted"}, sub) : null);
  const lockLabel = m => !m ? tr("Không tự khoá") : m % 1440 === 0 ? `${m / 1440} ${tr("ngày")}` : m % 60 === 0 ? `${m / 60} ${tr("giờ")}` : `${m} ${tr("phút")}`;
  const line = (ok, text, tab) => h("li", null, h("span", {class: "dot " + (ok === true ? "ok" : ok === false ? "bad" : "warn"), "aria-hidden": "true"}),
    h("span", null, text), tab ? h("button", {class: "link", onclick: go(tab)}, "Xem") : null);
  // Unfinished setup comes first, in order; once done it folds away at the end.
  const setup = h("details", {class: "card setup", open: !all}, h("summary", null, all ? tr("Thiết lập ban đầu: đã xong") : `${tr("Thiết lập ban đầu")}: ${done}/${need.length}`), stepList,
    all ? null : h("p", {class: "muted"}, "Các bước còn lại có thể làm bất cứ lúc nào."));
  fill(body,
    all ? null : setup,
    pending.length ? h("div", {class: "card attention"}, h("h2", null, `Đang chờ duyệt (${pending.length})`),
      pending.slice(0, 3).map(r => h("div", {class: "muted"}, h("b", null, r.profile === "agent-call" ? tr("Agent tự soạn") : r.profile), " · ", r.caller, r.reason ? " · " + r.reason : "")),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: go("requests")}, "Mở trang duyệt"))) : null,
    h("div", {class: "stats"},
      stat(secrets.length, tr("Secret"), ws.length > 1 ? `${ws.length} workspace` : "", "secrets"),
      stat(tokens.length, tr("Token agent"), "", "tokens"),
      stat(today.length, tr("Lần chạy 24 giờ qua"), failed ? `${failed} ${tr("lỗi")}` : "", "audit", failed ? "warn" : ""),
      stat(pending.length, tr("Đang chờ duyệt"), "", "requests", pending.length ? "attn" : "")),
    h("div", {class: "card"}, h("h2", null, "Trạng thái"),
      h("ul", {class: "health"},
        line(!!s.any_channel, s.any_channel ? tr("Đã nối kênh duyệt.") : tr("Chưa nối kênh duyệt nào."), "settings"),
        line(!!s.totp, s.totp ? tr(`TOTP đang bật, còn ${s.recovery_left} mã khôi phục.`) : tr("TOTP đang tắt."), "settings"),
        line(s.auto_lock_min ? true : null, `${tr("Tự khoá kho")}: ${lockLabel(s.auto_lock_min)}.`, "settings"),
        line(bad ? false : warn ? null : true, bad || warn ? `${tr("Sức khoẻ bảo mật")}: ${bad} ${tr("lỗi")}, ${warn} ${tr("cảnh báo")}.` : tr("Sức khoẻ bảo mật ổn."), "settings"),
        line(true, `${profiles.length} ${tr("hành động cố định")}.`, "profiles"),
        idle.length ? line(null, tr(`Agent chưa tự gọi được ${idle.length} secret vì chưa có máy chủ: ${idle.map(x => x.name).join(", ")}.`), "secrets") : null)),
    sys ? systemCard(sys, go) : null,
    devs ? devicesCard(devs, s, secrets, rinfo) : null,
    h("div", {class: "card"}, h("h2", null, "Lần chạy gần đây"),
      recent.length ? recent.map(runRow) : h("p", {class: "muted"}, "Chưa có lần chạy nào."),
      h("div", {class: "row"}, h("button", {onclick: go("audit")}, "Xem nhật ký"), h("button", {onclick: go("secrets")}, "Thêm secret"), h("button", {onclick: go("tokens")}, "Tạo token"))),
    all ? setup : null);
  window.scrollTo(0, 0);
}

// Who calls ucanrun from where, and where it runs commands with which rights.
// Built from the audit log and fixed actions; device names are what each
// agent reported about itself.
// What the server is and what it is connected to.
function systemCard(x, go) {
  const dur = sec => { const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return d ? `${d} ${tr("ngày")} ${hh} ${tr("giờ")}` : hh ? `${hh} ${tr("giờ")} ${m} ${tr("phút")}` : `${m} ${tr("phút")}`; };
  const size = mb => mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
  const row = (k, v) => [h("dt", null, tr(k)), h("dd", null, v)];
  const line = (ok, name, text, tab) => h("li", null, h("span", {class: "dot " + (ok === true ? "ok" : ok === false ? "bad" : "warn"), "aria-hidden": "true"}),
    h("span", {class: "grow"}, h("b", null, tr(name)), " ", h("span", {class: "muted"}, text)), tab ? h("button", {class: "link", onclick: go(tab)}, "Xem") : null);
  const t = x.telegram || {};
  const tg = !t.configured ? [null, tr("chưa cấu hình bot")] : t.connected ? [true, `${tr("đang kết nối")}${t.paired ? "" : " · " + tr("chưa ghép tài khoản")}`]
    : [false, [tr("mất kết nối"), t.last_ok ? `${tr("lần cuối")} ${new Date(t.last_ok).toLocaleString()}` : "", t.error].filter(Boolean).join(" · ")];
  const diskLow = x.disk_free_mb != null && x.disk_total_mb && x.disk_free_mb < x.disk_total_mb * 0.1;
  return h("div", {class: "card system"}, h("h2", null, "Hệ thống"),
    h("dl", {class: "kv"},
      row("Phiên bản", `ucanrun ${x.version}`),
      row("Đang chạy", `${dur(x.uptime_secs)} · ${tr("từ")} ${new Date(x.started).toLocaleString()}`),
      row("Máy", [x.container ? `${x.host} (${tr("trong container")})` : x.host, `${x.os}/${x.arch}`, `uid ${x.uid}${x.uid === 0 ? " (root)" : ""}`].filter(Boolean).join(" · ")),
      x.memory_mb != null ? row("Bộ nhớ", size(x.memory_mb)) : null,
      x.disk_free_mb != null ? row("Ổ dữ liệu", h("span", {class: diskLow ? "warn-text" : ""}, `${tr("còn")} ${size(x.disk_free_mb)} / ${size(x.disk_total_mb)}`)) : null,
      row("Nhật ký", `${x.audit_entries} ${tr("mục")}`),
      row("Chạy lệnh trên server", x.exec ? tr("bật") : tr("tắt"))),
    h("h3", null, "Kết nối"),
    h("ul", {class: "health"},
      line(x.gate ? true : null, "Web", [x.public_url || x.web_addr, x.gate ? tr("có mã truy cập") : tr("không có mã truy cập"), x.secure_cookie ? "cookie Secure" : ""].filter(Boolean).join(" · ")),
      line(true, "Agent API", [x.agent_url || x.agent_addr, `${x.tokens} token`, `${x.agents_24h} ${tr("agent gọi trong 24 giờ")}`].join(" · "), "tokens"),
      t.configured ? line(tg[0], "Telegram", tg[1], "settings") : null,
      (x.chats || []).filter(c => c.configured).map(c => line(c.paired ? (c.error ? false : true) : null, (CHANNELS.find(k => k.kind === c.kind) || {name: c.kind}).name,
        [c.paired ? tr("đã ghép nối") : tr("chưa ghép nối"), c.last_hook ? `${tr("gọi tới lần cuối")} ${new Date(c.last_hook).toLocaleString()}` : tr("nền tảng chưa gọi tới"), c.error].filter(Boolean).join(" · "), "settings")),
      !t.configured && !(x.chats || []).some(c => c.configured) ? line(null, "Kênh duyệt", tr("chưa nối kênh nào"), "settings") : null,
      line(x.runners ? x.runners_online === x.runners : null, "Runner", x.runners ? `${x.runners_online}/${x.runners} ${tr("đang kết nối")}` : tr("chưa có runner"), "runners")));
}

// Shell commands to put ucr on a machine, for the agent and runner guides.
const systems = [["linux-amd64", "Linux x86_64"], ["linux-arm64", "Linux ARM64"], ["darwin", "macOS"], ["windows", "Windows"]];
const guessOs = () => /Windows/.test(navigator.userAgent) ? "windows" : /Mac/.test(navigator.userAgent) ? "darwin" : "linux-amd64";
const WIN_UCR = '"$env:USERPROFILE\\.local\\bin\\ucr.exe"';
// Each command checks the download against the release's SHA256SUMS
// before putting it in place.
function fetchCmd(dl, os, file, dest) {
  if (os === "windows") return `$f = "$env:TEMP\\dl-${file}"; $s = "$env:TEMP\\ucr-SHA256SUMS"; Invoke-WebRequest ${dl}/${file} -OutFile $f; Invoke-WebRequest ${dl}/SHA256SUMS -OutFile $s; if (-not (Select-String -Path $s -SimpleMatch "$((Get-FileHash $f -Algorithm SHA256).Hash.ToLower())  ${file}" -Quiet)) { throw "checksum mismatch" }; New-Item -ItemType Directory -Force (Split-Path ${dest}) | Out-Null; Move-Item -Force $f ${dest}`;
  const sum = os === "darwin" ? "shasum -a 256 -c -" : "sha256sum -c -";
  return `d=$(mktemp -d) && curl -fsSL -o "$d/${file}" ${dl}/${file} && curl -fsSL -o "$d/SHA256SUMS" ${dl}/SHA256SUMS && (cd "$d" && grep " ${file}\$" SHA256SUMS | ${sum}) && mkdir -p "$(dirname ${dest})" && install -m 755 "$d/${file}" ${dest}`;
}
function installCmd(dl, os) {
  if (os === "windows") return fetchCmd(dl, os, "ucr-windows-amd64.exe", WIN_UCR);
  // The shell picks the Mac build, since browsers report every Mac as Intel.
  const file = os === "darwin" ? "ucr-darwin-$(uname -m | sed s/x86_64/amd64/)" : `ucr-${os}`;
  return fetchCmd(dl, os, file, "~/.local/bin/ucr");
}

function copyLine(text) {
  return h("div", {class: "copyline"}, h("code", null, text),
    h("button", {class: "icon", "aria-label": tr("Chép"), title: tr("Chép"), onclick: () => navigator.clipboard && navigator.clipboard.writeText(text)}, "⧉"));
}

function osSwitch(os, on) {
  return h("div", {class: "seg", role: "radiogroup", "aria-label": tr("Hệ điều hành")}, systems.map(([k, t]) =>
    h("button", {type: "button", role: "radio", "aria-checked": String(k === os), class: k === os ? "on" : "", onclick: () => on(k)}, t)));
}

// Pairing a new runner: a code, then the commands for the chosen system.
function enrollBox(rinfo, done) {
  const box = h("div", {class: "enroll", hidden: true});
  const url = (rinfo && rinfo.agent_url) || "http://<agent-api>:8781";
  const dl = (rinfo && rinfo.download_url) || "";
  const step = (n, title, ...cmds) => h("li", null, h("b", null, `${n}. ${tr(title)}`), ...cmds.map(c => typeof c === "string" ? copyLine(c) : c));
  const guide = (code, os, name) => {
    const enroll = bin => `${bin} runner enroll ${url} ${code} --name ${name}`;
    if (os === "windows") return [
      step(1, "Tải ucr.exe (PowerShell)", installCmd(dl, os)),
      step(2, "Ghép nối", `& ${WIN_UCR} ${enroll("").trim()}`),
      step(3, "Liệt kê chương trình được chạy", 'notepad "$env:APPDATA\\ucanrun\\runner.toml"',
        h("small", {class: "muted"}, tr("Ví dụ: allow = ['C:\\Windows\\System32\\ipconfig.exe']. Mặc định không chạy gì."))),
      step(4, "Chạy nền khi khởi động, quyền user thường (PowerShell admin)",
        fetchCmd(dl, "windows", "runner-windows.ps1", '"$env:TEMP\\runner-windows.ps1"'), 'powershell -ExecutionPolicy Bypass -File "$env:TEMP\\runner-windows.ps1"')];
    if (os === "darwin") return [
      step(1, "Tải ucr", installCmd(dl, os)),
      step(2, "Ghép nối", enroll("~/.local/bin/ucr")),
      step(3, "Liệt kê chương trình được chạy", "open -e ~/.config/ucanrun/runner.toml"),
      step(4, "Chạy", "~/.local/bin/ucr runner serve")];
    return [
      step(1, "Tải ucr và script cài đặt", fetchCmd(dl, os, `ucr-${os}`, "/tmp/ucr"), fetchCmd(dl, os, "runner-setup-linux.sh", "/tmp/runner-setup-linux.sh")),
      step(2, "Tạo user ucr-runner và service (cần sudo)", 'sudo SUDO_CMDS="/usr/bin/systemctl /usr/bin/journalctl" sh /tmp/runner-setup-linux.sh /tmp/ucr',
        h("small", {class: "muted"}, tr("SUDO_CMDS là chương trình được chạy bằng root. Script in ra mật khẩu sudo của ucr-runner một lần: lưu nó thành secret, bật dùng trong lệnh và luôn cần TOTP. Bỏ SUDO_CMDS nếu không cần root."))),
      step(3, "Ghép nối", `sudo -u ucr-runner UCANRUN_RUNNER_DIR=/var/lib/ucr-runner ${enroll("/usr/local/bin/ucr")}`),
      step(4, "Liệt kê chương trình được chạy", "sudoedit /var/lib/ucr-runner/runner.toml"),
      step(5, "Chạy nền", "sudo systemctl enable --now ucr-runner")];
  };
  const open = async () => {
    const c = await api("POST", "/api/runners/code");
    let os = guessOs();
    const name = h("input", {value: "ten-may", "aria-label": tr("Tên runner"), autocomplete: "off", spellcheck: "false", maxlength: 64});
    const steps = h("ol", {class: "steps-list"});
    const sw = h("div");
    const draw = () => {
      const n = name.value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-") || "ten-may";
      fill(sw, osSwitch(os, k => { os = k; draw(); }));
      fill(steps, guide(c.code, os, n));
    };
    name.addEventListener("input", draw);
    draw();
    fill(box,
      h("h3", null, "Thêm runner"),
      h("p", null, tr("Mã ghép nối, dùng một lần, hết hạn lúc"), " ", new Date(c.expires).toLocaleTimeString(), ": ", h("b", {class: "code"}, c.code)),
      h("div", {class: "row tight"}, sw, h("label", {class: "inline-field"}, h("span", null, tr("Tên runner")), name)),
      steps,
      h("p", {class: "muted"}, `${tr("Khi ghép xong, máy kia in ra khoá server; khoá đúng là")}: ${rinfo ? rinfo.server_key : "?"}.`),
      h("div", {class: "row"}, h("button", {class: "primary", onclick: done}, "Đã chạy xong, tải lại"), h("button", {onclick: () => { box.hidden = true; }}, "Huỷ")));
    box.hidden = false;
    box.scrollIntoView({block: "nearest"});
  };
  return {el: box, open};
}

// One runner: state, what it reports about itself, its last jobs.
function runnerCard(r, runs, redraw) {
  const i = r.info || {};
  const rights = i.root ? h("span", {class: "badge root"}, "root") : i.sudo ? h("span", {class: "badge high"}, "sudo") : h("span", {class: "badge"}, tr("quyền user"));
  const allow = !i.allow || !i.allow.length ? [h("span", {class: "muted"}, tr("chưa cho chạy chương trình nào, sửa runner.toml trên máy đó"))]
    : i.allow.includes("*") ? [h("span", {class: "chip warn"}, tr("mọi chương trình"))] : i.allow.map(a => h("span", {class: "chip"}, a));
  const mine = (runs || []).filter(x => (x.command || "").includes("\nrunner: " + r.name)).slice(0, 3);
  const row = (k, v) => [h("dt", null, tr(k)), h("dd", null, v)];
  return h("div", {class: "runner-card"},
    h("div", {class: "spread"},
      h("span", null, h("span", {class: "dot " + (r.online ? "ok" : "bad"), "aria-hidden": "true"}), " ", h("b", null, r.name), " ", rights, " ",
        h("span", {class: "muted"}, r.online ? tr("đang kết nối") : r.last_seen ? `${tr("mất kết nối từ")} ${new Date(r.last_seen).toLocaleString()}` : tr("chưa kết nối từ khi server khởi động"))),
      h("button", {class: "link danger", onclick: async () => {
        if (!confirm(tr(`Gỡ runner ${r.name}? Máy đó sẽ không nhận việc nữa.`))) return;
        await api("DELETE", "/api/runners/" + encodeURIComponent(r.name)); redraw();
      }}, "Gỡ")),
    i.policy_error ? h("div", {class: "warn-line"}, `${tr("Lỗi runner.toml")}: ${i.policy_error}`) : null,
    i.root ? h("div", {class: "warn-line"}, tr("Runner đang có quyền root hoặc admin. Nên chạy bằng user riêng, dùng sudo khi cần.")) : null,
    h("dl", {class: "kv"},
      row("Máy", [i.host, [i.os, i.arch].filter(Boolean).join("/")].filter(Boolean).join(" · ") || "—"),
      row("Chạy bằng", i.user ? `${i.user}${i.uid >= 0 ? " (uid " + i.uid + ")" : ""}` : "—"),
      row("Root qua sudo", i.sudo ? tr("cho phép, mật khẩu đi kèm từng việc") : tr("không")),
      row("TOTP", i.require_totp ? tr("bắt buộc khi duyệt") : tr("không bắt buộc")),
      row("Được chạy", h("span", {class: "chips"}, allow)),
      row("Phiên bản", i.version || "—"),
      row("Khoá runner", h("code", null, r.fingerprint))),
    mine.length ? h("details", {class: "runs"}, h("summary", null, `${tr("Lần chạy gần đây")} (${mine.length})`), mine.map(runRow)) : null);
}

async function viewRunners(body) {
  const [rinfo, runs, sys] = await Promise.all([api("GET", "/api/runners"), api("GET", "/api/runs").catch(() => ({runs: []})), api("GET", "/api/system").catch(() => null)]);
  const list = rinfo.runners || [];
  const redraw = () => viewRunners(body);
  const add = enrollBox(rinfo, redraw);
  const online = list.filter(r => r.online).length;
  const example = JSON.stringify({argv: ["/usr/bin/systemctl", "restart", "nginx"], runner: list[0] ? list[0].name : "ten-may", sudo: "{{secret:ten_may_sudo}}"}, null, 2);
  fill(body,
    h("div", {class: "card"},
      h("div", {class: "spread"}, h("h2", null, `Runner (${online}/${list.length} ${tr("đang kết nối")})`), h("button", {class: "primary", onclick: add.open}, "+ Thêm runner")),
      list.length ? list.map(r => runnerCard(r, runs.runs, redraw)) : h("p", {class: "muted"}, "Chưa có runner. Bấm Thêm runner để lấy mã ghép nối và lệnh cài cho từng hệ điều hành."),
      add.el),
    h("details", {class: "card"}, h("summary", null, tr("Runner hoạt động thế nào")),
      h("ul", {class: "plain"},
        h("li", null, tr("Runner tự gọi về Agent API để xin việc, nên chạy được sau NAT, trên laptop, không mở cổng nào.")),
        h("li", null, tr("Mỗi việc được ucanrun ký và chỉ mang secret nó cần, mã hoá riêng cho runner đó. Kết quả do runner ký.")),
        h("li", null, tr("runner.toml trên máy đó quyết định chương trình nào được chạy. Việc ngoài danh sách bị từ chối kể cả khi bạn đã duyệt.")),
        h("li", null, tr("Lệnh cần root đi qua sudo bằng mật khẩu của user runner, lưu thành secret trong ucanrun. Windows chỉ chạy bằng quyền user."))),
      h("p", {class: "muted"}, "Agent gọi list_runners để xem runner, rồi run_command kèm runner, ví dụ:"), h("pre", null, example)),
    h("div", {class: "card"}, h("h2", null, "Chạy lệnh ngay trên server"),
      h("p", {class: "muted"}, sys && sys.exec
        ? tr(`Đang bật: lệnh không ghi runner chạy trong ${sys.container ? "container ucanrun" : "máy chủ ucanrun"}, bằng uid ${sys.uid}.`)
        : tr("Đang tắt: lệnh chỉ chạy trên runner.")),
      h("p", {class: "muted"}, `${tr("Khoá server (runner ghim khi ghép nối)")}: `, h("code", null, rinfo.server_key))));
}

function devicesCard(d, s, secrets, rinfo) {
  const when = t => t ? new Date(t).toLocaleString() : tr("chưa gọi lần nào");
  const agents = d.agents.map(a => h("li", null,
    h("span", {class: "dot " + (a.last_seen ? "ok" : "warn"), "aria-hidden": "true"}),
    h("span", null, h("b", null, a.device || tr("không rõ máy")), " ",
      h("span", {class: "muted"}, [a.token, a.app, a.requests ? `${a.requests} ${tr("yêu cầu")}` : "", when(a.last_seen)].filter(Boolean).join(" · ")))));
  const targets = d.targets.map(t => h("li", null,
    h("span", {class: "badge " + (t.rights === "root" ? "root" : "")}, t.rights === "root" ? "root" : tr("thường")), " ",
    h("span", null, h("b", null, t.host === "ucanrun" ? tr("Container ucanrun") : t.host), " ",
      h("span", {class: "muted"}, [t.user ? `${tr("user")} ${t.user}` : "", t.via.map(v => v === "agent" ? tr("agent tự soạn") : v.replace(/^profile /, "")).join(", "),
        t.runs ? `${t.runs} ${tr("lần")}, ${tr("gần nhất")} ${when(t.last_run)}` : tr("chưa chạy")].filter(Boolean).join(" · ")))));
  return h("div", {class: "card devices"}, h("h2", null, "Agent và nơi chạy lệnh"),
    h("h3", null, "Agent gọi từ"),
    agents.length ? h("ul", {class: "health"}, agents) : h("p", {class: "muted"}, "Chưa có token agent."),
    h("h3", null, "Nơi ucanrun chạy lệnh"),
    !d.exec && !targets.length ? h("p", {class: "muted"}, "Server không tự chạy lệnh; lệnh chỉ chạy trên runner.") :
      targets.length ? h("ul", {class: "health"}, targets) : h("p", {class: "muted"}, "Chưa có lệnh nào chạy và chưa có hành động cố định chạy lệnh."),
    d.exec || (d.runners || []).length ? h("p", {class: "muted"}, d.command_secrets.length
      ? `${tr("Agent được tự soạn lệnh với")}: ${d.command_secrets.map(n => { const x = (secrets || []).find(y => y.name === n) || {};
        const f = [x.approve === "auto" ? tr("tự chạy, không hỏi") : "", x.totp === "never" ? tr("không cần TOTP") : x.totp === "always" ? tr("luôn cần TOTP") : ""].filter(Boolean);
        return f.length ? `${n} (${f.join(", ")})` : n; }).join(", ")}. ${tr("Lệnh chạy trên runner theo luật runner.toml của máy đó; qua SSH thì theo quyền của khoá.")}`
      : tr("Không secret nào cho phép dùng trong lệnh agent tự soạn.")) : null,
    h("small", {class: "foot muted"}, "Tên máy do agent tự khai. Danh sách lấy từ nhật ký và hành động cố định, không dò trực tiếp."));
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
