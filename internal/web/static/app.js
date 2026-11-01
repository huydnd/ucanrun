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
  if (state.tab === "requests") state.timer = setInterval(() => { if (!body.querySelector("input:focus")) draw(); }, 3000);
}

async function viewRequests(body) {
  const list = await api("GET", "/api/requests");
  const pending = list.filter(r => r.state === "pending");
  const rest = list.filter(r => r.state !== "pending");
  const card = r => {
    const code = h("input", {placeholder: "Mã TOTP", inputmode: "numeric", maxlength: 6});
    const err = h("div", {class: "err"});
    const act = approve => async () => {
      try { await api("POST", `/api/requests/${r.id}/decide`, {approve, hash: r.hash, totp: code.value}); viewRequests(body); }
      catch (e) { err.textContent = e.message; }
    };
    return h("div", {class: "card"},
      h("h3", null, r.profile, " ", h("span", {class: "badge " + (r.risk === "high" ? "high" : "")}, r.risk === "high" ? "rủi ro cao" : "rủi ro thấp")),
      h("div", {class: "muted"}, `Agent: ${r.caller} · Mã: ${r.hash.slice(0, 8)} · ${new Date(r.created).toLocaleTimeString()}`),
      h("pre", null, r.display),
      r.reason ? h("div", {class: "muted"}, "Lý do (agent tự khai, chưa kiểm chứng): " + r.reason) : null,
      r.state === "pending" ? h("div", null, r.risk === "high" ? code : null,
        h("div", {class: "row"}, h("button", {class: "primary", onclick: act(true)}, "Duyệt"), h("button", {class: "danger", onclick: act(false)}, "Từ chối")), err) : null,
      r.state !== "pending" ? h("div", {class: "muted"}, `Kết quả: ${r.state}` + (r.decided_by ? ` · ${r.decided_by}` : "")) : null,
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
  fill(body, 
    form("Thêm hoặc thay secret", [n, v], "Lưu", async () => {
      await api("PUT", "/api/secrets/" + encodeURIComponent(n.input.value), {value: v.input.value});
      viewSecrets(body);
    }, h("p", {class: "muted"}, "Giá trị chỉ ghi, không có cách xem lại trên giao diện. Nhập trùng tên để thay.")),
    h("div", {class: "card"}, h("h2", null, `Secret (${list.length})`),
      list.length ? list.map(s => h("div", {class: "spread"}, h("span", null, h("code", null, s.name), h("div", {class: "muted"}, new Date(s.updated).toLocaleString())),
        h("button", {class: "danger", onclick: async () => {
          if (confirm(`Xoá secret ${s.name}?`)) { await api("DELETE", "/api/secrets/" + encodeURIComponent(s.name)); viewSecrets(body); }
        }}, "Xoá"))) : h("p", {class: "muted"}, "Chưa có secret.")));
}

const sampleProfile = {name: "gitea-create-repo", description: "Tạo repo private trên Gitea", risk: "low",
  params: [{name: "repo", pattern: "[a-z0-9._-]{1,64}", required: true}],
  http: {method: "POST", url: "http://gitea:3000/api/v1/user/repos",
    headers: {Authorization: "token {{secret:gitea_token}}", "Content-Type": "application/json"},
    body: "{\"name\":\"{{repo}}\",\"private\":true}"}};

async function viewProfiles(body) {
  const list = await api("GET", "/api/profiles");
  const ta = h("textarea", {spellcheck: "false", "aria-label": "Profile JSON"});
  ta.value = JSON.stringify(sampleProfile, null, 2);
  const err = h("div", {class: "err"});
  fill(body, h("div", {class: "card"}, h("h2", null, "Thêm hoặc sửa profile (JSON)"),
    h("p", {class: "muted"}, "Agent chỉ điền được các param đã khai báo, mỗi param phải có pattern. Host và secret do profile cố định."), ta,
    h("div", {class: "row"}, h("button", {class: "primary", onclick: async () => {
      err.textContent = "";
      try { await api("PUT", "/api/profiles", JSON.parse(ta.value)); viewProfiles(body); } catch (e) { err.textContent = e.message; }
    }}, "Lưu")), err),
    h("div", {class: "card"}, h("h2", null, `Profile (${list.length})`),
      list.length ? list.map(p => h("div", {class: "spread"}, h("span", null, h("code", null, p.name), " ",
        h("span", {class: "badge " + (p.risk === "high" ? "high" : "")}, p.auto_approve ? "tự duyệt" : p.risk), h("div", {class: "muted"}, p.description || "")),
        h("span", null, h("button", {onclick: () => { ta.value = JSON.stringify(p, null, 2); ta.focus(); }}, "Sửa"), " ",
          h("button", {class: "danger", onclick: async () => { if (confirm(`Xoá profile ${p.name}?`)) { await api("DELETE", "/api/profiles/" + encodeURIComponent(p.name)); viewProfiles(body); } }}, "Xoá")))) : h("p", {class: "muted"}, "Chưa có profile.")));
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
  const pairHint = (bot, code) => out.replaceChildren(h("div", {class: "note"}, `Mở chat riêng với ${bot ? "@" + bot : "bot"} và gửi trong 10 phút:`, h("pre", null, "/pair " + code)));
  const tgCard = form("Telegram", [tg], "Lưu token", async () => {
    const r = await api("PUT", "/api/telegram", {token: tg.input.value});
    tg.input.value = ""; pairHint(r.bot, r.code);
  }, h("p", {class: "muted"}, s.telegram && s.telegram.paired ? `Đã ghép nối với user ${s.telegram.user_id}.` : (s.telegram && s.telegram.configured ? "Đã có bot, chưa ghép nối." : "Chưa cấu hình. Dùng bot riêng, không dùng chung bot khác.")));
  if (s.telegram && s.telegram.configured) tgCard.append(h("div", {class: "row"}, h("button", {onclick: async () => pairHint("", (await api("POST", "/api/telegram/pair")).code)}, "Tạo mã ghép nối mới")));
  tgCard.append(out);
  const box = h("div");
  const totpCard = h("div", {class: "card"}, h("h2", null, "TOTP"), s.totp ? h("p", {class: "muted"}, "Đã bật. Cần khi đăng nhập và duyệt yêu cầu rủi ro cao.") :
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
