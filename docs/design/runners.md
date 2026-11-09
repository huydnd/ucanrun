# Spec: tách ucanrun thành control plane và runner

Trạng thái: **giai đoạn 1 và 2 đã làm trong 0.8.0**, theo một bản rút gọn (xem mục "Đã làm" dưới đây). Giai đoạn 3 (passkey) chưa làm. Hướng dẫn dùng ở `docs/runners.md`.

## Đã làm (0.8.0)

- Gộp giai đoạn 1 và 2: không có unix socket riêng. Mọi runner, kể cả trên chính máy chủ, đều gọi ra Agent API (`/v1/runner/poll`, long-poll 25 giây).
- Không dùng Noise: gói việc đã được A ký (ed25519, khoá sinh từ identity của kho bằng HKDF), secret được seal bằng age cho khoá của B, và kết quả được B ký. Đường truyền chỉ chở byte.
- Policy của B là `runner.toml` (`allow`, `sudo`, `require_totp`). B áp lại các luật của A (cấm trình thông dịch, secret trong argv, env nguy hiểm), nên A bị chiếm cũng không có shell.
- Root: B chạy bằng user riêng. Việc có `sudo: {{secret:X}}` được bọc thành `sudo -S -k --`, mật khẩu đi qua stdin. `sudo` dùng làm argv[0] vẫn bị cấm.
- Windows: B chạy bằng quyền user (Scheduled Task, LogonType S4U, RunLevel Limited). Không có cách nâng quyền theo từng việc.
- Chống gửi lại: B nhớ `job` (nonce) trong bộ nhớ tới khi hết `not_after`.

Phiên bản ucanrun lúc viết bản nháp: 0.2.2 (Rust).

Tài liệu gồm hai phần. Phần I mô tả ucanrun đang chạy thế nào, đủ để người chưa đọc code đánh giá được. Phần II đề xuất tách thành hai thành phần, triển khai qua ba giai đoạn.

## Người review cần trả lời

1. Mô hình tin cậy ở mục 9 có lỗ hổng nào không? Đặc biệt là trường hợp A bị chiếm.
2. Chọn Noise trên WebSocket thay cho mTLS (mục 11.3) có hợp lý không?
3. Runner nên chạy bằng root, hay bằng user thường và chỉ dùng `sudo` khi gói việc mang mật khẩu (mục 10.4)?
4. Giai đoạn 3 (người duyệt ký bằng passkey) có đáng làm so với độ phức tạp của nó không?
5. Có thiết kế sẵn nào nên dùng thay vì tự làm, như Teleport, Boundary hay SSM?

---

# Phần I. ucanrun hiện tại

## 1. Mục đích

ucanrun là broker giữ secret cho AI agent. Agent không bao giờ nhận giá trị secret. Agent gửi yêu cầu, có thể là một request HTTP hay một lệnh có chỗ cần secret, hoặc tên một hành động cố định. Con người duyệt yêu cầu trên Telegram hoặc trên web. Sau đó ucanrun tự chèn secret, chạy, và trả output đã che secret cho agent.

Vấn đề cần giải quyết:

- Secret lọt vào transcript, log hay context của model.
- Prompt injection khiến agent gửi secret đi chỗ khác. Agent không có secret thì không gửi được.
- Agent làm việc ngoài ý muốn. Mỗi lần chạy đều cần người duyệt đúng nội dung sẽ chạy.

## 2. Thành phần

```
 Agent (Claude Code, Antigravity, ...)
   │  MCP stdio: `ucr mcp`, hoặc CLI `ucr run`
   ▼
 Agent API :8781  (Bearer token, không qua cổng truy cập)
   │
 ┌─┴──────────────── ucanrun server (`ucr serve`, một binary) ─────────────┐
 │ core: yêu cầu, duyệt, TOTP, token, khoá/mở kho                           │
 │ policy: profile, connection, lời gọi tự soạn, render, redact, chạy      │
 │ vault: secret mã hoá age     state: state.json có HMAC                  │
 │ audit: audit.jsonl nối chuỗi băm   telegram: long poll Bot API          │
 └─┬────────────────────────────────────────────────────────────────────────┘
   │  UI web :8780 (cổng mã truy cập → đăng nhập mật khẩu + TOTP)
   ▼
 Người duyệt: trình duyệt / PWA trên điện thoại, Telegram
```

Toàn bộ nằm trong một binary Rust tĩnh, không dùng database. Thông thường ucanrun chạy trong Docker với các thiết lập sau:

- user 10001, root filesystem chỉ đọc;
- `cap_drop: ALL`, `no-new-privileges`;
- giới hạn bộ nhớ 768 MB, vì scrypt cần nhiều bộ nhớ.

Có hai image:

- `slim`: chỉ có binary và CA, không có shell, chỉ gọi được HTTP;
- `exec`: thêm `git`, `ssh`, `curl`, `psql` cho các profile chạy lệnh.

## 3. Dữ liệu và mã hoá

| Thành phần | Cách làm |
|---|---|
| Kho (`vault/`) | `identity.age` là identity X25519, được bọc bằng mật khẩu chính qua scrypt của age. Mỗi secret là một file `secrets/<tên>.age` mã hoá cho recipient đó. File quyền 0600, ghi qua file tạm rồi rename. |
| Khoá kho | Identity chỉ nằm trong RAM khi kho mở. Khởi động lại thì kho khoá, agent nhận lỗi 423. |
| `state.json` | `{"mac", "data"}`. MAC là HMAC-SHA256 trên đúng byte của `data`. Khoá MAC sinh bằng HKDF-SHA256 từ identity, info `ucanrun state mac v1`. File bị sửa thì không mở khoá được. |
| `audit.jsonl` | Mỗi dòng có `prev` và `hash` (SHA-256), nối thành chuỗi. `state.json` ghi lại số dòng và hash cuối cùng mỗi lần lưu hoặc khoá, nên phát hiện được việc cắt bớt log. |
| Token agent | Chỉ lưu SHA-256 của token. |
| TOTP | RFC 6238, SHA-1, bước 30 giây, cửa sổ ±1 bước, mỗi bước chỉ dùng một lần. 8 mã khôi phục, lưu dạng băm. Mã khôi phục không duyệt được yêu cầu rủi ro cao. |
| Secret nhiều trường | Giá trị là `{"ucanrun_fields": {...}}`. Agent viết `{{secret:tên.trường}}`. Trường công khai thì agent thấy giá trị, trường riêng thì không. |

Không có API nào trả về giá trị secret, cho cả agent lẫn người dùng web.

## 4. Các kiểu yêu cầu

1. **Profile cố định:** người dùng định nghĩa `http` hoặc `exec` kèm `params` có regex. Agent chỉ điền tham số. Có `risk: low|high`, và `auto_approve` chỉ dùng được với `low`.
2. **Connection:** khai báo một dịch vụ với base URL, cách xác thực và header chung. Profile chỉ ghi đường dẫn, nên agent không đổi được máy chủ.
3. **Lời gọi HTTP tự soạn (`call`):** agent viết method, URL, header và body. Secret chỉ được đặt trong header, và chỉ gửi tới host mà secret cho phép. Trường công khai thì đặt ở đâu cũng được. Mỗi lời gọi đều cần duyệt.
4. **Lệnh tự soạn (`run_command`):** chỉ dùng được khi server bật `UCANRUN_ENABLE_EXEC=1` và secret được bật "cho dùng trong lệnh". Không có shell, `argv[0]` phải là đường dẫn tuyệt đối. Secret riêng chỉ được đặt trong env, stdin hoặc file. **Luôn cần TOTP.**

Token có danh sách profile thì chỉ chạy được các profile đó, không tự soạn lệnh.

## 5. Luồng xử lý một yêu cầu

1. Agent gửi `POST /v1/requests` kèm `profile` hoặc lời gọi tự soạn, `params`, `reason`, `wait_sec` tối đa 110.
2. Core kiểm tra token, giới hạn tốc độ (30 yêu cầu mỗi 10 phút, tối đa 5 yêu cầu chờ), rồi validate:
   - profile và connection được resolve thành profile đầy đủ;
   - kiểm tra regex của tham số;
   - chặn `{{` `}}` trong giá trị tham số, chặn `..`, ký tự điều khiển, ký tự bidi, và giá trị bắt đầu như một option dòng lệnh;
   - kiểm tra secret được dùng đúng vị trí và đúng host.
3. Render ra **bản hiển thị** để người duyệt xem, trong đó secret được thay bằng `‹secret:tên›`. Tính hash của hành động.
4. Gửi tin Telegram có nút Duyệt / Từ chối. Nếu cần chọn secret, người duyệt chọn trên Telegram. Rủi ro cao thì người duyệt gửi thêm mã TOTP 6 số. Web cũng duyệt được.
5. Quyết định phải gắn với hash của hành động, và yêu cầu hết hạn sau 2 phút (`UCANRUN_APPROVAL_TTL`). Không trả lời thì coi như từ chối.
6. Chạy:
   - **HTTP:** không theo redirect, có gửi `User-Agent: ucanrun/<phiên bản>`.
   - **exec:** chạy với HOME tạm riêng và env sạch, PATH cố định. File secret được tạo quyền 0600. Process group bị kill khi quá thời gian.
7. Output tối đa 64 KiB. Che secret ở cả dạng gốc, base64, hex và URL-encoded.
8. Ghi audit (gồm hash và sha256 của output), rồi trả kết quả cho agent.

## 6. Giao diện và đăng nhập

- **Cổng mã truy cập:** thiếu cookie `ucr_gate` thì mọi đường dẫn đều trả 401, trừ `/healthz`.
- **Đăng nhập:** mật khẩu chính (ít nhất 12 ký tự) cùng TOTP. Có backoff toàn cục khi đăng nhập sai.
- **Session:** hết hạn sau 30 phút không dùng, tối đa 12 giờ. Cookie HttpOnly, SameSite=Strict, có Secure khi chạy sau HTTPS.
- **CSRF:** request ghi phải có header `X-Ucanrun: 1`, và `Sec-Fetch-Site` phải là same-origin.
- **CSP chặt:** chỉ cho script từ `self`. DOM chỉ dựng qua `textContent`.
- **Các tab:** Bắt đầu, Yêu cầu, Secret, Token agent, Nâng cao (profile và connection), Cài đặt (Telegram, TOTP, mật khẩu), Nhật ký.
- **PWA:** cài lên điện thoại được, không có cache offline.

## 7. Lệnh và API

```
Server:  ucr serve | add NAME | list | rm NAME | backup FILE | restore FILE
         backup-check FILE | audit-verify | gate | health
Agent:   ucr profiles | run PROFILE k=v --reason "..." | doctor | mcp
```

**Biến môi trường:**

| Nhóm | Biến |
|---|---|
| Dữ liệu và cổng mạng | `UCANRUN_DATA`, `UCANRUN_WEB_ADDR`, `UCANRUN_AGENT_ADDR` |
| Truy cập web | `UCANRUN_PUBLIC_URL`, `UCANRUN_GATE_TOKEN`, `UCANRUN_GATE=off` |
| Tính năng | `UCANRUN_ENABLE_EXEC`, `UCANRUN_LANG`, `UCANRUN_APPROVAL_TTL`, `UCANRUN_UNLOCK_FILE` |
| Phía agent | `UCANRUN_URL`, `UCANRUN_TOKEN` |

**Agent API:**

- `GET /v1/profiles`
- `GET /v1/secrets`: tên, mô tả, host, các trường và giá trị của trường công khai.
- `POST /v1/requests`
- `GET /v1/requests/{id}`

**Công cụ MCP:** `list_secrets`, `call`, `run_command`, `list_profiles`, `run`, `get_request`. Lúc `initialize`, server gửi kèm `instructions` hướng dẫn agent cách dùng.

## 8. Giới hạn hiện tại

1. **Chạy lệnh trên máy chủ phải đi qua SSH.** Container không có quyền gì trên máy chủ, nên lệnh `sudo` phải SSH từ container ra `host.docker.internal`, dùng một khoá riêng và đưa mật khẩu sudo qua stdin. Cách này cần thêm khoá SSH, `authorized_keys` giới hạn mạng nguồn, và khoá máy chủ không được ghim.
2. **Chỉ chạy được trên một máy.** Muốn chạy lệnh trên laptop hay PC khác thì phải SSH ra từng máy, mỗi máy một khoá.
3. **Server là điểm tin cậy duy nhất.** Ai chiếm được server lúc kho đang mở thì có mọi secret và chạy được mọi lệnh.
4. **Rủi ro đã chấp nhận:** user agent thuộc nhóm `docker` thì vào được container.

---

# Phần II. Đề xuất: control plane A và runner B

## 9. Mô hình

- **A, control plane:** gồm toàn bộ ucanrun hiện tại (kho, giao diện, Telegram, TOTP, audit, policy), nhưng không tự chạy lệnh exec trên máy nữa.
- **B, runner:** một tiến trình nhỏ (`ucr runner`) trên từng thiết bị. B nhận gói việc đã được duyệt, kiểm tra lại, chạy, rồi trả kết quả.

**B luôn chủ động kết nối ra A.** Thiết bị chạy B không mở cổng nào, nên chạy được sau NAT và trên laptop.

**Nguyên tắc tin cậy:**

| Nguyên tắc | Cụ thể |
|---|---|
| A ra lệnh, B tự quyết có chạy hay không | B có policy cục bộ do chủ máy viết. Việc ngoài policy thì B từ chối, kể cả khi A đã ký. |
| Secret chỉ tới B lúc chạy | Secret được mã hoá age riêng cho khoá của B và nằm trong gói việc. B xoá khỏi bộ nhớ ngay sau khi chạy xong. B không lưu secret xuống đĩa. |
| Không tự chế mật mã | Chỉ dùng age, ed25519, Noise (crate `snow`) và rustls, là các thư viện chuẩn. |
| Mọi thứ ghi vào audit | A ghi audit như hiện nay. B ghi thêm log cục bộ có chuỗi băm. |

## 10. Giai đoạn 1: runner cục bộ, thay cho SSH

### 10.1 Mục tiêu

Chạy lệnh trên chính máy chủ đang chạy A mà không cần SSH. Đồng thời dựng sẵn định dạng gói việc, policy của B và log cục bộ để dùng lại ở giai đoạn 2.

### 10.2 Kiến trúc

```
 container A (uid 10001) ──unix socket──► B (systemd, trên máy chủ)
            /run/ucanrun/runner.sock          │ kiểm tra chữ ký, policy
                                              ▼
                                   chạy lệnh (user thường; sudo khi được phép)
```

- Socket được mount vào container A. Quyền 0660, chỉ group của uid 10001 truy cập được.
- Kênh này cục bộ nên không cần mã hoá, nhưng gói việc **vẫn được ký và secret vẫn được mã hoá**. Như vậy user khác trên máy có ghi được vào socket cũng không giả được việc.

### 10.3 Gói việc

```json
{
  "v": 1,
  "id": "a6eb4d8d9d56",
  "runner": "homeserver",
  "not_after": "2026-11-04T08:12:00Z",
  "nonce": "base64(16 byte)",
  "approval": {"hash": "sha256 của hành động", "by": "telegram:<id>", "totp": true},
  "exec": {"argv": ["/usr/bin/id", "-u"], "env": {}, "stdin": "", "files": {}, "user": "deploy", "sudo": true, "timeout_sec": 30},
  "secrets": "age(ciphertext cho khoá B): {\"stdin\": \"...\", \"env\": {...}, \"files\": {...}}",
  "redact": ["sha256 của từng giá trị secret"],
  "sig": "ed25519(A, canonical JSON của mọi trường trừ sig)"
}
```

- Phần `exec` không chứa giá trị secret, chỉ có chỗ giữ chỗ. Giá trị thật nằm trong `secrets`, đã được mã hoá.
- B kiểm tra theo thứ tự: chữ ký của A đúng khoá đã ghim → `runner` đúng tên của B → `not_after` chưa qua → `id` và `nonce` chưa từng dùng → policy cho phép → giải mã `secrets` → chạy.
- B tự che secret trong output. A che thêm một lần nữa.

### 10.4 Policy cục bộ của B (`/etc/ucanrun/runner.toml`)

```toml
name = "homeserver"
server_key = "ed25519:..."          # khoá công khai của A, ghim khi đăng ký

[[allow]]
user = "deploy"
sudo = true                          # cho chạy qua sudo, cần mật khẩu trong gói việc
argv0 = ["/usr/bin/id", "/usr/bin/systemctl", "/usr/bin/journalctl"]
require_totp = true

[[allow]]
user = "deploy"
sudo = false
argv0 = ["/usr/bin/git", "/usr/bin/psql"]
```

**Đề xuất cho câu hỏi 3:** B chạy bằng một user riêng không có quyền root, ví dụ `ucr-runner`.

- Lệnh cần root thì B gọi `sudo -S` với mật khẩu nằm trong gói việc đã duyệt. Bình thường B không có quyền root, chỉ có khi A gửi kèm mật khẩu trong một việc đã được duyệt có TOTP.
- Phương án khác: B chạy bằng root rồi hạ quyền theo từng việc. Đơn giản hơn, nhưng B bị chiếm thì mất root ngay.

### 10.5 Lệnh

```
ucr runner init --name homeserver                # sinh khoá B, in khoá công khai
ucr runner enroll --socket /run/ucanrun/runner.sock --code ABC#12
ucr runner serve                              # chạy dưới systemd
ucr runner status                             # đã ghép với A chưa, việc gần đây
ucr runner policy-check                       # kiểm tra runner.toml
```

Trên A cần thêm tab **Thiết bị** (danh sách runner, mã ghép nối, thu hồi), và trường `runner` trong profile exec và `run_command`. Nếu không ghi `runner` thì dùng runner mặc định.

### 10.6 Các bước triển khai

1. Tạo user `ucr-runner`, cấp quyền sudo có mật khẩu cho các lệnh trong policy.
2. Cài binary và unit systemd có hardening: `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges=no` vì cần sudo, và `RuntimeDirectory=ucanrun`.
3. Chạy `ucr runner init`, ghép nối bằng mã tạo trên web.
4. Mount socket vào container A, đặt `UCANRUN_RUNNER_SOCKET`.
5. Chuyển các profile đang dùng SSH sang `runner: "homeserver"`, rồi bỏ khoá SSH.

### 10.7 Test và tiêu chí xong

- Gói việc bị sửa một byte, chữ ký sai, hết hạn, gửi lại `id` cũ, hoặc ghi sai `runner`: B đều từ chối.
- Lệnh ngoài policy bị từ chối kể cả khi A đã ký. `sudo` không có mật khẩu thì thất bại.
- Output không chứa secret ở bất kỳ dạng mã hoá nào.
- B mất kết nối thì việc hết hạn, không treo.
- Chạy thật: `sudo id -u` trả `0`, có duyệt TOTP trên Telegram.

## 11. Giai đoạn 2: runner từ xa trên nhiều thiết bị

### 11.1 Mục tiêu

Laptop, PC hay Raspberry Pi đều chạy được B. Agent chọn `runner: "laptop"`, và mọi việc vẫn được duyệt tại một chỗ.

### 11.2 Kiến trúc

```
 B (laptop) ──WebSocket──► A :8782 /runner  (qua Tailscale, hoặc Cloudflare Tunnel)
          Noise IK bên trong: khoá tĩnh của A và B đều được ghim
```

### 11.3 Chọn giao thức

| Phương án | Ưu | Nhược |
|---|---|---|
| mTLS (rustls) | Chuẩn, quen thuộc | Cloudflare Tunnel cắt TLS ở biên, nên không giữ được mTLS từ đầu đến cuối. Phải tự quản CA hoặc ghim chứng chỉ. |
| **Noise IK trên WebSocket (đề xuất)** | Mã hoá ở tầng ứng dụng, không phụ thuộc đường truyền là Tailscale, Cloudflare hay LAN. Khoá tĩnh nhỏ, ghim đơn giản. Có forward secrecy. | Ít người biết hơn TLS. Phải định nghĩa khung tin nhắn. |
| Chỉ dùng Tailscale (WireGuard) | Không phải code mã hoá | Bắt buộc thiết bị nằm trong tailnet, và mọi thiết bị trong tailnet đều tới được A. Không hợp khi public sản phẩm. |

Dù kênh đã mã hoá, gói việc vẫn được ký và secret vẫn được mã hoá age riêng cho B. Nếu kênh bị phá, kẻ tấn công cũng không đọc được secret và không giả được việc.

### 11.4 Đăng ký thiết bị

1. Trên web: tab Thiết bị → **Thêm runner**. A tạo mã dùng một lần, có hạn 3 phút, sai 3 lần thì huỷ, giống `/pair`.
2. Trên thiết bị: `ucr runner enroll --server wss://ucanrun.example.com/runner --code <mã> --name laptop`.
3. B gửi khoá công khai ed25519 và X25519 của nó. A hiện vân tay khoá trên web để người dùng xác nhận, và B ghim khoá của A.
4. Thu hồi: xoá B trên web. A huỷ kết nối và từ chối khoá đó từ đó về sau.

### 11.5 Vận hành

- B gửi heartbeat 30 giây một lần. A hiện trạng thái trực tuyến, phiên bản và lần thấy cuối.
- B offline thì việc của B được báo ngay cho agent và người duyệt là "runner offline", không xếp hàng chờ.
- Cài trên Linux bằng systemd user hoặc system service, trên macOS bằng launchd. Windows cần làm riêng phần exec, hiện chưa hỗ trợ.

### 11.6 Test

- Hai B dùng cùng một tên: lần ghép nối thứ hai bị từ chối.
- B bị thu hồi thì không kết nối lại được.
- Gói việc của B khác bị gửi nhầm sang thì B từ chối.
- Mất mạng giữa chừng thì việc hết hạn và audit ghi đúng.
- Thử thật trên ít nhất hai máy.

## 12. Giai đoạn 3: người duyệt ký bằng passkey

### 12.1 Mục tiêu

A không còn là điểm tin cậy duy nhất. Với việc rủi ro cao, B chỉ chạy khi có **chữ ký của thiết bị người duyệt**. Nếu A bị chiếm, kẻ tấn công vẫn không ra được lệnh root.

### 12.2 Cách làm

1. Đăng ký passkey (WebAuthn) trên PWA. Khoá công khai của passkey được gửi xuống từng B và ghim vào policy: `require_human_sig = true`.
2. Khi có việc rủi ro cao, Telegram gửi link mở PWA. PWA hiện nguyên văn lệnh, rồi gọi WebAuthn với `challenge = hash của gói việc`.
3. A chuyển `authenticatorData`, `clientDataJSON` và chữ ký cho B. B kiểm tra chữ ký, `challenge`, `origin` và `rpId` với giá trị đã ghim.

### 12.3 Đánh đổi

- Không duyệt việc rủi ro cao chỉ bằng nút Telegram được nữa: phải mở PWA và chạm sinh trắc học.
- WebAuthn gắn với `rpId`, tức tên miền. Đổi tên miền thì phải đăng ký lại passkey.
- Mất điện thoại: cần passkey dự phòng, ví dụ một khoá bảo mật thứ hai, đăng ký sẵn trên mọi B.

## 13. Mô hình đe dọa sau khi tách

| Kẻ tấn công chiếm được | Giai đoạn 1–2 | Thêm giai đoạn 3 |
|---|---|---|
| Agent | Chỉ gửi được yêu cầu, mọi yêu cầu đều cần duyệt. Như hiện nay. | Như vậy |
| Một B | Có secret của những việc từng chạy trên B đó, và chạy được lệnh trong phạm vi user của B. Không đọc được kho. | Như vậy |
| A khi kho đang mở | Có mọi secret. Ra lệnh được cho mọi B, nhưng chỉ trong phạm vi policy của từng B. | Không ra được việc rủi ro cao vì thiếu chữ ký người duyệt |
| Đường truyền | Không đọc được, không giả được | Như vậy |
| Telegram | Thấy nội dung yêu cầu đã che secret, không duyệt được nếu không phải tài khoản đã ghép nối | Như vậy |

## 14. Phương án đã cân nhắc và loại

| Phương án | Lý do loại |
|---|---|
| Mount Docker socket vào A | Tương đương giao root của máy cho A |
| Chạy A trực tiếp trên máy bằng user riêng | Bỏ được SSH nhưng chỉ dùng được cho một máy, và A vẫn giữ quyền thực thi |
| polkit qua D-Bus | Chỉ làm được việc với systemd unit |
| Giữ SSH, thêm `command=` trong `authorized_keys` | Mỗi máy và mỗi việc một dòng cấu hình, khó quản lý khi nhiều máy |
| Dùng Teleport, Boundary hay SSM | Quá nặng cho một người dùng. Không có bước người duyệt xem đúng nội dung lệnh, và không có mô hình secret cho agent AI. |

## 15. Câu hỏi mở

1. Policy của B có nên cho phép điều kiện trên tham số, ví dụ `systemctl restart` chỉ với một số unit, hay chỉ nên giới hạn theo `argv0`?
2. A gửi secret theo từng việc, hay B được giữ một số secret lâu dài như khoá deploy?
3. Có nên có "runner trong container" làm mặc định, để người không cần chạy lệnh trên máy chủ thì không phải cài gì thêm?
4. Định dạng canonical JSON để ký: tự viết như `gojson` hiện nay, hay dùng RFC 8785 (JCS)?
5. Nên giữ bao nhiêu `id` và `nonce` đã dùng để chống gửi lại? Chỉ giữ trong khoảng `not_after` là đủ, hay cần lưu ra đĩa phòng trường hợp B khởi động lại?

## 16. Ước lượng

| Giai đoạn | Khối lượng | Phụ thuộc |
|---|---|---|
| 1 | Khoảng 1,5 lần phần exec hiện có | Không |
| 2 | Khoảng 1,5 lần giai đoạn 1 | Giai đoạn 1 |
| 3 | Khoảng 1 lần giai đoạn 1 | Giai đoạn 1. Không cần giai đoạn 2. |
