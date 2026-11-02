# ucanrun

Broker giữ mật khẩu và token cho AI agent. Lệnh là `ucr`.

Agent không bao giờ nhận secret. Agent xin chạy một **profile**, bạn duyệt trên Telegram hoặc web, rồi ucanrun tự chạy và trả về kết quả đã che secret.

```
Agent ──run(profile, params)──> ucanrun ──lệnh thật──> Telegram, bạn duyệt
                                   │ giải mã secret, chạy, che output
Agent <──── kết quả ───────────────┘
```

## Bảo mật

| Lớp | Cách làm |
|---|---|
| Kho | Mỗi secret một file `age` (X25519). Khoá giải mã được bọc bằng mật khẩu chính (scrypt), chỉ nằm trong RAM khi mở khoá. |
| Trạng thái | Profile, token, cấu hình được ký HMAC bằng khoá dẫn xuất từ kho. File bị sửa thì không mở khoá. |
| Profile | Host, secret và mẫu lệnh do người viết. Agent chỉ điền param đã khai báo, mỗi param phải qua regex. Không cho shell, không cho secret trong URL hay argv. |
| Duyệt | Gắn với hash của đúng lệnh, dùng một lần, hết hạn thì coi như từ chối, chỉ nhận đúng user và chat đã ghép nối. Tin nhắn hiện lệnh thật, không hiện lời agent tự mô tả. |
| Rủi ro cao | Cần thêm TOTP. Mỗi mã chỉ dùng một lần. |
| Tham số | Escape theo vị trí (path, query, JSON, form). Chặn `..`, ký tự điều khiển, bidi, giá trị bắt đầu bằng `-` trong lệnh, và tham số khai báo mà không dùng. |
| Lệnh | Không shell, không biến môi trường nguy hiểm, mỗi lần chạy một HOME riêng. |
| Output | Che giá trị secret và dạng base64, hex, URL-encode. Không theo redirect. |
| Web | Không có API đọc secret. Cookie HttpOnly, SameSite=Strict, chống CSRF, CSP chặt, giới hạn đăng nhập. |
| Audit | JSONL có chuỗi băm, phát hiện sửa hoặc xoá dòng. Không ghi secret. |

### Giới hạn cần biết

- ucanrun chỉ tách được agent khỏi secret khi agent không có quyền cao hơn nó. User thuộc nhóm `docker` có thể `docker exec` vào container hoặc đọc bộ nhớ, tức là vượt được mọi lớp trên. Muốn cô lập thật, agent phải chạy bằng user không thuộc nhóm `docker`.
- Setup token nằm trong log container. Hãy khởi tạo ngay sau khi deploy.
- Che output chỉ là lớp phụ. Lệnh chủ ý biến đổi secret thì che không được, nên profile phải viết chặt.
- Một secret đã nằm trong RAM của Go thì không xoá sạch được tuyệt đối.
- Hash chuỗi audit phát hiện sửa dòng, nhưng người có quyền ghi vẫn có thể cắt bớt phần cuối file.

## Chạy

```bash
docker compose up -d          # xem deploy/compose.yml
docker logs ucanrun           # lấy setup token
```

Mở `http://127.0.0.1:8780`, nhập setup token, đặt mật khẩu chính, rồi:

1. **Cài đặt:** dán token bot từ @BotFather, gửi `/pair <mã>` cho bot, bật TOTP.
2. **Secret:** thêm secret.
3. **Profile:** thêm profile.
4. **Token agent:** tạo token, lưu vào `~/.config/ucanrun/token` (quyền 600).

Mỗi lần container khởi động lại, kho ở trạng thái khoá. Agent nhận lỗi 423 cho đến khi bạn đăng nhập.

## Profile

Tạo profile trong tab **Profile**: chọn mẫu, điền form, xem trước đúng nội dung Telegram sẽ hiện. JSON chỉ cần khi muốn sao chép giữa các máy.

```json
{
  "name": "gitea-create-repo",
  "description": "Tạo repo private trên Gitea",
  "risk": "low",
  "params": [{"name": "repo", "pattern": "[a-z0-9._-]{1,64}", "required": true}],
  "http": {
    "method": "POST",
    "url": "http://gitea:3000/api/v1/user/repos",
    "headers": {"Authorization": "token {{secret:gitea_token}}", "Content-Type": "application/json"},
    "body": "{\"name\":\"{{repo}}\",\"private\":true}"
  }
}
```

`exec` dùng `{"argv": ["/usr/bin/git", "..."], "env": {"TOKEN": "{{secret:x}}"}}`. `risk: "high"` cần TOTP. `auto_approve` chỉ dùng cho rủi ro thấp.

## Agent

```bash
claude mcp add ucanrun -- ucr mcp      # công cụ: list_profiles, run, get_request
ucr run gitea-create-repo repo=foo --reason "repo cho dự án X"
```

## Phát triển

```bash
mise install
go test -race ./...
```

Biến `UCANRUN_LIVE_TG_TOKEN`, `UCANRUN_LIVE_TG_CHAT` bật bài test với Bot API thật.
