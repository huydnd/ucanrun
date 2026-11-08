# Cấu hình

Mặc định không cần cấu hình gì. Mọi biến đều tuỳ chọn.

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `UCANRUN_PUBLIC_URL` | Trống | Địa chỉ người dùng truy cập. Bắt đầu bằng `https://` thì bật cookie Secure và HSTS. |
| `UCANRUN_GATE_TOKEN` | Tự sinh | Mã truy cập. Để trống thì tạo một lần trong `data/gate.token`. |
| `UCANRUN_GATE` | Bật | `off` tắt lớp cổng. Chỉ dùng khi đã có lớp bảo vệ khác phía trước. |
| `UCANRUN_ENABLE_EXEC` | Tắt | `1` cho phép profile chạy lệnh. |
| `UCANRUN_LANG` | `en` | Ngôn ngữ tin nhắn Telegram, `vi` hoặc `en`. Giao diện web chọn riêng trong Cài đặt. |
| `UCANRUN_UNLOCK_FILE` | Trống | File chứa mật khẩu chính, đọc khi khởi động để khởi động lại không khoá agent. Bỏ qua TOTP. Dùng Docker secret, đọc [đánh đổi](security.md). |
| `UCANRUN_APPROVAL_TTL` | `2m` | Thời gian chờ duyệt. |
| `UCANRUN_PORT` | `8780` | Cổng web trong `compose.yml`. |
| `UCANRUN_AGENT_PORT` | `8781` | Cổng agent trong `compose.yml`. |

## Hai loại image

| Image | Nội dung | Làm được |
|---|---|---|
| Mặc định | Chỉ binary và CA, không shell, không công cụ | Gọi API |
| `exec` | Thêm Alpine, `git`, `ssh`, `curl` | Gọi API và chạy lệnh |

Nên dùng image mặc định trừ khi thật sự cần chạy lệnh. Bản `exec` có bề mặt tấn công lớn hơn.

```bash
docker build --target exec -t ucanrun:exec .
```

Image `exec` tự bật `UCANRUN_ENABLE_EXEC=1`.

## Truy cập từ xa

Chỉ publish cổng web `8780`, không bao giờ publish cổng agent `8781`. Đặt `UCANRUN_PUBLIC_URL` trùng domain.

**Caddy** tự lấy chứng chỉ TLS:

```
ucanrun.example.com {
    reverse_proxy 127.0.0.1:8780
}
```

**Cloudflare Tunnel:** thêm public hostname trỏ tới dịch vụ `ucanrun:8780`.

**Tailscale:** `tailscale serve --bg 8780`.

## Phát hành

Đẩy tag `v*` lên GitHub sẽ chạy `.github/workflows/release.yml`, build cho `amd64` và `arm64` rồi đưa lên GHCR. Sau đó có thể cài không cần clone:

```bash
docker run -d --name ucanrun -p 127.0.0.1:8780:8780 -p 127.0.0.1:8781:8781 \
  --memory 768m -v ucanrun-data:/data ghcr.io/<owner>/ucanrun:latest
```
