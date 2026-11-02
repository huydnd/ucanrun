# Danh mục mẫu

Tab **Profile**, mục **Thêm nhanh**. Mỗi mẫu cần một secret; nếu kho chưa có thì ô dán hiện ngay trên thẻ. Mẫu lưu ở `internal/web/static/catalog.json`, mỗi lần chạy test đều được kiểm tra.

| Mẫu | Tên lệnh | Secret | Duyệt |
|---|---|---|---|
| GitHub: xem repo | `github-list-repos` | `github_token` | Hỏi |
| GitHub: tạo issue | `github-create-issue` | `github_token` | Hỏi |
| Gitea: xem repo (cần sửa địa chỉ) | `gitea-list-repos` | `gitea_token` | Hỏi |
| Gitea: tạo repo private (cần sửa địa chỉ) | `gitea-create-repo` | `gitea_token` | Hỏi |
| Cloudflare: xem domain | `cloudflare-list-zones` | `cloudflare_token` | Hỏi |
| Cloudflare: xoá cache | `cloudflare-purge-cache` | `cloudflare_token` | TOTP |
| DeepSeek: xem số dư | `deepseek-balance` | `deepseek_key` | Tự chạy |
| Google AI: xem model | `google-ai-list-models` | `google_ai_key` | Tự chạy |
| Notion: tìm trang | `notion-search` | `notion_token` | Hỏi |
| GitHub: chọn tài khoản | `github-whoami` | Chọn trên Telegram | Hỏi |
| Khởi động lại dịch vụ qua SSH | `ssh-restart-service` | Khoá SSH và mật khẩu sudo | TOTP |

Các mục cần sửa phải bấm **Tuỳ chỉnh**. Mục SSH cần image `exec` và [thiết lập riêng](ssh-sudo.md).

## Cấp quyền token

Tạo token với quyền hẹp nhất đủ dùng. Mẫu đọc thì chỉ cần token đọc. Một token cho một việc giúp thu hồi dễ hơn.

## Thêm mẫu mới

Thêm một mục vào `catalog.json`, gồm `group`, `title`, `hint`, `secrets` và `profile`, rồi chạy `go test ./internal/web`. Test sẽ báo nếu profile sai luật.
