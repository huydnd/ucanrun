# Mẫu secret

Tab Secret có sẵn mẫu cho các dịch vụ phổ biến. Bấm một mẫu thì form điền sẵn tên, mô tả cho agent, máy chủ được phép và mức TOTP. Bạn dán giá trị rồi lưu. Mọi ô vẫn sửa được.

| Mẫu | Secret | Máy chủ | Ghi chú |
|---|---|---|---|
| GitHub | `github_token` | `api.github.com` | `Authorization: Bearer` |
| Gitea / Forgejo | `gitea_token` | đổi `git.example.com` thành máy của bạn | `Authorization: token` |
| Cloudflare | `cloudflare_token` | `api.cloudflare.com` | |
| OpenAI | `openai_key` | `api.openai.com` | |
| Anthropic | `anthropic_key` | `api.anthropic.com` | header `x-api-key` |
| Google AI (Gemini) | `google_ai_key` | `generativelanguage.googleapis.com` | header `x-goog-api-key` |
| DeepSeek | `deepseek_key` | `api.deepseek.com` | |
| Notion | `notion_token` | `api.notion.com` | |
| PostgreSQL | `postgres`, các trường host, port, user, database (công khai) và password | không | cho `psql` qua `run_command`, cần image `exec` |
| Khoá SSH | `ssh_key`, nhiều dòng | không | cho `ssh` qua `run_command`, cần image `exec` |
| Mật khẩu sudo | `sudo_password` | không | luôn cần TOTP, xem [ssh-sudo](ssh-sudo.md) |
| API key khác | bạn tự đặt tên | bạn tự ghi | |

Mô tả ghi rõ cách agent dùng secret, ví dụ gửi header nào, để agent gọi API mà không phải đoán. Secret dùng trong lệnh được đánh dấu "cho dùng trong lệnh"; ô này chỉ hiện khi server chạy với `UCANRUN_ENABLE_EXEC=1`.

Mẫu có secret trùng tên đã tồn tại sẽ mở secret đó để sửa.

Dữ liệu mẫu nằm ở `web/static/secret-templates.json`, test kiểm tra mọi mẫu đều lưu được.
