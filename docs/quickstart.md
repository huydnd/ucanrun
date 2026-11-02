# Bắt đầu nhanh

Hướng dẫn này dành cho người dùng mới. Khoảng 10 phút.

## 0. Mã truy cập

Trang công khai có một lớp cổng. Không có mã thì không thấy cả trang đăng nhập. Mã nằm trong `.env`, lấy trên máy chủ:

```bash
grep UCANRUN_GATE_TOKEN /srv/ucanrun/.env
```

Lưu mã vào Bitwarden. Mỗi trình duyệt chỉ nhập một lần trong 30 ngày. Đổi mã: sửa `.env` rồi chạy `docker compose up -d`.

## 1. Khởi tạo kho

1. Mở giao diện web. Ví dụ: `https://ucanrun.example.com`.
2. Lấy setup token: `docker logs ucanrun | tail -3`.
3. Đặt **mật khẩu chính**, lưu vào Bitwarden. Mất mật khẩu này thì không khôi phục được.

## 2. Nối Telegram

1. Tạo bot bằng @BotFather, lấy token. Dùng bot riêng, không dùng chung bot khác.
2. Vào **Cài đặt**, dán token.
3. Gửi `/pair <mã>` cho bot trong chat riêng. Mã có 6 ký tự, hạn 3 phút, sai 3 lần là huỷ.

## 3. Bật TOTP

Vào **Cài đặt**, bấm **Bật TOTP**, quét mã QR. Lưu mã bí mật vào Bitwarden, vì mất nó thì không đăng nhập được.

## 4. Thêm việc cho agent

Vào tab **Profile**, mục **Thêm nhanh**. Chọn dịch vụ, dán token, bấm **Thêm**. Xem [danh mục mẫu](catalog.md).

Muốn việc khác thì dùng [form tạo profile](profiles.md).

## 5. Nối agent

1. Vào **Token agent**, tạo một token cho mỗi agent.
2. Lưu token, chỉ hiện một lần:

   ```bash
   mkdir -p ~/.config/ucanrun
   (umask 077; cat > ~/.config/ucanrun/token)
   ```

   Dán token, nhấn Enter, rồi `Ctrl-D`. Không dán vào chat với AI.
3. Nối Claude Code: `claude mcp add --scope user ucanrun -- ucr mcp`.
4. Kiểm tra: `ucr profiles`.

## Cài lên điện thoại

Mở trang bằng trình duyệt, nhập mã truy cập, rồi:

- **Android, Chrome:** menu ⋮ → **Thêm vào Màn hình chính**.
- **iPhone, Safari:** nút Chia sẻ → **Thêm vào MH chính**.

App mở toàn màn hình như ứng dụng thường. iPhone giữ dữ liệu riêng cho app cài trên màn hình chính, nên phải nhập mã truy cập thêm một lần. App không lưu dữ liệu kho để dùng offline, nên cần có mạng.

## Dùng hằng ngày

- Agent xin làm việc, bạn nhận tin trên Telegram và bấm **Duyệt** hoặc **Từ chối**. Không bấm trong 2 phút thì coi như từ chối.
- Khi container khởi động lại, kho tự khoá. Bạn đăng nhập web để mở, trong lúc đó agent nhận lỗi 423.

Gặp lỗi: xem [xử lý sự cố](troubleshooting.md).
