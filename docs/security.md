# Mô hình bảo mật

## ucanrun chống được gì

- Secret lộ qua transcript, log, ngữ cảnh gửi lên cloud.
- Prompt injection khiến agent gửi secret ra ngoài: agent không có secret để gửi.
- Agent gọi lệnh lạ hoặc tới máy lạ: chỉ có profile được phép.
- Người lạ trên Telegram bấm duyệt: chỉ nhận đúng user và chat đã ghép nối.
- Dùng lại mã: duyệt và TOTP đều dùng một lần.

## ucanrun không chống được

- **Agent chủ động vượt rào khi có quyền cao hơn.** User thuộc nhóm `docker` vào được container. Nếu buộc phải dùng, hãy chấp nhận rủi ro này một cách có ý thức. Hướng vá: socket proxy có allowlist.
- Người duyệt bấm mà không đọc. Hãy đọc dòng lệnh, đừng đọc lý do. Lý do là agent tự viết.
- Dịch vụ đích bị lộ hoặc token có quyền quá rộng.
- Máy chủ bị chiếm root.

## Các lớp bảo vệ

| Lớp | Cách làm |
|---|---|
| Cổng | Không có mã truy cập thì mọi đường dẫn web đều trả 401, chỉ trừ `/healthz`. |
| Kho | Mỗi secret một file `age`. Khoá giải mã bọc bằng mật khẩu chính qua scrypt, chỉ ở RAM khi mở khoá. |
| Trạng thái | Profile, token ký HMAC bằng khoá dẫn xuất từ kho. File bị sửa thì không mở khoá. |
| Tham số | Escape theo vị trí, chặn `..`, ký tự điều khiển, bidi, giá trị bắt đầu bằng `-`. |
| Duyệt | Gắn với hash lệnh, hết hạn sau 2 phút, im lặng là từ chối. |
| Chọn secret | Chỉ người duyệt chọn, trong danh sách khai báo, ghi audit. |
| Lệnh | Không shell, HOME riêng mỗi lần chạy, chặn biến nguy hiểm. |
| Output | Che secret và dạng base64, hex, URL-encode. Không theo redirect. |
| Web | Không có API đọc secret, cookie HttpOnly và SameSite=Strict, CSP chặt, giới hạn đăng nhập. |
| Container | Không root, rootfs chỉ đọc, bỏ mọi capability. |
| Audit | Chuỗi băm phát hiện sửa dòng. Cắt bớt phần cuối file thì chưa phát hiện được. |

## Khi token bị lộ

- **Token bot:** `/revoke` với @BotFather, dán token mới vào **Cài đặt**, ghép nối lại.
- **Token agent:** thu hồi ở **Token agent**, tạo mới.
- **Secret dịch vụ:** đổi ở dịch vụ đó, nhập lại trùng tên trong **Secret**.
- **Mật khẩu chính:** đổi trong **Cài đặt**.

## Sao lưu

Sao lưu volume `data`. Secret vẫn ở dạng mã hoá, cần mật khẩu chính mới đọc được. Giữ bản gốc của secret quan trọng trong trình quản lý mật khẩu.
