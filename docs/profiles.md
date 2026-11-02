# Tạo profile

Profile là một việc cụ thể bạn cho phép agent xin làm. Agent chỉ điền được các giá trị bạn khai báo, còn nơi gửi và secret do bạn cố định.

## Các bước trên form

1. **Việc cần làm:** viết một câu. Tên lệnh tự sinh từ câu này.
2. **Gọi tới đâu:** chọn **Gọi API** nếu được. **Chạy lệnh** chạy chương trình trong container nên rủi ro hơn.
3. **Đăng nhập bằng gì:** chọn kiểu, rồi chọn secret, hoặc **Chọn khi duyệt trên Telegram**.
4. **Agent được điền gì:** thêm giá trị và chọn kiểu dữ liệu. Bấm nút tên giá trị để chèn vào ô đang chọn.
5. **Nội dung gửi đi:** chỉ cần với POST, PUT, PATCH.
6. **Ai duyệt:** chọn mức phù hợp.

Ô **Telegram sẽ hiện** bên cạnh là đúng nội dung bạn sẽ thấy khi duyệt. Nút Lưu chỉ bật khi profile hợp lệ.

## Chọn mức duyệt

| Mức | Dùng khi |
|---|---|
| Luôn hỏi tôi | Mặc định, cho mọi việc có ghi dữ liệu |
| Hỏi và cần TOTP | Xoá dữ liệu, thay đổi quan trọng, lệnh trên máy chủ |
| Tự chạy, không hỏi | Chỉ đọc và vô hại, như xem số dư |

## Chọn secret khi duyệt

Dùng khi một việc có nhiều tài khoản, như GitHub cá nhân và công việc.

1. Ở bước 3, chọn **Chọn khi duyệt trên Telegram**.
2. Tích các secret được phép chọn.

Telegram sẽ hiện mỗi secret một nút **✅ Dùng tên_secret**. Tin kết thúc ghi rõ secret đã dùng, audit log cũng ghi lại. Agent không chọn được secret, chỉ bạn chọn. Danh sách phải khai báo trước, vì mọi secret trong danh sách đều được gửi tới cùng một địa chỉ. Không đưa vào danh sách secret của dịch vụ khác.

## Luật hệ thống tự chặn

- Agent không đổi được tên máy đích.
- Không đặt secret trong URL hay đối số lệnh, vì sẽ lộ ở log và `/proc`.
- Không chạy shell hay trình thông dịch.
- Không dùng biến như `LD_PRELOAD`, `PATH`.
- Giá trị khai báo mà không dùng sẽ bị từ chối khi lưu.

## Định dạng JSON

Mục **Nâng cao** trên form cho xem và dán JSON. Chạy lệnh có thêm hai trường: `stdin` đưa secret vào đầu vào chương trình, `files` tạo file tạm quyền 600 trong thư mục chạy và xoá sau khi xong.

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
