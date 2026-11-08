# Lệnh root qua SSH

Cần image `exec`, xem [cấu hình](configuration.md).

Nhiều máy chủ tắt đăng nhập SSH bằng mật khẩu, và nên giữ như vậy. ucanrun dùng hai lớp:

1. **Khoá SSH riêng** để vào máy bằng một user thường.
2. **Mật khẩu `sudo`** của user đó, đưa vào `sudo -S` qua stdin.

Agent không thấy cả hai, và chỉ chạy được lệnh cố định trong profile.

## Thiết lập

Chạy trên máy đích, bằng user sẽ dùng:

```bash
ssh-keygen -t ed25519 -N "" -C ucanrun -f ~/ucanrun_key
printf 'restrict,from="172.16.0.0/12" %s\n' "$(cat ~/ucanrun_key.pub)" >> ~/.ssh/authorized_keys
cat ~/ucanrun_key
```

`restrict` tắt forwarding, `from` chỉ cho kết nối từ mạng Docker. Sửa `from` nếu ucanrun chạy trên máy khác.

Trong giao diện:

1. Tab **Secret**, mẫu **Khoá SSH**, dán nội dung khoá.
2. Tab **Secret**, mẫu **Mật khẩu sudo**, nhập mật khẩu sudo. Mẫu này luôn cần TOTP.
3. Tab **Nâng cao**, mục **Tự tạo profile**, bấm **Trống**, mở **Nâng cao: xem hoặc dán JSON** rồi dán profile dưới đây.
4. Sửa `deploy@server.example.com` và danh sách dịch vụ, rồi lưu.

```json
{
  "name": "ssh-restart-service",
  "description": "Khởi động lại một dịch vụ trên máy chủ",
  "risk": "high",
  "timeout_sec": 60,
  "params": [{"name": "service", "pattern": "nginx|cron", "required": true}],
  "exec": {
    "argv": ["/usr/bin/ssh", "-i", "id_key", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=known_hosts",
      "deploy@server.example.com", "sudo -S -p '' /usr/bin/systemctl restart {{service}}"],
    "stdin": "{{secret:sudo_password}}",
    "files": {"id_key": "{{secret:ssh_key}}"}
  }
}
```

Ô xem trước phải hiện `stdin: ‹secret:sudo_password›` và `file id_key: ‹secret:ssh_key›`.

Xoá khoá khỏi máy: `rm ~/ucanrun_key ~/ucanrun_key.pub`.

Nếu ucanrun chạy trên chính máy đích, dùng địa chỉ `host.docker.internal` và thêm `extra_hosts: ["host.docker.internal:host-gateway"]` vào `compose.yml`.

## Quy tắc khi viết thêm lệnh root

- Luôn dùng mức **Hỏi và cần mã TOTP**.
- Luôn dùng kiểu **Chọn trong danh sách** cho giá trị của agent. `ssh` đưa lệnh qua shell của máy đích, nên văn bản tự do sẽ thành chèn lệnh.
- Không làm profile "chạy lệnh bất kỳ". Làm vậy là giao root cho agent, chỉ thêm một nút bấm.
- Một việc một profile.

## Giới hạn

Khoá máy chủ không được ghim: mỗi lần chạy có HOME mới nên SSH chấp nhận khoá lần đầu gặp. Dùng cách này qua mạng nội bộ tin cậy.

## Lỗi thường gặp

`sudo: 3 incorrect password attempts` nghĩa là stdin không phải mật khẩu sudo. Xem ô xem trước, phải là secret mật khẩu, không phải khoá SSH.
