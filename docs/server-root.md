# Lệnh root trên máy chủ

Máy chủ tắt đăng nhập SSH bằng mật khẩu (`PasswordAuthentication no`), nên mật khẩu root không dùng để SSH được. Không nên bật lại. ucanrun dùng hai lớp thay thế:

1. **Khoá SSH riêng** để vào máy bằng user `huydnd`.
2. **Mật khẩu `sudo`** của `huydnd`, đưa vào `sudo -S` qua stdin.

Agent không thấy cả hai, và chỉ chạy được lệnh cố định trong profile.

## Thiết lập

Chạy trong terminal của bạn trên máy chủ.

```bash
ssh-keygen -t ed25519 -N "" -C ucanrun -f ~/ucanrun_key
printf 'restrict,from="172.16.0.0/12" %s\n' "$(cat ~/ucanrun_key.pub)" >> ~/.ssh/authorized_keys
cat ~/ucanrun_key
```

`restrict` tắt forwarding, `from` chỉ cho kết nối từ mạng Docker.

Trong giao diện:

1. Tab **Secret**, tên `server_ssh_key`, tích **Nhiều dòng**, dán nội dung khoá.
2. Tab **Secret**, tên `server_sudo_password`, nhập mật khẩu sudo.
3. Tab **Profile**, thẻ **Khởi động lại dịch vụ**, bấm **Tuỳ chỉnh**, sửa danh sách dịch vụ, chọn mức **Hỏi và cần mã TOTP**, rồi lưu.

Đặt tên secret khác cũng được. Trong form, mục 3 có ô **Mật khẩu đưa vào chương trình** cho mật khẩu sudo, và **File tạm từ secret** cho khoá SSH với tên file `id_key`. Không cần thêm biến môi trường.

Xoá khoá khỏi máy: `rm ~/ucanrun_key ~/ucanrun_key.pub`.

## Quy tắc khi viết thêm lệnh root

- Luôn dùng mức **Hỏi và cần mã TOTP**.
- Luôn dùng kiểu **Chọn trong danh sách** cho giá trị của agent. `ssh` đưa lệnh qua shell của máy đích, nên văn bản tự do sẽ thành chèn lệnh.
- Không làm profile "chạy lệnh bất kỳ". Làm vậy là giao root cho agent, chỉ thêm một nút bấm.
- Một việc một profile.

## Giới hạn

Khoá máy chủ không được ghim: mỗi lần chạy có HOME mới nên SSH chấp nhận khoá lần đầu gặp. Kết nối chỉ đi trong máy qua mạng Docker, nên rủi ro thấp.

Luồng này đã chạy thật: duyệt trên Telegram có TOTP, `systemctl restart cron` thành công.

## Lỗi thường gặp

`sudo: 3 incorrect password attempts` nghĩa là stdin không phải mật khẩu sudo. Xem ô xem trước, phải là secret mật khẩu, không phải khoá SSH.
