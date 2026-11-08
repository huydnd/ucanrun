# Mô hình bảo mật

## ucanrun chống được gì

- Secret lộ qua transcript, log, ngữ cảnh gửi lên cloud.
- Prompt injection khiến agent gửi secret ra ngoài: agent không có secret để gửi.
- Agent gọi lệnh lạ hoặc tới máy lạ: chỉ có profile được phép.
- Người lạ trên Telegram bấm duyệt: chỉ nhận đúng user và chat đã ghép nối.
- Dùng lại mã: duyệt và TOTP đều dùng một lần.

## ucanrun không chống được

- **Agent chủ động vượt rào khi có quyền cao hơn.** User thuộc nhóm `docker` vào được container. Đừng đưa agent vào nhóm `docker`. Nếu buộc phải dùng, hãy đặt socket proxy có allowlist phía trước.
- Người duyệt bấm mà không đọc. Hãy đọc dòng lệnh, đừng đọc lý do. Lý do là agent tự viết.
- Dịch vụ đích bị lộ hoặc token có quyền quá rộng.
- Máy chủ bị chiếm root.
- **Lệnh đã duyệt làm gì với secret của nó.** Lệnh có thể gửi biến môi trường tới bất kỳ máy nào, ví dụ `curl -d @/proc/self/environ`; container không chặn kết nối ra ngoài. Chỉ duyệt khi hiểu hết lệnh, và chỉ bật "cho dùng trong lệnh" cho secret thật sự cần.
- **`http://` không mã hoá.** Secret được phép gửi tới một máy chủ thì cũng được gửi qua `http://` tới máy đó. Chỉ khai báo máy chủ dùng HTTPS hoặc nằm trong mạng riêng.

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
| Audit | Chuỗi băm phát hiện sửa dòng; trạng thái có chữ ký lưu vị trí cuối khi lưu và khi khoá để phát hiện cắt bớt cuối file (các mục ghi sau lần lưu cuối chưa được phủ). |

## TOTP khi duyệt

Mỗi secret có lựa chọn **TOTP khi duyệt**:

| Lựa chọn | Duyệt cần mã TOTP khi |
|---|---|
| Theo mức rủi ro (mặc định) | việc rủi ro cao, hoặc lệnh agent tự soạn |
| Luôn cần TOTP | mọi yêu cầu dùng secret này, kể cả rủi ro thấp; và không tự duyệt nữa |
| Không cần TOTP | không bao giờ, với secret này |

Một yêu cầu cần TOTP nếu có secret nào đặt *Luôn cần*, hoặc nếu việc rủi ro cao mà không phải mọi secret đều đặt *Không cần*. Việc rủi ro cao không dùng secret nào vẫn cần TOTP. Đặt *Không cần TOTP* phải nhập mã TOTP hiện tại, và mục Sức khoẻ bảo mật liệt kê các secret đó. Với *Không cần TOTP*, ai chiếm được Telegram hoặc phiên web là duyệt được; đăng nhập vẫn cần TOTP. Yêu cầu đang chờ giữ nguyên quy tắc lúc được tạo.

## Nhật ký lần chạy

Mỗi lần chạy xong được ghi vào nhật ký audit: agent (tên token), phần mềm agent và tên máy do máy agent tự khai, các secret đã dùng, lệnh đúng như người duyệt thấy, kết quả và thời gian xử lý. **Nhật ký → Lần chạy** liệt kê và lọc được. Tên máy và phần mềm do phía agent tự khai; thứ xác định agent là token. Giá trị secret không bao giờ có trong nhật ký.

## Tự mở khoá khi khởi động

Mặc định, khởi động lại thì kho khoá tới khi bạn đăng nhập, và agent nhận lỗi 423. `UCANRUN_UNLOCK_FILE` đọc mật khẩu chính từ file lúc khởi động. Web vẫn cần mật khẩu và TOTP.

Đánh đổi: ai đọc được file đó thì giải mã được mọi secret. Chỉ dùng với Docker secret, trên máy mà agent không có quyền Docker hay root.

## Khi token bị lộ

- **Token bot:** `/revoke` với @BotFather, dán token mới vào **Cài đặt**, ghép nối lại.
- **Token agent:** thu hồi ở **Token agent**, tạo mới.
- **Secret dịch vụ:** đổi ở dịch vụ đó, nhập lại trùng tên trong **Secret**.
- **Mật khẩu chính:** đổi trong **Cài đặt**.

## Sao lưu

```bash
docker exec ucanrun ucr backup - > ucanrun-backup.tar.gz
docker exec -i ucanrun ucr backup-check - < ucanrun-backup.tar.gz
```

Secret vẫn ở dạng mã hoá, cần mật khẩu chính mới đọc được. `gate.token` không nằm trong bản sao lưu vì là mã truy cập dạng rõ. Giữ bản gốc của secret quan trọng trong trình quản lý mật khẩu.

Khôi phục: chạy một container mới, rồi:

```bash
docker exec -i ucanrun ucr restore - < ucanrun-backup.tar.gz
docker restart ucanrun
```

Lệnh từ chối ghi đè kho đã có dữ liệu. Phải khởi động lại, vì server đang chạy giữ vị trí audit trong bộ nhớ.
