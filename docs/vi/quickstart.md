# Bắt đầu nhanh

Hướng dẫn này dành cho người dùng mới. Khoảng 10 phút.

## 0. Cài đặt

```bash
git clone <repo> && cd ucanrun
docker compose up -d
docker logs ucanrun
```

Log in ra **Access code** (mã truy cập) và **Setup token**. Không cần tạo file cấu hình. Mở `http://127.0.0.1:8780`, nhập mã truy cập. Lưu mã vào trình quản lý mật khẩu; xem lại bằng `docker exec ucanrun ucr gate`.

Đổi cổng khi bị trùng: `UCANRUN_PORT=9000 docker compose up -d`.

### Dùng qua domain

Đặt địa chỉ công khai rồi chạy lại, xem [cấu hình](configuration.md):

```bash
UCANRUN_PUBLIC_URL=https://ucanrun.example.com docker compose up -d
```

## 1. Khởi tạo kho

1. Nhập setup token từ log.
2. Đặt **mật khẩu chính**, lưu vào trình quản lý mật khẩu. Mất mật khẩu này thì không khôi phục được.

## 2. Làm theo mục Bắt đầu

Sau khi khởi tạo, tab **Bắt đầu** dẫn bạn qua bốn bước. Bước nào chưa làm được thì bỏ qua và quay lại sau.

1. **Nối Telegram:** tạo bot bằng @BotFather, dán token, gửi `/pair <mã>` cho bot. Mã có 6 ký tự, hạn 3 phút, sai 3 lần là huỷ.
2. **Bật TOTP:** quét mã QR, rồi lưu 8 mã khôi phục. Các mã này chỉ hiện một lần.
3. **Lưu secret:** ở tab Secret, chọn một [mẫu](templates.md) hoặc tự điền, dán giá trị, ghi một dòng mô tả và máy chủ được phép.
4. **Tạo token cho agent:** chọn agent bạn dùng, chọn profile được phép, rồi làm theo hướng dẫn hiện ra. Token được đưa vào chính cài đặt MCP của agent đó.

Kiểm tra agent: `ucr profiles`.

## Agent dùng secret thế nào

Agent gọi công cụ MCP `list_secrets`, rồi `call` với header như `Authorization: Bearer {{secret:github_token}}`.

- Máy chủ trong URL phải nằm trong danh sách secret cho phép.
- Secret chỉ đặt trong header, không trong URL hay body.
- Mọi yêu cầu đều cần bạn duyệt, tin nhắn ghi rõ agent tự soạn.
- Với image `exec`, `run_command` dùng được secret có đánh dấu "cho dùng trong lệnh". Lệnh này tính là rủi ro cao, nên cần TOTP trừ khi mọi secret dùng đều đặt "Không cần TOTP".

### Secret nhiều trường

Thông tin đăng nhập database có máy chủ, cổng, user và mật khẩu. Khi lưu secret, chọn **Nhiều trường** và đánh dấu **Công khai** cho các trường agent được xem, như host, port, user, database. Agent viết `{{secret:db.host}}` hoặc `{{secret:db.password}}`.

- Trường công khai hiện cho agent và đặt được ở mọi chỗ, kể cả URL và tham số lệnh.
- Trường riêng theo các quy tắc ở trên và bị che trong kết quả.
- `{{secret:db}}` không ghi trường sẽ bị từ chối.

Muốn giới hạn chặt hơn, tab Nâng cao định nghĩa các hành động cố định, xem [hành động cố định](fixed-actions.md).

## Mất điện thoại

Đăng nhập bằng mật khẩu chính và một mã khôi phục, nhập vào ô mã TOTP. Mỗi mã dùng một lần. Sau đó vào **Cài đặt** → **TOTP** → **Đổi điện thoại** để đăng ký thiết bị mới.

Mã khôi phục không duyệt được yêu cầu rủi ro cao.

## Cài lên điện thoại

Mở trang bằng trình duyệt, nhập mã truy cập, rồi:

- **Android, Chrome:** menu ⋮ → **Thêm vào Màn hình chính**.
- **iPhone, Safari:** nút Chia sẻ → **Thêm vào MH chính**.

App mở toàn màn hình như ứng dụng thường. iPhone giữ dữ liệu riêng cho app cài trên màn hình chính, nên phải nhập mã truy cập thêm một lần. App không lưu dữ liệu kho để dùng offline, nên cần có mạng.

## Dùng hằng ngày

- Agent xin làm việc, bạn nhận tin trên Telegram và bấm **Duyệt** hoặc **Từ chối**. Không bấm trong 2 phút thì coi như từ chối.
- Khi container khởi động lại, kho tự khoá. Bạn đăng nhập web để mở, trong lúc đó agent nhận lỗi 423.

Gặp lỗi: xem [xử lý sự cố](troubleshooting.md).
