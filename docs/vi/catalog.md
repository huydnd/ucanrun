# Dịch vụ và hành động

ucanrun dùng một mô hình chung thay vì code riêng cho từng dịch vụ:

- **Kết nối** khai báo một dịch vụ một lần: địa chỉ gốc, cách đăng nhập, secret và header chung.
- **Hành động** (profile) dùng một kết nối, chỉ ghi phương thức, đường dẫn và các giá trị agent được điền.

Máy chủ và đăng nhập luôn lấy từ kết nối, nên hành động không thể gửi secret đi nơi khác. Sửa kết nối, ví dụ đổi máy chủ, thì mọi hành động đi theo; thay đổi làm hỏng hành động nào sẽ bị từ chối.

## Thêm nhanh

Tab Profile, **Thêm nhanh**. Chọn dịch vụ, dán token một lần, tích các hành động agent được xin, bấm **Thêm**. **Dịch vụ khác** khai báo được mọi API dùng token.

Danh sách sẵn là dữ liệu trong `internal/web/static/catalog.json`: GitHub, Gitea, Cloudflare, DeepSeek, Google AI, Notion, và một lệnh SSH đứng riêng (cần image `exec`, xem [ssh-sudo](ssh-sudo.md)).

## Nhiều tài khoản cho một dịch vụ

Sửa kết nối, chọn **Chọn khi duyệt**, tích các secret. Telegram hiện mỗi secret một nút **Dùng tên**, kết quả ghi rõ secret đã dùng.

## Mẫu riêng

Đặt file `*.json` vào `data/catalog.d/` (hoặc `UCANRUN_CATALOG_DIR`), cùng định dạng như bản tiếng Anh của tài liệu này. Mục sai được bỏ qua và ghi log.

Xuất và nhập ở tab Profile mang theo cả kết nối và profile. File chỉ có tên secret, không có giá trị.
