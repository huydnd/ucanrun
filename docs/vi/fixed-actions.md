# Hành động cố định (nâng cao)

Đa số trường hợp không cần phần này: lưu secret kèm mô tả và máy chủ được phép, agent tự soạn yêu cầu để bạn duyệt. Dùng hành động cố định khi muốn agent chỉ điền được giá trị bạn cho phép.

ucanrun dùng một mô hình chung thay vì code riêng cho từng dịch vụ:

- **Kết nối** khai báo một dịch vụ một lần: địa chỉ gốc, cách đăng nhập, secret và header chung.
- **Hành động** (profile) dùng một kết nối, chỉ ghi phương thức, đường dẫn và các giá trị agent được điền.

Máy chủ và đăng nhập luôn lấy từ kết nối, nên hành động không thể gửi secret đi nơi khác. Sửa kết nối, ví dụ đổi máy chủ, thì mọi hành động đi theo; thay đổi làm hỏng hành động nào sẽ bị từ chối.

## Cách thêm

Tab Nâng cao, mục **Kết nối**, bấm **Thêm kết nối**: tên, địa chỉ gốc, cách đăng nhập và secret. Sau đó bấm **Hành động mới** trên kết nối đó: phương thức, đường dẫn và các giá trị agent được điền. Bản thân secret lưu ở tab Secret, nơi có sẵn [mẫu](templates.md) cho dịch vụ phổ biến.

## Nhiều tài khoản cho một dịch vụ

Sửa kết nối, chọn **Chọn khi duyệt**, tích các secret. Telegram hiện mỗi secret một nút **Dùng tên**, kết quả ghi rõ secret đã dùng.

Xuất và nhập ở tab Nâng cao mang theo cả kết nối và profile. File chỉ có tên secret, không có giá trị.
