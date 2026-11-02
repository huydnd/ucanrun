# Xử lý sự cố

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| Chỉ thấy ô "Mã truy cập" | Trình duyệt chưa nhập mã cổng | Lấy mã trong `.env`, xem [Bắt đầu nhanh](quickstart.md) |
| Agent nhận lỗi 423 | Kho đang khoá | Đăng nhập web |
| Không có tin Telegram | Kho khoá, hoặc chưa ghép nối | Đăng nhập, xem **Cài đặt** |
| `/pair` không phản hồi | Mã sai, hết 3 phút, hoặc sai 3 lần | Tạo mã mới trong **Cài đặt** |
| Trang báo 502 | Container không chạy hoặc URL tunnel sai | `docker ps`, xem log `cloudflare-tunnel` |
| Setup token đổi liên tục | Container khởi động lại, thường do thiếu RAM | `docker inspect ucanrun`, cần `mem_limit` từ 768m |
| `secret "x" unavailable` | Kho chưa có secret này | Thêm ở tab **Secret** |
| Lỗi 429 | Quá 5 yêu cầu chờ, hoặc 30 yêu cầu trong 10 phút | Chờ, hoặc xử lý các yêu cầu đang chờ |
| Không đăng nhập được | Sai nhiều lần | Chờ tới 60 giây rồi thử lại |
| Không lưu được profile | Lỗi hiện dưới ô xem trước | Sửa theo thông báo |

## Lệnh hữu ích

```bash
docker logs --tail 50 ucanrun
docker exec ucanrun ucr audit-verify
ucr profiles
```

Log không chứa secret. Setup token chỉ hiện trong log khi kho chưa khởi tạo.
