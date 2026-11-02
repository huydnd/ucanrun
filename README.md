# ucanrun

Broker giữ mật khẩu và token cho AI agent. Lệnh là `ucr`.

Agent không bao giờ nhận secret. Agent xin chạy một **profile**, bạn duyệt trên Telegram hoặc web, rồi ucanrun tự chạy và trả về kết quả đã che secret.

```
Agent ──run(profile, params)──> ucanrun ──lệnh thật──> Telegram, bạn duyệt
                                   │ giải mã secret, chạy, che output
Agent <──── kết quả ───────────────┘
```

## Tài liệu

- [Bắt đầu nhanh](docs/quickstart.md)
- [Cấu hình](docs/configuration.md)
- [Danh mục mẫu](docs/catalog.md): thêm dịch vụ bằng một lần bấm.
- [Tạo profile](docs/profiles.md), gồm chọn secret trên Telegram.
- [Lệnh root trên máy chủ](docs/server-root.md)
- [Mô hình bảo mật](docs/security.md)
- [Xử lý sự cố](docs/troubleshooting.md)

## Chạy nhanh

```bash
git clone <repo> && cd ucanrun
docker compose up -d
docker logs ucanrun
```

Không cần tạo file cấu hình. Mở `http://127.0.0.1:8780`, nhập mã truy cập trong log, rồi làm theo [Bắt đầu nhanh](docs/quickstart.md).

Mặc định, image chỉ có binary và chỉ gọi được API. Muốn chạy lệnh, xem [cấu hình](docs/configuration.md).

## Phát triển

```bash
mise install
go test -race ./...
```

Biến `UCANRUN_LIVE_TG_TOKEN`, `UCANRUN_LIVE_TG_CHAT` bật bài test với Bot API thật.

## Giấy phép

[Apache-2.0](LICENSE)
