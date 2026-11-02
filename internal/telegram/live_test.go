package telegram

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestLiveBotAPI checks the request shapes against the real Bot API. It runs only
// when UCANRUN_LIVE_TG_TOKEN and UCANRUN_LIVE_TG_CHAT are set. It sends one
// message and removes its buttons, and never reads updates.
func TestLiveBotAPI(t *testing.T) {
	tok, chat := os.Getenv("UCANRUN_LIVE_TG_TOKEN"), os.Getenv("UCANRUN_LIVE_TG_CHAT")
	if tok == "" || chat == "" {
		t.Skip("live credentials not set")
	}
	id, err := strconv.ParseInt(chat, 10, 64)
	if err != nil {
		t.Fatal("bad chat id")
	}
	b := New(Config{Token: tok, ChatID: id, UserID: id}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := b.Check(ctx); err != nil {
		t.Fatal(err)
	}
	const req = "000000000000"
	if err := b.Notify(ctx, req, "0123456789abcdef", "ucanrun: kiểm tra kết nối, không cần bấm gì.\n\nPOST https://example.invalid/repos/a\nAuthorization: token ‹secret:demo›", nil); err != nil {
		t.Fatal(err)
	}
	if err := b.call(ctx, "editMessageText", map[string]any{"chat_id": id, "message_id": b.msgs[req], "text": "ucanrun: kiểm tra kết nối xong, sửa tin nhắn và gỡ nút hoạt động."}, nil); err != nil {
		t.Fatal(err)
	}
}
