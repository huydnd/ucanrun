// Package telegram is the approval channel: long polling, inline buttons, and a
// TOTP reply for high risk requests. Messages are plain text on purpose, so that
// agent-influenced text cannot inject formatting or links.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Handler is implemented by core. Identity is checked here before it is called.
type Handler interface {
	Decide(id, shortHash string, approve bool, actor, totp string) (string, error)
	NeedsTOTP(id string) bool
	Pair(code string, userID, chatID int64) bool
}

type Config struct {
	BaseURL string // empty means api.telegram.org
	Token   string
	UserID  int64
	ChatID  int64
}

type Bot struct {
	cfgMu sync.RWMutex
	cfg   Config
	h     Handler
	http  *http.Client

	mu      sync.Mutex
	waiting map[int64]pendingCode // user id -> request awaiting a TOTP reply
	msgs    map[string]int64      // request id -> message id
}

type pendingCode struct {
	id, short string
	until     time.Time
}

func New(cfg Config, h Handler) *Bot {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.telegram.org"
	}
	return &Bot{cfg: cfg, h: h, http: &http.Client{Timeout: 40 * time.Second},
		waiting: map[int64]pendingCode{}, msgs: map[string]int64{}}
}

// call never lets the token reach a returned error, because http errors embed
// the request URL and the URL contains the token.
func (b *Bot) call(ctx context.Context, method string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", b.cfg.BaseURL+"/bot"+b.cfg.Token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) {
			return fmt.Errorf("telegram %s: %w", method, ue.Unwrap())
		}
		return fmt.Errorf("telegram %s failed", method)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("telegram %s: bad response", method)
	}
	if !env.OK {
		return fmt.Errorf("telegram %s: %s", method, env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Check validates the token and returns the bot username.
func (b *Bot) Check(ctx context.Context) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	err := b.call(ctx, "getMe", map[string]any{}, &me)
	return me.Username, err
}

type button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func keyboard(id, short string) map[string]any {
	return map[string]any{"inline_keyboard": [][]button{{
		{Text: "✅ Duyệt", Data: "a:" + id + ":" + short},
		{Text: "❌ Từ chối", Data: "d:" + id + ":" + short},
	}}}
}

// Notify sends a request for approval.
func (b *Bot) Notify(ctx context.Context, id, short, text string) error {
	_, chat := b.owner()
	var m struct {
		MessageID int64 `json:"message_id"`
	}
	err := b.call(ctx, "sendMessage", map[string]any{
		"chat_id": chat, "text": text, "reply_markup": keyboard(id, short),
		"disable_web_page_preview": true,
	}, &m)
	if err == nil {
		b.mu.Lock()
		b.msgs[id] = m.MessageID
		b.mu.Unlock()
	}
	return err
}

// Finish replaces the message text and removes the buttons.
func (b *Bot) Finish(ctx context.Context, id, text string) {
	b.mu.Lock()
	mid, ok := b.msgs[id]
	delete(b.msgs, id)
	b.mu.Unlock()
	if !ok {
		return
	}
	_, chat := b.owner()
	if err := b.call(ctx, "editMessageText", map[string]any{"chat_id": chat, "message_id": mid, "text": text}, nil); err != nil {
		slog.Warn("telegram finish", "err", err)
	}
}

func (b *Bot) say(ctx context.Context, chat int64, text string) {
	if err := b.call(ctx, "sendMessage", map[string]any{"chat_id": chat, "text": text}, nil); err != nil {
		slog.Warn("telegram say", "err", err)
	}
}

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64  `json:"message_id"`
		Text      string `json:"text"`
		From      struct {
			ID    int64 `json:"id"`
			IsBot bool  `json:"is_bot"`
		} `json:"from"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
	Callback *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message *struct {
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

// Run polls until ctx ends. It first discards old updates, so a button pressed
// while the service was down cannot act later.
func (b *Bot) Run(ctx context.Context) {
	var offset int64
	var old []update
	if err := b.call(ctx, "getUpdates", map[string]any{"offset": -1, "timeout": 0}, &old); err == nil && len(old) > 0 {
		offset = old[len(old)-1].UpdateID + 1
	}
	backoff := time.Second
	for ctx.Err() == nil {
		var ups []update
		err := b.call(ctx, "getUpdates", map[string]any{
			"offset": offset, "timeout": 25, "allowed_updates": []string{"message", "callback_query"},
		}, &ups)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("telegram poll", "err", err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			offset = u.UpdateID + 1
			b.handle(ctx, u)
		}
	}
}

func (b *Bot) owner() (user, chat int64) {
	b.cfgMu.RLock()
	defer b.cfgMu.RUnlock()
	return b.cfg.UserID, b.cfg.ChatID
}

func (b *Bot) authorized(user, chat int64) bool {
	u, c := b.owner()
	return u != 0 && user == u && chat == c
}

var codeRe = regexp.MustCompile(`^\d{6}$`)

func (b *Bot) handle(ctx context.Context, u update) {
	if c := u.Callback; c != nil {
		b.handleCallback(ctx, u)
		return
	}
	m := u.Message
	if m == nil || m.From.IsBot {
		return
	}
	text := strings.TrimSpace(m.Text)
	if code, ok := strings.CutPrefix(text, "/pair "); ok {
		if m.Chat.Type == "private" && b.h.Pair(strings.TrimSpace(code), m.From.ID, m.Chat.ID) {
			b.cfgMu.Lock()
			b.cfg.UserID, b.cfg.ChatID = m.From.ID, m.Chat.ID
			b.cfgMu.Unlock()
			b.say(ctx, m.Chat.ID, "Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu.")
		}
		return
	}
	if !b.authorized(m.From.ID, m.Chat.ID) {
		return // stay silent for strangers
	}
	if !codeRe.MatchString(text) {
		return
	}
	b.mu.Lock()
	p, ok := b.waiting[m.From.ID]
	delete(b.waiting, m.From.ID)
	b.mu.Unlock()
	if !ok || time.Now().After(p.until) {
		b.say(ctx, m.Chat.ID, "Không có yêu cầu nào đang chờ mã.")
		return
	}
	msg, err := b.h.Decide(p.id, p.short, true, fmt.Sprintf("telegram:%d", m.From.ID), text)
	if err != nil {
		msg = "Không duyệt được: " + err.Error()
	}
	b.say(ctx, m.Chat.ID, msg)
}

func (b *Bot) handleCallback(ctx context.Context, u update) {
	c := u.Callback
	answer := func(t string) {
		if err := b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": c.ID, "text": t}, nil); err != nil {
			slog.Warn("telegram answer", "err", err)
		}
	}
	if c.Message == nil || !b.authorized(c.From.ID, c.Message.Chat.ID) {
		answer("Không có quyền")
		return
	}
	parts := strings.Split(c.Data, ":")
	if len(parts) != 3 {
		answer("Dữ liệu sai")
		return
	}
	approve, id, short := parts[0] == "a", parts[1], parts[2]
	if approve && b.h.NeedsTOTP(id) {
		b.mu.Lock()
		b.waiting[c.From.ID] = pendingCode{id: id, short: short, until: time.Now().Add(2 * time.Minute)}
		b.mu.Unlock()
		answer("Cần mã TOTP")
		b.say(ctx, c.Message.Chat.ID, "Yêu cầu rủi ro cao "+id+". Gửi mã TOTP 6 số trong 2 phút.")
		return
	}
	msg, err := b.h.Decide(id, short, approve, fmt.Sprintf("telegram:%d", c.From.ID), "")
	if err != nil {
		answer(err.Error())
		return
	}
	answer(msg)
}
