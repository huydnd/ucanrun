package core

import (
	"sort"

	"ucanrun/internal/audit"
	"ucanrun/internal/policy"
)

// HealthItem is one line of the security checklist. Names are profile, token or
// secret names, never values.
type HealthItem struct {
	Key     string   `json:"key"`
	Level   string   `json:"level"` // ok, warn or bad
	Message string   `json:"message"`
	Names   []string `json:"names,omitempty"`
}

const recoveryLow = 3

// Health reviews the current configuration. It reads state under c.mu, then
// does file work after releasing it.
func (c *Core) Health() ([]HealthItem, error) {
	c.mu.Lock()
	if c.st == nil {
		c.mu.Unlock()
		return nil, ErrLocked
	}
	totpOn, recovery, paired, cut := c.st.TOTPEnabled, len(c.st.RecoveryHashes), c.st.Telegram.UserID != 0, c.auditCut
	profiles := make([]policy.Profile, 0, len(c.st.Profiles))
	for _, p := range c.st.Profiles {
		// Judge what actually runs, with the connection applied.
		if r, err := policy.Resolve(p, c.st.Connections); err == nil {
			p = r
		}
		profiles = append(profiles, p)
	}
	var unscoped []string
	for _, t := range c.st.Tokens {
		if len(t.Profiles) == 0 {
			unscoped = append(unscoped, t.Name)
		}
	}
	c.mu.Unlock()
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	sort.Strings(unscoped)

	var out []HealthItem
	add := func(key string, names []string, ok, bad, level string) {
		if len(names) == 0 {
			out = append(out, HealthItem{Key: key, Level: "ok", Message: ok})
			return
		}
		out = append(out, HealthItem{Key: key, Level: level, Message: bad, Names: names})
	}

	if totpOn {
		out = append(out, HealthItem{Key: "totp", Level: "ok", Message: "TOTP đang bật."})
		switch {
		case recovery == 0:
			out = append(out, HealthItem{Key: "recovery", Level: "bad", Message: "Đã hết mã khôi phục. Mất điện thoại sẽ không đăng nhập được, hãy tạo mã mới."})
		case recovery < recoveryLow:
			out = append(out, HealthItem{Key: "recovery", Level: "warn", Message: "Mã khôi phục sắp hết, nên tạo bộ mới."})
		default:
			out = append(out, HealthItem{Key: "recovery", Level: "ok", Message: "Còn đủ mã khôi phục."})
		}
	} else {
		out = append(out, HealthItem{Key: "totp", Level: "bad", Message: "TOTP đang tắt. Đăng nhập chỉ có một lớp, và yêu cầu rủi ro cao không duyệt được."})
	}
	if paired {
		out = append(out, HealthItem{Key: "telegram", Level: "ok", Message: "Telegram đã nối."})
	} else {
		out = append(out, HealthItem{Key: "telegram", Level: "warn", Message: "Chưa nối Telegram, bạn chỉ duyệt được khi mở web."})
	}
	if c.opt.AllowExec {
		out = append(out, HealthItem{Key: "exec", Level: "warn", Message: "Tính năng chạy lệnh đang bật."})
	} else {
		out = append(out, HealthItem{Key: "exec", Level: "ok", Message: "Chạy lệnh đang tắt."})
	}

	var autoWrite, linted []string
	used := map[string]bool{}
	for _, p := range profiles {
		if p.AutoApprove && (p.Exec != nil || (p.HTTP != nil && p.HTTP.Method != "GET")) {
			autoWrite = append(autoWrite, p.Name)
		}
		if len(p.Lint()) > 0 {
			linted = append(linted, p.Name)
		}
		for _, n := range (&policy.Action{HTTP: p.HTTP, Exec: p.Exec}).Secrets() {
			used[n] = true
		}
		for _, n := range p.SecretChoices {
			used[n] = true
		}
	}
	delete(used, policy.ChoiceRef) // a placeholder, not a stored secret
	add("auto_write", autoWrite, "Không có profile tự chạy việc ghi.", "Profile tự chạy việc ghi hoặc chạy lệnh mà không ai duyệt.", "warn")
	add("lint", linted, "Các profile không có cảnh báo.", "Profile có cảnh báo cấu hình, xem khi sửa profile.", "warn")
	if len(profiles) >= 2 {
		add("unscoped_tokens", unscoped, "Mọi token đều giới hạn profile.", "Token dùng được mọi profile. Nên giới hạn theo việc agent cần.", "warn")
	}

	var unused, missing []string
	have := map[string]bool{}
	if l, err := c.Vault.List(); err == nil {
		for _, m := range l {
			have[m.Name] = true
			if !used[m.Name] {
				unused = append(unused, m.Name)
			}
		}
	}
	for n := range used {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	add("unused_secrets", unused, "Mọi secret đều có profile dùng.", "Secret không profile nào dùng. Xoá nếu không cần nữa.", "warn")
	add("missing_secrets", missing, "Profile không thiếu secret nào.", "Profile tham chiếu secret chưa có trong kho, lệnh sẽ không chạy được.", "bad")

	if _, err := audit.Verify(c.auditPath()); err != nil || cut {
		out = append(out, HealthItem{Key: "audit", Level: "bad", Message: "Nhật ký có dấu hiệu bị sửa hoặc cắt bớt."})
	} else {
		out = append(out, HealthItem{Key: "audit", Level: "ok", Message: "Chuỗi băm nhật ký hợp lệ."})
	}
	return out, nil
}
