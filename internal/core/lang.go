package core

// Source strings are Vietnamese. English is the default for new installs.
var english = map[string]string{
	"Từ chối":                        "Deny",
	"Duyệt":                          "Approve",
	"Dùng":                           "Use",
	"Đã duyệt":                       "Approved",
	"Đã từ chối":                     "Denied",
	"Không có quyền":                 "Not allowed",
	"Dữ liệu sai":                    "Bad data",
	"Lựa chọn không hợp lệ":          "Invalid choice",
	"Cần mã TOTP":                    "TOTP code needed",
	"Không duyệt được:":              "Could not approve:",
	"Yêu cầu rủi ro cao":             "High risk request",
	"Gửi mã TOTP 6 số trong 2 phút.": "Send the 6-digit TOTP code within 2 minutes.",
	"Không có yêu cầu nào đang chờ mã.":                         "No request is waiting for a code.",
	"Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu.": "Paired. Only this account can approve requests from now on.",
	"sai mã TOTP": "Wrong TOTP code",
	"cần mã TOTP": "A TOTP code is required",
	"yêu cầu đã được xử lý hoặc hết hạn":                   "This request was already handled or has expired",
	"yêu cầu không khớp":                                   "This request does not match",
	"hãy chọn một secret trong danh sách":                  "Choose a secret from the list",
	"chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao": "Turn on TOTP to approve high risk requests",
}

// Translate returns s in the configured language.
func (c *Core) Translate(s string) string {
	if c.opt.Lang == "vi" {
		return s
	}
	if v, ok := english[s]; ok {
		return v
	}
	return s
}
