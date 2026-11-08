//! Telegram and approval strings. Source strings are Vietnamese; English is
//! the default for new installs.

pub(crate) fn english(s: &str) -> Option<&'static str> {
    Some(match s {
        "Từ chối" => "Deny",
        "Duyệt" => "Approve",
        "Dùng" => "Use",
        "Đã duyệt" => "Approved",
        "Đã từ chối" => "Denied",
        "Không có quyền" => "Not allowed",
        "Dữ liệu sai" => "Bad data",
        "Lựa chọn không hợp lệ" => "Invalid choice",
        "Cần mã TOTP" => "TOTP code needed",
        "Không duyệt được:" => "Could not approve:",
        "Yêu cầu rủi ro cao" => "High risk request",
        "Gửi mã TOTP 6 số trong 2 phút." => "Send the 6-digit TOTP code within 2 minutes.",
        "Không có yêu cầu nào đang chờ mã." => "No request is waiting for a code.",
        "Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu." => {
            "Paired. Only this account can approve requests from now on."
        }
        "sai mã TOTP" => "Wrong TOTP code",
        "cần mã TOTP" => "A TOTP code is required",
        "yêu cầu đã được xử lý hoặc hết hạn" => {
            "This request was already handled or has expired"
        }
        "yêu cầu không khớp" => "This request does not match",
        "hãy chọn một secret trong danh sách" => "Choose a secret from the list",
        "chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao" => {
            "Turn on TOTP to approve high risk requests"
        }
        _ => return None,
    })
}

pub(crate) fn translate(vi: bool, s: &str) -> String {
    if vi {
        return s.to_string();
    }
    english(s).map_or_else(|| s.to_string(), str::to_string)
}

struct Labels {
    head: &'static str,
    high: &'static str,
    high_no_totp: &'static str,
    needs_totp: &'static str,
    agent: &'static str,
    exp: &'static str,
    sec: &'static str,
    cmd: &'static str,
    cut: &'static str,
    why: &'static str,
    pick: &'static str,
    code: &'static str,
    adhoc: &'static str,
}

const EN: Labels = Labels {
    head: "Approval request",
    high: "⚠️ HIGH RISK, needs TOTP",
    high_no_totp: "⚠️ HIGH RISK",
    needs_totp: "🔐 Needs TOTP",
    agent: "Agent",
    exp: "Expires in",
    sec: "seconds",
    cmd: "Command to run",
    cut: "… [SHORTENED, read it all on the web before approving]",
    why: "Reason (stated by the agent, unverified)",
    pick: "Tap the secret to use this time.",
    code: "Code",
    adhoc: "\n✍️ The agent wrote this command itself. Read it carefully.",
};

const VI: Labels = Labels {
    head: "Yêu cầu chạy lệnh",
    high: "⚠️ RỦI RO CAO, cần TOTP",
    high_no_totp: "⚠️ RỦI RO CAO",
    needs_totp: "🔐 Cần mã TOTP",
    agent: "Agent",
    exp: "Hết hạn sau",
    sec: "giây",
    cmd: "Lệnh sẽ chạy",
    cut: "… [ĐÃ CẮT BỚT, xem đủ trên web trước khi duyệt]",
    why: "Lý do (agent tự khai, chưa kiểm chứng)",
    pick: "Bấm tên secret muốn dùng cho lần này.",
    code: "Mã",
    adhoc: "\n✍️ Agent tự soạn lệnh này, hãy đọc kỹ.",
};

pub(crate) fn approval_text(r: &super::Request, vi: bool) -> String {
    let l = if vi { &VI } else { &EN };
    let high = r.risk == crate::policy::RISK_HIGH;
    let mut head = match (high, r.totp) {
        (true, true) => l.high.to_string(),
        (true, false) => l.high_no_totp.to_string(),
        (false, true) => format!("{} · {}", l.head, l.needs_totp),
        (false, false) => l.head.to_string(),
    };
    if r.profile == crate::policy::ADHOC_PROFILE {
        // The agent wrote this one, so the command is the only thing to trust.
        head.push_str(l.adhoc);
    }
    // Telegram drops messages over 4096 characters, which would leave the
    // request invisible. Say so plainly when text is cut.
    let mut shown = r.display.clone();
    if shown.chars().count() > super::MAX_DISPLAY {
        shown = shown.chars().take(super::MAX_DISPLAY).collect::<String>() + "\n" + l.cut;
    }
    let secs = r
        .expires
        .duration_since(r.created)
        .unwrap_or_default()
        .as_secs_f64();
    let mut b = format!(
        "{head}\n\nProfile: {}\n{}: {}\n{}: {secs:.0} {}\n\n{}:\n{shown}\n",
        r.profile, l.agent, r.caller, l.exp, l.sec, l.cmd
    );
    if !r.reason.is_empty() {
        b.push_str(&format!("\n{}: {}\n", l.why, r.reason));
    }
    if !r.choices.is_empty() {
        b.push_str(&format!("\n{}\n", l.pick));
    }
    b.push_str(&format!("\n{}: {}", l.code, &r.hash[..8]));
    b
}

/// Text that replaces an approval message once the request is final.
pub(crate) fn finish_text(r: &super::Request, vi: bool) -> String {
    let (label, used_label, code_label) = if vi {
        ("Kết thúc", "Secret đã dùng", "Mã")
    } else {
        ("Finished", "Secret used", "Code")
    };
    let used = if r.secret.is_empty() {
        String::new()
    } else {
        format!("\n{used_label}: {}", r.secret)
    };
    format!(
        "{label}: {} ({})\nProfile: {}{used}\n{code_label}: {}",
        r.state.as_str(),
        r.decided_by,
        r.profile,
        &r.hash[..8]
    )
}
