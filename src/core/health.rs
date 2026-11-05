//! Security checklist (port of `internal/core/health.go`).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{Core, Error, Result};
use crate::audit;
use crate::policy::{self, Action, CHOICE_REF, Profile};

/// One line of the checklist. Names are profile, token or secret names,
/// never values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HealthItem {
    pub key: String,
    /// ok, warn or bad
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

const RECOVERY_LOW: usize = 3;

fn item(key: &str, level: &str, message: &str) -> HealthItem {
    HealthItem {
        key: key.into(),
        level: level.into(),
        message: message.into(),
        names: vec![],
    }
}

impl Core {
    /// Reviews the current configuration. State is read under the lock, file
    /// work happens after releasing it.
    pub fn health(&self) -> Result<Vec<HealthItem>> {
        let approval_totp_off = self
            .inner()
            .st
            .as_ref()
            .is_some_and(|s| s.approval_totp_off);
        let (totp_on, recovery, paired, cut, mut profiles, mut unscoped, meta) = {
            let g = self.inner();
            let st = g.st.as_ref().ok_or(Error::Locked)?;
            let profiles: Vec<Profile> = st
                .profiles
                .values()
                // Judge what actually runs, with the connection applied.
                .map(|p| policy::resolve(p, &st.connections).unwrap_or_else(|_| p.clone()))
                .collect();
            let unscoped: Vec<String> = st
                .tokens
                .values()
                .filter(|t| t.profiles.is_empty())
                .map(|t| t.name.clone())
                .collect();
            (
                st.totp_enabled,
                st.recovery_hashes.len(),
                st.telegram.user_id != 0,
                g.audit_cut,
                profiles,
                unscoped,
                st.secrets.clone(),
            )
        };
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        unscoped.sort();

        let mut out = vec![];
        let add = |out: &mut Vec<HealthItem>,
                   key: &str,
                   names: Vec<String>,
                   ok: &str,
                   bad: &str,
                   level: &str| {
            if names.is_empty() {
                out.push(item(key, "ok", ok));
            } else {
                let mut i = item(key, level, bad);
                i.names = names;
                out.push(i);
            }
        };

        if totp_on {
            out.push(item("totp", "ok", "TOTP đang bật."));
            out.push(if recovery == 0 {
                item(
                    "recovery",
                    "bad",
                    "Đã hết mã khôi phục. Mất điện thoại sẽ không đăng nhập được, hãy tạo mã mới.",
                )
            } else if recovery < RECOVERY_LOW {
                item("recovery", "warn", "Mã khôi phục sắp hết, nên tạo bộ mới.")
            } else {
                item("recovery", "ok", "Còn đủ mã khôi phục.")
            });
        } else {
            out.push(item(
                "totp",
                "bad",
                "TOTP đang tắt. Đăng nhập chỉ có một lớp, và yêu cầu rủi ro cao không duyệt được.",
            ));
        }
        if approval_totp_off {
            out.push(item(
                "approval_totp",
                "warn",
                "Duyệt yêu cầu rủi ro cao không cần mã TOTP. Ai chiếm được Telegram hoặc phiên web là duyệt được lệnh nguy hiểm.",
            ));
        }
        out.push(if paired {
            item("telegram", "ok", "Telegram đã nối.")
        } else {
            item(
                "telegram",
                "warn",
                "Chưa nối Telegram, bạn chỉ duyệt được khi mở web.",
            )
        });
        out.push(if self.opt.allow_exec {
            item("exec", "warn", "Tính năng chạy lệnh đang bật.")
        } else {
            item("exec", "ok", "Chạy lệnh đang tắt.")
        });

        let have: BTreeMap<String, ()> = self
            .vault
            .list()
            .map(|l| l.into_iter().map(|m| (m.name, ())).collect())
            .unwrap_or_default();
        // A field reference such as "db.host" counts for the secret "db".
        let base = |n: &str| -> String {
            if !have.contains_key(n)
                && let Some((s, _)) = n.rsplit_once('.')
                && have.contains_key(s)
            {
                return s.to_string();
            }
            n.to_string()
        };

        let (mut auto_write, mut linted) = (vec![], vec![]);
        let mut used = BTreeSet::new();
        for p in &profiles {
            let writes = p.exec.is_some() || p.http.as_ref().is_some_and(|h| h.method != "GET");
            if p.auto_approve && writes {
                auto_write.push(p.name.clone());
            }
            if !p.lint().is_empty() {
                linted.push(p.name.clone());
            }
            let a = Action {
                http: p.http.clone(),
                exec: p.exec.clone(),
                timeout_sec: 0,
            };
            for n in a.secrets() {
                used.insert(base(&n));
            }
            for n in &p.secret_choices {
                used.insert(n.clone());
            }
        }
        for (n, m) in &meta {
            if !m.hosts.is_empty() || m.allow_commands {
                used.insert(n.clone());
            }
        }
        used.remove(CHOICE_REF); // a placeholder, not a stored secret
        add(
            &mut out,
            "auto_write",
            auto_write,
            "Không có profile tự chạy việc ghi.",
            "Profile tự chạy việc ghi hoặc chạy lệnh mà không ai duyệt.",
            "warn",
        );
        add(
            &mut out,
            "lint",
            linted,
            "Các profile không có cảnh báo.",
            "Profile có cảnh báo cấu hình, xem khi sửa profile.",
            "warn",
        );
        if profiles.len() >= 2 {
            add(
                &mut out,
                "unscoped_tokens",
                unscoped,
                "Mọi token đều giới hạn profile.",
                "Token dùng được mọi profile. Nên giới hạn theo việc agent cần.",
                "warn",
            );
        }

        let unused: Vec<String> = have
            .keys()
            .filter(|n| !used.contains(*n))
            .cloned()
            .collect();
        let missing: Vec<String> = used
            .iter()
            .filter(|n| !have.contains_key(*n))
            .cloned()
            .collect();
        add(
            &mut out,
            "unused_secrets",
            unused,
            "Mọi secret đều có profile dùng.",
            "Secret không profile nào dùng. Xoá nếu không cần nữa.",
            "warn",
        );
        add(
            &mut out,
            "missing_secrets",
            missing,
            "Profile không thiếu secret nào.",
            "Profile tham chiếu secret chưa có trong kho, lệnh sẽ không chạy được.",
            "bad",
        );

        if audit::verify(&self.audit_path()).is_err() || cut {
            out.push(item(
                "audit",
                "bad",
                "Nhật ký có dấu hiệu bị sửa hoặc cắt bớt.",
            ));
        } else {
            out.push(item("audit", "ok", "Chuỗi băm nhật ký hợp lệ."));
        }
        Ok(out)
    }
}
