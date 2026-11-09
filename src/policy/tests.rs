use super::*;
use std::collections::BTreeMap;
use std::time::Duration;

fn field(name: &str, public: bool) -> FieldMeta {
    FieldMeta {
        name: name.into(),
        public,
    }
}

fn db_meta() -> BTreeMap<String, SecretMeta> {
    let mut m = BTreeMap::new();
    m.insert(
        "db".to_string(),
        SecretMeta {
            allow_commands: true,
            fields: vec![field("host", true), field("password", false)],
            ..Default::default()
        },
    );
    m.insert(
        "gh".to_string(),
        SecretMeta {
            hosts: vec!["api.github.com".into()],
            ..Default::default()
        },
    );
    m.insert(
        "nocmd".to_string(),
        SecretMeta {
            fields: vec![field("host", true), field("password", false)],
            hosts: vec!["db.example.com".into()],
            ..Default::default()
        },
    );
    m
}

fn exec_call(argv: &[&str], env: &[(&str, &str)]) -> Call {
    Call {
        exec: Some(ExecSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn field_names_are_validated() {
    let mut m = SecretMeta {
        fields: vec![field("host", true), field("host", false)],
        ..Default::default()
    };
    assert_eq!(m.validate().unwrap_err().0, "duplicate field \"host\"");
    m.fields = vec![field("Host", true)];
    assert_eq!(m.validate().unwrap_err().0, "bad field name \"Host\"");
    m.fields = vec![field("1x", true)];
    assert!(m.validate().is_err());
    m.fields = vec![field(&"a".repeat(33), true)];
    assert!(m.validate().is_err());
    m.fields = vec![field("db_user_2", true)];
    assert!(m.validate().is_ok());
}

#[test]
fn fields_json_shape() {
    let m: SecretMeta =
        serde_json::from_str(r#"{"fields":[{"name":"host","public":true}]}"#).unwrap();
    assert_eq!(m.fields, vec![field("host", true)]);
    assert_eq!(serde_json::to_string(&SecretMeta::default()).unwrap(), "{}");
}

#[test]
fn split_ref_prefers_exact_name_then_last_dot() {
    let known = |n: &str| matches!(n, "db" | "a.b" | "a.b.c");
    assert_eq!(split_ref("db", &known), ("db", None));
    assert_eq!(split_ref("db.host", &known), ("db", Some("host")));
    assert_eq!(split_ref("a.b", &known), ("a.b", None));
    assert_eq!(split_ref("a.b.c", &known), ("a.b.c", None));
    assert_eq!(split_ref("a.b.x", &known), ("a.b", Some("x")));
    assert_eq!(split_ref("zzz.x", &known), ("zzz.x", None));
}

#[test]
fn action_secrets_lists_references_as_written() {
    let c = exec_call(
        &["/usr/bin/psql", "-h", "{{secret:db.host}}"],
        &[("PGPASSWORD", "{{secret:db.password}}")],
    );
    let p = from_call(&c, &db_meta()).unwrap();
    let a = p.render(&BTreeMap::new()).unwrap();
    assert_eq!(a.secrets(), vec!["db.host", "db.password"]);
    assert_eq!(
        a.display(),
        "\"/usr/bin/psql\" \"-h\" \"‹secret:db.host›\"\nenv PGPASSWORD=‹secret:db.password›"
    );
    assert_eq!(p.risk, RISK_HIGH);
}

#[test]
fn public_field_allowed_in_url_body_and_any_host() {
    let mut h = HttpSpec {
        method: "POST".into(),
        url: "https://api.github.com/{{secret:db.host}}/x?h={{secret:db.host}}".into(),
        body: "{\"h\":\"{{secret:db.host}}\"}".into(),
        ..Default::default()
    };
    h.headers
        .insert("Authorization".into(), "Bearer {{secret:gh}}".into());
    let c = Call {
        http: Some(h),
        ..Default::default()
    };
    assert!(from_call(&c, &db_meta()).is_ok());

    // A public field may go to a host the secret itself does not list.
    let mut h = HttpSpec {
        method: "GET".into(),
        url: "https://evil.example/x".into(),
        ..Default::default()
    };
    h.headers
        .insert("X-Host".into(), "{{secret:db.host}}".into());
    h.headers.insert("X-Key".into(), "{{secret:gh}}".into());
    let c = Call {
        http: Some(h),
        ..Default::default()
    };
    assert_eq!(
        from_call(&c, &db_meta()).unwrap_err().0,
        "secret \"gh\" may not be sent to evil.example"
    );
}

#[test]
fn private_field_keeps_the_rules() {
    let meta = db_meta();
    // In a url or body: refused.
    let mut h = HttpSpec {
        method: "GET".into(),
        url: "https://db.example.com/{{secret:nocmd.password}}".into(),
        ..Default::default()
    };
    let c = Call {
        http: Some(h.clone()),
        ..Default::default()
    };
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "secrets go in headers only, never in the url or body"
    );
    // In a header, to a listed host: fine; to another host: refused.
    h.url = "https://db.example.com/x".into();
    h.headers
        .insert("X".into(), "{{secret:nocmd.password}}".into());
    let c = Call {
        http: Some(h.clone()),
        ..Default::default()
    };
    assert!(from_call(&c, &meta).is_ok());
    h.url = "https://other.example.com/x".into();
    let c = Call {
        http: Some(h),
        ..Default::default()
    };
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "secret \"nocmd.password\" may not be sent to other.example.com"
    );
    // In a command without allow_commands: refused; in argv: refused.
    let c = exec_call(&["/usr/bin/psql"], &[("P", "{{secret:nocmd.password}}")]);
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "secret \"nocmd.password\" is not allowed in commands; ask the owner to turn on \"allow in commands\" for it"
    );
    let c = exec_call(&["/usr/bin/psql", "{{secret:db.password}}"], &[]);
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "secrets are only allowed in exec env, argv is visible in /proc"
    );
}

#[test]
fn bare_name_on_multi_field_secret_and_unknown_field() {
    let meta = db_meta();
    let c = exec_call(&["/usr/bin/psql"], &[("P", "{{secret:db}}")]);
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "secret \"db\" has fields, use {{secret:db.FIELD}}"
    );
    let c = exec_call(&["/usr/bin/psql"], &[("P", "{{secret:db.nope}}")]);
    assert_eq!(
        from_call(&c, &meta).unwrap_err().0,
        "unknown field \"nope\" of secret \"db\""
    );
}

#[test]
fn call_with_only_public_fields_uses_no_secret() {
    let c = exec_call(&["/usr/bin/psql", "{{secret:db.host}}"], &[]);
    assert_eq!(
        from_call(&c, &db_meta()).unwrap_err().0,
        "the call uses no secret, so run it yourself"
    );
}

#[test]
fn profile_validate_with_allows_public_in_url_and_argv_only() {
    let meta = db_meta();
    let p = Profile {
        name: "x".into(),
        risk: RISK_HIGH.into(),
        exec: Some(ExecSpec {
            argv: vec!["/usr/bin/psql".into(), "{{secret:db.host}}".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(p.validate().is_err());
    assert!(p.validate_with(&public_fn(&meta)).is_ok());
    let p = Profile {
        name: "x".into(),
        risk: RISK_LOW.into(),
        http: Some(HttpSpec {
            method: "GET".into(),
            url: "https://h.example{{secret:db.host}}/".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        p.validate_with(&public_fn(&meta)).unwrap_err().0,
        "template is not allowed in the url host"
    );
}

#[test]
fn display_masks_public_fields_in_url() {
    let a = Action {
        http: Some(HttpSpec {
            method: "GET".into(),
            url: "https://a.example/{{secret:db.host}}".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(a.display(), "GET https://a.example/‹secret:db.host›");
    assert_eq!(a.secrets(), vec!["db.host"]);
}

#[test]
fn hash_depends_on_all_inputs() {
    let p = Profile::default();
    let a = Action::default();
    let h = hash(&p, &a, "x");
    assert_eq!(h.len(), 64);
    assert_ne!(h, hash(&p, &a, "y"));
    let a2 = Action {
        timeout_sec: 5,
        ..Default::default()
    };
    assert_ne!(h, hash(&p, &a2, "x"));
}

#[test]
fn lint_matches_go() {
    let p = Profile {
        name: "x".into(),
        risk: RISK_LOW.into(),
        auto_approve: true,
        http: Some(HttpSpec {
            method: "DELETE".into(),
            url: "http://api.example.com/x".into(),
            headers: [("A".to_string(), "{{secret:s}}".to_string())].into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(p.lint().len(), 3);
}

fn exec_action(argv: &[&str], env: &[(&str, &str)], stdin: &str, timeout: i64) -> Action {
    Action {
        exec: Some(ExecSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            stdin: stdin.into(),
            ..Default::default()
        }),
        timeout_sec: timeout,
        ..Default::default()
    }
}

fn getter(n: &str) -> Result<Vec<u8>, String> {
    match n {
        "tok" => Ok(b"s3cr3t-value".to_vec()),
        "db.host" => Ok(b"db.internal".to_vec()),
        _ => Err("missing".into()),
    }
}

#[tokio::test]
async fn run_exec_redacts_and_cleans_env() {
    let a = exec_action(&["/usr/bin/env"], &[("T", "{{secret:tok}}")], "", 10);
    let r = run(&a, getter).await;
    assert!(r.ok, "{r:?}");
    assert!(r.output.contains("T=[REDACTED]"), "{}", r.output);
    assert!(!r.output.contains("s3cr3t"));
    assert!(r.output.contains("GIT_TERMINAL_PROMPT=0"));
    assert!(r.output.contains("PATH=/usr/local/bin:/usr/bin:/bin"));
    assert!(!r.output.contains("USER="));
}

#[tokio::test]
async fn run_public_value_is_not_redacted() {
    let a = exec_action(&["/usr/bin/env"], &[("H", "{{secret:db.host}}")], "", 10);
    let mut public = BTreeSet::new();
    public.insert("db.host".to_string());
    let r = run_with(&a, getter, &public).await;
    assert!(r.output.contains("H=db.internal"), "{}", r.output);
}

#[tokio::test]
async fn run_missing_secret_and_missing_program() {
    let a = exec_action(&["/usr/bin/env"], &[("T", "{{secret:nope}}")], "", 10);
    let r = run(&a, getter).await;
    assert_eq!(
        r,
        RunResult {
            ok: false,
            exit: -1,
            output: "secret \"nope\" unavailable".into()
        }
    );
    let r = run(&exec_action(&["/nonexistent/prog"], &[], "", 5), getter).await;
    assert!(!r.ok && r.exit == -1 && r.output.starts_with("could not start: "));
}

/// Alpine keeps core tools in /bin, most other systems in /usr/bin.
fn bin(name: &str) -> &'static str {
    ["/usr/bin/", "/bin/"]
        .iter()
        .map(|d| format!("{d}{name}"))
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| &*p.leak())
        .unwrap_or_else(|| panic!("{name} not found"))
}

#[tokio::test]
async fn run_exec_stdin_cwd_and_timeout() {
    let r = run(
        &exec_action(&[bin("cat")], &[], "{{secret:tok}}", 10),
        getter,
    )
    .await;
    assert_eq!(r.output, "[REDACTED]\n");
    let r = run(&exec_action(&[bin("pwd")], &[], "", 10), getter).await;
    assert!(r.output.contains("ucr-run-"), "{}", r.output);
    let t = std::time::Instant::now();
    let r = run(&exec_action(&[bin("sleep"), "30"], &[], "", 1), getter).await;
    assert!(!r.ok && r.output.ends_with("[timed out]"), "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn run_exec_files_are_private_and_end_with_newline() {
    // ls is the same on Linux and macOS; stat's flags are not.
    let mut a = exec_action(&[bin("ls"), "-l", "key"], &[], "", 10);
    a.exec
        .as_mut()
        .unwrap()
        .files
        .insert("key".into(), "{{secret:tok}}".into());
    let r = run(&a, getter).await;
    assert!(r.output.starts_with("-rw-------"), "{r:?}");
    let mut a = exec_action(&[bin("cat"), "key"], &[], "", 10);
    a.exec
        .as_mut()
        .unwrap()
        .files
        .insert("key".into(), "{{secret:tok}}".into());
    assert_eq!(run(&a, getter).await.output, "[REDACTED]\n");
}

#[tokio::test]
async fn run_http_does_not_follow_redirects_and_caps_output() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = if req.starts_with("GET /redir") {
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                } else {
                    let body = format!(
                        "echo {}\n{}",
                        req.contains("s3cr3t-value"),
                        "x".repeat(100_000)
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    let mk = |path: &str| Action {
        http: Some(HttpSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}{path}"),
            headers: [("X-Key".to_string(), "{{secret:tok}}".to_string())].into(),
            ..Default::default()
        }),
        timeout_sec: 10,
        ..Default::default()
    };
    let r = run(&mk("/redir"), getter).await;
    assert!(!r.ok && r.exit == 302, "{r:?}");
    let r = run(&mk("/big"), getter).await;
    assert!(r.ok && r.exit == 200);
    assert!(r.output.starts_with("HTTP 200\necho true"));
    assert!(r.output.ends_with("\n[output truncated]"));
    assert!(r.output.len() < 65_536 + 40);
}

/// GitHub answers 403 to requests without a User-Agent.
#[tokio::test]
async fn run_http_sends_a_user_agent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let body: Vec<&str> = req
                    .lines()
                    .filter_map(|l| l.strip_prefix("user-agent: "))
                    .collect();
                let body = body.join("|");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    let mk = |headers: Vec<(&str, &str)>| Action {
        http: Some(HttpSpec {
            method: "GET".into(),
            url: format!("http://127.0.0.1:{port}/"),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }),
        timeout_sec: 10,
        ..Default::default()
    };
    let r = run(&mk(vec![]), getter).await;
    assert_eq!(r.output, format!("HTTP 200\n{}", super::exec::USER_AGENT));
    let r = run(&mk(vec![("User-Agent", "Custom/1")]), getter).await;
    assert_eq!(r.output, "HTTP 200\ncustom/1");
}

#[test]
fn needs_totp_follows_risk_and_each_secret() {
    let mut m = BTreeMap::new();
    let set = |totp: &str| SecretMeta {
        totp: totp.into(),
        ..Default::default()
    };
    m.insert("plain".to_string(), set(""));
    m.insert("free".to_string(), set(TOTP_NEVER));
    m.insert("db".to_string(), set(TOTP_ALWAYS));
    let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert!(needs_totp(RISK_HIGH, &v(&[]), &m), "high risk, no secret");
    assert!(!needs_totp(RISK_LOW, &v(&["plain"]), &m));
    assert!(needs_totp(RISK_HIGH, &v(&["plain"]), &m));
    assert!(!needs_totp(RISK_HIGH, &v(&["free"]), &m));
    assert!(
        needs_totp(RISK_HIGH, &v(&["free", "plain"]), &m),
        "one secret keeps it"
    );
    assert!(
        needs_totp(RISK_LOW, &v(&["db.password"]), &m),
        "field of an always secret"
    );
    assert!(
        needs_totp(RISK_HIGH, &v(&["unknown"]), &m),
        "unknown follows risk"
    );
}

#[test]
fn approval_screen_shows_control_and_bidi_characters_escaped() {
    let a = Action {
        exec: Some(ExecSpec {
            argv: vec!["/usr/bin/psql".into()],
            env: [(
                "A".to_string(),
                "x\nstdin: harmless\u{202e}gnp.exe".to_string(),
            )]
            .into(),
            stdin: "line1\nline2".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let d = a.display();
    assert_eq!(d.lines().count(), 3, "{d}");
    assert!(d.contains("x\\nstdin: harmless\\u{202e}gnp.exe"), "{d}");
    assert!(d.contains("stdin: line1\\nline2"), "{d}");
    let b = Action {
        http: Some(HttpSpec {
            method: "POST".into(),
            url: "https://a.example/".into(),
            body: "{\n  \"x\": \"\u{2066}y\"\n}".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let d = b.display();
    assert!(
        d.contains("{\n  \"x\": \"\\u{2066}y\"\n}"),
        "body keeps lines: {d}"
    );
}

#[test]
fn header_values_with_control_characters_are_refused() {
    for v in ["a\r\nX-Evil: 1", "a\u{202e}b", "a\0b"] {
        let p = Profile {
            name: "h".into(),
            risk: RISK_LOW.into(),
            http: Some(HttpSpec {
                method: "GET".into(),
                url: "https://a.example/".into(),
                headers: [("X".to_string(), v.to_string())].into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(p.validate().is_err(), "{v:?} accepted");
    }
}

#[test]
fn wildcard_hosts_mean_the_default_port() {
    let mut m = BTreeMap::new();
    m.insert(
        "t".to_string(),
        SecretMeta {
            hosts: vec!["*.example.com".into(), "*.other.test:8443".into()],
            ..Default::default()
        },
    );
    let call = |url: &str| {
        from_call(
            &Call {
                http: Some(HttpSpec {
                    method: "GET".into(),
                    url: url.into(),
                    headers: [("A".to_string(), "{{secret:t}}".to_string())].into(),
                    ..Default::default()
                }),
                exec: None,
            },
            &m,
        )
    };
    assert!(call("https://api.example.com/").is_ok());
    assert!(call("https://api.example.com:9999/").is_err());
    assert!(call("https://x.other.test:8443/").is_ok());
    assert!(call("https://x.other.test/").is_err());
}
