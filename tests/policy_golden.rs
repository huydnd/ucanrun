//! Every case in testdata/golden/policy.json must give the Go result.

use serde_json::Value;
use std::collections::BTreeMap;
use ucanrun::policy::{Call, Connection, Profile, SecretMeta, expand, from_call, redact, resolve};

fn golden() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/golden/policy.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .unwrap_or_default()
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .unwrap_or_default()
}

/// Checks the outcome of validate+render against the `want` object.
fn check(name: &str, p: &Profile, params: &BTreeMap<String, String>, want: &Value) {
    let outcome = p.validate().and_then(|_| p.render(params));
    let ok = want["ok"].as_bool().unwrap();
    if !ok {
        let e = outcome.expect_err(&format!("{name}: expected an error"));
        assert_eq!(e.to_string(), want["error"].as_str().unwrap(), "{name}");
        return;
    }
    let a = outcome.unwrap_or_else(|e| panic!("{name}: unexpected error {e}"));
    let h = a.http.as_ref();
    assert_eq!(
        h.map(|h| h.url.as_str()),
        want["url"].as_str(),
        "{name} url"
    );
    assert_eq!(
        h.map(|h| h.method.as_str()),
        want["method"].as_str(),
        "{name} method"
    );
    assert_eq!(
        h.map(|h| h.headers.clone()).unwrap_or_default(),
        str_map(want.get("headers")),
        "{name} headers"
    );
    assert_eq!(
        h.map(|h| h.body.as_str()).unwrap_or(""),
        want["body"].as_str().unwrap_or(""),
        "{name} body"
    );
    let e = a.exec.as_ref();
    assert_eq!(
        e.map(|e| e.argv.clone()).unwrap_or_default(),
        str_list(want.get("argv")),
        "{name} argv"
    );
    assert_eq!(
        e.map(|e| e.env.clone()).unwrap_or_default(),
        str_map(want.get("env")),
        "{name} env"
    );
    assert_eq!(
        a.display(),
        want["display"].as_str().unwrap(),
        "{name} display"
    );
    assert_eq!(a.secrets(), str_list(want.get("secrets")), "{name} secrets");
    assert_eq!(p.risk, want["risk"].as_str().unwrap(), "{name} risk");
    assert_eq!(
        p.secret_choices,
        str_list(want.get("choices")),
        "{name} choices"
    );
}

#[test]
fn render_cases() {
    let g = golden();
    let cases = g["render"].as_array().unwrap();
    for c in cases {
        let p: Profile = serde_json::from_value(c["profile"].clone()).unwrap();
        let params = str_map(c.get("params"));
        check(c["name"].as_str().unwrap(), &p, &params, &c["want"]);
    }
    assert_eq!(cases.len(), 37);
}

#[test]
fn resolve_cases() {
    let g = golden();
    let cases = g["resolve"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let p: Profile = serde_json::from_value(c["profile"].clone()).unwrap();
        let conns: BTreeMap<String, Connection> =
            serde_json::from_value(c["connections"].clone()).unwrap();
        let params = str_map(c.get("params"));
        match resolve(&p, &conns) {
            Ok(r) => check(name, &r, &params, &c["want"]),
            Err(e) => {
                assert!(!c["want"]["ok"].as_bool().unwrap(), "{name}: {e}");
                assert_eq!(
                    e.to_string(),
                    c["want"]["error"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
    assert_eq!(cases.len(), 7);
}

#[test]
fn call_cases() {
    let g = golden();
    let cases = g["calls"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let call: Call = serde_json::from_value(c["call"].clone()).unwrap();
        let meta: BTreeMap<String, SecretMeta> = serde_json::from_value(c["meta"].clone()).unwrap();
        match from_call(&call, &meta) {
            Ok(p) => check(name, &p, &BTreeMap::new(), &c["want"]),
            Err(e) => {
                assert!(!c["want"]["ok"].as_bool().unwrap(), "{name}: {e}");
                assert_eq!(
                    e.to_string(),
                    c["want"]["error"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
    assert_eq!(cases.len(), 22);
}

#[test]
fn connection_cases() {
    let g = golden();
    let cases = g["connections"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let conn: Connection = serde_json::from_value(c["conn"].clone()).unwrap();
        match (conn.validate(), c.get("error")) {
            (Ok(()), None) => {}
            (Err(e), Some(w)) => assert_eq!(e.to_string(), w.as_str().unwrap(), "{name}"),
            (r, w) => panic!("{name}: got {r:?}, want {w:?}"),
        }
    }
    assert_eq!(cases.len(), 11);
}

#[test]
fn secret_meta_cases() {
    let g = golden();
    let cases = g["secret_meta"].as_array().unwrap();
    for c in cases {
        let m: SecretMeta = serde_json::from_value(c["meta"].clone()).unwrap();
        match (m.validate(), c.get("error")) {
            (Ok(()), None) => {}
            (Err(e), Some(w)) => assert_eq!(e.to_string(), w.as_str().unwrap()),
            (r, w) => panic!("got {r:?}, want {w:?}"),
        }
    }
    assert_eq!(cases.len(), 6);
}

#[test]
fn redact_cases() {
    let g = golden();
    let cases = g["redact"].as_array().unwrap();
    for c in cases {
        let secrets: Vec<String> = str_list(c.get("secrets"));
        let got = redact(c["input"].as_str().unwrap(), &secrets);
        assert_eq!(got, c["want"].as_str().unwrap(), "{}", c["input"]);
    }
    assert_eq!(cases.len(), 4);
}

#[test]
fn expand_replaces_only_secrets() {
    let got = expand("a {{x}} {{ secret:db.pw }}", &|n| format!("<{n}>"));
    assert_eq!(got, "a {{x}} <db.pw>");
}

#[test]
fn public_field_cannot_choose_the_host() {
    use std::collections::BTreeMap;
    use ucanrun::policy::{Call, FieldMeta, HttpSpec, SecretMeta, from_call};
    let mut meta = BTreeMap::new();
    meta.insert(
        "gh".to_string(),
        SecretMeta {
            hosts: vec!["api.github.com".into()],
            ..Default::default()
        },
    );
    meta.insert(
        "db".to_string(),
        SecretMeta {
            fields: vec![FieldMeta {
                name: "host".into(),
                public: true,
            }],
            ..Default::default()
        },
    );
    let mut h = BTreeMap::new();
    h.insert(
        "Authorization".to_string(),
        "Bearer {{secret:gh}}".to_string(),
    );
    for url in [
        "https://{{secret:db.host}}/x",
        "https://api.github.com{{secret:db.host}}/x",
        "https://{{secret:db.host}}.api.github.com/x",
    ] {
        let call = Call {
            http: Some(HttpSpec {
                method: "GET".into(),
                url: url.into(),
                headers: h.clone(),
                body: String::new(),
            }),
            exec: None,
            runner: String::new(),
        };
        assert!(from_call(&call, &meta).is_err(), "{url} accepted");
    }
}
