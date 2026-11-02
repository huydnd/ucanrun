use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ucanrun::vault::Vault;
use ucanrun::{audit, backup, state, totp};

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/golden")
}

fn expected() -> Value {
    serde_json::from_slice(&fs::read(golden().join("expected.json")).unwrap()).unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let t = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            fs::copy(e.path(), t).unwrap();
        }
    }
}

fn setup() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    copy_dir(&golden().join("datadir"), &data);
    (d, data)
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn unlocked(data: &Path) -> Vault {
    let ex = expected();
    let v = Vault::new(data.join("vault"));
    v.unlock(ex["passphrase"].as_str().unwrap().as_bytes())
        .unwrap();
    v
}

#[test]
fn vault_secrets_and_mac_key() {
    let (_d, data) = setup();
    let ex = expected();
    let v = Vault::new(data.join("vault"));
    assert!(v.initialized() && v.is_locked());
    v.unlock(ex["passphrase"].as_str().unwrap().as_bytes())
        .unwrap();
    for (name, val) in ex["secrets"].as_object().unwrap() {
        assert_eq!(
            &**v.get(name).unwrap(),
            val.as_str().unwrap().as_bytes(),
            "{name}"
        );
    }
    assert_eq!(
        &**v.get("_totp_secret").unwrap(),
        ex["totp_secret"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        hex::encode(v.mac_key().unwrap()),
        ex["mac_key_hex"].as_str().unwrap()
    );
    let names: Vec<_> = v.list().unwrap().into_iter().map(|m| m.name).collect();
    assert_eq!(names, ["github_token", "multi", "unicode"]);
}

#[test]
fn wrong_passphrase_rejected() {
    let (_d, data) = setup();
    let v = Vault::new(data.join("vault"));
    let e = v.unlock(b"nope").unwrap_err();
    assert_eq!(e.to_string(), "wrong passphrase");
    assert!(v.is_locked());
}

#[test]
fn state_loads_and_rejects_tamper() {
    let (_d, data) = setup();
    let ex = expected();
    let v = unlocked(&data);
    let key = v.mac_key().unwrap();
    let st = state::load(&data.join("state.json"), &key).unwrap();
    assert_eq!(st.version, 1);
    assert!(st.profiles.contains_key("github-whoami"));
    assert!(st.connections.contains_key("github"));
    let tok = ex["token"].as_str().unwrap();
    assert!(st.tokens.values().any(|t| t.hash == sha(tok)));
    let want: Vec<String> = ex["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            sha(&format!(
                "ucanrun recovery v1:{}",
                c.as_str().unwrap().replace('-', "")
            ))
        })
        .collect();
    assert_eq!(st.recovery_hashes, want);
    assert_eq!(st.audit_count as u64, ex["audit_entries"].as_u64().unwrap());
    assert!(st.totp_enabled);

    // saving and reloading keeps everything
    let p2 = data.join("state2.json");
    state::save(&p2, &st, &key).unwrap();
    assert_eq!(state::load(&p2, &key).unwrap(), st);

    let p = data.join("state.json");
    let raw = fs::read_to_string(&p).unwrap();
    fs::write(&p, raw.replace("github-whoami", "github-whoamX")).unwrap();
    assert!(matches!(state::load(&p, &key), Err(state::Error::Tampered)));
    assert!(matches!(
        state::load(&data.join("missing.json"), &key),
        Err(state::Error::Tampered)
    ));
}

#[test]
fn audit_chain_continues_from_go() {
    let (_d, data) = setup();
    let ex = expected();
    let p = data.join("audit.jsonl");
    let n = ex["audit_entries"].as_u64().unwrap() as usize;
    assert_eq!(audit::verify(&p).unwrap(), n);
    let log = audit::Log::open(&p).unwrap();
    let (cnt, h) = log.head();
    assert_eq!(cnt, n);
    assert!(audit::contains(&p, cnt, &h).unwrap());
    let mut f = Map::new();
    f.insert("note".into(), json!("a<b>&c \u{2028} é"));
    f.insert("n".into(), json!(7));
    log.append("rust_test", "rust", f).unwrap();
    log.append("rust_test2", "", Map::new()).unwrap();
    assert_eq!(audit::verify(&p).unwrap(), n + 2);
    assert_eq!(log.tail(1).unwrap()[0].event, "rust_test2");
    // tamper a Go-written entry
    let raw = fs::read_to_string(&p).unwrap();
    fs::write(
        &p,
        raw.replacen("\"event\":\"setup\"", "\"event\":\"setuq\"", 1),
    )
    .unwrap();
    assert!(matches!(
        audit::verify(&p),
        Err(audit::Error::ChainBroken(1))
    ));
}

#[test]
fn totp_vectors() {
    let v: Value = serde_json::from_slice(&fs::read(golden().join("totp.json")).unwrap()).unwrap();
    for c in v.as_array().unwrap() {
        let (s, unix) = (c["secret"].as_str().unwrap(), c["unix"].as_i64().unwrap());
        let code = c["code"].as_str().unwrap();
        assert_eq!(totp::code(s, unix).unwrap(), code);
        assert_eq!(totp::verify(s, code, unix, 0), (unix / 30) as u64);
    }
}

#[test]
fn backup_round_trip_golden() {
    let (d, data) = setup();
    let mut buf = Vec::new();
    backup::create(&mut buf, &data).unwrap();
    assert!(backup::check(buf.as_slice()).unwrap() >= 6);
    let dst = d.path().join("restored");
    backup::restore(buf.as_slice(), &dst).unwrap();
    for rel in [
        "state.json",
        "audit.jsonl",
        "vault/identity.age",
        "vault/secrets/multi.age",
    ] {
        assert_eq!(
            fs::read(data.join(rel)).unwrap(),
            fs::read(dst.join(rel)).unwrap(),
            "{rel}"
        );
    }
    // the restored copy still unlocks and verifies
    let v = unlocked(&dst);
    state::load(&dst.join("state.json"), &v.mac_key().unwrap()).unwrap();
    assert_eq!(audit::verify(&dst.join("audit.jsonl")).unwrap(), 8);
}

#[test]
fn backup_rejects_traversal_and_symlinks() {
    let (d, data) = setup();
    let mut buf = Vec::new();
    backup::create(&mut buf, &data).unwrap();
    // tamper by building archives with hostile entries appended to valid files
    for (name, ty, link) in [
        ("../escape", tar::EntryType::Regular, ""),
        ("link", tar::EntryType::Symlink, "/etc/passwd"),
        ("hard", tar::EntryType::Link, "state.json"),
    ] {
        let mut tw = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for rel in ["state.json", "vault/identity.age", "vault/recipient.txt"] {
            let b = fs::read(data.join(rel)).unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(b.len() as u64);
            h.set_mode(0o600);
            tw.append_data(&mut h, rel, b.as_slice()).unwrap();
        }
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(ty);
        h.set_size(0);
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        if !link.is_empty() {
            h.set_link_name(link).unwrap();
        }
        h.set_cksum();
        tw.append(&h, std::io::empty()).unwrap();
        let a = tw.into_inner().unwrap().finish().unwrap();
        assert!(backup::check(a.as_slice()).is_err(), "{name}");
        let dst = d
            .path()
            .join(format!("r-{}", name.replace(['/', '.'], "_")));
        assert!(backup::restore(a.as_slice(), &dst).is_err());
        assert!(!dst.exists());
    }
    assert!(!d.path().join("escape").exists());
}
