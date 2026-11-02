//! Templates for the profile builder: the embedded catalog plus extra files
//! from a directory, each entry checked the way a save would check it.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Static, log_warn};
use crate::policy::{self, Connection, Profile};

const MAX_FILE: u64 = 1 << 20;

/// One action of a catalog entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CatalogAction {
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title_en: String,
    pub profile: Profile,
}

/// One service (a connection and its actions) or a group of standalone
/// actions such as command profiles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CatalogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Connection>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title_en: String,
    pub hint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hint_en: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub custom: bool,
    pub actions: Vec<CatalogAction>,
}

/// Checks every action the way a save would, so a template can never produce
/// a profile the server refuses.
pub fn valid_entry(e: &CatalogEntry) -> Result<(), String> {
    let mut conns = BTreeMap::new();
    if let Some(s) = &e.service {
        s.validate().map_err(|e| e.to_string())?;
        conns.insert(s.name.clone(), s.clone());
    }
    if e.actions.is_empty() {
        return Err("no actions".into());
    }
    for a in &e.actions {
        let mut p = a.profile.clone();
        if let Some(s) = &e.service {
            p.connection = s.name.clone();
        } else if !p.connection.is_empty() {
            return Err("standalone action names a connection".into());
        }
        p.validate().map_err(|err| format!("{}: {err}", p.name))?;
        policy::resolve(&p, &conns)
            .and_then(|r| r.validate())
            .map_err(|err| format!("{}: {err}", p.name))?;
    }
    Ok(())
}

/// The embedded catalog followed by the valid, non-duplicate entries of every
/// regular `*.json` file in `dir`, in file name order.
pub fn read_catalog(dir: Option<&Path>) -> Vec<CatalogEntry> {
    let raw = Static::get("catalog.json")
        .map(|f| f.data)
        .unwrap_or_default();
    let mut out: Vec<CatalogEntry> = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR embedded catalog err={e}");
            return vec![];
        }
    };
    let mut seen_conn = HashSet::new();
    let mut seen_profile = HashSet::new();
    let mark = |e: &CatalogEntry, conn: &mut HashSet<String>, prof: &mut HashSet<String>| {
        if let Some(s) = &e.service {
            conn.insert(s.name.clone());
        }
        for a in &e.actions {
            prof.insert(a.profile.name.clone());
        }
    };
    for e in &out {
        mark(e, &mut seen_conn, &mut seen_profile);
    }
    let Some(dir) = dir else { return out };
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                log_warn(
                    "reading catalog dir",
                    &[
                        ("dir", &dir.display().to_string()),
                        ("reason", &e.to_string()),
                    ],
                );
            }
            return out;
        }
    };
    let mut files: Vec<_> = rd.filter_map(Result::ok).collect();
    files.sort_by_key(|d| d.file_name());
    for d in files {
        let name = d.file_name().to_string_lossy().into_owned();
        // file_type does not follow symlinks.
        let Ok(ft) = d.file_type() else { continue };
        if !name.ends_with(".json") || !ft.is_file() {
            continue;
        }
        match d.metadata() {
            Ok(m) if m.is_file() && m.len() <= MAX_FILE => {}
            _ => continue,
        }
        let b = match std::fs::read(d.path()) {
            Ok(b) if b.len() as u64 <= MAX_FILE => b,
            _ => continue,
        };
        let extra: Vec<CatalogEntry> = match serde_json::from_slice(&b) {
            Ok(v) => v,
            Err(e) => {
                log_warn(
                    "skipping catalog file",
                    &[("file", &name), ("reason", &e.to_string())],
                );
                continue;
            }
        };
        'next: for e in extra {
            if let Err(why) = valid_entry(&e) {
                log_warn(
                    "skipping catalog entry",
                    &[("file", &name), ("reason", &why)],
                );
                continue;
            }
            if let Some(s) = &e.service
                && seen_conn.contains(&s.name)
            {
                let why = format!("duplicate service {}", s.name);
                log_warn(
                    "skipping catalog entry",
                    &[("file", &name), ("reason", &why)],
                );
                continue;
            }
            for a in &e.actions {
                if seen_profile.contains(&a.profile.name) {
                    let why = format!("duplicate profile {}", a.profile.name);
                    log_warn(
                        "skipping catalog entry",
                        &[("file", &name), ("reason", &why)],
                    );
                    continue 'next;
                }
            }
            mark(&e, &mut seen_conn, &mut seen_profile);
            out.push(e);
        }
    }
    out
}
