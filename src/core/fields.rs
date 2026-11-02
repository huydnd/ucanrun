//! Secrets with several named fields, stored in the vault as
//! `{"ucanrun_fields": {...}}`. Any other value is a single-value secret.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Core, Error, Result, Token};
use crate::policy::{self, CHOICE_REF, SecretMeta, gourl};
use crate::vault::{self, Vault};

pub(crate) const FIELDS_KEY: &str = "ucanrun_fields";

/// What an agent may know about a secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SecretInfo {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_commands: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldInfo>,
}

/// A field of a multi-field secret. Only public fields carry their value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FieldInfo {
    pub name: String,
    pub public: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

pub(crate) type Fields = BTreeMap<String, Zeroizing<String>>;

/// The fields of a stored value, or None for a single-value secret.
pub(crate) fn parse(v: &[u8]) -> Option<Fields> {
    let v: Value = serde_json::from_slice(v).ok()?;
    let Value::Object(top) = v else { return None };
    if top.len() != 1 {
        return None;
    }
    let Some(Value::Object(m)) = top.get(FIELDS_KEY) else {
        return None;
    };
    let mut out = Fields::new();
    for (k, v) in m {
        out.insert(k.clone(), Zeroizing::new(v.as_str()?.to_string()));
    }
    Some(out)
}

fn has_fields_err(s: &str) -> String {
    format!(
        "secret {} has fields, use {{{{secret:{s}.FIELD}}}}",
        gourl::quote(s)
    )
}

/// Refuses references that cannot resolve against the owner's field list: a
/// bare name of a multi-field secret, or a field it does not have.
pub(crate) fn check_refs(refs: &[String], meta: &BTreeMap<String, SecretMeta>) -> Result<()> {
    for r in refs {
        if r == CHOICE_REF {
            continue;
        }
        let (s, f) = policy::split_ref(r, &|n| meta.contains_key(n));
        let Some(m) = meta.get(s) else { continue };
        if m.fields.is_empty() {
            continue;
        }
        match f {
            None => return Err(Error::Msg(has_fields_err(s))),
            Some(f) if !m.fields.iter().any(|x| x.name == f) => {
                return Err(Error::Msg(format!(
                    "unknown field {} of secret {}",
                    gourl::quote(f),
                    gourl::quote(s)
                )));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Resolves a reference as written for the executor. The exact name wins,
/// then the last dot splits off a field. Internal `_` secrets never resolve.
pub(crate) fn resolve(v: &Vault, r: &str) -> std::result::Result<Vec<u8>, String> {
    if r.starts_with('_') {
        return Err("forbidden".into());
    }
    match v.get(r) {
        Ok(val) => {
            if parse(&val).is_some() {
                return Err(has_fields_err(r));
            }
            Ok(val.to_vec())
        }
        Err(vault::Error::NotFound) | Err(vault::Error::InvalidName) => {
            let (s, f) = r.rsplit_once('.').ok_or("secret not found")?;
            if s.starts_with('_') {
                return Err("forbidden".into());
            }
            let val = v.get(s).map_err(|e| e.to_string())?;
            let m = parse(&val).ok_or("secret not found")?;
            m.get(f)
                .map(|x| x.as_bytes().to_vec())
                .ok_or_else(|| "secret not found".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn is_public(meta: &BTreeMap<String, SecretMeta>, secret: &str, field: &str) -> bool {
    meta.get(secret)
        .is_some_and(|m| m.fields.iter().any(|f| f.name == field && f.public))
}

/// Every private field value of the multi-field secrets the references
/// touch, so the output hides fields the action did not name as well.
pub(crate) fn private_values(
    v: &Vault,
    refs: &[String],
    meta: &BTreeMap<String, SecretMeta>,
) -> Vec<Zeroizing<String>> {
    let mut names = BTreeSet::new();
    for r in refs {
        names.insert(r.as_str());
        if let Some((s, _)) = r.rsplit_once('.') {
            names.insert(s);
        }
    }
    let mut out = vec![];
    for n in names {
        if n.starts_with('_') || n == CHOICE_REF {
            continue;
        }
        let Some(m) = v.get(n).ok().and_then(|x| parse(&x)) else {
            continue;
        };
        for (k, val) in m {
            if !is_public(meta, n, &k) {
                out.push(val);
            }
        }
    }
    out
}

impl Core {
    /// Stores a single-value secret. A value shaped like a multi-field secret
    /// is refused, and any field list in the notes is cleared.
    pub fn put_secret(&self, name: &str, value: &[u8]) -> Result<()> {
        if name.starts_with('_') {
            return Err(Error::Vault(vault::Error::InvalidName));
        }
        if parse(value).is_some() {
            return Err(Error::Msg(format!(
                "a value with {FIELDS_KEY} is only stored through fields"
            )));
        }
        self.vault.put(name, value)?;
        self.log("secret_put", "web", json!({"name": name}));
        let mut g = self.inner();
        let Some(st) = g.st.as_mut() else {
            return Ok(());
        };
        if let Some(m) = st.secrets.get_mut(name)
            && !m.fields.is_empty()
        {
            m.fields.clear();
            return self.save_locked(&mut g);
        }
        Ok(())
    }

    /// Stores a multi-field secret and its notes. A field missing from
    /// `values`, or given empty, keeps its stored value.
    pub fn put_secret_fields(
        &self,
        name: &str,
        meta: SecretMeta,
        values: &BTreeMap<String, String>,
    ) -> Result<()> {
        if name.starts_with('_') || !vault::valid_name(name) {
            return Err(Error::Vault(vault::Error::InvalidName));
        }
        meta.validate()?;
        if meta.fields.is_empty() {
            return Err(Error::Msg(
                "a secret with fields needs at least one field".into(),
            ));
        }
        for k in values.keys() {
            if !meta.fields.iter().any(|f| &f.name == k) {
                return Err(Error::Msg(format!("unknown field {}", gourl::quote(k))));
            }
        }
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        let old = match self.vault.get(name) {
            Ok(v) => parse(&v).unwrap_or_default(),
            Err(vault::Error::NotFound) => Fields::new(),
            Err(e) => return Err(e.into()),
        };
        let mut m = serde_json::Map::new();
        for f in &meta.fields {
            let v = match values.get(&f.name).filter(|v| !v.is_empty()) {
                Some(v) => v.clone(),
                None => match old.get(&f.name) {
                    Some(v) => v.to_string(),
                    None => {
                        return Err(Error::Msg(format!(
                            "field {} needs a value",
                            gourl::quote(&f.name)
                        )));
                    }
                },
            };
            m.insert(f.name.clone(), Value::String(v));
        }
        let mut top = serde_json::Map::new();
        top.insert(FIELDS_KEY.into(), Value::Object(m));
        let raw = Zeroizing::new(serde_json::to_vec(&Value::Object(top)).unwrap_or_default());
        self.vault.put(name, &raw)?;
        let names: Vec<&str> = meta.fields.iter().map(|f| f.name.as_str()).collect();
        self.log("secret_put", "web", json!({"name": name, "fields": names}));
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.secrets.insert(name.to_string(), meta);
        self.save_locked(&mut g)
    }

    /// Values of the public fields of a secret, for the owner's screen.
    pub fn secret_public_values(&self, name: &str) -> Result<BTreeMap<String, String>> {
        let meta = {
            let g = self.inner();
            let st = g.st.as_ref().ok_or(Error::Locked)?;
            st.secrets.get(name).cloned().unwrap_or_default()
        };
        let v = self.vault.get(name)?;
        let mut out = BTreeMap::new();
        if let Some(m) = parse(&v) {
            for f in meta.fields.iter().filter(|f| f.public) {
                if let Some(x) = m.get(&f.name) {
                    out.insert(f.name.clone(), x.to_string());
                }
            }
        }
        Ok(out)
    }

    /// Removes a secret and its notes.
    pub fn delete_secret(&self, name: &str) -> Result<()> {
        if name.starts_with('_') {
            return Err(Error::Vault(vault::Error::InvalidName));
        }
        self.vault.delete(name)?;
        self.log("secret_delete", "web", json!({"name": name}));
        let _ = self.delete_secret_meta(name);
        Ok(())
    }

    /// Lists the secrets an agent can use in its own calls. A token limited
    /// to profiles sees none.
    pub fn secrets_for(&self, t: &Token) -> Result<Vec<SecretInfo>> {
        let meta = {
            let g = self.inner();
            let st = g.st.as_ref().ok_or(Error::Locked)?;
            st.secrets.clone()
        };
        let mut out = vec![];
        if !t.profiles.is_empty() {
            return Ok(out);
        }
        let exec = self.opt.allow_exec;
        for s in self.vault.list()? {
            let Some(m) = meta.get(&s.name) else { continue };
            if m.hosts.is_empty() && !(m.allow_commands && exec) {
                continue;
            }
            let mut fields = vec![];
            if !m.fields.is_empty() {
                let values = self.vault.get(&s.name).ok().and_then(|v| parse(&v));
                for f in &m.fields {
                    let value = if f.public {
                        values
                            .as_ref()
                            .and_then(|v| v.get(&f.name))
                            .map(|x| x.to_string())
                    } else {
                        None
                    };
                    fields.push(FieldInfo {
                        name: f.name.clone(),
                        public: f.public,
                        value,
                    });
                }
            }
            out.push(SecretInfo {
                name: s.name,
                description: m.description.clone(),
                hosts: m.hosts.clone(),
                allow_commands: m.allow_commands && exec,
                fields,
            });
        }
        Ok(out)
    }
}
