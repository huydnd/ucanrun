//! JSON output byte-identical to Go's encoding/json, needed to verify and
//! extend audit hash chains written by the Go version.

use serde_json::Value;

pub fn to_string(v: &Value) -> String {
    let mut out = String::new();
    write(&mut out, v);
    out
}

fn write(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write(out, &m[*k]);
            }
            out.push('}');
        }
    }
}

/// Go escapes control characters, HTML-sensitive characters and the two
/// JavaScript line separators.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_go() {
        let v = json!({"z": 1, "a": "x<y>&z", "n": {"k": [1, "two", true]}, "u": "\u{2028} line", "c": "\u{1}"});
        assert_eq!(
            to_string(&v),
            r#"{"a":"x\u003cy\u003e\u0026z","c":"\u0001","n":{"k":[1,"two",true]},"u":"\u2028 line","z":1}"#
        );
    }
}
