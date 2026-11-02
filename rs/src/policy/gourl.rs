//! Small helpers that reproduce Go's `net/url` and `strconv` behaviour where the
//! policy rules depend on it.

/// Go's `url.PathEscape`.
pub fn path_escape(s: &str) -> String {
    escape(s, false)
}

/// Go's `url.QueryEscape`.
pub fn query_escape(s: &str) -> String {
    escape(s, true)
}

fn escape(s: &str, query: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (!query && matches!(b, b'$' | b'&' | b'+' | b'=' | b':' | b'@'));
        if keep {
            out.push(b as char);
        } else if query && b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The parts of Go's `url.URL` that the rules look at.
#[derive(Debug)]
pub struct GoUrl {
    pub scheme: String,
    pub host: String,
    pub has_user: bool,
    pub query: String,
    pub fragment: String,
}

impl GoUrl {
    pub fn hostname(&self) -> String {
        let (h, _) = split_host_port(&self.host);
        h.to_string()
    }

    pub fn port(&self) -> String {
        let (_, p) = split_host_port(&self.host);
        p.to_string()
    }
}

fn split_host_port(host: &str) -> (&str, &str) {
    let (mut h, mut port) = (host, "");
    if let Some(i) = host.rfind(':')
        && host[i + 1..].bytes().all(|c| c.is_ascii_digit())
    {
        h = &host[..i];
        port = &host[i + 1..];
    }
    let h = h.strip_prefix('[').unwrap_or(h);
    (h.strip_suffix(']').unwrap_or(h), port)
}

fn good_percent(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return false;
            }
            if !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

fn valid_host(host: &str) -> bool {
    if host.starts_with('[') {
        return host.contains(']');
    }
    if let Some(i) = host.rfind(':') {
        let p = &host[i + 1..];
        if !p.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    if !good_percent(host) {
        return false;
    }
    host.bytes().all(|b| {
        b >= 0x80
            || b == b'%'
            || b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'['
                    | b']'
                    | b'<'
                    | b'>'
                    | b'"'
            )
    })
}

/// Parses like Go's `url.Parse`; `None` where Go returns an error.
pub fn parse(raw: &str) -> Option<GoUrl> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let (rest, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let mut scheme = String::new();
    let mut rest = rest;
    for (i, c) in rest.char_indices() {
        if c.is_ascii_alphabetic() {
            continue;
        }
        if c.is_ascii_digit() || matches!(c, '+' | '-' | '.') {
            if i == 0 {
                break;
            }
            continue;
        }
        if c == ':' {
            if i == 0 {
                return None;
            }
            scheme = rest[..i].to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
        break;
    }
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut host = "";
    let mut has_user = false;
    if rest.starts_with("//") && (!scheme.is_empty() || !rest.starts_with("///")) {
        let auth_and_path = &rest[2..];
        let end = auth_and_path.find('/').unwrap_or(auth_and_path.len());
        let (auth, path) = auth_and_path.split_at(end);
        host = auth;
        if let Some(i) = auth.rfind('@') {
            has_user = true;
            host = &auth[i + 1..];
        }
        if !valid_host(host) || !good_percent(path) {
            return None;
        }
    } else if !good_percent(rest) {
        return None;
    }
    Some(GoUrl {
        scheme,
        host: host.to_string(),
        has_user,
        query: query.to_string(),
        fragment: fragment.to_string(),
    })
}

fn is_cf(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x8E2 | 0x180E | 0x200B..=0x200F
        | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0001 | 0xE0020..=0xE007F)
}

/// Go's `unicode.IsControl(r) || unicode.Is(unicode.Cf, r)`.
pub fn is_control_or_format(c: char) -> bool {
    c.is_control() || is_cf(c)
}

fn is_print(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    let u = c as u32;
    !(is_control_or_format(c)
        || c.is_whitespace()
        || (0xE000..=0xF8FF).contains(&u)
        || u >= 0xF0000)
}

/// Go's `%q` for a string.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if is_print(c) => out.push(c),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// The inside of Go's `json.Marshal` of a string (HTML-safe escaping).
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}
