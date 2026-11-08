//! Stdio MCP server for agents. There is deliberately no tool that returns a
//! secret value.

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::client::Client;

/// Sent once at initialize, so the agent knows when to reach for ucanrun
/// before it asks the user for a token.
pub const INSTRUCTIONS: &str = "\
ucanrun holds the user's secrets (API tokens, passwords, database logins) and \
uses them for you after a human approves. You never see secret values.

- When a task needs a token, password or login, call list_secrets first. Do not \
ask the user for secret values and do not search files or the environment for them.
- Use call for HTTP APIs: write {{secret:NAME}} or {{secret:NAME.FIELD}} in a \
header. Use run_command only for secrets that allow commands. If list_profiles \
has a fixed action that fits, prefer run.
- Every request waits for the human to approve it on Telegram. Write a short, \
specific reason: it is what they decide on.
- If a request is denied or expires, tell the user and stop. Do not resend it \
in a loop or reword it to get past a denial.
- If no secret fits, say which secret and hosts are missing so the user can add \
them in ucanrun. Output has secrets replaced by [REDACTED]; that is expected.";

fn tools() -> Value {
    let map = json!({"type": "object", "additionalProperties": {"type": "string"}});
    json!([
        {"name": "list_secrets", "description": "List the secrets you may use: name, what it is for, the hosts it may be sent to, and for secrets with fields, the field names (public fields include their value). Secret values are never shown.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "call", "description": "Make an HTTP request that needs a secret. Put {{secret:NAME}} or {{secret:NAME.FIELD}} in a header value, for example Authorization: Bearer {{secret:github_token}}. The URL host must be one the secret allows. Private secrets are not allowed in the URL or body; public fields are. A human approves the exact request on Telegram, then ucanrun sends it and returns the response with secrets redacted. Waits up to 110 s.",
         "inputSchema": {"type": "object", "required": ["method", "url"], "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
            "url": {"type": "string"}, "headers": map, "body": {"type": "string"},
            "reason": {"type": "string", "description": "Short reason shown to the approver."}}}},
        {"name": "run_command", "description": "Run a program with secrets, only for secrets that allow commands and only when the server enables it. argv[0] is an absolute path; there is no shell. Put private {{secret:NAME}} or {{secret:NAME.FIELD}} values in env, stdin or files, never in argv; public fields may go in argv. Needs human approval, usually with TOTP.",
         "inputSchema": {"type": "object", "required": ["argv"], "properties": {
            "argv": {"type": "array", "items": {"type": "string"}}, "env": map, "stdin": {"type": "string"}, "files": map,
            "reason": {"type": "string"}}}},
        {"name": "list_profiles", "description": "List the fixed actions you may request, with their parameters.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "run", "description": "Request a fixed action. A human usually approves on Telegram. Waits up to 110 s, then returns state=pending and an id for get_request.",
         "inputSchema": {"type": "object", "required": ["profile"], "properties": {
            "profile": {"type": "string"}, "params": map, "reason": {"type": "string", "description": "Short reason shown to the approver."}}}},
        {"name": "get_request", "description": "Get the state and result of a request.",
         "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}}
    ])
}

fn text(v: &Value, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(v).unwrap_or_default()}], "isError": is_error})
}

async fn call(c: &Client, p: &Value) -> Value {
    let a = p.get("arguments").cloned().unwrap_or(json!({}));
    let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let res = match p.get("name").and_then(Value::as_str).unwrap_or("") {
        "list_secrets" => c.secrets().await,
        "list_profiles" => c.profiles().await,
        "call" => {
            let http = json!({"method": s("method"), "url": s("url"), "headers": a.get("headers").cloned().unwrap_or(json!({})), "body": s("body")});
            c.call(json!({"http": http}), &s("reason"), 110).await
        }
        "run_command" => {
            let exec = json!({"argv": a.get("argv").cloned().unwrap_or(json!([])), "env": a.get("env").cloned().unwrap_or(json!({})),
                              "stdin": s("stdin"), "files": a.get("files").cloned().unwrap_or(json!({}))});
            c.call(json!({"exec": exec}), &s("reason"), 110).await
        }
        "run" => {
            c.run(
                &s("profile"),
                a.get("params").cloned().unwrap_or(json!({})),
                &s("reason"),
                110,
            )
            .await
        }
        "get_request" => c.request(&s("id")).await,
        other => Err(format!("unknown tool \"{other}\"")),
    };
    match res {
        Ok(v) => text(&v, false),
        Err(e) => text(&json!({"error": e}), true),
    }
}

/// Speaks newline-delimited JSON-RPC 2.0 until stdin closes.
pub async fn serve(mut c: Client) -> std::io::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let m: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let e = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}});
                out.write_all(format!("{e}\n").as_bytes()).await?;
                continue;
            }
        };
        let Some(id) = m.get("id").cloned() else {
            continue;
        }; // a notification
        let params = m.get("params").cloned().unwrap_or(json!({}));
        let resp = match m.get("method").and_then(Value::as_str).unwrap_or("") {
            "initialize" => {
                if let Some(ci) = params.get("clientInfo") {
                    let name = ci.get("name").and_then(Value::as_str).unwrap_or("");
                    let ver = ci.get("version").and_then(Value::as_str).unwrap_or("");
                    if !name.is_empty() {
                        c.app = format!("{name} {ver}").trim().to_string();
                    }
                }
                let v = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-06-18");
                json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": v, "capabilities": {"tools": {}},
                       "serverInfo": {"name": "ucanrun", "version": env!("CARGO_PKG_VERSION")},
                       "instructions": INSTRUCTIONS}})
            }
            "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
            "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools()}}),
            "tools/call" => json!({"jsonrpc": "2.0", "id": id, "result": call(&c, &params).await}),
            _ => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
            }
        };
        out.write_all(format!("{resp}\n").as_bytes()).await?;
        out.flush().await?;
    }
    Ok(())
}
