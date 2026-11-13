//! ucanrun: agents ask, a person approves, ucanrun runs the action without
//! showing the secret. Data on disk is compatible with the Go version.

//!
//! The server side (vault, approvals, web) runs on Unix. The agent side
//! (`client`, `mcp`, `tokenstore`) also builds for Windows as `ucr.exe`.

#[cfg(unix)]
pub mod audit;
#[cfg(unix)]
pub mod backup;
#[cfg(unix)]
pub mod chat;
pub mod client;
#[cfg(unix)]
pub mod core;
pub mod gojson;
pub mod mcp;
pub mod policy;
pub mod prompt;
pub mod runner;
#[cfg(unix)]
pub mod state;
#[cfg(unix)]
pub mod telegram;
pub mod tokenstore;
#[cfg(unix)]
pub mod totp;
#[cfg(unix)]
pub mod vault;
#[cfg(unix)]
pub mod web;
#[cfg(unix)]
pub mod webauthn;
