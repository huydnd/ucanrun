//! Runners: small agents on other machines that run approved commands. The
//! server signs each job and seals its secrets to the runner; the runner
//! checks the job against its own rules before anything starts.

pub mod local;
pub mod proto;
