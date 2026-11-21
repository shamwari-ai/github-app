//! Shamwari for GitHub: a Cloudflare Worker (`shamwari-github-mcp`) serving an
//! MCP server, an A2A endpoint and a GitHub webhook at github.shamwari.ai.
//!
//! Everything that decides behaviour is plain Rust over a small [`platform`]
//! abstraction (HTTP, Workers AI, clock), so it runs under `cargo test` on the
//! host. Only `worker_entry` (compiled for wasm32 alone) touches the Workers
//! runtime.

pub mod a2a;
pub mod auth;
pub mod config;
pub mod error;
pub mod github;
pub mod log;
pub mod mcp;
pub mod origin;
pub mod platform;
pub mod review;
pub mod router;
pub mod setup;
pub mod tracing;
pub mod util;
pub mod webhook;

#[cfg(target_arch = "wasm32")]
mod worker_entry;

#[cfg(test)]
mod tests;
