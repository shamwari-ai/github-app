//! The three kinds of failure the Worker distinguishes, and what a caller may
//! be told about each.

use serde_json::Value;
use std::fmt;

/// An error written for the caller: it names the repository, permission or
/// status, and is the only kind of error whose message crosses the wire.
#[derive(Debug, Clone)]
pub struct GitHubError {
    pub message: String,
    pub status: u16,
    pub detail: Value,
}

impl GitHubError {
    pub fn new(message: impl Into<String>, status: u16) -> Self {
        Self {
            message: message.into(),
            status,
            detail: Value::Null,
        }
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

impl fmt::Display for GitHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GitHubError {}

/// Why a tool call or review failed.
#[derive(Debug, Clone)]
pub enum Failure {
    /// The caller sent arguments the tool cannot use; the message names the
    /// field, so it is returned to the caller.
    Argument(String),
    /// A GitHub or configuration problem written for the caller.
    GitHub(GitHubError),
    /// Anything else. Logged in full, answered generically.
    Internal(String),
}

impl From<GitHubError> for Failure {
    fn from(e: GitHubError) -> Self {
        Failure::GitHub(e)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Argument(m) | Failure::Internal(m) => f.write_str(m),
            Failure::GitHub(e) => f.write_str(&e.message),
        }
    }
}

impl std::error::Error for Failure {}
