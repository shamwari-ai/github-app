//! What the Worker needs from its runtime, as one trait.
//!
//! Production implements it with the Workers `fetch`, the `AI` binding and
//! `Date.now()`; tests implement it with scripted responses. Nothing outside
//! `worker_entry` touches the runtime directly.

use crate::tracing::SpanHandle;
use serde_json::{Map, Value};
use std::future::Future;

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[allow(async_fn_in_trait)]
pub trait Platform {
    /// An outbound HTTPS request. `Err` is a network-level failure.
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, String>;

    /// Run a Workers AI model. `options` is the AI Gateway options object,
    /// passed as the THIRD argument of `AI.run` (see `review::gateway_options`).
    async fn ai_run(
        &self,
        model: &str,
        input: &Value,
        options: Option<&Value>,
    ) -> Result<Value, String>;

    /// Whether the `AI` binding exists at all.
    fn has_ai(&self) -> bool;

    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;

    /// Run `f` inside a tracing span named `name` carrying `attrs`, ended when
    /// the future completes. The default records nothing.
    async fn in_span<T, F, Fut>(&self, name: &str, attrs: Map<String, Value>, f: F) -> T
    where
        F: FnOnce(SpanHandle) -> Fut,
        Fut: Future<Output = T>,
    {
        let _ = (name, attrs);
        f(SpanHandle::noop()).await
    }
}
