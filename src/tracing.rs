//! Agent tracing: metadata only.
//!
//! The reviewer is a "custom harness" in Cloudflare's agent-tracing terms: one
//! `invoke_agent` span per review with a nested `chat` span for the model call,
//! each carrying the three identity attributes the Agents dashboard keys on.
//!
//! METADATA ONLY, by owner decision. No `gen_ai.input.messages`,
//! `gen_ai.output.messages` or `gen_ai.system_instructions` is ever set: the
//! prompt is a diff of private work and the response is model prose about it.
//! Repository and pull request number are already in every GitHub URL this
//! worker touches, and neither identifies a person.
//!
//! Spans are opened through [`Platform::in_span`](crate::platform::Platform::in_span):
//! on Workers it is `worker::observability::enter_span_async` (the
//! `cloudflare:workers` `tracing` export); everywhere else it is a no-op, so
//! the unit tests exercise the same code paths without a tracer.

use serde_json::{json, Map, Value};
use std::rc::Rc;

pub const AGENT_NAME: &str = "shamwari-github-mcp";
/// A single deployed reviewer, so the agent id is as stable as its name.
pub const AGENT_ID: &str = "shamwari-github-mcp/review";

/// The identity every agent span carries. `conversation` is opaque.
pub fn identity(operation: &str, conversation: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("gen_ai.operation.name".into(), json!(operation));
    m.insert("gen_ai.agent.name".into(), json!(AGENT_NAME));
    m.insert("gen_ai.agent.id".into(), json!(AGENT_ID));
    m.insert("gen_ai.conversation.id".into(), json!(conversation));
    m
}

/// A handle for attaching scalar attributes to the open span. Only scalars
/// are accepted: a payload never becomes an attribute.
type Setter = Rc<dyn Fn(&str, &Value)>;

#[derive(Clone)]
pub struct SpanHandle(Option<Setter>);

impl SpanHandle {
    /// A span that records nothing.
    pub fn noop() -> Self {
        SpanHandle(None)
    }

    pub fn new(f: impl Fn(&str, &Value) + 'static) -> Self {
        SpanHandle(Some(Rc::new(f)))
    }

    /// Set one attribute. Arrays, objects and nulls are dropped.
    pub fn set(&self, key: &str, value: Value) {
        if let Some(f) = &self.0 {
            if matches!(value, Value::Bool(_) | Value::Number(_) | Value::String(_)) {
                f(key, &value);
            }
        }
    }

    pub fn set_all(&self, attrs: &Map<String, Value>) {
        for (k, v) in attrs {
            self.set(k, v.clone());
        }
    }
}
