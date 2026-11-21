//! The Cloudflare Workers entry point: the only module that touches the
//! runtime. Everything it calls is plain Rust over [`Platform`].

use crate::config::Config;
use crate::platform::{HttpRequest, HttpResponse, Platform};
use crate::router::{self, Req};
use crate::tracing::SpanHandle;
use crate::webhook::run_job;
use js_sys::futures::JsFuture;
use js_sys::{Function, Reflect, JSON};
use serde_json::{Map, Value};
use std::future::Future;
use wasm_bindgen::{JsCast, JsValue};
use worker::observability::enter_span_async;
use worker::{event, Context, Env, Fetch, Headers, Method, RequestInit, Response, Result};

/// The Workers runtime behind [`Platform`].
#[derive(Clone)]
struct WorkerPlatform {
    env: Env,
}

impl WorkerPlatform {
    fn ai_binding(&self) -> Option<JsValue> {
        Reflect::get(&self.env, &JsValue::from_str("AI"))
            .ok()
            .filter(|v| !v.is_undefined() && !v.is_null())
    }
}

fn js_err(e: JsValue) -> String {
    e.as_string()
        .or_else(|| {
            Reflect::get(&e, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| "javascript exception".to_owned())
}

impl Platform for WorkerPlatform {
    async fn fetch(&self, req: HttpRequest) -> std::result::Result<HttpResponse, String> {
        let headers = Headers::new();
        for (k, v) in &req.headers {
            headers.set(k, v).map_err(|e| e.to_string())?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::from(req.method.clone()))
            .with_headers(headers);
        if let Some(body) = &req.body {
            init.with_body(Some(JsValue::from_str(body)));
        }
        let request = worker::Request::new_with_init(&req.url, &init).map_err(|e| e.to_string())?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status_code();
        let body = response.text().await.map_err(|e| e.to_string())?;
        Ok(HttpResponse { status, body })
    }

    async fn ai_run(
        &self,
        model: &str,
        input: &Value,
        options: Option<&Value>,
    ) -> std::result::Result<Value, String> {
        let ai = self.ai_binding().ok_or("no AI binding")?;
        let run: Function = Reflect::get(&ai, &JsValue::from_str("run"))
            .map_err(js_err)?
            .dyn_into()
            .map_err(|_| "AI.run is not a function".to_owned())?;
        let input = JSON::parse(&input.to_string()).map_err(js_err)?;
        let options = match options {
            Some(o) => JSON::parse(&o.to_string()).map_err(js_err)?,
            None => JsValue::UNDEFINED,
        };
        // The gateway options are the THIRD argument of AI.run, not part of
        // the input: see review::gateway_options.
        let promise = run
            .call3(&ai, &JsValue::from_str(model), &input, &options)
            .map_err(js_err)?;
        let out = JsFuture::from(js_sys::Promise::from(promise))
            .await
            .map_err(js_err)?;
        let json = JSON::stringify(&out)
            .map_err(js_err)?
            .as_string()
            .ok_or("AI returned a non-serialisable value")?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }

    fn has_ai(&self) -> bool {
        self.ai_binding().is_some()
    }

    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }

    async fn in_span<T, F, Fut>(&self, name: &str, attrs: Map<String, Value>, f: F) -> T
    where
        F: FnOnce(SpanHandle) -> Fut,
        Fut: Future<Output = T>,
    {
        enter_span_async(name, |span| {
            let set = |span: &worker::observability::Span, k: &str, v: &Value| match v {
                Value::Bool(b) => {
                    span.set_attribute(k, *b);
                }
                Value::Number(n) => {
                    span.set_attribute(k, n.as_f64().unwrap_or(0.0));
                }
                Value::String(s) => {
                    span.set_attribute(k, s.as_str());
                }
                _ => {}
            };
            for (k, v) in &attrs {
                set(&span, k, v);
            }
            let handle_span = span.clone();
            f(SpanHandle::new(move |k, v| set(&handle_span, k, v)))
        })
        .await
    }
}

/// A binding as a string, whether it is a `[vars]` entry or a Worker secret.
fn binding(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .map(|v| v.to_string())
        .or_else(|_| env.secret(name).map(|s| s.to_string()))
        .ok()
}

fn config_from(env: &Env) -> Config {
    let b = |n: &str| binding(env, n);
    Config {
        github_app_private_key: b("GITHUB_APP_PRIVATE_KEY"),
        github_app_id: b("GITHUB_APP_ID"),
        github_api: b("GITHUB_API"),
        github_allowed_repos: b("GITHUB_ALLOWED_REPOS"),
        github_token_permissions: b("GITHUB_TOKEN_PERMISSIONS"),
        github_webhook_secret: b("GITHUB_WEBHOOK_SECRET"),
        workos_jwks_url: b("WORKOS_JWKS_URL"),
        workos_issuer: b("WORKOS_ISSUER"),
        workos_audience: b("WORKOS_AUDIENCE"),
        workos_authorization_server: b("WORKOS_AUTHORIZATION_SERVER"),
        workos_org_id: b("WORKOS_ORG_ID"),
        workos_required_roles: b("WORKOS_REQUIRED_ROLES"),
        workos_required_permissions: b("WORKOS_REQUIRED_PERMISSIONS"),
        mcp_resource_url: b("MCP_RESOURCE_URL"),
        mcp_resource_hosts: b("MCP_RESOURCE_HOSTS"),
        review_model: b("REVIEW_MODEL"),
        review_max_diff_bytes: b("REVIEW_MAX_DIFF_BYTES"),
        review_mention: b("REVIEW_MENTION"),
        review_trigger_associations: b("REVIEW_TRIGGER_ASSOCIATIONS"),
        ai_gateway_id: b("AI_GATEWAY_ID"),
        review_enabled: b("REVIEW_ENABLED"),
    }
}

#[event(fetch)]
async fn fetch(mut request: worker::Request, env: Env, ctx: Context) -> Result<Response> {
    let method = request.method().to_string();
    let url = request.url()?.to_string();
    let headers: Vec<(String, String)> = request
        .headers()
        .entries()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    // The body is read once, as text: the webhook signature is over exactly
    // these bytes, so nothing may re-serialise them.
    let body = if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE") {
        String::new()
    } else {
        request.text().await.unwrap_or_default()
    };

    let platform = WorkerPlatform { env: env.clone() };
    let cfg = config_from(&env);
    let outcome = router::handle(
        &platform,
        &cfg,
        Req {
            method,
            url,
            headers,
            body,
        },
    )
    .await;

    if let Some(job) = outcome.job {
        // Answer GitHub now; the review runs after (it takes far longer than
        // the ten seconds a webhook is allowed).
        ctx.wait_until(async move {
            run_job(&platform, &cfg, &job).await;
        });
    }

    let resp = outcome.resp;
    let mut out = if resp.body.is_empty() {
        Response::empty()?
    } else {
        Response::ok(resp.body)?
    }
    .with_status(resp.status);
    for (k, v) in &resp.headers {
        out.headers_mut().set(k, v)?;
    }
    Ok(out)
}
