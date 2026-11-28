//! The Rust port of the TypeScript test suite (`test/*.test.ts`), one file per
//! original, plus the shared fixtures. The mapping from each old test to its
//! new one is in docs/rust-port.md.

use crate::config::Config;
use crate::platform::{HttpRequest, HttpResponse, Platform};
use crate::util::b64url_encode;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::PrivateKey;
use serde_json::{json, Value};
use sha2::Sha256;
use std::cell::{Cell, RefCell};
use std::sync::OnceLock;

mod a2a;
mod auth;
mod der;
mod origin;
mod policy;
mod resource;
mod review;
mod setup;
mod transport;
mod webhook;

/// A fixed clock, so token lifetimes are deterministic.
pub const NOW_MS: u64 = 1_790_000_000_000;
pub const NOW_SEC: u64 = NOW_MS / 1000;

pub const ISSUER: &str = "https://accounts.mukoko.com";
pub const AUDIENCE: &str = "https://github.shamwari.ai/mcp";
pub const JWKS_URL: &str = "https://accounts.mukoko.com/oauth2/jwks";
pub const ORG: &str = "org_01KRDAB894DJF5V38PT5617TV1";
pub const KID: &str = "test-key-1";

/// One throw-away key for the whole test run, generated in memory. No key
/// material is committed to the repository.
pub fn test_key() -> &'static PrivateKey {
    static KEY: OnceLock<PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| PrivateKey::new(&mut getrandom::SysRng, 2048).expect("generate test key"))
}

pub fn jwk() -> Value {
    let k = test_key().to_public_key();
    json!({
        "kty": "RSA",
        "kid": KID,
        "alg": "RS256",
        "use": "sig",
        "n": b64url_encode(&k.n_bytes()),
        "e": b64url_encode(&k.e_bytes()),
    })
}

pub fn pkcs8_der(key: &PrivateKey) -> Vec<u8> {
    key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec()
}

pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let b64 = STANDARD.encode(der);
    let body: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        body.join("\n")
    )
}

/// Sign `claims` (merged over a default iat/exp) into an RS256 JWT.
pub fn mint_token(claims: Value) -> String {
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": KID });
    let mut payload = json!({ "iat": NOW_SEC, "exp": NOW_SEC + 3600 });
    if let (Some(p), Some(c)) = (payload.as_object_mut(), claims.as_object()) {
        for (k, v) in c {
            if v.is_null() {
                p.remove(k); // `undefined` in the TypeScript fixtures
            } else {
                p.insert(k.clone(), v.clone());
            }
        }
    }
    let unsigned = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let sig = test_key()
        .pkcs1v15_sign::<Sha256>(unsigned.as_bytes())
        .expect("sign");
    format!("{unsigned}.{}", b64url_encode(&sig))
}

type Route = Box<dyn Fn(&HttpRequest) -> Option<HttpResponse>>;
type AiFn = Box<dyn Fn(&str, &Value, Option<&Value>) -> Result<Value, String>>;

/// A scripted [`Platform`]: canned HTTP routes, an optional AI binding, and a
/// request log. An unmatched request fails loudly, as the TypeScript tests'
/// `fetch` stub did.
pub struct Mock {
    pub now: Cell<u64>,
    routes: RefCell<Vec<Route>>,
    ai: RefCell<Option<AiFn>>,
    pub requests: RefCell<Vec<HttpRequest>>,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            now: Cell::new(NOW_MS),
            routes: RefCell::new(vec![]),
            ai: RefCell::new(None),
            requests: RefCell::new(vec![]),
        }
    }
}

impl Mock {
    pub fn route(self, f: impl Fn(&HttpRequest) -> Option<HttpResponse> + 'static) -> Self {
        self.routes.borrow_mut().push(Box::new(f));
        self
    }

    /// Serve the test JWKS at the WorkOS JWKS URL.
    pub fn with_jwks(self) -> Self {
        self.route(|r| {
            (r.url == JWKS_URL).then(|| HttpResponse {
                status: 200,
                body: json!({ "keys": [jwk()] }).to_string(),
            })
        })
    }

    pub fn with_ai(
        self,
        f: impl Fn(&str, &Value, Option<&Value>) -> Result<Value, String> + 'static,
    ) -> Self {
        *self.ai.borrow_mut() = Some(Box::new(f));
        self
    }

    pub fn count(&self, needle: &str) -> usize {
        self.requests
            .borrow()
            .iter()
            .filter(|r| r.url.contains(needle))
            .count()
    }
}

impl Platform for Mock {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        self.requests.borrow_mut().push(req.clone());
        for r in self.routes.borrow().iter() {
            if let Some(res) = r(&req) {
                return Ok(res);
            }
        }
        Err(format!("unexpected fetch: {}", req.url))
    }

    async fn ai_run(
        &self,
        model: &str,
        input: &Value,
        options: Option<&Value>,
    ) -> Result<Value, String> {
        match self.ai.borrow().as_ref() {
            Some(f) => f(model, input, options),
            None => Err("no AI".into()),
        }
    }

    fn has_ai(&self) -> bool {
        self.ai.borrow().is_some()
    }

    fn now_ms(&self) -> u64 {
        self.now.get()
    }
}

/// The WorkOS-gated configuration most auth tests start from.
pub fn auth_config() -> Config {
    Config {
        workos_jwks_url: Some(JWKS_URL.into()),
        workos_issuer: Some(ISSUER.into()),
        workos_audience: Some(AUDIENCE.into()),
        workos_org_id: Some(ORG.into()),
        workos_required_roles: Some("platform-team".into()),
        workos_required_permissions: Some("github:access".into()),
        ..Default::default()
    }
}

pub fn run<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}
