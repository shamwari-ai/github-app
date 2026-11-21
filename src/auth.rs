//! WorkOS Connect OAuth for the GitHub MCP worker.
//!
//! This Worker is a *tool/integration*, not a user-facing application, so it
//! acts as an OAuth 2.0 protected resource (MCP auth spec / RFC 9728): it
//! verifies the WorkOS-issued access token on each call against the WorkOS
//! JWKS (RS256) and advertises WorkOS as its authorization server through
//! resource metadata. No secret is needed for auth, only the public JWKS URL.

use crate::config::{non_empty, Config};
use crate::platform::{HttpRequest, Platform};
use crate::util::{b64url_decode, split_csv};
use rsa::{BoxedUint, PublicKey};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::cell::RefCell;
use url::Url;

pub type Claims = Map<String, Value>;

/// A token was refused. `message` is returned to the caller (it names the
/// gate, never the token or its claims); `detail` is for the operator's log.
#[derive(Debug, Clone)]
pub struct AuthError {
    pub message: String,
    pub detail: Option<String>,
}

impl AuthError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            detail: None,
        }
    }
    fn with(message: impl Into<String>, detail: String) -> Self {
        Self {
            message: message.into(),
            detail: Some(detail),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

thread_local! {
    // Per-isolate JWKS cache (isolates are ephemeral; this only avoids
    // refetching on every request within one).
    static JWKS_CACHE: RefCell<Option<(String, Vec<Jwk>, u64)>> = const { RefCell::new(None) };
}

/// Forget the cached JWKS (tests).
pub fn clear_jwks_cache() {
    JWKS_CACHE.with(|c| *c.borrow_mut() = None);
}

fn decode_json(segment: &str) -> Result<Value, AuthError> {
    let bytes = b64url_decode(segment).map_err(|_| AuthError::new("unauthorized"))?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::new("unauthorized"))
}

async fn get_jwks<P: Platform>(p: &P, cfg: &Config) -> Result<Vec<Jwk>, AuthError> {
    let Some(url) = non_empty(&cfg.workos_jwks_url) else {
        return Err(AuthError::new(
            "WorkOS auth is not configured (WORKOS_JWKS_URL unset)",
        ));
    };
    let now = p.now_ms();
    let hit = JWKS_CACHE.with(|c| {
        c.borrow().as_ref().and_then(|(u, keys, at)| {
            (u == url && now.saturating_sub(*at) < JWKS_TTL_MS).then(|| keys.clone())
        })
    });
    if let Some(keys) = hit {
        return Ok(keys);
    }
    let res = p
        .fetch(HttpRequest {
            method: "GET".into(),
            url: url.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(|_| AuthError::new("unauthorized"))?;
    if !res.ok() {
        return Err(AuthError::new(format!("JWKS fetch failed: {}", res.status)));
    }
    #[derive(Deserialize)]
    struct Body {
        #[serde(default)]
        keys: Vec<Jwk>,
    }
    let body: Body = serde_json::from_str(&res.body).map_err(|_| AuthError::new("unauthorized"))?;
    JWKS_CACHE.with(|c| *c.borrow_mut() = Some((url.to_owned(), body.keys.clone(), now)));
    Ok(body.keys)
}

fn biguint(b64: &str) -> Option<BoxedUint> {
    let mut bytes = b64url_decode(b64).ok()?;
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let bits = u32::try_from(bytes.len() * 8).ok()?;
    BoxedUint::from_be_slice(&bytes, bits).ok()
}

/// Verify an RS256 signature with a JWK's modulus and exponent.
pub fn verify_rs256(jwk: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
    if jwk.kty.as_deref().is_some_and(|k| k != "RSA") {
        return false;
    }
    let (Some(n), Some(e)) = (
        jwk.n.as_deref().and_then(biguint),
        jwk.e.as_deref().and_then(biguint),
    ) else {
        return false;
    };
    let Ok(key) = PublicKey::new(n, e) else {
        return false;
    };
    key.pkcs1v15_verify::<Sha256>(signing_input, signature)
        .is_ok()
}

fn json_str(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// Verify a WorkOS access token (RS256 JWT) and return its claims. Fails
/// closed on every error.
pub async fn verify_workos_token<P: Platform>(
    p: &P,
    token: &str,
    cfg: &Config,
    resource: Option<&str>,
) -> Result<Claims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::new("malformed token"));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header = decode_json(header_b64)?;
    let alg = header.get("alg").and_then(Value::as_str);
    if alg != Some("RS256") {
        return Err(AuthError::new(format!(
            "unsupported alg: {}",
            alg.unwrap_or("undefined")
        )));
    }

    let keys = get_jwks(p, cfg).await?;
    let kid = header.get("kid").and_then(Value::as_str);
    let jwk = keys
        .iter()
        .find(|k| k.kid.as_deref() == kid)
        .or_else(|| keys.first())
        .ok_or_else(|| AuthError::new("no matching signing key"))?;

    let signature = b64url_decode(sig_b64).map_err(|_| AuthError::new("unauthorized"))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    if !verify_rs256(jwk, signing_input.as_bytes(), &signature) {
        return Err(AuthError::new("invalid token signature"));
    }

    let claims = match decode_json(payload_b64)? {
        Value::Object(m) => m,
        _ => return Err(AuthError::new("unauthorized")),
    };
    let now_sec = p.now_ms() / 1000;
    if let Some(exp) = claims.get("exp").and_then(Value::as_f64) {
        if exp < now_sec as f64 {
            return Err(AuthError::new("token expired"));
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_f64) {
        if nbf > now_sec as f64 {
            return Err(AuthError::new("token not yet valid"));
        }
    }

    // Required, not optional: treating an unset WORKOS_ISSUER as "skip the
    // check" would accept tokens from any issuer whose key is in the JWKS.
    let Some(issuer) = non_empty(&cfg.workos_issuer) else {
        return Err(AuthError::new(
            "WorkOS auth is not configured (WORKOS_ISSUER unset)",
        ));
    };
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(AuthError::with(
            "issuer mismatch",
            format!(
                "token iss={} expected={issuer}",
                claims
                    .get("iss")
                    .map(json_str)
                    .unwrap_or("undefined".into())
            ),
        ));
    }

    // Also required: the audience claim is the only thing binding a token to
    // THIS resource (the confused-deputy case). Accepted audiences are
    // WORKOS_AUDIENCE plus the resource URI this request was served under.
    let mut accepted = split_csv(cfg.workos_audience.as_deref());
    if let Some(r) = resource.filter(|r| !r.is_empty()) {
        accepted.push(r.to_owned());
    }
    if accepted.is_empty() {
        return Err(AuthError::new(
            "WorkOS auth is not configured (WORKOS_AUDIENCE unset)",
        ));
    }
    let token_auds: Vec<Value> = match claims.get("aud") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => vec![],
        Some(Value::String(s)) if s.is_empty() => vec![],
        Some(other) => vec![other.clone()],
    };
    let aud_ok = accepted
        .iter()
        .any(|a| token_auds.iter().any(|t| t.as_str() == Some(a.as_str())));
    if !aud_ok {
        return Err(AuthError::with(
            "audience mismatch",
            format!(
                "token aud={} accepted={}",
                Value::Array(token_auds),
                json!(accepted)
            ),
        ));
    }

    // Org gate: only members of the configured organisation.
    if let Some(org) = non_empty(&cfg.workos_org_id) {
        if claims.get("org_id").and_then(Value::as_str) != Some(org) {
            return Err(AuthError::with(
                "organization not permitted",
                format!(
                    "token org_id={} expected={org}",
                    claims
                        .get("org_id")
                        .map(|v| v.as_str().map(str::to_owned).unwrap_or(v.to_string()))
                        .unwrap_or("undefined".into())
                ),
            ));
        }
    }

    // Platform gate: the required role OR permission. WorkOS expresses the
    // same grant three ways depending on how the token was obtained:
    //   role / roles   an AuthKit user
    //   permissions    a third-party Connect app
    //   scope          a WorkOS agent token (space-separated, RFC 6749)
    let req_roles = split_csv(cfg.workos_required_roles.as_deref());
    let req_perms = split_csv(cfg.workos_required_permissions.as_deref());
    if !req_roles.is_empty() || !req_perms.is_empty() {
        let mut token_roles: Vec<String> = vec![];
        if let Some(r) = claims.get("role").and_then(Value::as_str) {
            token_roles.push(r.to_owned());
        }
        if let Some(Value::Array(rs)) = claims.get("roles") {
            token_roles.extend(rs.iter().filter_map(|v| v.as_str().map(str::to_owned)));
        }
        let mut token_perms = permissions_of(&claims);
        token_perms.extend(scopes_of(&claims));
        let role_ok = req_roles.iter().any(|r| token_roles.contains(r));
        let perm_ok = req_perms.iter().any(|p| token_perms.contains(p));
        if !role_ok && !perm_ok {
            return Err(AuthError::with(
                "missing required platform role/permission",
                format!(
                    "token roles={} permissions={} required_roles={} required_permissions={}",
                    json!(token_roles),
                    json!(token_perms),
                    json!(req_roles),
                    json!(req_perms)
                ),
            ));
        }
    }

    Ok(claims)
}

fn permissions_of(claims: &Claims) -> Vec<String> {
    match claims.get("permissions") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

fn scopes_of(claims: &Claims) -> Vec<String> {
    match claims.get("scope") {
        Some(Value::String(s)) => s
            .split(' ')
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub kind: &'static str,
    pub subject: String,
    pub on_behalf_of: Option<String>,
    pub org: Option<String>,
}

/// Who this token says is calling, for logs and audit. An agent token's `sub`
/// is its registration id and `act` (RFC 8693) names the person who
/// authorised it: the difference between "an agent did this" and "an agent
/// did this FOR someone".
pub fn caller_identity(claims: &Claims) -> CallerIdentity {
    let sub = claims.get("sub").and_then(Value::as_str).unwrap_or("");
    CallerIdentity {
        kind: if sub.starts_with("agent_") {
            "agent"
        } else {
            "user"
        },
        subject: sub.to_owned(),
        on_behalf_of: claims
            .get("act")
            .and_then(|a| a.get("sub"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        org: claims
            .get("org_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// The canonical resource, used when a request arrives on no allowed host.
pub const DEFAULT_RESOURCE_URL: &str = "https://github.shamwari.ai/mcp";

pub fn resource_url(cfg: &Config) -> String {
    non_empty(&cfg.mcp_resource_url)
        .unwrap_or(DEFAULT_RESOURCE_URL)
        .to_owned()
}

/// Hosts this worker may name itself under: MCP_RESOURCE_HOSTS plus the host
/// of the canonical MCP_RESOURCE_URL. Lower-cased, de-duplicated, in order.
pub fn allowed_resource_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts: Vec<String> = split_csv(cfg.mcp_resource_hosts.as_deref())
        .into_iter()
        .map(|h| h.to_lowercase())
        .collect();
    if let Ok(u) = Url::parse(&resource_url(cfg)) {
        if let Some(h) = host_with_port(&u) {
            hosts.push(h.to_lowercase());
        }
    }
    let mut seen = vec![];
    for h in hosts {
        if !seen.contains(&h) {
            seen.push(h);
        }
    }
    seen
}

/// `url.host` in the WHATWG sense: hostname plus a non-default port.
pub fn host_with_port(u: &Url) -> Option<String> {
    let h = u.host_str()?;
    Some(match u.port() {
        Some(p) => format!("{h}:{p}"),
        None => h.to_owned(),
    })
}

/// The resource URI for THIS request: `https://<served host>/mcp`.
///
/// RFC 9728 requires the metadata `resource` to be the URL the client is
/// talking to; deriving it from the request means it can never disagree with
/// the host serving it. Only an allowlisted host (or this worker's own
/// `*.workers.dev` preview host) is reflected; anything else gets the
/// canonical URL, never an arbitrary Host header.
pub fn resource_url_for(request_url: &str, cfg: &Config) -> String {
    let Ok(url) = Url::parse(request_url) else {
        return resource_url(cfg);
    };
    let Some(host) = host_with_port(&url).map(|h| h.to_lowercase()) else {
        return resource_url(cfg);
    };
    let allowed = allowed_resource_hosts(cfg).contains(&host) || host.ends_with(".workers.dev");
    if !allowed || url.scheme() != "https" {
        return resource_url(cfg);
    }
    format!("https://{host}/mcp")
}

pub const AUTHORIZATION_SERVER_MISSING: &str = "WORKOS_AUTHORIZATION_SERVER is not configured";

/// Parse (never concatenate) a configured AuthKit domain into an https
/// origin. Accepts a bare host or an https origin, in any case; path, query
/// and fragment are dropped. Blank, `http:`, any other scheme, embedded
/// credentials and anything unparseable are errors starting with
/// [`AUTHORIZATION_SERVER_MISSING`].
pub fn normalise_authkit_domain(value: Option<&str>) -> Result<String, String> {
    let raw = value.map(str::trim).unwrap_or("");
    if raw.is_empty() {
        return Err(AUTHORIZATION_SERVER_MISSING.to_owned());
    }
    let has_scheme = {
        let mut chars = raw.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && raw.split_once("://").is_some_and(|(s, _)| {
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
            })
    };
    let candidate = if has_scheme {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate)
        .map_err(|_| format!("{AUTHORIZATION_SERVER_MISSING} (not a valid host or URL)"))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{AUTHORIZATION_SERVER_MISSING} (must be an https origin)"
        ));
    }
    Ok(url.origin().ascii_serialization())
}

/// The AuthKit issuer to advertise, from configuration only: there is no
/// compiled-in default and no fallback host.
pub fn authorization_server(cfg: &Config) -> Option<String> {
    normalise_authkit_domain(cfg.workos_authorization_server.as_deref()).ok()
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728). `None` when
/// WORKOS_AUTHORIZATION_SERVER is unset: the caller answers 503 rather than
/// advertising a guessed host.
///
/// NO `scopes_supported`, deliberately: advertising a scope the authorization
/// server does not define makes a client ask for it and WorkOS answer
/// `invalid_scope` straight to the client's callback, so the user never
/// reaches a login page. This Worker gates on org, role and permission
/// claims, not on scopes.
pub fn protected_resource_metadata(cfg: &Config, resource: &str) -> Option<Value> {
    let issuer = authorization_server(cfg)?;
    Some(json!({
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }))
}
