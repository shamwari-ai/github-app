//! GitHub App client.
//!
//! Does the three things that matter by hand:
//!
//!   1. Sign an App JWT (RS256).
//!   2. Exchange it for an INSTALLATION token scoped down to one repository
//!      and a reduced permission set.
//!   3. Call the REST API with that token.
//!
//! Step 2 is the security story. The App holds more than the agent needs
//! (it may hold `workflows`, and its installation may hold `contents:write`);
//! an installation token may request a SUBSET of what the App holds, so the
//! agent runs with `pull_requests: write`, `issues: write`, `contents: read`
//! and NO `workflows`. It can review and file; it cannot push a workflow file
//! or cut a release.

use crate::config::{non_empty, Config};
use crate::error::{Failure, GitHubError};
use crate::platform::{HttpRequest, HttpResponse, Platform};
use crate::util::{b64_decode, b64url_encode, parse_iso8601_ms, split_csv};
use rsa::pkcs8::DecodePrivateKey;
use rsa::PrivateKey;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub type GhResult<T> = Result<T, Failure>;

pub const DEFAULT_PERMISSIONS: &str =
    "pull_requests:write,issues:write,contents:read,metadata:read";

fn api(cfg: &Config) -> &str {
    non_empty(&cfg.github_api).unwrap_or("https://api.github.com")
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

/// Resolve "owner/repo" into its two parts, or refuse a malformed slug.
///
/// Checked before a token is minted, so a malformed slug never reaches
/// GitHub. There is no worker-side repository list: the outer bound is what
/// each installation grants (GitHub's own repository selection), and the
/// token mint narrows it further, per repository and per permission.
pub fn resolve_repo(repo: &str) -> Result<(String, String), GitHubError> {
    let slug = repo.trim();
    let mut it = slug.split('/');
    let (owner, name) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    if owner.is_empty() || name.is_empty() {
        return Err(GitHubError::new(
            format!("malformed repo \"{slug}\", expected owner/repo"),
            400,
        ));
    }
    Ok((owner.to_owned(), name.to_owned()))
}

// ---------------------------------------------------------------------------
// App JWT
// ---------------------------------------------------------------------------

/// DER length octets: short form below 128, long form at or above it.
pub fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = vec![];
    let mut v = n;
    while v > 0 {
        bytes.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// Wrap a PKCS#1 RSA key in the PKCS#8 envelope:
///
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING pkcs1 }`
///
/// GitHub hands out "BEGIN RSA PRIVATE KEY" (PKCS#1). Rather than make every
/// operator run `openssl pkcs8 -topk8`, the Worker wraps it itself.
pub fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let version = [0x02, 0x01, 0x00];
    // rsaEncryption (1.2.840.113549.1.1.1) + NULL params.
    let algorithm = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut octet = vec![0x04];
    octet.extend(der_length(pkcs1.len()));
    let body_len = version.len() + algorithm.len() + octet.len() + pkcs1.len();
    let mut out = vec![0x30];
    out.extend(der_length(body_len));
    out.extend(version);
    out.extend(algorithm);
    out.extend(octet);
    out.extend(pkcs1);
    out
}

/// The DER bytes of a PEM private key and whether it is PKCS#1.
pub fn pem_body(pem: &str) -> Result<(Vec<u8>, bool), GitHubError> {
    let bad = || GitHubError::new("GITHUB_APP_PRIVATE_KEY is empty or not a PEM", 500);
    let trimmed = pem.trim();
    // Insist on the markers: without them any base64-shaped string would
    // survive to produce a junk key that fails much later with an opaque error.
    let begin = trimmed.find("-----BEGIN ").ok_or_else(bad)?;
    let after = &trimmed[begin + "-----BEGIN ".len()..];
    let label_end = after.find("-----").ok_or_else(bad)?;
    let label = &after[..label_end];
    if !label.ends_with("PRIVATE KEY") || !label.chars().all(|c| c.is_ascii_uppercase() || c == ' ')
    {
        return Err(bad());
    }
    let pkcs1 = trimmed.contains("BEGIN RSA PRIVATE KEY");
    let body_start = begin + "-----BEGIN ".len() + label_end + "-----".len();
    let body = &trimmed[body_start..];
    let body = match body.find("-----END ") {
        Some(i) => &body[..i],
        None => body,
    };
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if base64.is_empty() {
        return Err(bad());
    }
    let der = b64_decode(&base64).map_err(|_| bad())?;
    Ok((der, pkcs1))
}

thread_local! {
    static SIGNING_KEY: RefCell<Option<Rc<PrivateKey>>> = const { RefCell::new(None) };
}

fn signing_key(cfg: &Config) -> Result<Rc<PrivateKey>, GitHubError> {
    if let Some(k) = SIGNING_KEY.with(|c| c.borrow().clone()) {
        return Ok(k);
    }
    let Some(pem) = non_empty(&cfg.github_app_private_key) else {
        return Err(GitHubError::new("GITHUB_APP_PRIVATE_KEY is not set", 500));
    };
    let (der, pkcs1) = pem_body(pem)?;
    let pkcs8 = if pkcs1 { pkcs1_to_pkcs8(&der) } else { der };
    let key = PrivateKey::from_pkcs8_der(&pkcs8).map_err(|_| {
        GitHubError::new("GITHUB_APP_PRIVATE_KEY is not a valid RSA private key", 500)
    })?;
    let key = Rc::new(key);
    SIGNING_KEY.with(|c| *c.borrow_mut() = Some(key.clone()));
    Ok(key)
}

/// Forget the parsed key and cached tokens (tests).
pub fn clear_caches() {
    SIGNING_KEY.with(|c| *c.borrow_mut() = None);
    TOKEN_CACHE.with(|c| c.borrow_mut().clear());
}

/// Mint an App JWT. `iat` is backdated 60s because GitHub rejects a token
/// whose `iat` is in the future relative to its own clock and a Worker's
/// clock can be marginally ahead. Ten-minute maximum life; nine is polite.
pub fn app_jwt<P: Platform>(p: &P, cfg: &Config) -> Result<String, GitHubError> {
    let app_id = cfg.github_app_id.as_deref().unwrap_or("").trim();
    if app_id.is_empty() {
        return Err(GitHubError::new("GITHUB_APP_ID is not set", 500));
    }
    let now = (p.now_ms() / 1000) as i64;
    let header = json!({ "alg": "RS256", "typ": "JWT" });
    let payload = json!({ "iat": now - 60, "exp": now + 540, "iss": app_id });
    let unsigned = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let key = signing_key(cfg)?;
    let sig = key
        .pkcs1v15_sign::<Sha256>(unsigned.as_bytes())
        .map_err(|_| GitHubError::new("signing the App JWT failed", 500))?;
    Ok(format!("{unsigned}.{}", b64url_encode(&sig)))
}

// ---------------------------------------------------------------------------
// Installation tokens, scoped down
// ---------------------------------------------------------------------------

thread_local! {
    // Per-isolate cache keyed by owner/repo (lower-cased): token + expiry ms.
    static TOKEN_CACHE: RefCell<HashMap<String, (String, u64)>> = RefCell::new(HashMap::new());
}

/// The permission set a minted token asks for: GITHUB_TOKEN_PERMISSIONS, or
/// the default.
pub fn requested_permissions(cfg: &Config) -> Map<String, Value> {
    let spec = non_empty(&cfg.github_token_permissions).unwrap_or(DEFAULT_PERMISSIONS);
    let mut out = Map::new();
    for pair in split_csv(Some(spec)) {
        let mut it = pair.splitn(2, ':').map(str::trim);
        let name = it.next().unwrap_or("");
        let level = it.next().unwrap_or("");
        if !name.is_empty() && !level.is_empty() {
            out.insert(name.to_owned(), Value::String(level.to_owned()));
        }
    }
    out
}

fn default_headers() -> Vec<(String, String)> {
    vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
        ("User-Agent".into(), "shamwari-github-mcp".into()),
    ]
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value.to_owned()));
}

async fn net<P: Platform>(p: &P, req: HttpRequest) -> GhResult<HttpResponse> {
    p.fetch(req)
        .await
        .map_err(|e| Failure::Internal(format!("fetch failed: {e}")))
}

/// One GitHub JSON call. Non-2xx becomes a [`GitHubError`] whose message is
/// GitHub's own, so a missing permission is diagnosable rather than mysterious.
async fn github_json<P: Platform>(
    p: &P,
    method: &str,
    url: String,
    extra: Vec<(String, String)>,
    body: Option<String>,
    context: &str,
) -> GhResult<Value> {
    let mut headers = default_headers();
    for (k, v) in extra {
        set_header(&mut headers, &k, &v);
    }
    let res = net(
        p,
        HttpRequest {
            method: method.to_owned(),
            url,
            headers,
            body,
        },
    )
    .await?;
    let parsed = if res.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&res.body).unwrap_or(Value::String(res.body.clone()))
    };
    if !res.ok() {
        let message = parsed
            .get("message")
            .map(|m| m.as_str().map(str::to_owned).unwrap_or(m.to_string()))
            .unwrap_or_else(|| format!("HTTP {}", res.status));
        return Err(
            GitHubError::new(format!("{context}: {message}"), res.status)
                .with_detail(parsed)
                .into(),
        );
    }
    Ok(parsed)
}

/// Which requested permissions an installation does not satisfy, as
/// `name:level`. `write` satisfies a `read` request; `read` does not satisfy
/// `write`. Getting that backwards would hide a real gap or report a false one.
pub fn missing_permissions(
    requested: &Map<String, Value>,
    granted: &Map<String, Value>,
) -> Vec<String> {
    requested
        .iter()
        .filter(|(perm, level)| {
            let level = level.as_str().unwrap_or("");
            match granted.get(*perm).and_then(Value::as_str) {
                None | Some("") => true,
                Some(held) => level == "write" && held != "write",
            }
        })
        .map(|(perm, level)| format!("{perm}:{}", level.as_str().unwrap_or("")))
        .collect()
}

async fn installation_for<P: Platform>(
    p: &P,
    cfg: &Config,
    owner: &str,
    name: &str,
    jwt: &str,
) -> GhResult<Value> {
    github_json(
        p,
        "GET",
        format!("{}/repos/{owner}/{name}/installation", api(cfg)),
        vec![("Authorization".into(), format!("Bearer {jwt}"))],
        None,
        &format!("resolving the App installation on {owner}/{name}"),
    )
    .await
}

async fn installation_token<P: Platform>(
    p: &P,
    cfg: &Config,
    owner: &str,
    name: &str,
) -> GhResult<String> {
    let cache_key = format!("{owner}/{name}").to_lowercase();
    if let Some((tok, expires)) = TOKEN_CACHE.with(|c| c.borrow().get(&cache_key).cloned()) {
        if expires.saturating_sub(60_000) > p.now_ms() {
            return Ok(tok);
        }
    }

    let jwt = app_jwt(p, cfg)?;
    let install = installation_for(p, cfg, owner, name, &jwt).await?;
    let Some(id) = install.get("id").and_then(Value::as_i64) else {
        return Err(GitHubError::new(
            format!("no installation id returned for {owner}/{name}"),
            502,
        )
        .with_detail(install)
        .into());
    };

    let minted = github_json(
        p,
        "POST",
        format!("{}/app/installations/{id}/access_tokens", api(cfg)),
        vec![
            ("Authorization".into(), format!("Bearer {jwt}")),
            ("Content-Type".into(), "application/json".into()),
        ],
        Some(
            json!({
                "repositories": [name],
                "permissions": requested_permissions(cfg),
            })
            .to_string(),
        ),
        &format!("minting a scoped installation token for {owner}/{name}"),
    )
    .await?;

    let Some(token) = minted.get("token").and_then(Value::as_str) else {
        return Err(
            GitHubError::new("no token in installation token response", 502)
                .with_detail(minted)
                .into(),
        );
    };
    let expires = minted
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(parse_iso8601_ms)
        .unwrap_or_else(|| p.now_ms() + 30 * 60_000);
    let token = token.to_owned();
    TOKEN_CACHE.with(|c| {
        c.borrow_mut().insert(cache_key, (token.clone(), expires));
    });
    Ok(token)
}

/// Authenticated REST call against a repository granted by an installation.
async fn repo_api<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    path: &str,
    method: &str,
    body: Option<Value>,
) -> GhResult<Value> {
    let (owner, name) = resolve_repo(repo)?;
    let token = installation_token(p, cfg, &owner, &name).await?;
    let mut extra = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
    if body.is_some() {
        extra.push(("Content-Type".into(), "application/json".into()));
    }
    github_json(
        p,
        method,
        format!("{}/repos/{owner}/{name}{path}", api(cfg)),
        extra,
        body.map(|b| b.to_string()),
        &format!("{method} {path}"),
    )
    .await
}

/// Raw-text REST call (diffs and patches are not JSON).
async fn repo_text<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    path: &str,
    accept: &str,
) -> GhResult<String> {
    let (owner, name) = resolve_repo(repo)?;
    let token = installation_token(p, cfg, &owner, &name).await?;
    let res = net(
        p,
        HttpRequest {
            method: "GET".into(),
            url: format!("{}/repos/{owner}/{name}{path}", api(cfg)),
            headers: vec![
                ("Authorization".into(), format!("Bearer {token}")),
                ("Accept".into(), accept.into()),
                ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
                ("User-Agent".into(), "shamwari-github-mcp".into()),
            ],
            body: None,
        },
    )
    .await?;
    if !res.ok() {
        return Err(
            GitHubError::new(format!("GET {path}: HTTP {}", res.status), res.status)
                .with_detail(Value::String(res.body))
                .into(),
        );
    }
    Ok(res.body)
}

// ---------------------------------------------------------------------------
// Operations: plain functions, so the webhook-driven layer calls the same
// code the MCP tools do rather than reimplementing it.
// ---------------------------------------------------------------------------

pub async fn whoami<P: Platform>(p: &P, cfg: &Config) -> GhResult<Value> {
    let jwt = app_jwt(p, cfg)?;
    let app = github_json(
        p,
        "GET",
        format!("{}/app", api(cfg)),
        vec![("Authorization".into(), format!("Bearer {jwt}"))],
        None,
        "reading the authenticated App",
    )
    .await?;
    let declared = app.get("permissions").cloned().unwrap_or_else(|| json!({}));
    let requested = requested_permissions(cfg);
    let installation_list = github_json(
        p,
        "GET",
        format!("{}/app/installations", api(cfg)),
        vec![("Authorization".into(), format!("Bearer {jwt}"))],
        None,
        "listing the App's installations",
    )
    .await?;

    // Probe every installation rather than reporting the App alone: a token
    // mint asks for the WHOLE permission set at once, so one missing
    // permission fails every tool on that installation, and an App declaring
    // a permission does not mean the installation has accepted it.
    // `GET /app/installations` already carries what each installation holds,
    // so no further requests are needed.
    let installations: Vec<Value> = installation_list
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|install| {
            let granted = install
                .get("permissions")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let missing = missing_permissions(&requested, &granted);
            json!({
                "account": install.pointer("/account/login").cloned().unwrap_or(Value::Null),
                "installation_id": install.get("id").cloned().unwrap_or(Value::Null),
                "repository_selection": install.get("repository_selection").cloned().unwrap_or(Value::Null),
                "granted": granted,
                "missing": missing,
                "ok": missing.is_empty(),
            })
        })
        .collect();

    let broken: Vec<&str> = installations
        .iter()
        .filter(|i| i.get("ok") != Some(&Value::Bool(true)))
        .filter_map(|i| i.get("account").and_then(Value::as_str))
        .collect();
    let note = if installations.is_empty() {
        "The App is not installed anywhere yet; install it on an organisation to switch it on."
            .to_owned()
    } else if broken.is_empty() {
        "Every installation grants the permissions the scoped token asks for.".to_owned()
    } else {
        format!(
            "Not ready: {}. A token mint requests the whole permission set at once, so any gap here fails EVERY tool on that installation, not only the ones needing the missing permission. Note that adding a permission to the App leaves the installation pending an owner's approval — \"granted\" above is what the installation actually holds, which is what matters.",
            broken.join(", ")
        )
    };
    let ready = broken.is_empty();
    let mut app_info = Map::new();
    if let Some(s) = app.get("slug") {
        app_info.insert("slug".into(), s.clone());
    }
    if let Some(n) = app.get("name") {
        app_info.insert("name".into(), n.clone());
    }
    Ok(json!({
        "app": app_info,
        "app_declared_permissions": declared,
        "token_permissions_requested": requested,
        "installations": installations,
        "ready": ready,
        "note": note,
    }))
}

/// One page of results, fetched one item over the limit: if the extra item
/// arrives, another page exists. Costs nothing and needs no Link parsing.
pub fn paginate(rows: Vec<Value>, limit: usize, page: u64) -> Value {
    let has_more = rows.len() > limit;
    let items: Vec<Value> = rows.into_iter().take(limit).collect();
    let count = items.len();
    let mut out = Map::new();
    out.insert("items".into(), Value::Array(items));
    out.insert("count".into(), json!(count));
    out.insert("page".into(), json!(page));
    out.insert("has_more".into(), json!(has_more));
    if has_more {
        out.insert("next_page".into(), json!(page + 1));
    }
    Value::Object(out)
}

/// `v[key]`, omitted from the result when absent (JavaScript `undefined`).
fn put(out: &mut Map<String, Value>, key: &str, v: Option<Value>) {
    if let Some(v) = v {
        out.insert(key.to_owned(), v);
    }
}

fn nested(v: &Value, a: &str, b: &str) -> Option<Value> {
    v.get(a).and_then(|x| x.get(b)).cloned()
}

fn names(v: &Value, key: &str, field: &str) -> Option<Value> {
    v.get(key).and_then(Value::as_array).map(|a| {
        Value::Array(
            a.iter()
                .map(|l| l.get(field).cloned().unwrap_or(Value::Null))
                .collect(),
        )
    })
}

/// Trim a GitHub pull request down to what a reviewer or triager needs. A raw
/// pull request carries 36 top-level fields, 99% of the payload being
/// structure nothing reads; anything omitted is one `get_pull_request` away.
pub fn slim_pull(p: &Value) -> Value {
    let mut o = Map::new();
    for k in ["number", "title", "state", "draft"] {
        put(&mut o, k, p.get(k).cloned());
    }
    put(&mut o, "author", nested(p, "user", "login"));
    put(&mut o, "base", nested(p, "base", "ref"));
    put(&mut o, "head", nested(p, "head", "ref"));
    put(&mut o, "labels", names(p, "labels", "name"));
    put(&mut o, "created_at", p.get("created_at").cloned());
    put(&mut o, "updated_at", p.get("updated_at").cloned());
    put(&mut o, "url", p.get("html_url").cloned());
    Value::Object(o)
}

pub fn slim_issue(i: &Value) -> Value {
    let mut o = Map::new();
    for k in ["number", "title", "state"] {
        put(&mut o, k, i.get(k).cloned());
    }
    // GitHub returns pull requests from the issues endpoint too; flagging it
    // is cheaper than making the caller notice the pull_request field.
    o.insert(
        "is_pull_request".into(),
        json!(i.get("pull_request").is_some()),
    );
    put(&mut o, "author", nested(i, "user", "login"));
    put(&mut o, "labels", names(i, "labels", "name"));
    put(&mut o, "assignees", names(i, "assignees", "login"));
    put(&mut o, "comments", i.get("comments").cloned());
    put(&mut o, "created_at", i.get("created_at").cloned());
    put(&mut o, "updated_at", i.get("updated_at").cloned());
    put(&mut o, "url", i.get("html_url").cloned());
    Value::Object(o)
}

fn list_query(state: &str, limit: usize, page: u64) -> String {
    format!(
        "state={state}&per_page={}&page={page}&sort=updated&direction=desc",
        limit + 1
    )
}

fn rows(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        _ => vec![],
    }
}

pub async fn list_pull_requests<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    state: &str,
    limit: usize,
    page: u64,
) -> GhResult<Value> {
    let path = format!("/pulls?{}", list_query(state, limit, page));
    let v = repo_api(p, cfg, repo, &path, "GET", None).await?;
    let mut result = paginate(rows(v), limit, page);
    let items: Vec<Value> = result["items"]
        .as_array()
        .map(|a| a.iter().map(slim_pull).collect())
        .unwrap_or_default();
    result["items"] = Value::Array(items);
    Ok(result)
}

pub async fn get_pull_request<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
) -> GhResult<Value> {
    let pr = repo_api(p, cfg, repo, &format!("/pulls/{number}"), "GET", None).await?;
    let head = pr
        .get("head")
        .and_then(|h| h.get("sha"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let files_path = format!("/pulls/{number}/files?per_page=100");
    let files_fut = repo_api(p, cfg, repo, &files_path, "GET", None);
    let checks_fut = async {
        match &head {
            Some(h) => {
                let path = format!("/commits/{h}/check-runs");
                repo_api(p, cfg, repo, &path, "GET", None).await.ok()
            }
            None => None,
        }
    };
    let (files, checks) = futures_util::future::join(files_fut, checks_fut).await;
    let files = files?;
    let runs: Vec<Value> = checks
        .as_ref()
        .and_then(|c| c.get("check_runs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let name_of = |c: &Value| c.get("name").cloned().unwrap_or(Value::Null);
    let status = |c: &Value| {
        c.get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let failing: Vec<Value> = runs
        .iter()
        .filter(|c| {
            status(c) == "completed"
                && !matches!(
                    c.get("conclusion").and_then(Value::as_str),
                    Some("success" | "skipped" | "neutral")
                )
        })
        .map(name_of)
        .collect();
    let pending: Vec<Value> = runs
        .iter()
        .filter(|c| status(c) != "completed")
        .map(name_of)
        .collect();

    let mut o = Map::new();
    for k in ["number", "title", "state", "draft"] {
        put(&mut o, k, pr.get(k).cloned());
    }
    put(&mut o, "author", nested(&pr, "user", "login"));
    put(&mut o, "base", nested(&pr, "base", "ref"));
    put(&mut o, "head", nested(&pr, "head", "ref"));
    put(&mut o, "head_sha", head.map(Value::String));
    for k in [
        "mergeable",
        "mergeable_state",
        "additions",
        "deletions",
        "changed_files",
        "body",
    ] {
        put(&mut o, k, pr.get(k).cloned());
    }
    let files: Vec<Value> = rows(files)
        .iter()
        .map(|f| {
            let mut m = Map::new();
            for k in ["filename", "status", "additions", "deletions"] {
                put(&mut m, k, f.get(k).cloned());
            }
            Value::Object(m)
        })
        .collect();
    o.insert("files".into(), Value::Array(files));
    o.insert(
        "checks".into(),
        json!({ "total": runs.len(), "failing": failing, "pending": pending }),
    );
    Ok(Value::Object(o))
}

pub async fn get_pull_request_diff<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
) -> GhResult<String> {
    repo_text(
        p,
        cfg,
        repo,
        &format!("/pulls/{number}"),
        "application/vnd.github.v3.diff",
    )
    .await
}

pub struct PullHead {
    pub sha: String,
    pub draft: bool,
    pub state: String,
}

/// Just the head sha and draft flag of a pull request. The `issue_comment`
/// payload carries neither (a pull request is an issue with extra URLs), so a
/// mention costs one lookup, and this is the cheap one.
pub async fn get_pull_request_head<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
) -> GhResult<PullHead> {
    let pr = repo_api(p, cfg, repo, &format!("/pulls/{number}"), "GET", None).await?;
    let Some(sha) = pr
        .get("head")
        .and_then(|h| h.get("sha"))
        .and_then(Value::as_str)
    else {
        return Err(GitHubError::new(format!("{repo}#{number}: no head sha"), 502).into());
    };
    Ok(PullHead {
        sha: sha.to_owned(),
        draft: pr.get("draft") == Some(&Value::Bool(true)),
        state: pr
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
    })
}

/// The diff a push introduced, as a unified diff: what the reviewer reads
/// after a commit (what just arrived, not the whole pull request).
pub async fn compare_commits<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    base: &str,
    head: &str,
) -> GhResult<String> {
    repo_text(
        p,
        cfg,
        repo,
        &format!("/compare/{base}...{head}"),
        "application/vnd.github.v3.diff",
    )
    .await
}

/// Comment on a commit. Deliberately NOT a pull request review: a commit
/// comment carries no review event, so it cannot request changes, cannot
/// approve and cannot satisfy or block branch protection.
pub async fn create_commit_comment<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    sha: &str,
    body: &str,
) -> GhResult<Value> {
    repo_api(
        p,
        cfg,
        repo,
        &format!("/commits/{sha}/comments"),
        "POST",
        Some(json!({ "body": body })),
    )
    .await
}

/// Existing comments on a commit: how the reviewer knows it already ran.
pub async fn list_commit_comments<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    sha: &str,
) -> GhResult<Vec<Value>> {
    let v = repo_api(
        p,
        cfg,
        repo,
        &format!("/commits/{sha}/comments?per_page=100"),
        "GET",
        None,
    )
    .await?;
    Ok(rows(v))
}

pub async fn list_issues<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    state: &str,
    limit: usize,
    page: u64,
) -> GhResult<Value> {
    let path = format!("/issues?{}", list_query(state, limit, page));
    let v = repo_api(p, cfg, repo, &path, "GET", None).await?;
    let mut result = paginate(rows(v), limit, page);
    let items: Vec<Value> = result["items"]
        .as_array()
        .map(|a| a.iter().map(slim_issue).collect())
        .unwrap_or_default();
    result["items"] = Value::Array(items);
    Ok(result)
}

pub async fn get_issue<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
) -> GhResult<Value> {
    repo_api(p, cfg, repo, &format!("/issues/{number}"), "GET", None).await
}

/// Open a pull request. Draft unless explicitly told otherwise: a PR this
/// agent opens should not start demanding review attention on its own.
pub async fn create_pull_request<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    args: Map<String, Value>,
) -> GhResult<Value> {
    let mut body = args;
    let draft = body.get("draft") != Some(&Value::Bool(false));
    body.insert("draft".into(), Value::Bool(draft));
    repo_api(p, cfg, repo, "/pulls", "POST", Some(Value::Object(body))).await
}

pub async fn update_pull_request<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
    patch: Map<String, Value>,
) -> GhResult<Value> {
    repo_api(
        p,
        cfg,
        repo,
        &format!("/pulls/{number}"),
        "PATCH",
        Some(Value::Object(patch)),
    )
    .await
}

/// Submit a review. APPROVE is refused, deliberately and permanently.
///
/// An agent that can approve can satisfy a repository's own review
/// requirement and let code reach a protected branch with no human having
/// read it. COMMENT and REQUEST_CHANGES carry every finding a review needs to
/// carry, and neither one unblocks a merge. This runs before any repository
/// is touched, so no installation grant can reach it.
pub async fn create_review<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
    event: &str,
    body: &str,
    comments: Vec<Value>,
) -> GhResult<Value> {
    let ev = event.to_uppercase();
    if ev == "APPROVE" {
        return Err(GitHubError::new(
            "this server does not approve pull requests; use COMMENT or REQUEST_CHANGES",
            403,
        )
        .into());
    }
    if ev != "COMMENT" && ev != "REQUEST_CHANGES" {
        return Err(GitHubError::new(format!("unsupported review event \"{event}\""), 400).into());
    }
    repo_api(
        p,
        cfg,
        repo,
        &format!("/pulls/{number}/reviews"),
        "POST",
        Some(json!({ "event": ev, "body": body, "comments": comments })),
    )
    .await
}

pub async fn create_comment<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
    body: &str,
) -> GhResult<Value> {
    // Issues and PRs share the issue-comments endpoint.
    repo_api(
        p,
        cfg,
        repo,
        &format!("/issues/{number}/comments"),
        "POST",
        Some(json!({ "body": body })),
    )
    .await
}

pub async fn create_issue<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    args: Map<String, Value>,
) -> GhResult<Value> {
    repo_api(p, cfg, repo, "/issues", "POST", Some(Value::Object(args))).await
}

pub async fn update_issue<P: Platform>(
    p: &P,
    cfg: &Config,
    repo: &str,
    number: u64,
    patch: Map<String, Value>,
) -> GhResult<Value> {
    repo_api(
        p,
        cfg,
        repo,
        &format!("/issues/{number}"),
        "PATCH",
        Some(Value::Object(patch)),
    )
    .await
}
