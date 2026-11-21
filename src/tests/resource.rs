//! Port of test/resource.test.ts: the resource metadata must name the URL it is
//! served from.
//!
//! RFC 9728 requires `resource` to be the protected resource the client is
//! talking to, and MCP clients abandon OAuth when it is not. A worker on
//! github.nyuchi.dev once advertised "https://github.shmwari.ai/mcp" (a typo in
//! a dashboard variable) and every connection failed before reaching a login
//! page. These tests pin the rule that makes that impossible: the metadata's
//! resource is derived from the request, for every host this worker serves.

use super::*;
use crate::auth::{allowed_resource_hosts, resource_url_for};
use crate::router::{handle, Req};

fn cfg(over: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config {
        workos_authorization_server: Some("https://accounts.mukoko.com".into()),
        mcp_resource_url: Some("https://github.shamwari.ai/mcp".into()),
        mcp_resource_hosts: Some("github.shamwari.ai,github.nyuchi.dev".into()),
        ..Default::default()
    };
    over(&mut c);
    c
}

fn get(url: &str) -> Req {
    Req {
        method: "GET".into(),
        url: url.into(),
        ..Default::default()
    }
}

fn metadata(url: &str, c: &Config) -> Value {
    let out = run(handle(&Mock::default(), c, get(url)));
    assert_eq!(out.resp.status, 200, "{url}");
    serde_json::from_str(&out.resp.body).unwrap()
}

#[test]
fn metadata_names_the_served_origin_on_every_host_and_path() {
    for host in ["github.shamwari.ai", "github.nyuchi.dev"] {
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let meta = metadata(&format!("https://{host}{path}"), &cfg(|_| {}));
            assert_eq!(
                meta["resource"],
                format!("https://{host}/mcp"),
                "{host}{path}"
            );
        }
    }
}

#[test]
fn a_mistyped_mcp_resource_url_cannot_leak_into_an_allowed_hosts_metadata() {
    // The exact misconfiguration found on 2026-10-06.
    let c = cfg(|c| c.mcp_resource_url = Some("https://github.shmwari.ai/mcp".into()));
    let meta = metadata(
        "https://github.nyuchi.dev/.well-known/oauth-protected-resource",
        &c,
    );
    assert_eq!(meta["resource"], "https://github.nyuchi.dev/mcp");
}

#[test]
fn the_workers_dev_preview_names_itself() {
    let meta = metadata(
        "https://shamwari-github-mcp.nyuchi.workers.dev/.well-known/oauth-protected-resource",
        &cfg(|_| {}),
    );
    assert_eq!(
        meta["resource"],
        "https://shamwari-github-mcp.nyuchi.workers.dev/mcp"
    );
}

#[test]
fn an_unknown_host_is_never_reflected_and_the_canonical_url_is_used() {
    assert_eq!(
        resource_url_for("https://evil.example/mcp", &cfg(|_| {})),
        "https://github.shamwari.ai/mcp"
    );
}

#[test]
fn hosts_are_matched_case_insensitively_and_the_canonical_host_is_always_allowed() {
    assert_eq!(
        resource_url_for("https://GitHub.Nyuchi.Dev/mcp", &cfg(|_| {})),
        "https://github.nyuchi.dev/mcp"
    );
    assert_eq!(
        allowed_resource_hosts(&cfg(|c| c.mcp_resource_hosts = Some(String::new()))),
        vec!["github.shamwari.ai"]
    );
}

#[test]
fn the_401_challenge_points_at_the_served_hosts_metadata() {
    let out = run(handle(
        &Mock::default(),
        &cfg(|_| {}),
        Req {
            method: "POST".into(),
            url: "https://github.nyuchi.dev/mcp".into(),
            body: "{}".into(),
            ..Default::default()
        },
    ));
    assert_eq!(out.resp.status, 401);
    assert_eq!(
        out.resp.header("WWW-Authenticate"),
        Some(
            r#"Bearer resource_metadata="https://github.nyuchi.dev/.well-known/oauth-protected-resource""#
        )
    );
}

#[test]
fn the_committed_wrangler_toml_names_only_real_hosts() {
    // Guards the typo at its source: every configured resource host must be a
    // domain this worker is meant to serve.
    let toml = include_str!("../../wrangler.toml");
    let mut hosts: Vec<String> = vec![];
    for chunk in toml.split("https://").skip(1) {
        if let Some(end) = chunk.find("/mcp") {
            let h = &chunk[..end];
            if h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
            {
                hosts.push(h.to_owned());
            }
        }
    }
    for line in toml.lines() {
        if let Some(v) = line.strip_prefix("MCP_RESOURCE_HOSTS = \"") {
            hosts.extend(
                v.trim_end_matches('"')
                    .split(',')
                    .map(|h| h.trim().to_owned()),
            );
        }
    }
    assert!(!hosts.is_empty());
    for h in hosts {
        assert!(h == "github.shamwari.ai" || h == "github.nyuchi.dev", "{h}");
    }
}
