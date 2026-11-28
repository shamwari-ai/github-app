//! Worker configuration: the `[vars]` in wrangler.toml plus the secrets.
//!
//! Every field is optional because an unset value must fail closed in the
//! place that needs it, with a message that says what to set, rather than
//! stop the Worker from starting.

#[derive(Debug, Clone, Default)]
pub struct Config {
    // ---- GitHub App (secret + public identity) -------------------------
    /// SECRET. The App's `.pem`, PKCS#1 ("BEGIN RSA PRIVATE KEY") or PKCS#8.
    pub github_app_private_key: Option<String>,
    /// The App's numeric id (public, `[vars]`).
    pub github_app_id: Option<String>,
    pub github_api: Option<String>,
    /// Inner bound: `name:level` pairs requested when minting a token.
    pub github_token_permissions: Option<String>,
    /// SECRET. GitHub's webhook secret. Unset means /webhook answers 503.
    pub github_webhook_secret: Option<String>,

    // ---- WorkOS (verification only) ------------------------------------
    pub workos_jwks_url: Option<String>,
    pub workos_issuer: Option<String>,
    pub workos_audience: Option<String>,
    pub workos_authorization_server: Option<String>,
    pub workos_org_id: Option<String>,
    pub workos_required_roles: Option<String>,
    pub workos_required_permissions: Option<String>,
    pub mcp_resource_url: Option<String>,
    pub mcp_resource_hosts: Option<String>,

    // ---- Review agent ---------------------------------------------------
    pub review_model: Option<String>,
    pub review_max_diff_bytes: Option<String>,
    pub review_mention: Option<String>,
    pub review_trigger_associations: Option<String>,
    pub ai_gateway_id: Option<String>,
    /// Exactly `"false"` disables the reviewer.
    pub review_enabled: Option<String>,
}

/// A config value that is set and non-empty (JavaScript `value || default`).
pub fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}
