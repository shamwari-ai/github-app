# Security

Please report vulnerabilities privately. Use **GitHub private vulnerability
reporting** on this repository (Security tab, "Report a vulnerability") where
it is available, or email **<security@nyuchi.com>**.

Do not open a public issue. Include what you found, how to reproduce it, and
the impact. We acknowledge within three working days.

This Worker holds a GitHub App private key and verifies WorkOS access tokens.
Reports about token audience or issuer checks, the repository allowlist,
webhook signature verification, or anything that lets the App act outside
`GITHUB_ALLOWED_REPOS`, are especially welcome.
