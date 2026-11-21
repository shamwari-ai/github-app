//! Small helpers shared by every module.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

/// Split a comma-separated config value, trimming and dropping empties.
pub fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Base64url without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, tolerating the standard alphabet and padding (the
/// TypeScript version translated `-`/`_` and fed `atob`, which accepts both).
pub fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let normalised: String = input
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD
        .decode(normalised)
        .map_err(|e| format!("invalid base64: {e}"))
}

/// Standard base64 (with padding) decode, for PEM bodies.
pub fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(input.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(input))
        .map_err(|e| format!("invalid base64: {e}"))
}

/// Parse an RFC 3339 / ISO 8601 UTC timestamp ("2026-11-21T10:00:00Z", with
/// optional fractional seconds) to epoch milliseconds. `None` if unparseable.
pub fn parse_iso8601_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let rest = rest.strip_suffix('Z').unwrap_or(rest);
    // Numeric offsets are not emitted by GitHub; refuse rather than guess.
    if rest.contains('+') || rest.rfind('-').is_some() {
        return None;
    }
    let (hms, frac) = match rest.split_once('.') {
        Some((h, f)) => (h, f),
        None => (rest, ""),
    };
    let mut t = hms.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    let millis: i64 = if frac.is_empty() {
        0
    } else {
        let f: String = frac.chars().take(3).collect();
        format!("{f:0<3}").parse().ok()?
    };
    // days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    u64::try_from(secs * 1000 + millis).ok()
}

/// A random RFC 4122 version 4 UUID.
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    // A failure here means the platform has no entropy source at all; there is
    // no safe fallback for an identifier that must not collide.
    getrandom::fill(&mut b).expect("no entropy source");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
