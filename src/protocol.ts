// MCP protocol version handling — dual-era.
//
// Revision 2026-07-28 ("modern") removed the `initialize` handshake. Instead
// every request carries its protocol version in `params._meta`, mirrored into
// an `MCP-Protocol-Version` header, and the server accepts or rejects each
// request on its own. Revisions up to 2025-11-25 ("legacy") negotiate once via
// `initialize` and keep a session.
//
// This server speaks both, which the spec explicitly allows: "A dual-era
// server MAY serve both eras concurrently on the same endpoint or process."
// Serving only the modern revision would break every client that has already
// connected — and the era is selected by the shape of the request, not by
// configuration:
//
//   a request carrying modern `_meta.protocolVersion`  -> modern
//   an `initialize` request                            -> legacy
//
// Spec: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning

/** The modern revision this server implements. */
export const MODERN_VERSION = "2026-07-28";

/** The legacy revision this server implements, via the initialize handshake. */
export const LEGACY_VERSION = "2025-06-18";

/**
 * Versions accepted on the modern per-request path.
 *
 * LEGACY_VERSION is deliberately absent: it is handshake-based, so a client
 * declaring it as a per-request version is confused, and listing it in an
 * UnsupportedProtocolVersionError would invite a retry that fails identically.
 */
export const SUPPORTED_MODERN_VERSIONS = [MODERN_VERSION] as const;

export const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
export const META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo";
export const META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";

/** Protocol-defined JSON-RPC error codes (spec § Error Codes). */
export const HEADER_MISMATCH = -32020;
export const UNSUPPORTED_PROTOCOL_VERSION = -32022;
export const METHOD_NOT_FOUND = -32601;

/** Methods whose `Mcp-Name` header mirrors a body field, and which field. */
const NAME_HEADER_SOURCE: Record<string, "name" | "uri"> = {
  "tools/call": "name",
  "prompts/get": "name",
  "resources/read": "uri",
};

export interface JsonRpcLike {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

/**
 * Decode the Base64 sentinel form `=?base64?<b64>?=`.
 *
 * Header values are restricted to visible ASCII, so a tool name or resource
 * URI outside that set arrives encoded. Servers MUST decode before comparing
 * to the body — otherwise a perfectly valid call with a non-ASCII name is
 * rejected as a header mismatch.
 */
export function decodeHeaderValue(value: string): string {
  if (!value.startsWith("=?base64?") || !value.endsWith("?=")) return value;
  const payload = value.slice("=?base64?".length, -"?=".length);
  try {
    const bin = atob(payload);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    // Undecodable: return as-is so it fails the comparison below rather than
    // throwing. A mismatch is the correct outcome, not a 500.
    return value;
  }
}

/** The protocol version a request declares in `params._meta`, if any. */
export function declaredVersion(body: JsonRpcLike): string | undefined {
  const meta = body.params?._meta as Record<string, unknown> | undefined;
  const version = meta?.[META_PROTOCOL_VERSION];
  return typeof version === "string" ? version : undefined;
}

/**
 * Which era a request belongs to.
 *
 * `initialize` is legacy by definition — it does not exist in the modern
 * revision, and the spec says an `initialize` request selects legacy
 * semantics. Everything else is modern if it declares a version, legacy
 * otherwise (a legacy client's post-handshake calls carry no version).
 */
export function detectEra(body: JsonRpcLike): "modern" | "legacy" {
  if (body.method === "initialize") return "legacy";
  return declaredVersion(body) !== undefined ? "modern" : "legacy";
}

export interface ProtocolError {
  code: number;
  message: string;
  status: number;
  data?: unknown;
}

/**
 * Validate a modern request's mirrored headers against its body.
 *
 * The headers exist so intermediaries can route and rate-limit without
 * parsing the body; validating them here is what stops a load balancer and
 * this worker acting on different values for the same request.
 *
 * Returns null when the request is valid.
 */
export function validateModernRequest(
  headers: Headers,
  body: JsonRpcLike,
): ProtocolError | null {
  const version = declaredVersion(body);
  const headerVersion = headers.get("MCP-Protocol-Version");

  if (!headerVersion) {
    return {
      code: HEADER_MISMATCH,
      status: 400,
      message: "Header mismatch: MCP-Protocol-Version header is required",
    };
  }
  if (headerVersion !== version) {
    return {
      code: HEADER_MISMATCH,
      status: 400,
      message: `Header mismatch: MCP-Protocol-Version header value '${headerVersion}' does not match body value '${version}'`,
    };
  }
  if (!(SUPPORTED_MODERN_VERSIONS as readonly string[]).includes(version!)) {
    return {
      code: UNSUPPORTED_PROTOCOL_VERSION,
      status: 400,
      message: "Unsupported protocol version",
      data: { supported: [...SUPPORTED_MODERN_VERSIONS], requested: version },
    };
  }

  const headerMethod = headers.get("Mcp-Method");
  if (!headerMethod) {
    return {
      code: HEADER_MISMATCH,
      status: 400,
      message: "Header mismatch: Mcp-Method header is required",
    };
  }
  if (headerMethod !== body.method) {
    return {
      code: HEADER_MISMATCH,
      status: 400,
      message: `Header mismatch: Mcp-Method header value '${headerMethod}' does not match body value '${body.method}'`,
    };
  }

  const nameField = body.method ? NAME_HEADER_SOURCE[body.method] : undefined;
  if (nameField) {
    const bodyName = body.params?.[nameField];
    const headerName = headers.get("Mcp-Name");
    if (!headerName) {
      return {
        code: HEADER_MISMATCH,
        status: 400,
        message: `Header mismatch: Mcp-Name header is required for ${body.method}`,
      };
    }
    if (decodeHeaderValue(headerName) !== bodyName) {
      return {
        code: HEADER_MISMATCH,
        status: 400,
        message: `Header mismatch: Mcp-Name header value does not match body value '${String(bodyName)}'`,
      };
    }
  }

  return null;
}

/**
 * Whether an Origin header is acceptable.
 *
 * Servers MUST validate Origin to prevent DNS rebinding. An absent Origin is
 * allowed — non-browser MCP clients do not send one, and rejecting those would
 * break every legitimate caller to guard against an attack that only browsers
 * can mount.
 */
export function originAllowed(
  origin: string | null,
  resourceUrl: string,
): boolean {
  if (!origin) return true;
  let expected: string;
  try {
    expected = new URL(resourceUrl).origin;
  } catch {
    return false;
  }
  return origin === expected;
}
