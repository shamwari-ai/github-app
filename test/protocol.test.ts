// Dual-era protocol handling: era detection, the 2026-07-28 mirrored-header
// rules, and Origin validation.
//
// The mirrored headers exist so intermediaries can route and rate-limit
// without parsing the body. Validating them is what stops a proxy and this
// worker acting on different values for the same request, so each failure
// mode gets its own case rather than one happy-path check.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  HEADER_MISMATCH,
  LEGACY_VERSION,
  MODERN_VERSION,
  UNSUPPORTED_PROTOCOL_VERSION,
  decodeHeaderValue,
  declaredVersion,
  detectEra,
  originAllowed,
  validateModernRequest,
  type JsonRpcLike,
} from "../src/protocol";

const META = "io.modelcontextprotocol/protocolVersion";

const modernBody = (
  method: string,
  params: Record<string, unknown> = {},
  version = MODERN_VERSION,
): JsonRpcLike => ({
  jsonrpc: "2.0",
  id: 1,
  method,
  params: { ...params, _meta: { [META]: version } },
});

const hdrs = (o: Record<string, string>) => new Headers(o);

// --- era detection --------------------------------------------------------

test("a request declaring a version is modern", () => {
  assert.equal(detectEra(modernBody("tools/list")), "modern");
});

test("initialize is always legacy, even carrying modern metadata", () => {
  // `initialize` does not exist in the modern revision, and the spec says an
  // initialize request selects legacy semantics. Routing it as modern would
  // answer a legacy client with a 404 for the only method it knows.
  assert.equal(detectEra(modernBody("initialize")), "legacy");
});

test("a request with no declared version is legacy", () => {
  assert.equal(
    detectEra({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    "legacy",
  );
});

test("a non-string version is not a declaration", () => {
  assert.equal(
    declaredVersion({ method: "x", params: { _meta: { [META]: 42 } } }),
    undefined,
  );
});

// --- header validation ----------------------------------------------------

test("a correctly mirrored request validates", () => {
  assert.equal(
    validateModernRequest(
      hdrs({
        "MCP-Protocol-Version": MODERN_VERSION,
        "Mcp-Method": "tools/list",
      }),
      modernBody("tools/list"),
    ),
    null,
  );
});

test("a missing MCP-Protocol-Version header is a header mismatch", () => {
  const e = validateModernRequest(
    hdrs({ "Mcp-Method": "tools/list" }),
    modernBody("tools/list"),
  );
  assert.equal(e?.code, HEADER_MISMATCH);
  assert.equal(e?.status, 400);
});

test("a version header that disagrees with the body is refused", () => {
  // The whole point of mirroring: if these can disagree, a router and the
  // server can act on different versions of the same request.
  const e = validateModernRequest(
    hdrs({ "MCP-Protocol-Version": "2025-11-25", "Mcp-Method": "tools/list" }),
    modernBody("tools/list"),
  );
  assert.equal(e?.code, HEADER_MISMATCH);
  assert.match(e!.message, /does not match body value/);
});

test("an unsupported version returns the supported list", () => {
  const e = validateModernRequest(
    hdrs({ "MCP-Protocol-Version": "1900-01-01", "Mcp-Method": "tools/list" }),
    modernBody("tools/list", {}, "1900-01-01"),
  );
  assert.equal(e?.code, UNSUPPORTED_PROTOCOL_VERSION);
  assert.equal(e?.status, 400);
  assert.deepEqual(e?.data, {
    supported: [MODERN_VERSION],
    requested: "1900-01-01",
  });
});

test("the legacy version is not accepted on the modern path", () => {
  // It is handshake-based. Listing it as a per-request option would invite a
  // retry that fails identically.
  const e = validateModernRequest(
    hdrs({
      "MCP-Protocol-Version": LEGACY_VERSION,
      "Mcp-Method": "tools/list",
    }),
    modernBody("tools/list", {}, LEGACY_VERSION),
  );
  assert.equal(e?.code, UNSUPPORTED_PROTOCOL_VERSION);
});

test("a missing or mismatched Mcp-Method is refused", () => {
  assert.equal(
    validateModernRequest(
      hdrs({ "MCP-Protocol-Version": MODERN_VERSION }),
      modernBody("tools/list"),
    )?.code,
    HEADER_MISMATCH,
  );
  assert.equal(
    validateModernRequest(
      hdrs({
        "MCP-Protocol-Version": MODERN_VERSION,
        "Mcp-Method": "tools/call",
      }),
      modernBody("tools/list"),
    )?.code,
    HEADER_MISMATCH,
  );
});

test("tools/call requires an Mcp-Name matching params.name", () => {
  const body = modernBody("tools/call", { name: "github_whoami" });
  const base = {
    "MCP-Protocol-Version": MODERN_VERSION,
    "Mcp-Method": "tools/call",
  };
  assert.equal(validateModernRequest(hdrs(base), body)?.code, HEADER_MISMATCH);
  assert.equal(
    validateModernRequest(
      hdrs({ ...base, "Mcp-Name": "github_get_issue" }),
      body,
    )?.code,
    HEADER_MISMATCH,
  );
  assert.equal(
    validateModernRequest(hdrs({ ...base, "Mcp-Name": "github_whoami" }), body),
    null,
  );
});

test("resources/read mirrors params.uri, not params.name", () => {
  const body = modernBody("resources/read", { uri: "file:///a.json" });
  assert.equal(
    validateModernRequest(
      hdrs({
        "MCP-Protocol-Version": MODERN_VERSION,
        "Mcp-Method": "resources/read",
        "Mcp-Name": "file:///a.json",
      }),
      body,
    ),
    null,
  );
});

test("a method with no name source does not require Mcp-Name", () => {
  assert.equal(
    validateModernRequest(
      hdrs({
        "MCP-Protocol-Version": MODERN_VERSION,
        "Mcp-Method": "server/discover",
      }),
      modernBody("server/discover"),
    ),
    null,
  );
});

// --- Base64 sentinel ------------------------------------------------------

test("a Base64-sentinel Mcp-Name is decoded before comparison", () => {
  // A non-ASCII tool name or resource URI arrives encoded. Comparing without
  // decoding would reject a perfectly valid call as a header mismatch.
  const uri = "file:///世界.json";
  const encoded = `=?base64?${Buffer.from(uri, "utf8").toString("base64")}?=`;
  assert.equal(decodeHeaderValue(encoded), uri);
  assert.equal(
    validateModernRequest(
      hdrs({
        "MCP-Protocol-Version": MODERN_VERSION,
        "Mcp-Method": "resources/read",
        "Mcp-Name": encoded,
      }),
      modernBody("resources/read", { uri }),
    ),
    null,
  );
});

test("a plain header value passes through unchanged", () => {
  assert.equal(decodeHeaderValue("github_whoami"), "github_whoami");
});

test("an undecodable sentinel fails the comparison rather than throwing", () => {
  // Returning the raw value means a malformed header is a 400 header
  // mismatch, which is the correct outcome — not a 500.
  assert.doesNotThrow(() => decodeHeaderValue("=?base64?!!!not-base64!!!?="));
});

// --- Origin ---------------------------------------------------------------

test("Origin validation allows the resource's own origin and refuses others", () => {
  const resource = "https://github.nyuchi.dev/mcp";
  assert.equal(originAllowed("https://github.nyuchi.dev", resource), true);
  assert.equal(originAllowed("https://evil.example.com", resource), false);
});

test("an absent Origin is allowed", () => {
  // Non-browser MCP clients send none. Rejecting them would break every
  // legitimate caller to guard against an attack only browsers can mount.
  assert.equal(originAllowed(null, "https://github.nyuchi.dev/mcp"), true);
});
