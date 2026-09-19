// The WorkOS token gate, exercised against real RS256 signatures.
//
// These cover the fail-closed behaviour specifically. The issuer and audience
// checks were originally written as `if (env.X) { ...check... }`, which reads
// as "check it when configured" and behaves as "accept anything when an
// operator forgets it". That shipped, and the live worker ran for a while
// verifying signature, org and role but neither issuer nor audience — so a
// token minted for a different MCP resource in the same WorkOS environment
// would have been accepted here. These tests exist so that cannot return.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, webcrypto } from "node:crypto";
import type { Env } from "../src/env";
import { verifyWorkosToken } from "../src/auth";

const ISSUER = "https://accounts.mukoko.com";
const AUDIENCE = "https://github.shamwari.ai/mcp";
const JWKS_URL = "https://accounts.mukoko.com/oauth2/jwks";
const ORG = "org_01KRDAB894DJF5V38PT5617TV1";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const pubJwk = publicKey.export({ format: "jwk" }) as {
  n: string;
  e: string;
  kty: string;
};
const KID = "test-key-1";

const b64url = (b: Buffer | Uint8Array) =>
  Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

async function mintToken(claims: Record<string, unknown>): Promise<string> {
  const header = { alg: "RS256", typ: "JWT", kid: KID };
  const now = Math.floor(Date.now() / 1000);
  const payload = { iat: now, exp: now + 3600, ...claims };
  const unsigned = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(payload)),
  )}`;
  const key = await webcrypto.subtle.importKey(
    "pkcs8",
    privateKey.export({ type: "pkcs8", format: "der" }) as Uint8Array,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await webcrypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );
  return `${unsigned}.${b64url(new Uint8Array(sig))}`;
}

const realFetch = globalThis.fetch;
before(() => {
  globalThis.fetch = (async (url: string) => {
    if (String(url) === JWKS_URL) {
      return new Response(
        JSON.stringify({
          keys: [{ ...pubJwk, kid: KID, alg: "RS256", use: "sig" }],
        }),
        { status: 200 },
      );
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;
});
after(() => {
  globalThis.fetch = realFetch;
});

const env = (over: Partial<Env> = {}): Env =>
  ({
    WORKOS_JWKS_URL: JWKS_URL,
    WORKOS_ISSUER: ISSUER,
    WORKOS_AUDIENCE: AUDIENCE,
    WORKOS_ORG_ID: ORG,
    WORKOS_REQUIRED_ROLES: "platform-team",
    WORKOS_REQUIRED_PERMISSIONS: "mongodb:access",
    ...over,
  }) as Env;

const goodClaims = {
  iss: ISSUER,
  aud: AUDIENCE,
  org_id: ORG,
  role: "platform-team",
};

test("a correctly-scoped token is accepted", async () => {
  const claims = await verifyWorkosToken(await mintToken(goodClaims), env());
  assert.equal(claims.iss, ISSUER);
});

test("an unset WORKOS_ISSUER is refused, not skipped", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken(goodClaims),
      env({ WORKOS_ISSUER: undefined }),
    ),
    /WORKOS_ISSUER unset/,
  );
});

test("an unset WORKOS_AUDIENCE is refused, not skipped", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken(goodClaims),
      env({ WORKOS_AUDIENCE: undefined }),
    ),
    /WORKOS_AUDIENCE unset/,
  );
});

test("a token minted for another MCP resource is refused", async () => {
  // The case the audience check exists for: same environment, same org, same
  // role, valid signature — but issued to a different resource.
  await assert.rejects(
    verifyWorkosToken(
      await mintToken({ ...goodClaims, aud: "https://mongodb.nyuchi.dev/mcp" }),
      env(),
    ),
    /audience mismatch/,
  );
});

test("a token from another issuer is refused", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken({ ...goodClaims, iss: "https://evil.example.com" }),
      env(),
    ),
    /issuer mismatch/,
  );
});

test("a token from another organization is refused", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken({ ...goodClaims, org_id: "org_someone_else" }),
      env(),
    ),
    /organization not permitted/,
  );
});

test("an org member with neither the role nor the permission is refused", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken({ ...goodClaims, role: "member" }),
      env(),
    ),
    /missing required platform role\/permission/,
  );
});

test("the permission alone satisfies the gate", async () => {
  const claims = await verifyWorkosToken(
    await mintToken({
      ...goodClaims,
      role: "member",
      permissions: ["mongodb:access"],
    }),
    env(),
  );
  assert.equal(claims.org_id, ORG);
});

test("an expired token is refused", async () => {
  const now = Math.floor(Date.now() / 1000);
  await assert.rejects(
    verifyWorkosToken(await mintToken({ ...goodClaims, exp: now - 10 }), env()),
    /token expired/,
  );
});

test("an unset WORKOS_JWKS_URL is refused", async () => {
  await assert.rejects(
    verifyWorkosToken(
      await mintToken(goodClaims),
      env({ WORKOS_JWKS_URL: undefined }),
    ),
    /WORKOS_JWKS_URL unset/,
  );
});
