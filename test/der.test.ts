// The PKCS#1 -> PKCS#8 wrapper in src/github.ts, checked against keys OpenSSL
// generated rather than against the byte layout it was written to produce.
//
// GitHub hands out PKCS#1 ("BEGIN RSA PRIVATE KEY"); WebCrypto's importKey
// takes only PKCS#8. A subtly wrong DER envelope yields a key that imports at
// one modulus size and fails at another — an intermittent production auth
// failure rather than an error at build time.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, webcrypto } from "node:crypto";
import { derLength, pemBody, pkcs1ToPkcs8 } from "../src/github";

for (const modulusLength of [2048, 3072, 4096]) {
  test(`RSA-${modulusLength}: wrapper output is byte-identical to real PKCS#8`, () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength });
    const { der: pkcs1 } = pemBody(
      privateKey.export({ type: "pkcs1", format: "pem" }) as string,
    );
    const { der: real } = pemBody(
      privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    );
    assert.deepEqual([...pkcs1ToPkcs8(pkcs1)], [...real]);
  });

  test(`RSA-${modulusLength}: WebCrypto imports the wrapped key and signs`, async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength });
    const { der: pkcs1 } = pemBody(
      privateKey.export({ type: "pkcs1", format: "pem" }) as string,
    );
    const key = await webcrypto.subtle.importKey(
      "pkcs8",
      pkcs1ToPkcs8(pkcs1),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await webcrypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode("header.payload"),
    );
    assert.equal(sig.byteLength, modulusLength / 8);
  });
}

test("pemBody distinguishes PKCS#1 from PKCS#8", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.equal(
    pemBody(privateKey.export({ type: "pkcs1", format: "pem" }) as string)
      .pkcs1,
    true,
  );
  assert.equal(
    pemBody(privateKey.export({ type: "pkcs8", format: "pem" }) as string)
      .pkcs1,
    false,
  );
});

test("pemBody rejects a non-PEM value rather than producing a junk key", () => {
  assert.throws(() => pemBody("not a pem at all"), /empty or not a PEM/);
});

test("derLength uses short form below 128 and long form at or above it", () => {
  // The long-form boundary is where a hand-rolled DER encoder usually breaks,
  // and every RSA key body of interest sits well past it.
  assert.deepEqual(derLength(0), [0]);
  assert.deepEqual(derLength(127), [127]);
  assert.deepEqual(derLength(128), [0x81, 128]);
  assert.deepEqual(derLength(255), [0x81, 255]);
  assert.deepEqual(derLength(256), [0x82, 1, 0]);
  assert.deepEqual(derLength(65535), [0x82, 255, 255]);
  assert.deepEqual(derLength(65536), [0x83, 1, 0, 0]);
});
