// The review engine.
//
// Weighted towards annotateDiff, because that is where a defect is invisible:
// a wrong line number does not throw, it posts a careful-looking comment on
// unrelated code. The tests below pin exact numbers against a diff whose
// arithmetic is worked out by hand in the comments.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Env } from "../src/env";
import {
  anchor,
  annotateDiff,
  parseFindings,
  rank,
  renderBody,
  reviewPullRequest,
  truncate,
  type Finding,
} from "../src/review";

// @@ -10,6 +10,7 @@ — the new side starts at line 10.
//
//   10  const a = 1;      context
//   11  const b = 2;      context
//   --  const c = 3;      REMOVED, no new-file line
//   12  const c = 4;      ADDED
//   13  const d = 5;      ADDED
//   14  const e = 6;      context
//   15  return a;         context
const DIFF = `diff --git a/src/a.ts b/src/a.ts
index 1111111..2222222 100644
--- a/src/a.ts
+++ b/src/a.ts
@@ -10,6 +10,7 @@ function f() {
 const a = 1;
 const b = 2;
-const c = 3;
+const c = 4;
+const d = 5;
 const e = 6;
 return a;
`;

test("annotateDiff numbers added lines from the hunk header", () => {
  const { addedLines } = annotateDiff(DIFF);
  assert.deepEqual([...(addedLines.get("src/a.ts") ?? [])], [12, 13]);
});

test("a removed line never becomes a comment target", () => {
  const { addedLines, text } = annotateDiff(DIFF);
  // "const c = 3;" was removed. Nothing may anchor to it, and the line it
  // occupied (11 on the old side) belongs to `const b = 2;` on the new side.
  assert.ok(!addedLines.get("src/a.ts")?.has(11));
  assert.match(text, /-\s+\|const c = 3;/);
});

test("context lines advance the counter but are not targets", () => {
  const { text, addedLines } = annotateDiff(DIFF);
  assert.match(text, /^\s+14\|const e = 6;$/m);
  assert.ok(!addedLines.get("src/a.ts")?.has(14));
});

test("a new file numbers from 1", () => {
  const { addedLines } = annotateDiff(`diff --git a/new.ts b/new.ts
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.ts
@@ -0,0 +1,3 @@
+one
+two
+three
`);
  assert.deepEqual([...(addedLines.get("new.ts") ?? [])], [1, 2, 3]);
});

test("a rename attributes added lines to the new path, not the old", () => {
  const { addedLines } = annotateDiff(`diff --git a/old.ts b/renamed.ts
similarity index 90%
rename from old.ts
rename to renamed.ts
index 4444444..5555555 100644
--- a/old.ts
+++ b/renamed.ts
@@ -1,2 +1,3 @@
 keep
+added
 keep2
`);
  assert.deepEqual([...(addedLines.get("renamed.ts") ?? [])], [2]);
  assert.equal(addedLines.get("old.ts"), undefined);
});

test("several hunks in one file each restart from their own header", () => {
  const { addedLines } = annotateDiff(`diff --git a/m.ts b/m.ts
index 6666666..7777777 100644
--- a/m.ts
+++ b/m.ts
@@ -1,2 +1,3 @@
 a
+b
 c
@@ -50,2 +51,3 @@
 x
+y
 z
`);
  assert.deepEqual([...(addedLines.get("m.ts") ?? [])], [2, 52]);
});

test("two files do not share a line-number space", () => {
  const { addedLines } = annotateDiff(
    DIFF +
      `diff --git a/src/b.ts b/src/b.ts
index 8888888..9999999 100644
--- a/src/b.ts
+++ b/src/b.ts
@@ -1,1 +1,2 @@
 first
+second
`,
  );
  assert.deepEqual([...(addedLines.get("src/a.ts") ?? [])], [12, 13]);
  assert.deepEqual([...(addedLines.get("src/b.ts") ?? [])], [2]);
});

test("a binary file is noted, not numbered", () => {
  const { text, addedLines } = annotateDiff(`diff --git a/logo.png b/logo.png
index aaa..bbb 100644
Binary files a/logo.png and b/logo.png differ
`);
  assert.match(text, /binary file/);
  assert.equal(addedLines.size, 0);
});

// --- anchoring ------------------------------------------------------------

const f = (
  path: string,
  line: number,
  severity: Finding["severity"] = "note",
): Finding => ({
  path,
  line,
  severity,
  title: "t",
  body: "b",
});

test("a finding on a line the diff does not add is held back, not posted", () => {
  const { addedLines } = annotateDiff(DIFF);
  const { anchored, unanchored } = anchor(
    [f("src/a.ts", 12), f("src/a.ts", 99), f("other.ts", 12)],
    addedLines,
  );
  assert.deepEqual(
    anchored.map((x) => `${x.path}:${x.line}`),
    ["src/a.ts:12"],
  );
  // GitHub 422s the whole review call on one bad position — which would lose
  // every real finding alongside the invented one.
  assert.equal(unanchored.length, 2);
});

test("findings are ranked so a cap keeps the serious ones", () => {
  const ordered = rank([
    f("a", 1, "note"),
    f("a", 2, "blocking"),
    f("a", 3, "concern"),
  ]);
  assert.deepEqual(
    ordered.map((x) => x.severity),
    ["blocking", "concern", "note"],
  );
});

// --- model output is not trusted -----------------------------------------
//
// Cloudflare's JSON-mode docs say outright it "can't guarantee that the model
// responds according to the requested JSON Schema".

test("a JSON string response is parsed, an object response is taken as is", () => {
  const asString = parseFindings(
    JSON.stringify({ summary: "s", findings: [f("a.ts", 3)] }),
  );
  const asObject = parseFindings({ summary: "s", findings: [f("a.ts", 3)] });
  assert.deepEqual(asString, asObject);
});

test("malformed findings are dropped individually, not fatally", () => {
  const { findings } = parseFindings({
    summary: "s",
    findings: [
      f("good.ts", 5),
      { path: "", line: 5, body: "x", severity: "note" },
      { path: "a.ts", line: 0, body: "x", severity: "note" },
      { path: "a.ts", line: 2.5, body: "x", severity: "note" },
      { path: "a.ts", line: 5, body: "", severity: "note" },
      null,
      "not an object",
    ],
  });
  assert.deepEqual(
    findings.map((x) => x.path),
    ["good.ts"],
  );
});

test("an unknown severity degrades to note rather than throwing", () => {
  const { findings } = parseFindings({
    summary: "",
    findings: [{ path: "a.ts", line: 1, body: "b", severity: "CRITICAL!!" }],
  });
  assert.equal(findings[0].severity, "note");
});

test("a model that returns prose instead of JSON fails loudly", () => {
  assert.throws(
    () => parseFindings("I reviewed the code and it looks fine!"),
    /did not return JSON/,
  );
});

test("a missing findings array is an empty review, not a crash", () => {
  const { findings, summary } = parseFindings({ summary: "clean" });
  assert.deepEqual(findings, []);
  assert.equal(summary, "clean");
});

// --- the body a human reads ----------------------------------------------

test("unanchored findings appear in the body instead of vanishing", () => {
  const body = renderBody({
    model: "@cf/zai-org/glm-5.3",
    summary: "Checked the diff.",
    findings: [],
    unanchored: [{ ...f("src/a.ts", 99), title: "possible null" }],
    truncated: false,
  });
  assert.match(body, /src\/a\.ts:99/);
  assert.match(body, /possible null/);
});

test("the body says the reviewer cannot approve", () => {
  const body = renderBody({
    model: "m",
    summary: "s",
    findings: [],
    unanchored: [],
    truncated: false,
  });
  assert.match(body, /cannot approve/);
});

test("truncation is disclosed, because a partial read is not a clean review", () => {
  const body = renderBody({
    model: "m",
    summary: "s",
    findings: [],
    unanchored: [],
    truncated: true,
  });
  assert.match(body, /truncated/);
});

test("truncate cuts on a line boundary", () => {
  const { text, truncated } = truncate("aaaa\nbbbb\ncccc\n", 7);
  assert.equal(truncated, true);
  assert.equal(text, "aaaa\n");
});

test("text within budget is returned untouched", () => {
  const { text, truncated } = truncate("short", 100);
  assert.equal(truncated, false);
  assert.equal(text, "short");
});

// --- the guards that run before anything is spent ------------------------

test("the kill switch fails closed before any model call", async () => {
  await assert.rejects(
    reviewPullRequest(
      {
        REVIEW_ENABLED: "false",
        AI: { run: async () => ({}) },
      } as unknown as Env,
      "nyuchi/web-services",
      1,
    ),
    /disabled/,
  );
});

test("a missing AI binding says what to add rather than throwing on undefined", async () => {
  await assert.rejects(
    reviewPullRequest(
      { REVIEW_ENABLED: "true" } as unknown as Env,
      "nyuchi/web-services",
      1,
    ),
    /wrangler\.toml/,
  );
});
