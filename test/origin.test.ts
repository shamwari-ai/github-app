// Origin validation: the one protocol-adjacent rule this Worker still owns.

import { test } from "node:test";
import assert from "node:assert/strict";
import { originAllowed } from "../src/origin";

test("Origin validation allows the resource's own origin and refuses others", () => {
  const resource = "https://github.shamwari.ai/mcp";
  assert.equal(originAllowed("https://github.shamwari.ai", resource), true);
  assert.equal(originAllowed("https://evil.example.com", resource), false);
});

test("an absent Origin is allowed", () => {
  // Non-browser MCP clients send none. Rejecting them would break every
  // legitimate caller to guard against an attack only browsers can mount.
  assert.equal(originAllowed(null, "https://github.shamwari.ai/mcp"), true);
});
