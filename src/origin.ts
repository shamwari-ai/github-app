// Origin validation for the MCP endpoint. Everything else about the protocol
// (versions, eras, headers, JSON-RPC) is the MCP SDK's job.

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
