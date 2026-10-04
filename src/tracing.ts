// Agent tracing — metadata only.
//
// The review agent owns its own turn (one model call, no AI SDK, no Think or
// Flue), so it is a "custom harness" in Cloudflare's agent-tracing terms: one
// `invoke_agent` span per review with a nested `chat` span for the model call.
// Both carry the three identity attributes the Agents dashboard keys on.
//
// METADATA ONLY, by owner decision. No `gen_ai.input.messages`,
// `gen_ai.output.messages` or `gen_ai.system_instructions` is ever set: the
// prompt is a diff of private work and the response is model prose about it.
// Repository and pull request number are already in every GitHub URL this
// worker touches, and neither identifies a person.
//
// `cloudflare:workers` only exists inside workerd. It is imported lazily and
// a failed import means "no tracing" rather than an error, so the unit tests
// (which run under Node) exercise the same code paths without a tracer.

type Attributes = Record<string, string | number | boolean | undefined>;

interface SpanLike {
  setAttributes(attributes: Attributes): unknown;
}

interface TracingLike {
  enterSpan<T>(name: string, callback: (span: SpanLike) => T): T;
}

export const AGENT_NAME = "shamwari-github-mcp";
/** A single deployed reviewer, so the agent id is as stable as its name. */
export const AGENT_ID = "shamwari-github-mcp/review";

let tracer: Promise<TracingLike | null> | undefined;

function getTracer(): Promise<TracingLike | null> {
  tracer ??= import("cloudflare:workers")
    .then((m) => (m as { tracing?: TracingLike }).tracing ?? null)
    .catch(() => null);
  return tracer;
}

/** The identity every agent span carries. `conversation` is opaque. */
export function identity(operation: string, conversation: string): Attributes {
  return {
    "gen_ai.operation.name": operation,
    "gen_ai.agent.name": AGENT_NAME,
    "gen_ai.agent.id": AGENT_ID,
    "gen_ai.conversation.id": conversation,
  };
}

/**
 * Run `fn` inside a span, or plainly when tracing is unavailable. Only the
 * scalar attributes passed here are recorded — never a payload.
 */
export async function inSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: SpanLike | null) => Promise<T>,
): Promise<T> {
  const t = await getTracer();
  if (!t) return fn(null);
  return t.enterSpan(name, (span) => {
    span.setAttributes(attributes);
    return fn(span);
  });
}
