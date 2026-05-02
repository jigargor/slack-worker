import { AGENT_IDS, ALL_AGENTS, ROUTING_RULES, USE_THREADS } from "./config";

interface Env {
  KV: KVNamespace;
  SLACK_CLIENT_ID: string;
  SLACK_CLIENT_SECRET: string;
  SLACK_SIGNING_SECRET: string;
  SLACK_SCOPES: string;
  SLACK_REDIRECT_URI?: string;
  SLACK_BOT_TOKEN?: string;
  CURSOR_API_KEY?: string;
}

interface CursorDispatchResult {
  ok: boolean;
  target: string;
  status?: number;
  error?: string;
  runId?: string;
}

const BRIDGE_MARKER = "[bridge]";
const HISTORY_ONCE_TTL_SECONDS = 60 * 60 * 24;
const HISTORY_LIMIT = 8;
const HERE_MENTION_RE = /(?:<!here>|@here)/i;

// ── Helpers ──────────────────────────────────────────────────────────

async function hmacSha256(secret: string, data: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
}

function timeSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomState(): string {
  return hex(crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

function addBridgeMarker(text: string): string {
  if (text.startsWith(BRIDGE_MARKER)) return text;
  return `${BRIDGE_MARKER} ${text}`;
}

function normalizeSlackText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

async function fetchThreadHistory(
  token: string,
  channel: string,
  rootTs: string,
): Promise<string> {
  const params = new URLSearchParams({
    channel,
    ts: rootTs,
    inclusive: "true",
    limit: String(HISTORY_LIMIT),
  });

  const response = await fetch(`https://slack.com/api/conversations.replies?${params}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  const payload = (await response.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: string;
    messages?: Array<{ text?: string; user?: string; bot_id?: string; ts?: string }>;
  };

  if (!response.ok || !payload.ok || !payload.messages?.length) {
    console.error("conversations.replies failed", {
      status: response.status,
      error: payload.error,
      channel,
      rootTs,
    });
    return "";
  }

  return payload.messages
    .map((message) => {
      const author = message.user ?? (message.bot_id ? `bot:${message.bot_id}` : "unknown");
      const text = normalizeSlackText(message.text ?? "");
      if (!text) return "";
      return `- (${message.ts ?? "no-ts"}) ${author}: ${text}`;
    })
    .filter(Boolean)
    .join("\n");
}

async function fetchChannelHistory(
  token: string,
  channel: string,
  latestTs: string,
): Promise<string> {
  const params = new URLSearchParams({
    channel,
    latest: latestTs,
    inclusive: "true",
    limit: String(HISTORY_LIMIT),
  });

  const response = await fetch(`https://slack.com/api/conversations.history?${params}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  const payload = (await response.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: string;
    messages?: Array<{ text?: string; user?: string; bot_id?: string; ts?: string }>;
  };

  if (!response.ok || !payload.ok || !payload.messages?.length) {
    console.error("conversations.history failed", {
      status: response.status,
      error: payload.error,
      channel,
      latestTs,
    });
    return "";
  }

  // Slack returns newest-first; reverse for readable chronology.
  return [...payload.messages]
    .reverse()
    .map((message) => {
      const author = message.user ?? (message.bot_id ? `bot:${message.bot_id}` : "unknown");
      const text = normalizeSlackText(message.text ?? "");
      if (!text) return "";
      return `- (${message.ts ?? "no-ts"}) ${author}: ${text}`;
    })
    .filter(Boolean)
    .join("\n");
}

async function getOneTimeHistoryContext(
  env: Env,
  botToken: string,
  channel: string,
  messageTs: string,
  threadTs?: string,
): Promise<string> {
  if (!botToken || !channel || !messageTs) return "";

  const scopeTs = threadTs ?? messageTs;
  const markerKey = `ctx_once:${channel}:${scopeTs}`;
  const alreadySent = await env.KV.get(markerKey);
  if (alreadySent) return "";

  const history = threadTs
    ? await fetchThreadHistory(botToken, channel, threadTs)
    : await fetchChannelHistory(botToken, channel, messageTs);
  if (!history) return "";

  await env.KV.put(markerKey, "1", { expirationTtl: HISTORY_ONCE_TTL_SECONDS });
  const label = threadTs ? "thread" : "channel";
  return `Recent Slack ${label} context (one-time):\n${history}\n\n`;
}

// ── Slack signature verification ─────────────────────────────────────

async function verifySlackSignature(
  signingSecret: string,
  signature: string | null,
  timestamp: string | null,
  body: string,
): Promise<boolean> {
  if (!signature || !timestamp) return false;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 300) return false;

  const basestring = `v0:${timestamp}:${body}`;
  const digest = hex(await hmacSha256(signingSecret, basestring));
  return timeSafeEqual(`v0=${digest}`, signature);
}

// ── Route: GET / ─────────────────────────────────────────────────────

function handleRoot(): Response {
  return htmlResponse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>mem-ache Slack Bot</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:4rem auto;text-align:center}
a{display:inline-block;padding:.75rem 1.5rem;background:#4A154B;color:#fff;border-radius:6px;text-decoration:none;font-weight:600}
a:hover{opacity:.9}</style></head>
<body><h2>mem-ache Slack Bot</h2><p>Personal bot for agent communication.</p>
<a href="/slack/install">Add to Slack</a></body></html>`);
}

// ── Route: GET /healthz ──────────────────────────────────────────────

function handleHealthz(): Response {
  return jsonResponse({ ok: true });
}

// ── Route: GET /slack/install ────────────────────────────────────────

async function handleInstall(env: Env): Promise<Response> {
  const state = randomState();
  await env.KV.put(`oauth_state:${state}`, "1", { expirationTtl: 300 });

  const redirectUri = env.SLACK_REDIRECT_URI ?? "";
  const params = new URLSearchParams({
    client_id: env.SLACK_CLIENT_ID,
    scope: env.SLACK_SCOPES,
    redirect_uri: redirectUri,
    state,
  });

  return Response.redirect(`https://slack.com/oauth/v2/authorize?${params}`, 302);
}

// ── Route: GET /slack/oauth/callback ─────────────────────────────────

async function handleOAuthCallback(url: URL, env: Env): Promise<Response> {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) return htmlResponse(`<p>Installation cancelled: ${error}</p>`, 400);
  if (!code || !state) return htmlResponse("<p>Bad request: missing code or state.</p>", 400);

  const stored = await env.KV.get(`oauth_state:${state}`);
  if (!stored) return htmlResponse("<p>Invalid or expired state.</p>", 400);
  await env.KV.delete(`oauth_state:${state}`);

  const redirectUri = env.SLACK_REDIRECT_URI ?? "";
  const resp = await fetch("https://slack.com/api/oauth.v2.access", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.SLACK_CLIENT_ID,
      client_secret: env.SLACK_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });

  const data = (await resp.json()) as Record<string, unknown>;
  if (!data.ok) {
    console.error("oauth.v2.access error", data.error);
    return htmlResponse("<p>Slack OAuth failed. Check logs.</p>", 500);
  }

  const botToken = (data.access_token as string) ?? "";
  const teamName = ((data.team as Record<string, string>)?.name) ?? "workspace";

  // Store token for later use if KV is available
  if (botToken) {
    await env.KV.put("slack_bot_token", botToken);
  }

  return htmlResponse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Installed</title></head>
<body style="font-family:system-ui,sans-serif;max-width:420px;margin:4rem auto;text-align:center">
<h2>Installed to ${teamName}</h2><p>You can close this tab.</p></body></html>`);
}

// ── Route: POST /slack/events ────────────────────────────────────────

const TAG_RE = /^\[([a-z0-9_-]+):([a-z0-9_-]+)\]/i;

interface SlackEvent {
  type: string;
  event_id?: string;
  event?: {
    type: string;
    subtype?: string;
    text?: string;
    user?: string;
    ts?: string;
    thread_ts?: string;
    channel?: string;
    bot_id?: string;
  };
  challenge?: string;
}

async function handleSlackEvents(request: Request, env: Env): Promise<Response> {
  const body = await request.text();

  const valid = await verifySlackSignature(
    env.SLACK_SIGNING_SECRET,
    request.headers.get("x-slack-signature"),
    request.headers.get("x-slack-request-timestamp"),
    body,
  );
  if (!valid) return jsonResponse({ error: "invalid signature" }, 401);

  const payload = JSON.parse(body) as SlackEvent;
  console.log("Slack event received", {
    type: payload.type,
    eventId: payload.event_id,
  });

  // URL verification challenge
  if (payload.type === "url_verification") {
    return jsonResponse({ challenge: payload.challenge });
  }

  // Deduplicate via event_id
  const eventId = payload.event_id;
  if (eventId) {
    const seen = await env.KV.get(`evt:${eventId}`);
    if (seen) return jsonResponse({ ok: true, deduped: true });
    await env.KV.put(`evt:${eventId}`, "1", { expirationTtl: 3600 });
  }

  const evt = payload.event;
  if (!evt || evt.type !== "message" || evt.bot_id || !evt.text) {
    console.log("Slack event ignored before routing", {
      hasEvent: Boolean(evt),
      eventType: evt?.type,
      subtype: evt?.subtype,
      hasBotId: Boolean(evt?.bot_id),
      hasText: Boolean(evt?.text),
    });
    return jsonResponse({ ok: true });
  }

  const trimmedText = evt.text.trim();
  const match = TAG_RE.exec(trimmedText);
  let senderTag = "";
  let messageType = "";

  if (match) {
    senderTag = match[1].toLowerCase();
    messageType = match[2].toLowerCase();
  } else if (HERE_MENTION_RE.test(trimmedText)) {
    // Team shorthand: @here means broadcast request to both agents.
    senderTag = "jigar";
    messageType = "question";
    console.log("Using @here fallback routing", {
      senderTag,
      messageType,
      textPreview: trimmedText.slice(0, 120),
    });
  } else {
    console.log("Slack message missing bridge tag", {
      textPreview: trimmedText.slice(0, 120),
    });
    return jsonResponse({ ok: true });
  }

  if (messageType === "escalate") {
    return jsonResponse({ ok: true, escalated: true });
  }

  const targets = resolveTargets(senderTag, messageType);
  if (targets.length === 0) {
    console.log("No routing target for tag", { senderTag, messageType });
    return jsonResponse({ ok: true });
  }

  const botToken = env.SLACK_BOT_TOKEN ?? (await env.KV.get("slack_bot_token")) ?? "";
  const cursorKey = (env.CURSOR_API_KEY ?? "").trim();
  const historyContext = await getOneTimeHistoryContext(
    env,
    botToken,
    evt.channel ?? "",
    evt.ts ?? "",
    evt.thread_ts,
  );
  const dispatchOutcomes: CursorDispatchResult[] = [];
  console.log("Dispatch attempt", {
    senderTag,
    messageType,
    targets,
    hasCursorKey: Boolean(cursorKey),
    hasBotToken: Boolean(botToken),
  });

  for (const target of targets) {
    const prompt = buildPrompt(
      target,
      senderTag,
      evt.text ?? "",
      evt.ts ?? "",
      evt.thread_ts,
      historyContext,
    );

    if (cursorKey) {
      const result = await dispatchToCursor(cursorKey, target, prompt);
      dispatchOutcomes.push(result);
      if (!result.ok) {
        console.error("Cursor dispatch failed", result);
        if (botToken) {
          await postToSlack(
            botToken,
            evt.channel ?? "",
            evt.ts ?? "",
            `[bridge:error] Cursor dispatch to ${target} failed` +
              ` (status=${result.status ?? "n/a"}${result.error ? `, error=${result.error}` : ""}).`,
          );
        }
      } else {
        console.log(`Cursor dispatch succeeded for ${target}`, { runId: result.runId });
      }
    } else if (botToken) {
      await postToSlack(botToken, evt.channel ?? "", evt.ts ?? "",
        `[bridge:info] Would dispatch to ${target} but CURSOR_API_KEY is not set.`);
    }
  }

  if (cursorKey && botToken && dispatchOutcomes.length > 0) {
    const okTargets = dispatchOutcomes.filter((o) => o.ok).map((o) => o.target);
    const failedTargets = dispatchOutcomes
      .filter((o) => !o.ok)
      .map((o) => `${o.target}${o.status ? `(${o.status})` : ""}`);
    const parts: string[] = [];
    if (okTargets.length > 0) parts.push(`dispatched to ${okTargets.join(", ")}`);
    if (failedTargets.length > 0) parts.push(`failed for ${failedTargets.join(", ")}`);
    await postToSlack(
      botToken,
      evt.channel ?? "",
      evt.ts ?? "",
      `[bridge:dispatch] ${parts.join(" | ")}`,
    );
  }

  return jsonResponse({ ok: true, dispatched: targets });
}

// ── Routing logic (driven by config.yaml via src/config.ts) ──────────

function resolveTargets(sender: string, msgType: string): string[] {
  let senderFallbackRoute: string | undefined;
  for (const rule of ROUTING_RULES) {
    if (rule.prefix !== sender) continue;

    if (!senderFallbackRoute) senderFallbackRoute = rule.route;

    if (rule.type === msgType) {
      if (rule.route === "both") {
        return ALL_AGENTS.filter((a) => a !== sender);
      }
      return rule.route !== sender ? [rule.route] : [];
    }
  }

  // If message type is new/unknown, still route by sender family.
  if (senderFallbackRoute) {
    if (senderFallbackRoute === "both") {
      return ALL_AGENTS.filter((a) => a !== sender);
    }
    return senderFallbackRoute !== sender ? [senderFallbackRoute] : [];
  }

  return [];
}

function buildPrompt(
  target: string,
  sender: string,
  text: string,
  ts: string,
  threadTs?: string,
  historyContext = "",
): string {
  const threadCtx = threadTs ? `This is a thread reply. Thread parent ts: ${threadTs}. ` : "";
  return (
    `You have a new message from ${sender}.\n\n${threadCtx}` +
    historyContext +
    `Message:\n${text}\n\n` +
    `Before replying, read relevant Slack history/context with Slack tools.\n` +
    `Read the message. Post a [${target}:response] reply in the thread ` +
    `(use thread_ts=${ts}). Use the Slack MCP tools to read context and respond.`
  );
}

// ── Cursor Cloud Agents dispatch ─────────────────────────────────────

async function dispatchToCursor(
  apiKey: string,
  target: string,
  prompt: string,
): Promise<CursorDispatchResult> {
  const agentId = AGENT_IDS[target];
  if (!agentId) {
    return { ok: false, target, error: "missing agent id in AGENT_IDS" };
  }

  const auth = btoa(`${apiKey}:`);
  try {
    const response = await fetch(`https://api.cursor.com/v1/agents/${agentId}/runs`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ prompt: { text: prompt } }),
    });

    const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) {
      const error = typeof payload.error === "string"
        ? payload.error
        : typeof payload.message === "string"
          ? payload.message
          : "unknown cursor api error";
      return { ok: false, target, status: response.status, error };
    }

    const runId = typeof payload.id === "string" ? payload.id : undefined;
    return { ok: true, target, status: response.status, runId };
  } catch (err) {
    console.error(`Dispatch to ${target} failed:`, err);
    const error = err instanceof Error ? err.message : "unknown fetch error";
    return { ok: false, target, error };
  }
}

// ── Slack post helper ────────────────────────────────────────────────

async function postToSlack(
  token: string, channel: string, threadTs: string, text: string,
): Promise<void> {
  const markedText = addBridgeMarker(text);
  await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ channel, ...(USE_THREADS ? { thread_ts: threadTs } : {}), text: markedText }),
  });
}

// ── Main fetch handler ───────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    console.log("Incoming request", { method, path: url.pathname });

    if (method === "GET") {
      switch (url.pathname) {
        case "/":
          return handleRoot();
        case "/healthz":
          return handleHealthz();
        case "/slack/install":
          return handleInstall(env);
        case "/slack/oauth/callback":
          return handleOAuthCallback(url, env);
      }
    }

    if (method === "POST" && url.pathname === "/slack/events") {
      return handleSlackEvents(request, env);
    }

    return jsonResponse({ error: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;
