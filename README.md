# slack-worker

Minimal Cloudflare Worker serving as the Slack OAuth install surface and Events API bridge for mem-ache agent communication.

## Routes

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Static install page with Add-to-Slack link |
| GET | `/healthz` | Health check |
| GET | `/slack/install` | Redirects to Slack OAuth authorize |
| GET | `/slack/oauth/callback` | Exchanges code for token server-side |
| POST | `/slack/events` | Receives Slack Events API payloads |

## Setup

### 1. Create Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app.
2. Under **OAuth & Permissions**, add scopes: `chat:write`, `channels:history`.
3. Under **Event Subscriptions**, enable events and set the Request URL to `https://slack.<yourdomain>/slack/events`.
4. Subscribe to bot events: `message.channels`.
5. Under **OAuth & Permissions**, set the Redirect URL to `https://slack.<yourdomain>/slack/oauth/callback`.
6. Note your **Client ID**, **Client Secret**, and **Signing Secret**.

### 2. Create KV Namespace

```sh
npx wrangler kv namespace create KV
```

Copy the `id` into `wrangler.toml`.

### 3. Set Secrets

```sh
npx wrangler secret put SLACK_CLIENT_ID
npx wrangler secret put SLACK_CLIENT_SECRET
npx wrangler secret put SLACK_SIGNING_SECRET
npx wrangler secret put SLACK_BOT_TOKEN       # after installing
npx wrangler secret put CURSOR_API_KEY         # for agent dispatch
```

### 4. Configure Domain

Update `wrangler.toml` with your custom domain route, or use the default `*.workers.dev` URL for initial testing.

Set `SLACK_REDIRECT_URI` in `wrangler.toml` `[vars]` to match the Slack app Redirect URL exactly.

### 5. Deploy

```sh
npm run deploy
```

### 6. Local Development

```sh
# Create .dev.vars with secrets for local testing
# SLACK_CLIENT_ID=...
# SLACK_CLIENT_SECRET=...
# SLACK_SIGNING_SECRET=...
npm run dev
```

## Event Flow

1. A tagged message like `[plat:question] How should we structure X?` is posted in the configured Slack channel.
2. Slack pushes the event to `POST /slack/events`.
3. The Worker verifies the Slack signature, deduplicates via `event_id` in KV, parses the tag, and dispatches to the target Cursor Cloud Agent.
4. The target agent reads context via Slack MCP tools and posts a `[target:response]` reply in the thread.
