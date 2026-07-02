# Cloudflare Audit Logs v2 to Google Chat Webhook

Send Cloudflare Audit Logs v2 events to Google Chat with an auditor-friendly format (`who`, `when`, `what`, `old vs new`) using Cloudflare Workers.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/pongpisit/cf-audit-gchat-webhook)

## Features

- Polls Cloudflare Audit Logs v2 (`/accounts/{account_id}/logs/audit`)
- Pushes structured Google Chat cards with concise audit focus
- Dedupes events across cron runs
- Keeps a delivery ledger in KV for verification (`/ledger`)
- Supports severity tagging and event categories
- Supports optional multi-webhook routing (security/config/default)
- Includes daily summary card (`/summary` + daily cron)

## Architecture

- **Worker cron (`*/1 * * * *`)**: fetch new events, dedupe, send cards
- **Worker cron (`0 0 * * *`)**: send daily summary
- **KV (`STATE`)**:
  - Cursor: `cursor:last_seen_iso`
  - Dedupe: `dedupe:<event_id>`
  - Ledger by event: `ledger:event:<event_id>`
  - Ledger recent index: `ledger:recent:<reverse_ts>:<event_id>`

```mermaid
flowchart TD
    A[Cloudflare Audit Logs v2 API] -->|since/before/cursor| B[Worker Cron Poller]
    B --> C[Filter + Severity + Routing]
    C --> D[Dedup Check in KV]
    D --> E[Google Chat Webhook\nCardsV2 Auditor View]
    E --> F[Mark Sent + Write Ledger in KV]
    G[Daily Cron 00:00 UTC] --> H[24h Summary Builder]
    H --> E
    I[/run endpoint] --> B
    J[/summary endpoint] --> H
    K[/ledger endpoint] --> L[Ledger Query from KV]
```

## Prerequisites

- Cloudflare account
- Google Chat incoming webhook URL
- API token with account audit log read access

Cloudflare docs:
- Audit Logs v2: https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/

## Setup

1. Install dependencies:

```bash
npm install
```

2. Create KV namespace and set it in `wrangler.jsonc`:

```bash
npx wrangler kv namespace create STATE
```

3. Update `wrangler.jsonc`:

- `account_id`: your account ID
- `kv_namespaces[0].id`: your KV namespace ID

4. Set required secrets:

```bash
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put GCHAT_WEBHOOK_URL
```

5. Optional secrets:

```bash
npx wrangler secret put GCHAT_WEBHOOK_SECURITY
npx wrangler secret put GCHAT_WEBHOOK_CONFIG
npx wrangler secret put ALERT_MODE
npx wrangler secret put ALERT_ACTION_ALLOWLIST
```

## Deploy

```bash
npm run deploy
```

## One-Click Deploy

1. Click the **Deploy to Cloudflare** button at the top of this README.
2. Connect your GitHub repo/fork and complete the Worker deployment flow.
3. Add required secrets in Worker settings or via Wrangler:
   - `CF_ACCOUNT_ID`
   - `CF_API_TOKEN`
   - `GCHAT_WEBHOOK_URL`
4. Create KV namespace `STATE`, then set its ID in `wrangler.jsonc`.
5. Run `GET /health`, then `GET /run` to validate.

## Endpoints

- `GET /health` - health check
- `GET|POST /run` - manual incremental sync
- `GET|POST /summary` - manual daily summary send
- `GET /ledger?limit=20` - recent sent events
- `GET /ledger?event_id=<id>` - lookup specific sent event

## Auditor-Focused Output

Each event card emphasizes:

- Who (actor + IP)
- When (timestamp)
- What (action + target resource)
- Result (success/failure)
- Change details (`old -> new` fields)

## Notes

- Dedupe is only marked after webhook delivery succeeds.
- Ledger retention is 180 days by default.
- Rotate all secrets/webhooks if they were ever shared in logs or chats.
