# poke-ical

An iCloud CalDAV MCP bridge for Poke, deployed as a Cloudflare Worker.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mollyvita/poke-ical)

## How auth works

poke-ical is a self-contained **OAuth 2.1 authorization server** (authorization-code + PKCE) wrapped around the MCP endpoint. Each user connects with their own iCloud account. **Connecting your own client? See [CONNECTING.md](CONNECTING.md) for the full flow — or just point an OAuth-capable MCP client at `/mcp` and it handles everything.**

1. The MCP client hits `/mcp` unauthenticated and gets a `401` with a `WWW-Authenticate` header pointing at the protected-resource metadata.
2. The client discovers the authorization server via `/.well-known/oauth-authorization-server` and registers itself via `/oauth/register` (dynamic client registration).
3. The client opens `/oauth/authorize`, which renders a login page asking for the user's **Apple ID email** and an **app-specific password**.
4. Credentials are verified against iCloud, stored AES-GCM-encrypted in KV, and an authorization code is returned to the client.
5. The client exchanges the code (PKCE S256) at `/oauth/token` for a Bearer access token (1h) + refresh token (30d, rotating). All `/mcp` calls then run against **that user's** calendar.

## Deployment guide

### 1. Create the KV namespace

```bash
npx wrangler kv namespace create OAUTH_KV
```

Paste the returned `id` into `wrangler.toml` (and a `preview_id` for local dev if you want persistence across `wrangler dev` restarts — local mode simulates KV regardless).

### 2. Set the encryption secret

```bash
npx wrangler secret put TOKEN_ENC_KEY   # any long random string
```

This key encrypts stored iCloud app passwords at rest. Rotating it invalidates stored credentials — users just re-connect.

### 3. Deploy

```bash
npm install
npx wrangler deploy
```

### 4. Connect to Poke

Add your Worker URL as an MCP integration in Poke:

```
https://<your-worker>.workers.dev/mcp
```

Poke will follow the OAuth flow and present the login page on first connect.

## Legacy single-account mode (optional)

If `CALDAV_USERNAME` and `CALDAV_PASSWORD` Worker secrets are set, requests **without** a Bearer token fall back to that shared account. To require OAuth for everyone, simply don't set those secrets (or remove them):

```bash
npx wrangler secret put CALDAV_USERNAME
npx wrangler secret put CALDAV_PASSWORD
```

## OAuth endpoints

| Endpoint | Purpose |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp]` | RFC 9728 protected-resource metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata |
| `POST /oauth/register` | RFC 7591 dynamic client registration |
| `GET/POST /oauth/authorize` | Login page + authorization-code issuance |
| `POST /oauth/token` | Code exchange / refresh (PKCE S256) |
| `POST /oauth/revoke` | RFC 7009 token revocation |

## MCP endpoint

All MCP communication happens at:

```
/mcp
```

Accepts `GET` (SSE stream) and `POST` (JSON-RPC 2.0), both requiring `Authorization: Bearer <token>` once OAuth is configured.

## Available tools

- `list_calendars` — list all iCloud calendars on the account
- `list_events` — list events in a calendar, with optional date range filter
- `get_event` — fetch raw iCalendar data for a specific event
- `create_event` — create a new event
- `update_event` — update fields on an existing event
- `delete_event` — delete an event
- `search_events` — search events by keyword
- `get_freebusy` — return busy intervals within a date range
- `get_ical_feed` — return all events as a complete `.ics` feed
