# Connecting to poke-ical

poke-ical is an iCloud CalDAV MCP server with a built-in OAuth 2.1
authorization server. Each user authenticates with their own Apple ID +
app-specific password and gets access to their own calendars.

Base URL used below: `https://<your-worker>.workers.dev` — replace with
your deployed worker (e.g. `https://poke-ical-dev.fedor010908.workers.dev` for
the dev deployment).

---

## Option A — OAuth (recommended)

Use this if your MCP client supports OAuth, or you're wiring up the flow
yourself. It's the standard MCP authorization pattern: the client
registers itself, sends the user to a login page, and exchanges a code
for tokens.

### 1. Discover the endpoints

```bash
curl https://<worker>/.well-known/oauth-protected-resource
# → { "resource": ".../mcp", "authorization_servers": ["https://<worker>"] }

curl https://<worker>/.well-known/oauth-authorization-server
# → authorization_endpoint, token_endpoint, registration_endpoint, ...
```

### 2. Register a client (dynamic client registration)

```bash
curl -X POST https://<worker>/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "redirect_uris": ["https://your-app.example.com/oauth/callback"],
    "client_name": "Your App Name"
  }'
```

Response:

```json
{
  "client_id": "...",
  "client_id_issued_at": 1234567890,
  "redirect_uris": ["https://your-app.example.com/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Save the `client_id`. **There is no client_secret** — this is a public
client; security comes from PKCE (below), not a shared secret.

### 3. Send the user to the authorize URL

Build the URL with these query parameters:

| Param | Required | Value |
|---|---|---|
| `response_type` | yes | `code` |
| `client_id` | yes | from step 2 |
| `redirect_uri` | yes | one of the registered URIs, exact match |
| `code_challenge` | yes | `base64url(SHA256(code_verifier))`, no padding |
| `code_challenge_method` | yes | `S256` |
| `state` | recommended | random string, verify on callback |
| `scope` | optional | `calendar` |
| `resource` | optional | `https://<worker>/mcp` |

Example:

```
https://<worker>/oauth/authorize?response_type=code
  &client_id=<client_id>
  &redirect_uri=https%3A%2F%2Fyour-app.example.com%2Foauth%2Fcallback
  &code_challenge=<challenge>
  &code_challenge_method=S256
  &state=<random>
  &scope=calendar
```

The user sees a Poke-styled login page asking for their Apple ID email
and an app-specific password (generate at
[account.apple.com](https://account.apple.com) → Sign-In and Security →
App-Specific Passwords). On success they're redirected to your
`redirect_uri` with `?code=...&state=...`. On failure, `?error=...`.

Generate the PKCE pair first:

```bash
# code_verifier: any high-entropy string, 43–128 chars
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=+/' | tr '/+' '_-')
```

### 4. Exchange the code for tokens

```bash
curl -X POST https://<worker>/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=<code from redirect>' \
  -d 'redirect_uri=https://your-app.example.com/oauth/callback' \
  -d 'client_id=<client_id>' \
  -d 'code_verifier=<verifier from step 3>'
```

Response:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "calendar"
}
```

### 5. Call the MCP endpoint

```bash
curl -X POST https://<worker>/mcp \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

`GET /mcp` opens the SSE stream (also Bearer-protected).

### Refreshing

Access tokens last 1 hour. When expired:

```bash
curl -X POST https://<worker>/oauth/token \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=<refresh_token>' \
  -d 'client_id=<client_id>'
```

Refresh tokens last 30 days and **rotate** — the old one is invalidated
on use, so always store the new pair.

### Revoking

```bash
curl -X POST https://<worker>/oauth/revoke \
  -d 'token=<access_or_refresh_token>'
```

---

## Option B — MCP clients that speak OAuth

If your client implements the MCP authorization spec (Claude, Cursor,
Poke, etc.), you don't do any of the above manually — just give it the
MCP URL:

```
https://<worker>/mcp
```

Unauthenticated requests return `401` with a `WWW-Authenticate` header
pointing at `/.well-known/oauth-protected-resource/mcp`. The client
handles discovery, registration, the browser redirect, PKCE, and token
refresh on its own.

## Option C — Legacy shared account (single user, no OAuth)

For clients that can't do OAuth at all, the worker operator can set
`CALDAV_USERNAME` / `CALDAV_PASSWORD` Worker secrets; requests without a
Bearer token then use that one shared iCloud account. This is
single-tenant only — don't use it for multi-user hosting.

---

## Reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/oauth-protected-resource[/mcp]` | GET | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 AS metadata |
| `/oauth/register` | POST | RFC 7591 dynamic client registration |
| `/oauth/authorize` | GET/POST | Login page + code issuance |
| `/oauth/token` | POST | Code exchange / refresh |
| `/oauth/revoke` | POST | RFC 7009 revocation |
| `/mcp` | GET/POST | MCP over SSE, Bearer-protected |
| `/health` | GET | Liveness check |

### Errors you'll see

- `401` on `/mcp` → missing/expired token; restart the OAuth flow.
  `WWW-Authenticate` tells compliant clients where to look.
- `error=access_denied` on redirect → user cancelled or login failed.
- `invalid_grant` on `/oauth/token` → code expired (>10 min), already
  used, PKCE mismatch, or redirect_uri/client_id mismatch.
- HTTP `400` JSON on `/oauth/authorize` → bad client_id or redirect_uri
  (can't redirect safely, so it returns JSON instead).
