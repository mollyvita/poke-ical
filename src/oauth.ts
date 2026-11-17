/**
 * OAuth 2.1 authorization server for poke-ical (MCP spec compliant).
 *
 * Implements:
 *   - RFC 9728  OAuth 2.0 Protected Resource Metadata
 *   - RFC 8414  OAuth 2.0 Authorization Server Metadata
 *   - RFC 7591  OAuth 2.0 Dynamic Client Registration
 *   - RFC 7009  Token Revocation
 *   - Authorization-code + PKCE (S256) flow with a hosted login page that
 *     collects the user's iCloud email + app-specific password.
 *
 * Per-user iCloud credentials are stored AES-GCM-encrypted in KV, keyed by a
 * hash of the account email. Access tokens (1h) and refresh tokens (30d,
 * rotating) are opaque random strings stored in KV.
 *
 * Required bindings/secrets:
 *   OAUTH_KV       — KV namespace for clients, codes, tokens, credentials
 *   TOKEN_ENC_KEY  — secret used to derive the AES-GCM key for stored creds
 */

import { caldavRequest, type CalCreds } from './caldav-http';

export interface OAuthEnv {
  OAUTH_KV?: KVNamespace;
  TOKEN_ENC_KEY?: string;
}

// ---------------------------------------------------------------------------
// Constants & KV key helpers
// ---------------------------------------------------------------------------

const ICLOUD_CALDAV_ROOT = 'https://caldav.icloud.com';

const CODE_TTL_SECONDS = 600; // 10 minutes
const ACCESS_TOKEN_TTL_SECONDS = 3600; // 1 hour
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

const keyClient = (id: string) => `client:${id}`;
const keyCode = (code: string) => `code:${code}`;
const keyAccess = (token: string) => `at:${token}`;
const keyRefresh = (token: string) => `rt:${token}`;
const keyCred = (userId: string) => `cred:${userId}`;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function base64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function randomToken(byteLength = 32): Promise<string> {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function sha256Base64url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(input),
  );
  return base64url(new Uint8Array(digest));
}

// ---------------------------------------------------------------------------
// Credential encryption (AES-GCM, key = SHA-256(TOKEN_ENC_KEY))
// ---------------------------------------------------------------------------

async function encKey(env: OAuthEnv): Promise<CryptoKey | null> {
  if (!env.TOKEN_ENC_KEY) return null;
  const keyBytes = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(env.TOKEN_ENC_KEY),
  );
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

async function encryptJson(env: OAuthEnv, value: unknown): Promise<string> {
  const key = await encKey(env);
  if (!key) throw new Error('TOKEN_ENC_KEY secret is not configured');
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(value)),
  );
  return `v1.${base64url(iv)}.${base64url(new Uint8Array(ct))}`;
}

async function decryptJson<T>(env: OAuthEnv, stored: string): Promise<T | null> {
  const key = await encKey(env);
  if (!key || !stored.startsWith('v1.')) return null;
  const [, ivB64, ctB64] = stored.split('.');
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64urlDecode(ivB64) as BufferSource },
      key,
      base64urlDecode(ctB64) as BufferSource,
    );
    return JSON.parse(new TextDecoder().decode(pt)) as T;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// KV record types
// ---------------------------------------------------------------------------

interface OAuthClient {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  created_at: number;
}

interface AuthCode {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  user_id: string;
  scope?: string;
  expires_at: number;
}

interface AccessTokenRecord {
  client_id: string;
  user_id: string;
  expires_at: number;
}

interface RefreshTokenRecord {
  client_id: string;
  user_id: string;
  expires_at: number;
}

interface StoredCreds {
  email: string;
  app_password: string;
}

// ---------------------------------------------------------------------------
// iCloud credential verification
// ---------------------------------------------------------------------------

/** Returns true if the email + app password can authenticate to iCloud CalDAV. */
async function verifyIcloudLogin(email: string, appPassword: string): Promise<boolean> {
  const creds: CalCreds = { username: email, password: appPassword };
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop><D:current-user-principal/></D:prop>
</D:propfind>`;
  const { status } = await caldavRequest(
    creds,
    `${ICLOUD_CALDAV_ROOT}/`,
    'PROPFIND',
    body,
    { Depth: '0' },
  );
  return status < 400;
}

// ---------------------------------------------------------------------------
// Small HTTP helpers
// ---------------------------------------------------------------------------

function jsonResponse(data: unknown, status = 200, extraHeaders?: Record<string, string>) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    },
  });
}

function oauthError(error: string, description?: string, status = 400) {
  return jsonResponse(
    { error, ...(description ? { error_description: description } : {}) },
    status,
  );
}

function htmlResponse(html: string, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function redirectWithParams(
  redirectUri: string,
  params: Record<string, string>,
): Response {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return new Response(null, {
    status: 302,
    headers: { Location: u.toString(), 'Cache-Control': 'no-store' },
  });
}

// ---------------------------------------------------------------------------
// Credential resolution for MCP tool calls
// ---------------------------------------------------------------------------

/**
 * Resolve CalDAV credentials for an MCP request.
 * Returns CalCreds on success, or a Response to send back (401) on failure.
 */
export async function authenticateRequest(
  request: Request,
  env: OAuthEnv & { CALDAV_USERNAME?: string; CALDAV_PASSWORD?: string },
): Promise<CalCreds | Response> {
  const header = request.headers.get('Authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());

  if (match && env.OAUTH_KV) {
    const token = match[1];
    const rec = await env.OAUTH_KV.get<AccessTokenRecord>(keyAccess(token), 'json');
    if (rec && rec.expires_at > Date.now()) {
      const stored = await env.OAUTH_KV.get<string>(keyCred(rec.user_id));
      const creds = stored ? await decryptJson<StoredCreds>(env, stored) : null;
      if (creds) {
        return { username: creds.email, password: creds.app_password };
      }
    }
    return unauthorizedResponse(request);
  }

  // Legacy fallback: single shared account via Worker secrets.
  if (env.CALDAV_USERNAME && env.CALDAV_PASSWORD) {
    return { username: env.CALDAV_USERNAME, password: env.CALDAV_PASSWORD };
  }

  return unauthorizedResponse(request);
}

function unauthorizedResponse(request: Request): Response {
  const origin = new URL(request.url).origin;
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32001, message: 'Unauthorized: connect via OAuth' },
    }),
    {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate':
          `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Login page
// ---------------------------------------------------------------------------

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function loginPage(
  params: Record<string, string>,
  error?: string,
): string {
  const hidden = Object.entries(params)
    .filter(([k]) => !['email', 'app_password'].includes(k))
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('\n      ');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Poke — Connect iCloud</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    @font-face {
      font-family: 'Open Runde';
      src: url('/fonts/openrunde-regular.woff2') format('woff2');
      font-weight: 400; font-style: normal; font-display: swap;
    }
    @font-face {
      font-family: 'Open Runde';
      src: url('/fonts/openrunde-medium.woff2') format('woff2');
      font-weight: 500; font-style: normal; font-display: swap;
    }
    @font-face {
      font-family: 'Open Runde';
      src: url('/fonts/openrunde-semibold.woff2') format('woff2');
      font-weight: 600; font-style: normal; font-display: swap;
    }
    @font-face {
      font-family: 'Exposure';
      src: url('/fonts/exposure-var.woff2') format('woff2');
      font-weight: 400; font-style: normal; font-display: swap;
    }
    @font-face {
      font-family: 'Exposure';
      src: url('/fonts/exposure-var-italic.woff2') format('woff2');
      font-weight: 400; font-style: italic; font-display: swap;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Open Runde', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 15px;
      line-height: 1.5;
      background: #fff;
      color: #1c1c1c;
      -webkit-font-smoothing: antialiased;
      min-height: 100vh;
      display: flex;
      justify-content: center;
    }
    main {
      width: 100%;
      max-width: 460px;
      padding: 14vh 24px 64px;
    }
    .eyebrow {
      font-family: 'JetBrains Mono', ui-monospace, monospace;
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: #837d7c;
      margin: 0 0 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .eyebrow img { width: 22px; height: 22px; border-radius: 6px; display: block; }
    h1 {
      font-family: 'Exposure', Georgia, serif;
      font-variation-settings: 'EXPO' -10;
      font-weight: 400;
      font-size: clamp(38px, 7vw, 52px);
      line-height: 1.05;
      letter-spacing: -0.03em;
      color: #000;
      margin: 0 0 16px;
    }
    .lede { color: #6b6b6b; margin: 0 0 28px; max-width: 30em; }
    .card {
      background: linear-gradient(180deg, #ffffff 0%, #fafaf9 55%, #f4f4f3 100%);
      border: 1px solid #d7d6d3;
      border-radius: 24px;
      box-shadow:
        0 1px 2px rgba(0,0,0,0.04),
        0 12px 32px rgba(0,0,0,0.07),
        inset 0 0 0 1px rgba(255,255,255,0.6);
      padding: 28px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: #555;
      margin-bottom: 7px;
    }
    input {
      width: 100%;
      height: 46px;
      padding: 0 15px;
      font-family: inherit;
      font-size: 15px;
      color: #1c1c1c;
      background: #fff;
      border: 1px solid #d7d6d3;
      border-radius: 12px;
      outline: none;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
      transition: border-color .15s ease, box-shadow .15s ease;
      margin-bottom: 16px;
    }
    input:focus {
      border-color: #1c1c1c;
      box-shadow: 0 0 0 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
    }
    input::placeholder { color: #b5b3b0; }
    button {
      width: 100%;
      height: 44px;
      font-family: inherit;
      font-size: 15px;
      font-weight: 500;
      letter-spacing: -0.01em;
      color: #fff;
      text-shadow: 0 0.5px 0 rgba(0,0,0,0.5);
      background: linear-gradient(180deg, #3a3a3a 0%, #3a3a3a 52.4%, #2c2c2c 80.29%, #1f1f1f 100%);
      border: 0;
      border-radius: 12px;
      cursor: pointer;
      box-shadow:
        0 0.5px 1px rgba(0,0,0,0.08),
        0 1px 3px rgba(0,0,0,0.1),
        0 4px 12px rgba(0,0,0,0.08),
        inset 0 0 0 1.25px #353535,
        inset 0 0 12px 0 rgba(255,255,255,0.1);
      transition: filter .15s ease, transform .1s ease;
    }
    button:hover { filter: brightness(1.2); }
    button:active { transform: scale(0.98); }
    .err {
      font-size: 13px;
      font-weight: 500;
      color: #d92d20;
      margin: 0 0 16px;
    }
    .hint {
      font-size: 12.5px;
      color: #999;
      margin-top: 20px;
      line-height: 1.6;
    }
    .hint a { color: inherit; text-decoration: underline; text-underline-offset: 2px; }
  </style>
</head>
<body>
  <main>
    <p class="eyebrow"><img src="https://poke.com/icons/poke-192.png" alt="">poke × icloud</p>
    <h1>Connect your iCloud</h1>
    <p class="lede">
      Poke needs your Apple ID and an app-specific password to read your
      calendar over CalDAV. It's verified with Apple, stored encrypted,
      and only ever used for your account.
    </p>

    <form class="card" method="POST" action="/oauth/authorize">
      ${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
      <label for="email">Apple ID email</label>
      <input id="email" name="email" type="email" required autocomplete="username"
             placeholder="you@icloud.com">
      <label for="app_password">App-specific password</label>
      <input id="app_password" name="app_password" type="password" required
             autocomplete="off" placeholder="xxxx-xxxx-xxxx-xxxx">
      ${hidden}
      <button type="submit">Connect</button>
      <p class="hint">
        Need an app-specific password? Generate one at
        <a href="https://account.apple.com" target="_blank" rel="noopener">account.apple.com</a>
        under Sign-In and Security → App-Specific Passwords.
      </p>
    </form>
  </main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// /oauth/authorize — GET renders login, POST verifies creds and issues code
// ---------------------------------------------------------------------------

interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  resource?: string;
}

async function loadClient(
  env: OAuthEnv,
  clientId: string,
): Promise<OAuthClient | null> {
  if (!env.OAUTH_KV) return null;
  return env.OAUTH_KV.get<OAuthClient>(keyClient(clientId), 'json');
}

/** Validate the authorize request; returns params or an error Response. */
async function validateAuthorize(
  env: OAuthEnv,
  q: URLSearchParams,
): Promise<AuthorizeParams | Response> {
  const clientId = q.get('client_id') ?? '';
  const redirectUri = q.get('redirect_uri') ?? '';
  const client = await loadClient(env, clientId);

  // Client / redirect_uri problems can't be redirected — return JSON error.
  if (!client || !client.redirect_uris.includes(redirectUri)) {
    return oauthError('invalid_request', 'Unknown client_id or redirect_uri');
  }

  const errRedirect = (error: string, desc?: string) =>
    redirectWithParams(redirectUri, {
      error,
      ...(desc ? { error_description: desc } : {}),
      ...(q.get('state') ? { state: q.get('state')! } : {}),
    });

  if (q.get('response_type') !== 'code') {
    return errRedirect('unsupported_response_type');
  }
  const codeChallenge = q.get('code_challenge') ?? '';
  if (!codeChallenge || q.get('code_challenge_method') !== 'S256') {
    return errRedirect('invalid_request', 'PKCE with S256 is required');
  }

  return {
    client_id: clientId,
    redirect_uri: redirectUri,
    state: q.get('state') ?? undefined,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    scope: q.get('scope') ?? undefined,
    resource: q.get('resource') ?? undefined,
  };
}

async function handleAuthorize(
  request: Request,
  env: OAuthEnv,
  url: URL,
): Promise<Response> {
  if (!env.OAUTH_KV) {
    return oauthError('server_error', 'OAuth is not configured on this worker', 500);
  }

  if (request.method === 'GET') {
    const result = await validateAuthorize(env, url.searchParams);
    if (result instanceof Response) return result;
    return htmlResponse(
      loginPage(Object.fromEntries(url.searchParams.entries())),
    );
  }

  if (request.method === 'POST') {
    const form = await request.formData();
    const q = new URLSearchParams();
    for (const [k, v] of form.entries()) {
      if (typeof v === 'string' && k !== 'email' && k !== 'app_password') {
        q.set(k, v);
      }
    }
    const email = String(form.get('email') ?? '').trim();
    const appPassword = String(form.get('app_password') ?? '').trim();

    const result = await validateAuthorize(env, q);
    if (result instanceof Response) {
      // If it's a redirect response (protocol error), pass it through.
      if (result.headers.get('Location')) return result;
      return htmlResponse(
        loginPage(Object.fromEntries(q.entries()), 'Invalid authorization request.'),
        result.status,
      );
    }
    const params = result;

    if (!email || !appPassword) {
      return htmlResponse(
        loginPage(
          Object.fromEntries(q.entries()),
          'Email and app-specific password are required.',
        ),
        400,
      );
    }

    const ok = await verifyIcloudLogin(email, appPassword);
    if (!ok) {
      return htmlResponse(
        loginPage(
          Object.fromEntries(q.entries()),
          'Could not sign in to iCloud. Check your email and app-specific password.',
        ),
        401,
      );
    }

    // Upsert per-user credentials (keyed by email hash → stable user id).
    const userId = `u_${(await sha256Base64url(email.toLowerCase())).slice(0, 32)}`;
    await env.OAUTH_KV.put(
      keyCred(userId),
      await encryptJson(env, { email, app_password: appPassword } satisfies StoredCreds),
    );

    const code = await randomToken(32);
    const record: AuthCode = {
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      code_challenge: params.code_challenge,
      user_id: userId,
      scope: params.scope,
      expires_at: Date.now() + CODE_TTL_SECONDS * 1000,
    };
    await env.OAUTH_KV.put(keyCode(code), JSON.stringify(record), {
      expirationTtl: CODE_TTL_SECONDS,
    });

    return redirectWithParams(params.redirect_uri, {
      code,
      ...(params.state ? { state: params.state } : {}),
    });
  }

  return oauthError('invalid_request', 'GET or POST only', 405);
}

// ---------------------------------------------------------------------------
// /oauth/token — authorization_code + refresh_token grants
// ---------------------------------------------------------------------------

async function issueTokenPair(
  env: OAuthEnv,
  clientId: string,
  userId: string,
): Promise<{ access_token: string; refresh_token: string; expires_in: number }> {
  const accessToken = await randomToken(32);
  const refreshToken = await randomToken(32);
  const now = Date.now();

  await env.OAUTH_KV!.put(
    keyAccess(accessToken),
    JSON.stringify({
      client_id: clientId,
      user_id: userId,
      expires_at: now + ACCESS_TOKEN_TTL_SECONDS * 1000,
    } satisfies AccessTokenRecord),
    { expirationTtl: ACCESS_TOKEN_TTL_SECONDS },
  );
  await env.OAUTH_KV!.put(
    keyRefresh(refreshToken),
    JSON.stringify({
      client_id: clientId,
      user_id: userId,
      expires_at: now + REFRESH_TOKEN_TTL_SECONDS * 1000,
    } satisfies RefreshTokenRecord),
    { expirationTtl: REFRESH_TOKEN_TTL_SECONDS },
  );

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
  };
}

async function handleToken(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  if (!env.OAUTH_KV) {
    return oauthError('server_error', 'OAuth is not configured', 500);
  }

  const ct = request.headers.get('Content-Type') ?? '';
  let params: URLSearchParams;
  if (ct.includes('application/json')) {
    const body = (await request.json()) as Record<string, string>;
    params = new URLSearchParams(body);
  } else {
    params = new URLSearchParams(await request.text());
  }

  const grantType = params.get('grant_type');
  const clientId = params.get('client_id') ?? '';

  if (grantType === 'authorization_code') {
    const code = params.get('code') ?? '';
    const redirectUri = params.get('redirect_uri') ?? '';
    const verifier = params.get('code_verifier') ?? '';

    const record = code
      ? await env.OAUTH_KV.get<AuthCode>(keyCode(code), 'json')
      : null;
    if (!record || record.expires_at < Date.now()) {
      return oauthError('invalid_grant', 'Invalid or expired authorization code');
    }
    if (record.client_id !== clientId || record.redirect_uri !== redirectUri) {
      return oauthError('invalid_grant', 'client_id or redirect_uri mismatch');
    }
    // Codes are single-use — delete before further checks so a failed PKCE
    // attempt can't be retried.
    await env.OAUTH_KV.delete(keyCode(code));

    const computed = await sha256Base64url(verifier);
    if (computed !== record.code_challenge) {
      return oauthError('invalid_grant', 'PKCE verification failed');
    }

    const pair = await issueTokenPair(env, clientId, record.user_id);
    return jsonResponse({
      ...pair,
      token_type: 'Bearer',
      scope: record.scope ?? '',
    });
  }

  if (grantType === 'refresh_token') {
    const refreshToken = params.get('refresh_token') ?? '';
    const record = refreshToken
      ? await env.OAUTH_KV.get<RefreshTokenRecord>(keyRefresh(refreshToken), 'json')
      : null;
    if (!record || record.expires_at < Date.now()) {
      return oauthError('invalid_grant', 'Invalid or expired refresh token');
    }
    if (record.client_id !== clientId) {
      return oauthError('invalid_grant', 'client_id mismatch');
    }
    // Rotate: old refresh token is invalidated on use.
    await env.OAUTH_KV.delete(keyRefresh(refreshToken));
    const pair = await issueTokenPair(env, clientId, record.user_id);
    return jsonResponse({ ...pair, token_type: 'Bearer' });
  }

  return oauthError('unsupported_grant_type', `Unsupported grant_type: ${grantType}`);
}

// ---------------------------------------------------------------------------
// /oauth/revoke — RFC 7009 (best-effort, always 200)
// ---------------------------------------------------------------------------

async function handleRevoke(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  if (env.OAUTH_KV) {
    const ct = request.headers.get('Content-Type') ?? '';
    let token = '';
    if (ct.includes('application/json')) {
      const body = (await request.json().catch(() => ({}))) as { token?: string };
      token = body.token ?? '';
    } else {
      token = new URLSearchParams(await request.text()).get('token') ?? '';
    }
    if (token) {
      await Promise.all([
        env.OAUTH_KV.delete(keyAccess(token)),
        env.OAUTH_KV.delete(keyRefresh(token)),
      ]);
    }
  }
  return new Response(null, { status: 200 });
}

// ---------------------------------------------------------------------------
// /.well-known metadata
// ---------------------------------------------------------------------------

function asMetadata(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    revocation_endpoint: `${origin}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['calendar'],
  };
}

function protectedResourceMetadata(origin: string) {
  return {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    bearer_methods_supported: ['header'],
    scopes_supported: ['calendar'],
  };
}

// ---------------------------------------------------------------------------
// /oauth/register — RFC 7591 dynamic client registration (public clients)
// ---------------------------------------------------------------------------

async function handleRegister(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  if (!env.OAUTH_KV) {
    return oauthError('server_error', 'OAuth is not configured', 500);
  }
  if (request.method !== 'POST') {
    return oauthError('invalid_request', 'POST only', 405);
  }

  const body = (await request.json().catch(() => ({}))) as {
    redirect_uris?: unknown;
    client_name?: unknown;
  };
  const redirectUris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((u): u is string => typeof u === 'string')
    : [];

  const validUris = redirectUris.filter((u) => {
    try {
      const url = new URL(u);
      return (
        url.protocol === 'https:' ||
        (url.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
      );
    } catch {
      return false;
    }
  });
  if (validUris.length === 0) {
    return oauthError('invalid_redirect_uri', 'At least one valid redirect_uri is required');
  }

  const client: OAuthClient = {
    client_id: await randomToken(16),
    client_name: typeof body.client_name === 'string' ? body.client_name : undefined,
    redirect_uris: validUris,
    created_at: Date.now(),
  };
  await env.OAUTH_KV.put(keyClient(client.client_id), JSON.stringify(client));

  return jsonResponse(
    {
      client_id: client.client_id,
      client_id_issued_at: Math.floor(client.created_at / 1000),
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    },
    201,
  );
}

// ---------------------------------------------------------------------------
// Router — returns null when the path isn't an OAuth route
// ---------------------------------------------------------------------------

export async function handleOAuthRequest(
  request: Request,
  env: OAuthEnv,
  url: URL,
): Promise<Response | null> {
  const path = url.pathname;

  // Protected resource metadata — both root form and path-suffixed form
  // (RFC 9728 §3.1 inserts the resource path into the well-known URI).
  if (
    path === '/.well-known/oauth-protected-resource' ||
    path === '/.well-known/oauth-protected-resource/mcp'
  ) {
    return jsonResponse(protectedResourceMetadata(url.origin));
  }

  if (path === '/.well-known/oauth-authorization-server') {
    return jsonResponse(asMetadata(url.origin));
  }

  if (path === '/oauth/authorize') {
    return handleAuthorize(request, env, url);
  }
  if (path === '/oauth/token') {
    if (request.method !== 'POST') return oauthError('invalid_request', 'POST only', 405);
    return handleToken(request, env);
  }
  if (path === '/oauth/register') {
    return handleRegister(request, env);
  }
  if (path === '/oauth/revoke') {
    if (request.method !== 'POST') return oauthError('invalid_request', 'POST only', 405);
    return handleRevoke(request, env);
  }

  return null;
}
