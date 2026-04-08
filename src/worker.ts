/**
 * poke-ical: iCloud Calendar MCP Server (Cloudflare Worker)
 *
 * Exposes 9 CalDAV tools via the Model Context Protocol over SSE.
 * Endpoints: /mcp, /authorize, /token
 *
 * Required Worker secrets:
 *   OAUTH_ENCRYPTION_KEY  — high-entropy secret used to encrypt stored credentials
 *
 * Required Worker binding:
 *   TOKEN_KV              — KV namespace used to store encrypted CalDAV credentials
 *
 * Optional legacy fallback environment variables:
 *   CALDAV_USERNAME  — Apple ID email (will be imported into TOKEN_KV if present)
 *   CALDAV_PASSWORD  — App-specific password (will be imported into TOKEN_KV if present)
 *
 * Simple setup page:
 *   /auth, /setup, /login — enter Apple ID + app-specific password and save to TOKEN_KV
 *
 * iCloud CalDAV discovery is a 2-step process:
 *   1. PROPFIND https://caldav.icloud.com/ → current-user-principal href
 *   2. PROPFIND {principal} → calendar-home-set href
 *   3. PROPFIND {home-set} → enumerate individual calendars
 */

export interface Env {
  TOKEN_KV: KVLike;
  OAUTH_ENCRYPTION_KEY: string;
  CALDAV_USERNAME?: string;
  CALDAV_PASSWORD?: string;
}

interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

type StoredCaldavCredentials = {
  appleId: string;
  appPassword: string;
  createdAt: number;
  updatedAt: number;
};

function getMissingRuntimeConfig(env: Env): string[] {
  const missing: string[] = [];
  if (!env.TOKEN_KV) missing.push('TOKEN_KV');
  if (!env.OAUTH_ENCRYPTION_KEY) missing.push('OAUTH_ENCRYPTION_KEY');
  return missing;
}

function formatMissingRuntimeConfigMessage(missing: string[]): string {
  return `Missing required Worker configuration: ${missing.join(', ')}.`;
}

function buildMissingRuntimeConfigResponse(missing: string[], wantsHtml: boolean): Response {
  const message = formatMissingRuntimeConfigMessage(missing);
  if (wantsHtml) {
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>poke-ical configuration error</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0f172a; color: #e2e8f0; }
    .card { width: min(92vw, 560px); padding: 28px; border-radius: 20px; background: #111827; border: 1px solid rgba(148,163,184,.25); }
    h1 { margin: 0 0 12px; }
    p { line-height: 1.5; }
    code { background: rgba(15,23,42,.85); padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Configuration required</h1>
    <p>${escapeHtml(message)}</p>
    <p>Bind <code>TOKEN_KV</code> and set <code>OAUTH_ENCRYPTION_KEY</code>, then reload this page.</p>
  </main>
</body>
</html>`;
    return new Response(html, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  return new Response(JSON.stringify({ error: message }), {
    status: 500,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function assertRuntimeConfig(env: Env): void {
  const missing = getMissingRuntimeConfig(env);
  if (missing.length > 0) {
    throw new Error(formatMissingRuntimeConfigMessage(missing));
  }
}

const CREDENTIALS_KV_KEY = 'caldav:credentials:default';
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((input.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value));
  return new Uint8Array(digest);
}

async function deriveAesKey(secret: string): Promise<CryptoKey> {
  const raw = await sha256Bytes(secret);
  return await crypto.subtle.importKey('raw', raw as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptJson(secret: string, data: unknown): Promise<string> {
  const key = await deriveAesKey(secret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = textEncoder.encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return JSON.stringify({ iv: base64UrlEncode(iv), data: base64UrlEncode(new Uint8Array(ciphertext as ArrayBuffer)) });
}

async function decryptJson<T>(secret: string, payload: string): Promise<T> {
  const parsed = JSON.parse(payload) as { iv: string; data: string };
  const key = await deriveAesKey(secret);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64UrlDecode(parsed.iv) as unknown as BufferSource }, key, base64UrlDecode(parsed.data) as unknown as BufferSource);
  return JSON.parse(textDecoder.decode(new Uint8Array(plaintext as ArrayBuffer))) as T;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function maskAppleId(appleId: string): string {
  const atIndex = appleId.indexOf('@');
  if (atIndex <= 1) return appleId;
  const local = appleId.slice(0, atIndex);
  const domain = appleId.slice(atIndex);
  return `${local.slice(0, 2)}•••${domain}`;
}

const CREDENTIALS_KV_PREFIX = 'caldav:token:';
const LATEST_TOKEN_KV_KEY = 'caldav:token:latest';
const LEGACY_CREDENTIALS_KV_KEY = 'caldav:credentials:default';

type ConfiguredCredentials = {
  token: string;
  credentials: StoredCaldavCredentials;
};

type StoredOAuthAuthorizationCode = {
  kind: 'authorization_code';
  credentialToken: string;
  clientId?: string;
  redirectUri?: string;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  state?: string;
  createdAt: number;
  expiresAt: number;
};

type StoredOAuthAccessToken = {
  kind: 'access_token';
  credentialToken: string;
  clientId?: string;
  scope?: string;
  refreshToken: string;
  createdAt: number;
  expiresAt: number;
};

type StoredOAuthRefreshToken = {
  kind: 'refresh_token';
  credentialToken: string;
  clientId?: string;
  scope?: string;
  accessToken: string;
  createdAt: number;
  expiresAt: number;
};

const OAUTH_AUTH_CODE_KV_PREFIX = 'oauth:auth-code:';
const OAUTH_ACCESS_TOKEN_KV_PREFIX = 'oauth:access-token:';
const OAUTH_REFRESH_TOKEN_KV_PREFIX = 'oauth:refresh-token:';
const OAUTH_AUTH_CODE_TTL_SECONDS = 300;
const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600;
const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;

function makeOAuthAuthCodeKey(code: string): string {
  return `${OAUTH_AUTH_CODE_KV_PREFIX}${code}`;
}

function makeOAuthAccessTokenKey(token: string): string {
  return `${OAUTH_ACCESS_TOKEN_KV_PREFIX}${token}`;
}

function makeOAuthRefreshTokenKey(token: string): string {
  return `${OAUTH_REFRESH_TOKEN_KV_PREFIX}${token}`;
}

function makeCredentialsKey(token: string): string {
  return `${CREDENTIALS_KV_PREFIX}${token}`;
}

function generateAuthToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function isValidAuthToken(token: string): boolean {
  return /^[A-Za-z0-9_-]{16,}$/.test(token);
}

async function saveStoredCredentials(env: Env, token: string, appleId: string, appPassword: string): Promise<void> {
  assertRuntimeConfig(env);
  const credentials: StoredCaldavCredentials = {
    appleId,
    appPassword,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  await env.TOKEN_KV.put(makeCredentialsKey(token), await encryptJson(env.OAUTH_ENCRYPTION_KEY, credentials));
  await env.TOKEN_KV.put(LATEST_TOKEN_KV_KEY, token);
}

async function resolveCredentialToken(env: Env, token: string): Promise<string | null> {
  const direct = await env.TOKEN_KV.get(makeCredentialsKey(token));
  if (direct) return token;

  const accessRecord = await readJsonRecord<StoredOAuthAccessToken>(env, makeOAuthAccessTokenKey(token));
  if (accessRecord && accessRecord.kind === 'access_token' && accessRecord.expiresAt > Date.now()) {
    return accessRecord.credentialToken;
  }

  return null;
}

async function loadStoredCredentials(env: Env, token: string): Promise<StoredCaldavCredentials | null> {
  assertRuntimeConfig(env);
  const credentialToken = await resolveCredentialToken(env, token);
  if (!credentialToken) return null;
  const raw = await env.TOKEN_KV.get(makeCredentialsKey(credentialToken));
  if (raw) {
    return await decryptJson<StoredCaldavCredentials>(env.OAUTH_ENCRYPTION_KEY, raw);
  }
  return null;
}

async function loadConfiguredCredentials(env: Env): Promise<ConfiguredCredentials | null> {
  assertRuntimeConfig(env);

  const latestToken = await env.TOKEN_KV.get(LATEST_TOKEN_KV_KEY);
  if (latestToken) {
    const credentials = await loadStoredCredentials(env, latestToken);
    if (credentials) {
      return { token: latestToken, credentials };
    }
  }

  const legacyRaw = await env.TOKEN_KV.get(LEGACY_CREDENTIALS_KV_KEY);
  if (legacyRaw) {
    const credentials = await decryptJson<StoredCaldavCredentials>(env.OAUTH_ENCRYPTION_KEY, legacyRaw);
    const token = generateAuthToken();
    await saveStoredCredentials(env, token, credentials.appleId, credentials.appPassword);
    try {
      await env.TOKEN_KV.delete(LEGACY_CREDENTIALS_KV_KEY);
    } catch {
      // Best-effort cleanup of the legacy single-record storage key.
    }
    return { token, credentials };
  }

  if (env.CALDAV_USERNAME && env.CALDAV_PASSWORD) {
    const token = generateAuthToken();
    const credentials: StoredCaldavCredentials = {
      appleId: env.CALDAV_USERNAME,
      appPassword: env.CALDAV_PASSWORD,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    await saveStoredCredentials(env, token, credentials.appleId, credentials.appPassword);
    return { token, credentials };
  }

  return null;
}

function normalizeFormValue(value: FormDataEntryValue | null): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseOAuthRequestData(source: URLSearchParams | FormData): Record<string, string> {
  const out: Record<string, string> = {};
  if (source instanceof URLSearchParams) {
    for (const [key, value] of source.entries()) out[key] = value.trim();
  } else {
    for (const [key, value] of source.entries()) out[key] = normalizeFormValue(value);
  }
  return out;
}

async function readJsonRecord<T>(env: Env, key: string): Promise<T | null> {
  const raw = await env.TOKEN_KV.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function writeJsonRecord(env: Env, key: string, value: unknown, expirationTtl?: number): Promise<void> {
  await env.TOKEN_KV.put(key, JSON.stringify(value), expirationTtl ? { expirationTtl } : undefined);
}

function oauthError(status: number, error: string, description: string): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function computePkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function renderAuthorizePage(options: {
  credentials: StoredCaldavCredentials | null;
  responseType?: string;
  clientId?: string;
  redirectUri?: string;
  scope?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  error?: string;
}): string {
  const currentStatus = options.credentials
    ? `Authorize access to the calendars linked to ${escapeHtml(maskAppleId(options.credentials.appleId))}.`
    : 'No CalDAV credentials are configured yet.';
  const error = options.error ? `<p style="color:#ff8a8a">${escapeHtml(options.error)}</p>` : '';
  const hidden = (name: string, value = '') => `<input type="hidden" name="${name}" value="${escapeHtml(value)}" />`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize poke-ical</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 48px auto; padding: 0 16px; line-height: 1.5; }
    .card { border: 1px solid #ddd; border-radius: 16px; padding: 24px; }
    button { padding: 10px 16px; border: 0; border-radius: 10px; background: #2563eb; color: #fff; cursor: pointer; }
    code { word-break: break-all; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize</h1>
    <p>${escapeHtml(currentStatus)}</p>
    ${error}
    ${options.credentials ? `<form method="post" action="/authorize">
      ${hidden('response_type', options.responseType || 'code')}
      ${hidden('client_id', options.clientId)}
      ${hidden('redirect_uri', options.redirectUri)}
      ${hidden('scope', options.scope)}
      ${hidden('state', options.state)}
      ${hidden('code_challenge', options.codeChallenge)}
      ${hidden('code_challenge_method', options.codeChallengeMethod)}
      <button type="submit">Authorize</button>
    </form>` : `<p>Set up CalDAV credentials at <code>/auth</code> first.</p>`}
  </div>
</body>
</html>`;
}

function buildOAuthRedirectUri(redirectUri: string, code: string, state?: string): string {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set('code', code);
  if (state) redirect.searchParams.set('state', state);
  return redirect.toString();
}

async function issueOAuthTokens(env: Env, args: {
  credentialToken: string;
  clientId?: string;
  scope?: string;
}): Promise<{ accessToken: string; refreshToken: string; expiresIn: number; scope?: string }> {
  const accessToken = generateAuthToken();
  const refreshToken = generateAuthToken();
  const createdAt = Date.now();
  const accessRecord: StoredOAuthAccessToken = {
    kind: 'access_token',
    credentialToken: args.credentialToken,
    clientId: args.clientId,
    scope: args.scope,
    refreshToken,
    createdAt,
    expiresAt: createdAt + OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000,
  };
  const refreshRecord: StoredOAuthRefreshToken = {
    kind: 'refresh_token',
    credentialToken: args.credentialToken,
    clientId: args.clientId,
    scope: args.scope,
    accessToken,
    createdAt,
    expiresAt: createdAt + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000,
  };
  await writeJsonRecord(env, makeOAuthAccessTokenKey(accessToken), accessRecord, OAUTH_ACCESS_TOKEN_TTL_SECONDS);
  await writeJsonRecord(env, makeOAuthRefreshTokenKey(refreshToken), refreshRecord, OAUTH_REFRESH_TOKEN_TTL_SECONDS);
  return { accessToken, refreshToken, expiresIn: OAUTH_ACCESS_TOKEN_TTL_SECONDS, scope: args.scope };
}

async function handleAuthorizeRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const missing = getMissingRuntimeConfig(env);
  if (missing.length > 0) return buildMissingRuntimeConfigResponse(missing, true);

  const configured = await loadConfiguredCredentials(env);
  const query = parseOAuthRequestData(url.searchParams);

  if (request.method === 'GET') {
    if (query.response_type && query.response_type !== 'code') {
      return new Response(renderAuthorizePage({
        credentials: configured?.credentials ?? null,
        responseType: query.response_type,
        clientId: query.client_id,
        redirectUri: query.redirect_uri,
        scope: query.scope,
        state: query.state,
        codeChallenge: query.code_challenge,
        codeChallengeMethod: query.code_challenge_method,
        error: 'Only response_type=code is supported.',
      }), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    return new Response(renderAuthorizePage({
      credentials: configured?.credentials ?? null,
      responseType: query.response_type || 'code',
      clientId: query.client_id,
      redirectUri: query.redirect_uri,
      scope: query.scope,
      state: query.state,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: query.code_challenge_method,
    }), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, POST' } });
  }

  if (!configured) {
    return new Response(renderAuthorizePage({ credentials: null, error: 'No CalDAV credentials are configured yet.' }), {
      status: 400,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const form = parseOAuthRequestData(await request.formData());
  const responseType = form.response_type || query.response_type || 'code';
  if (responseType !== 'code') {
    return new Response(renderAuthorizePage({
      credentials: configured.credentials,
      responseType,
      clientId: form.client_id || query.client_id,
      redirectUri: form.redirect_uri || query.redirect_uri,
      scope: form.scope || query.scope,
      state: form.state || query.state,
      codeChallenge: form.code_challenge || query.code_challenge,
      codeChallengeMethod: form.code_challenge_method || query.code_challenge_method,
      error: 'Only response_type=code is supported.',
    }), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const redirectUri = form.redirect_uri || query.redirect_uri;
  if (!redirectUri) {
    return new Response(renderAuthorizePage({
      credentials: configured.credentials,
      clientId: form.client_id || query.client_id,
      scope: form.scope || query.scope,
      state: form.state || query.state,
      codeChallenge: form.code_challenge || query.code_challenge,
      codeChallengeMethod: form.code_challenge_method || query.code_challenge_method,
      error: 'redirect_uri is required.',
    }), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const code = generateAuthToken();
  const codeRecord: StoredOAuthAuthorizationCode = {
    kind: 'authorization_code',
    credentialToken: configured.token,
    clientId: form.client_id || query.client_id || undefined,
    redirectUri,
    scope: form.scope || query.scope || undefined,
    codeChallenge: form.code_challenge || query.code_challenge || undefined,
    codeChallengeMethod: form.code_challenge_method || query.code_challenge_method || undefined,
    state: form.state || query.state || undefined,
    createdAt: Date.now(),
    expiresAt: Date.now() + OAUTH_AUTH_CODE_TTL_SECONDS * 1000,
  };
  await writeJsonRecord(env, makeOAuthAuthCodeKey(code), codeRecord, OAUTH_AUTH_CODE_TTL_SECONDS);

  let redirectLocation: string;
  try {
    redirectLocation = buildOAuthRedirectUri(redirectUri, code, codeRecord.state);
  } catch {
    return new Response(renderAuthorizePage({
      credentials: configured.credentials,
      clientId: codeRecord.clientId,
      redirectUri,
      scope: codeRecord.scope,
      state: codeRecord.state,
      codeChallenge: codeRecord.codeChallenge,
      codeChallengeMethod: codeRecord.codeChallengeMethod,
      error: 'redirect_uri must be an absolute URL.',
    }), { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  return Response.redirect(redirectLocation, 302);
}

async function handleTokenRequest(request: Request, env: Env): Promise<Response> {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-API-Key',
      },
    });
  }

  const missing = getMissingRuntimeConfig(env);
  if (missing.length > 0) return buildMissingRuntimeConfigResponse(missing, false);

  if (request.method !== 'POST') {
    return oauthError(405, 'invalid_request', 'Method Not Allowed');
  }

  const form = parseOAuthRequestData(await request.formData());
  const grantType = form.grant_type;
  if (!grantType) return oauthError(400, 'invalid_request', 'grant_type is required.');

  if (grantType === 'authorization_code') {
    const code = form.code;
    const redirectUri = form.redirect_uri;
    const codeVerifier = form.code_verifier;
    if (!code) return oauthError(400, 'invalid_request', 'code is required.');

    const codeKey = makeOAuthAuthCodeKey(code);
    const codeRecord = await readJsonRecord<StoredOAuthAuthorizationCode>(env, codeKey);
    if (!codeRecord || codeRecord.kind !== 'authorization_code' || codeRecord.expiresAt <= Date.now()) {
      return oauthError(400, 'invalid_grant', 'Authorization code is invalid or expired.');
    }
    if (codeRecord.redirectUri && redirectUri && codeRecord.redirectUri !== redirectUri) {
      return oauthError(400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    }
    if (codeRecord.redirectUri && !redirectUri) {
      return oauthError(400, 'invalid_grant', 'redirect_uri is required.');
    }
    if (codeRecord.clientId && form.client_id && codeRecord.clientId !== form.client_id) {
      return oauthError(400, 'invalid_grant', 'client_id does not match the authorization request.');
    }
    if (codeRecord.codeChallenge) {
      if (!codeVerifier) return oauthError(400, 'invalid_grant', 'code_verifier is required.');
      const method = (codeRecord.codeChallengeMethod || 'S256').toUpperCase();
      const expected = method === 'PLAIN' ? codeVerifier : await computePkceChallenge(codeVerifier);
      if (expected !== codeRecord.codeChallenge) {
        return oauthError(400, 'invalid_grant', 'PKCE verification failed.');
      }
    }

    try {
      await env.TOKEN_KV.delete(codeKey);
    } catch {
      // best effort
    }

    const tokenSet = await issueOAuthTokens(env, {
      credentialToken: codeRecord.credentialToken,
      clientId: codeRecord.clientId,
      scope: codeRecord.scope,
    });

    return new Response(JSON.stringify({
      access_token: tokenSet.accessToken,
      refresh_token: tokenSet.refreshToken,
      token_type: 'Bearer',
      expires_in: tokenSet.expiresIn,
      scope: tokenSet.scope,
    }), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  if (grantType === 'refresh_token') {
    const refreshToken = form.refresh_token;
    if (!refreshToken) return oauthError(400, 'invalid_request', 'refresh_token is required.');

    const refreshRecord = await readJsonRecord<StoredOAuthRefreshToken>(env, makeOAuthRefreshTokenKey(refreshToken));
    if (!refreshRecord || refreshRecord.kind !== 'refresh_token' || refreshRecord.expiresAt <= Date.now()) {
      return oauthError(400, 'invalid_grant', 'Refresh token is invalid or expired.');
    }
    if (refreshRecord.clientId && form.client_id && refreshRecord.clientId !== form.client_id) {
      return oauthError(400, 'invalid_grant', 'client_id does not match the refresh token.');
    }

    const tokenSet = await issueOAuthTokens(env, {
      credentialToken: refreshRecord.credentialToken,
      clientId: refreshRecord.clientId,
      scope: refreshRecord.scope,
    });

    return new Response(JSON.stringify({
      access_token: tokenSet.accessToken,
      refresh_token: tokenSet.refreshToken,
      token_type: 'Bearer',
      expires_in: tokenSet.expiresIn,
      scope: tokenSet.scope,
    }), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  return oauthError(400, 'unsupported_grant_type', 'Supported grant_type values are authorization_code and refresh_token.');
}

function renderSetupPage(options: { credentials: StoredCaldavCredentials | null; token?: string; notice?: string; error?: string }): string {
  const currentAppleId = options.credentials?.appleId ?? "";
  const currentStatus = options.credentials
    ? `Stored credentials are configured for ${escapeHtml(maskAppleId(options.credentials.appleId))}.`
    : 'No credentials are stored yet.';
  const tokenBanner = options.token
    ? `<p><strong>Authorization token:</strong><br /><code>${escapeHtml(options.token)}</code><br />Use <code>Authorization: Bearer ${escapeHtml(options.token)}</code> for <code>/mcp</code>.</p>`
    : '';
  const notice = options.notice ? `<p>${escapeHtml(options.notice)}</p>` : "";
  const error = options.error ? `<p style="color:#ff8a8a">${escapeHtml(options.error)}</p>` : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>poke-ical setup</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; line-height: 1.5; }
    .card { padding: 20px; border: 1px solid #ddd; border-radius: 12px; margin: 16px 0; }
    input { width: 100%; padding: 10px 12px; margin-top: 6px; box-sizing: border-box; }
    label { display: block; margin: 14px 0; }
    button { padding: 10px 14px; border-radius: 10px; border: 0; background: #2563eb; color: white; cursor: pointer; }
    code { word-break: break-all; }
  </style>
</head>
<body>
  <h1>poke-ical setup</h1>
  <div class="card">
    <p>${escapeHtml(currentStatus)}</p>
    ${notice}
    ${error}
    ${tokenBanner}
    <form method="post" action="">
      <label>
        Apple ID email
        <input name="appleId" type="email" required value="${escapeHtml(currentAppleId)}" placeholder="you@icloud.com" />
      </label>
      <label>
        App-specific password
        <input name="appPassword" type="password" required placeholder="xxxx-xxxx-xxxx-xxxx" />
      </label>
      <button type="submit">Save securely to KV</button>
    </form>
  </div>
</body>
</html>`;
}

async function handleSetupRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const missing = getMissingRuntimeConfig(env);
  if (missing.length > 0) {
    return buildMissingRuntimeConfigResponse(missing, true);
  }

  if (request.method === 'POST') {
    const form = await request.formData();
    const appleId = String(form.get('appleId') ?? "").trim();
    const appPassword = String(form.get('appPassword') ?? "").trim();
    const providedToken = String(form.get('token') ?? "").trim();
    const token = providedToken || generateAuthToken();

    if (!appleId || !appPassword) {
      const configured = await loadConfiguredCredentials(env);
      return new Response(renderSetupPage({
        credentials: configured?.credentials ?? null,
        token: configured?.token,
        error: 'Apple ID and app-specific password are required.',
      }), {
        status: 400,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    if (!isValidAuthToken(token)) {
      const configured = await loadConfiguredCredentials(env);
      return new Response(renderSetupPage({
        credentials: configured?.credentials ?? null,
        token: configured?.token,
        error: 'Token must use only letters, numbers, underscore, and hyphen, and be at least 16 characters long.',
      }), {
        status: 400,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    await saveStoredCredentials(env, token, appleId, appPassword);
    const credentials: StoredCaldavCredentials = {
      appleId,
      appPassword,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    return new Response(renderSetupPage({
      credentials,
      token,
      notice: 'Credentials saved successfully.',
    }), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const configured = await loadConfiguredCredentials(env);
  const notice = url.searchParams.get('saved') ? 'Credentials saved successfully.' : undefined;
  return new Response(renderSetupPage({
    credentials: configured?.credentials ?? null,
    token: configured?.token,
    notice,
  }), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

export const setupSteps = [
  'Create a KV namespace for encrypted credential storage and bind it as TOKEN_KV.',
  'Set OAUTH_ENCRYPTION_KEY to a high-entropy secret used to encrypt credentials at rest.',
  'Open /auth, enter the Apple ID email and app-specific password, and save them.',
  'Use the bearer token shown after saving as Authorization: Bearer <token> on /mcp.',
  'The worker will store each token/credential pair in KV and use it for CalDAV requests.',
  'Optional legacy CALDAV_USERNAME and CALDAV_PASSWORD env vars will be imported into KV on first use.',
] as const;
// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

// ---------------------------------------------------------------------------
// CalDAV constants & low-level helpers
// ---------------------------------------------------------------------------

const ICLOUD_CALDAV_ROOT = 'https://caldav.icloud.com';

function isIcloudHostname(hostname: string): boolean {
  return hostname.toLowerCase().endsWith('.icloud.com');
}

function ensureIcloudUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !isIcloudHostname(parsed.hostname)) {
    throw new Error(`Refusing outbound CalDAV request to non-iCloud host: ${parsed.hostname}`);
  }
  return parsed.toString();
}

function basicAuth(credentials: StoredCaldavCredentials): string {
  return 'Basic ' + btoa(`${credentials.appleId}:${credentials.appPassword}`);
}

/**
 * Perform a raw CalDAV / WebDAV request.
 * Throws (and logs) on network-level errors; returns status + body text for
 * HTTP-level errors so callers can decide how to handle them.
 */
async function caldavRequest(
  env: Env,
  authToken: string,
  url: string,
  method: string,
  body?: string,
  extraHeaders?: Record<string, string>,
): Promise<{ status: number; text: string }> {
  const credentials = await loadStoredCredentials(env, authToken);
  if (!credentials) {
    throw new Error('No CalDAV credentials are configured for this bearer token. Use /auth to save credentials and the token shown after saving.');
  }

  const safeUrl = ensureIcloudUrl(url);
  const headers: Record<string, string> = {
    Authorization: basicAuth(credentials),
    'Content-Type': 'application/xml; charset=utf-8',
    ...extraHeaders,
  };
  let res: Response;
  try {
    res = await fetch(safeUrl, { method, headers, body });
  } catch (err) {
    console.error(`[poke-ical] fetch failed — ${method} ${safeUrl}:`, err);
    throw err;
  }
  const text = await res.text();
  if (res.status >= 400) {
    console.error(
      `[poke-ical] HTTP error — ${method} ${safeUrl} → ${res.status}\n`,
      text.slice(0, 500),
    );
  }
  return { status: res.status, text };
}

// ---------------------------------------------------------------------------
// XML helpers  (no dependency on a full XML parser)
// ---------------------------------------------------------------------------

/** Return ALL text contents of every element matching `localName` (namespace-agnostic). */
function xmlAll(xml: string, localName: string): string[] {
  const out: string[] = [];
  // matches both <D:foo> … </D:foo>  and  <foo> … </foo>
  const re = new RegExp(
    `<(?:[^:>]+:)?${localName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[^:>]+:)?${localName}>`,
    'gi',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) out.push(m[1].trim());
  return out;
}

/** Return the text content of the FIRST matching element. */
function xmlFirst(xml: string, localName: string): string {
  return xmlAll(xml, localName)[0] ?? '';
}

// ---------------------------------------------------------------------------
// Step 1 – resolve current-user-principal
// ---------------------------------------------------------------------------
async function fetchPrincipalUrl(env: Env, authToken: string): Promise<string> {
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(
    env,
    authToken,
    `${ICLOUD_CALDAV_ROOT}/`,
    'PROPFIND',
    body,
    { Depth: '0' },
  );

  if (status >= 400) {
    throw new Error(
      `PROPFIND for current-user-principal returned ${status}. ` +
      'Check CALDAV_USERNAME and CALDAV_PASSWORD.',
    );
  }

  // <D:current-user-principal><D:href>/123456789/principal/</D:href>…
  const href = xmlFirst(xmlFirst(text, 'current-user-principal'), 'href');
  if (!href) {
    console.error('[poke-ical] current-user-principal href not found in:\n', text.slice(0, 800));
    throw new Error('Could not find current-user-principal href in PROPFIND response.');
  }
  const principalUrl = href.startsWith('http') ? href : `${ICLOUD_CALDAV_ROOT}${href}`;
  console.log('[poke-ical] principal URL:', principalUrl);
  return principalUrl;
}

// ---------------------------------------------------------------------------
// Step 2 – resolve calendar-home-set from principal URL
// ---------------------------------------------------------------------------
async function fetchCalendarHomeSet(env: Env, authToken: string, principalUrl: string): Promise<string> {
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-home-set/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(
    env,
    authToken,
    principalUrl,
    'PROPFIND',
    body,
    { Depth: '0' },
  );

  if (status >= 400) {
    throw new Error(`PROPFIND for calendar-home-set returned ${status}.`);
  }

  const href = xmlFirst(xmlFirst(text, 'calendar-home-set'), 'href');
  if (!href) {
    console.error('[poke-ical] calendar-home-set href not found in:\n', text.slice(0, 800));
    throw new Error('Could not find calendar-home-set href in PROPFIND response.');
  }
  const homeSetUrl = href.startsWith('http') ? href : `${ICLOUD_CALDAV_ROOT}${href}`;
  console.log('[poke-ical] calendar-home-set URL:', homeSetUrl);
  return homeSetUrl;
}

// ---------------------------------------------------------------------------
// Full 2-step iCloud discovery → calendar-home-set URL
// ---------------------------------------------------------------------------
async function resolveHomeSet(env: Env, authToken: string): Promise<string> {
  const principalUrl = await fetchPrincipalUrl(env, authToken);
  return fetchCalendarHomeSet(env, authToken, principalUrl);
}

// ---------------------------------------------------------------------------
// Step 3 – list calendars under the home-set URL
// ---------------------------------------------------------------------------
async function discoverCalendars(
  env: Env,
  authToken: string,
): Promise<Array<{ url: string; displayName: string; ctag: string }>> {
  const homeSetUrl = await resolveHomeSet(env, authToken);

  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
            xmlns:CS="http://calendarserver.org/ns/">
  <D:prop>
    <D:displayname/>
    <D:resourcetype/>
    <CS:getctag/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(env, authToken, homeSetUrl, 'PROPFIND', body, { Depth: '1' });
  if (status >= 400) {
    throw new Error(`PROPFIND for calendars at ${homeSetUrl} returned ${status}.`);
  }

  // Split into per-response blocks
  const responseBlocks = text.split(/<(?:[^:>]+:)?response(?:\s[^>]*)?>/).slice(1);
  const calendars: Array<{ url: string; displayName: string; ctag: string }> = [];

  for (const block of responseBlocks) {
    // Must be a calendar collection (resourcetype contains 'calendar')
    if (!/calendar/i.test(block)) continue;
    // But skip the home-set container itself (which is only a collection, not a calendar)
    if (/principal/i.test(block)) continue;

    const rawHref = xmlFirst(block, 'href');
    if (!rawHref) continue;

    const url = rawHref.startsWith('http')
      ? rawHref
      : `${ICLOUD_CALDAV_ROOT}${rawHref}`;

    const displayName = xmlFirst(block, 'displayname') || rawHref;
    const ctag = xmlFirst(block, 'getctag');

    calendars.push({ url, displayName, ctag });
  }

  console.log(`[poke-ical] discovered ${calendars.length} calendar(s):`,
    calendars.map((c) => c.displayName));
  return calendars;
}

// ---------------------------------------------------------------------------
// Fetch events via calendar-query REPORT
// ---------------------------------------------------------------------------
async function fetchEvents(
  env: Env,
  authToken: string,
  calendarUrl: string,
  start?: string,
  end?: string,
): Promise<Array<Record<string, string>>> {
  let timeFilter = "";
  if (start || end) {
    const s = start ?? '19700101T000000Z';
    const e = end ?? '20991231T235959Z';
    timeFilter = `
      <C:time-range start="${s}" end="${e}"/>`;
  }

  const body = `<?xml version="1.0" encoding="utf-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">${timeFilter}
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>`;

  const { status, text } = await caldavRequest(env, authToken, calendarUrl, 'REPORT', body, {
    Depth: '1',
  });
  if (status >= 400) {
    throw new Error(`REPORT on ${calendarUrl} returned ${status}.`);
  }

  return parseEvents(text);
}

// ---------------------------------------------------------------------------
// Parse multi-status REPORT response into event objects
// ---------------------------------------------------------------------------
function parseEvents(xml: string): Array<Record<string, string>> {
  const events: Array<Record<string, string>> = [];
  const dataBlocks = xmlAll(xml, 'calendar-data');
  const etagBlocks = xmlAll(xml, 'getetag');
  const hrefBlocks = xmlAll(xml, 'href');

  for (let i = 0; i < dataBlocks.length; i++) {
    const ical = dataBlocks[i];
    const event: Record<string, string> = {};
    event.etag = etagBlocks[i] ?? '';
    event.href = hrefBlocks[i] ?? '';

    const veventMatch = /BEGIN:VEVENT([\s\S]*?)END:VEVENT/i.exec(ical);
    if (!veventMatch) continue;
    const vevent = veventMatch[1];

    for (const line of vevent.split(/\r?\n/)) {
      const colonIdx = line.indexOf(':');
      if (colonIdx < 0) continue;
      const key = line.substring(0, colonIdx).split(';')[0].toUpperCase();
      const val = line.substring(colonIdx + 1);
      event[key] = val;
    }
    events.push(event);
  }
  return events;
}

// ---------------------------------------------------------------------------
// Build a minimal VCALENDAR / VEVENT string for PUT requests
// ---------------------------------------------------------------------------
function makeVEvent(params: {
  uid: string;
  summary: string;
  dtstart: string;
  dtend: string;
  description?: string;
  location?: string;
  allDay?: boolean;
}): string {
  const stamp = new Date().toISOString().replace(/[-:.]/g, '').substring(0, 15) + 'Z';
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//poke-ical//EN',
    'BEGIN:VEVENT',
    `UID:${params.uid}`,
    `DTSTAMP:${stamp}`,
    `SUMMARY:${params.summary}`,
    params.allDay
      ? `DTSTART;VALUE=DATE:${params.dtstart}`
      : `DTSTART:${params.dtstart}`,
    params.allDay
      ? `DTEND;VALUE=DATE:${params.dtend}`
      : `DTEND:${params.dtend}`,
  ];
  if (params.description) lines.push(`DESCRIPTION:${params.description}`);
  if (params.location) lines.push(`LOCATION:${params.location}`);
  lines.push('END:VEVENT', 'END:VCALENDAR');
  return lines.join('\r\n');
}

// ---------------------------------------------------------------------------
// MCP tool definitions
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'list_calendars',
    description:
      'List all iCloud calendars on the account. Performs the required 2-step ' +
      'iCloud discovery (principal → calendar-home-set) automatically.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'list_events',
    description: 'List events in a calendar, optionally filtered by a date range.',
    inputSchema: {
      type: 'object',
      properties: {
        calendar_url: {
          type: 'string',
          description: 'CalDAV URL of the calendar (from list_calendars).',
        },
        start: {
          type: 'string',
          description: 'Start in iCalendar basic format, e.g. 20260101T000000Z.',
        },
        end: {
          type: 'string',
          description: 'End in iCalendar basic format, e.g. 20261231T235959Z.',
        },
      },
      required: ['calendar_url'],
    },
  },
  {
    name: 'get_event',
    description: 'Fetch the raw iCalendar (.ics) data for a specific event by URL.',
    inputSchema: {
      type: 'object',
      properties: {
        event_url: {
          type: 'string',
          description: 'Full CalDAV URL of the .ics resource.',
        },
      },
      required: ['event_url'],
    },
  },
  {
    name: 'create_event',
    description: 'Create a new event in a calendar.',
    inputSchema: {
      type: 'object',
      properties: {
        calendar_url: { type: 'string', description: 'CalDAV URL of the target calendar.' },
        summary: { type: 'string', description: 'Event title.' },
        dtstart: { type: 'string', description: 'Start, e.g. 20260315T140000Z.' },
        dtend: { type: 'string', description: 'End, e.g. 20260315T150000Z.' },
        description: { type: 'string', description: 'Optional description.' },
        location: { type: 'string', description: 'Optional location.' },
        all_day: {
          type: 'boolean',
          description: 'True for all-day events; use DATE format (YYYYMMDD) for dtstart/dtend.',
        },
      },
      required: ['calendar_url', 'summary', 'dtstart', 'dtend'],
    },
  },
  {
    name: 'update_event',
    description: 'Update fields on an existing event (fetches, patches, saves back).',
    inputSchema: {
      type: 'object',
      properties: {
        event_url: { type: 'string', description: 'Full CalDAV URL of the .ics event.' },
        etag: { type: 'string', description: 'Current ETag for conflict detection (optional).' },
        summary: { type: 'string', description: 'New title.' },
        dtstart: { type: 'string', description: 'New start datetime.' },
        dtend: { type: 'string', description: 'New end datetime.' },
        description: { type: 'string', description: 'New description.' },
        location: { type: 'string', description: 'New location.' },
      },
      required: ['event_url'],
    },
  },
  {
    name: 'delete_event',
    description: 'Delete an event by its CalDAV URL.',
    inputSchema: {
      type: 'object',
      properties: {
        event_url: { type: 'string', description: 'Full CalDAV URL of the .ics event.' },
        etag: { type: 'string', description: 'ETag for safe deletion (optional).' },
      },
      required: ['event_url'],
    },
  },
  {
    name: 'search_events',
    description:
      'Search events by keyword (case-insensitive) across summary, description, and location.',
    inputSchema: {
      type: 'object',
      properties: {
        calendar_url: { type: 'string', description: 'CalDAV URL of the calendar to search.' },
        query: { type: 'string', description: 'Keyword to match.' },
        start: { type: 'string', description: 'Optional start bound (iCal format).' },
        end: { type: 'string', description: 'Optional end bound (iCal format).' },
      },
      required: ['calendar_url', 'query'],
    },
  },
  {
    name: 'get_freebusy',
    description: 'Return a list of busy intervals (start/end/summary) within a date range.',
    inputSchema: {
      type: 'object',
      properties: {
        calendar_url: { type: 'string', description: 'CalDAV URL of the calendar.' },
        start: { type: 'string', description: 'Range start in iCal format.' },
        end: { type: 'string', description: 'Range end in iCal format.' },
      },
      required: ['calendar_url', 'start', 'end'],
    },
  },
  {
    name: 'get_ical_feed',
    description: 'Return all events as a complete iCalendar (.ics) feed string.',
    inputSchema: {
      type: 'object',
      properties: {
        calendar_url: { type: 'string', description: 'CalDAV URL of the calendar.' },
      },
      required: ['calendar_url'],
    },
  },
];

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

async function executeTool(
  name: string,
  args: Record<string, unknown>,
  env: Env,
  authToken: string,
): Promise<unknown> {
  switch (name) {
    // ---- list_calendars ---------------------------------------------------
    case 'list_calendars': {
      const calendars = await discoverCalendars(env, authToken);
      return { calendars };
    }

    // ---- list_events ------------------------------------------------------
    case 'list_events': {
      const events = await fetchEvents(
        env,
        authToken,
        args.calendar_url as string,
        args.start as string | undefined,
        args.end as string | undefined,
      );
      return { events };
    }

    // ---- get_event --------------------------------------------------------
    case 'get_event': {
      const { status, text } = await caldavRequest(env, authToken, args.event_url as string, 'GET');
      if (status >= 400) throw new Error(`GET event returned ${status}`);
      return { ical: text };
    }

    // ---- create_event -----------------------------------------------------
    case 'create_event': {
      const calUrl = (args.calendar_url as string).replace(/\/?$/, '/');
      const uid = crypto.randomUUID();
      const ical = makeVEvent({
        uid,
        summary: args.summary as string,
        dtstart: args.dtstart as string,
        dtend: args.dtend as string,
        description: args.description as string | undefined,
        location: args.location as string | undefined,
        allDay: args.all_day as boolean | undefined,
      });
      const eventUrl = `${calUrl}${uid}.ics`;
      const { status } = await caldavRequest(env, authToken, eventUrl, 'PUT', ical, {
        'Content-Type': 'text/calendar; charset=utf-8',
        'If-None-Match': '*',
      });
      if (status >= 400) throw new Error(`PUT new event returned ${status}`);
      return { uid, event_url: eventUrl, status };
    }

    // ---- update_event -----------------------------------------------------
    case 'update_event': {
      const eventUrl = args.event_url as string;
      const { status: gs, text: existing } = await caldavRequest(env, authToken, eventUrl, 'GET');
      if (gs >= 400) throw new Error(`GET event for update returned ${gs}`);

      let updated = existing;
      if (args.summary)
        updated = updated.replace(/SUMMARY:.*/i, `SUMMARY:${args.summary}`);
      if (args.dtstart)
        updated = updated.replace(/DTSTART[^:\r\n]*:.*/i, `DTSTART:${args.dtstart}`);
      if (args.dtend)
        updated = updated.replace(/DTEND[^:\r\n]*:.*/i, `DTEND:${args.dtend}`);
      if (args.description) {
        if (/DESCRIPTION:/i.test(updated))
          updated = updated.replace(/DESCRIPTION:.*/i, `DESCRIPTION:${args.description}`);
        else
          updated = updated.replace(
            /END:VEVENT/i,
            `DESCRIPTION:${args.description}\r\nEND:VEVENT`,
          );
      }
      if (args.location) {
        if (/LOCATION:/i.test(updated))
          updated = updated.replace(/LOCATION:.*/i, `LOCATION:${args.location}`);
        else
          updated = updated.replace(
            /END:VEVENT/i,
            `LOCATION:${args.location}\r\nEND:VEVENT`,
          );
      }

      const putHeaders: Record<string, string> = {
        'Content-Type': 'text/calendar; charset=utf-8',
      };
      if (args.etag) putHeaders['If-Match'] = args.etag as string;

      const { status } = await caldavRequest(env, authToken, eventUrl, 'PUT', updated, putHeaders);
      if (status >= 400) throw new Error(`PUT update returned ${status}`);
      return { event_url: eventUrl, status };
    }

    // ---- delete_event -----------------------------------------------------
    case 'delete_event': {
      const eventUrl = args.event_url as string;
      const headers: Record<string, string> = {};
      if (args.etag) headers['If-Match'] = args.etag as string;
      const { status } = await caldavRequest(env, authToken, eventUrl, 'DELETE', undefined, headers);
      if (status >= 400 && status !== 404)
        throw new Error(`DELETE returned ${status}`);
      return { deleted: true, status };
    }

    // ---- search_events ----------------------------------------------------
    case 'search_events': {
      const q = (args.query as string).toLowerCase();
      const events = await fetchEvents(
        env,
        authToken,
        args.calendar_url as string,
        args.start as string | undefined,
        args.end as string | undefined,
      );
      const matched = events.filter(
        (e) =>
          (e['SUMMARY'] ?? '').toLowerCase().includes(q) ||
          (e['DESCRIPTION'] ?? '').toLowerCase().includes(q) ||
          (e['LOCATION'] ?? '').toLowerCase().includes(q),
      );
      return { events: matched };
    }

    // ---- get_freebusy -----------------------------------------------------
    case 'get_freebusy': {
      const events = await fetchEvents(
        env,
        authToken,
        args.calendar_url as string,
        args.start as string,
        args.end as string,
      );
      const busy = events.map((e) => ({
        start: e['DTSTART'],
        end: e['DTEND'],
        summary: e['SUMMARY'],
      }));
      return { start: args.start, end: args.end, busy };
    }

    // ---- get_ical_feed ----------------------------------------------------
    case 'get_ical_feed': {
      const events = await fetchEvents(env, authToken, args.calendar_url as string);
      const lines = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//poke-ical//EN',
        'CALSCALE:GREGORIAN',
        'METHOD:PUBLISH',
      ];
      for (const e of events) {
        lines.push('BEGIN:VEVENT');
        for (const [k, v] of Object.entries(e)) {
          if (k !== 'etag' && k !== 'href') lines.push(`${k}:${v}`);
        }
        lines.push('END:VEVENT');
      }
      lines.push('END:VCALENDAR');
      return { ical: lines.join('\r\n') };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatcher
// ---------------------------------------------------------------------------

async function handleJsonRpc(req: JsonRpcRequest, env: Env, authToken: string): Promise<JsonRpcResponse | null> {
  const { method, params, id } = req;

  try {
    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'poke-ical', version: '2.0.0' },
          capabilities: { tools: {} },
        },
      };
    }

    // Notifications have no response
    if (method === 'notifications/initialized' || method === 'initialized') {
      return null;
    }

    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
    }

    if (method === 'tools/call') {
      const p = params as { name: string; arguments?: Record<string, unknown> };
      const toolResult = await executeTool(p.name, p.arguments ?? {}, env, authToken);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(toolResult, null, 2) }],
        },
      };
    }

    if (method === 'ping') {
      return { jsonrpc: '2.0', id, result: {} };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[poke-ical] tool error (${method}):`, err);
    return { jsonrpc: '2.0', id, error: { code: -32000, message } };
  }
}

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

function sseEvent(eventType: string, data: unknown): string {
  return `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
}

// ---------------------------------------------------------------------------
// Cloudflare Worker entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    console.log('Request Path:', pathname);

    if (['/mcp', '/login', '/setup', '/auth', '/authorize', '/token'].includes(pathname)) {
      if (pathname === '/authorize') return await handleAuthorizeRequest(request, env);
      if (pathname === '/token') return await handleTokenRequest(request, env);
      if (pathname === '/auth' || pathname === '/setup' || pathname === '/login') return await handleSetupRequest(request, env);

      if (pathname === '/mcp') {
        if (request.method === 'OPTIONS') {
          return new Response(null, {
            status: 204,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, X-API-Key, X-Requested-With',
            },
          });
        }

        if (request.method === 'GET') {
          const origin = new URL(request.url).origin;
          const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
          const writer = writable.getWriter();
          const encoder = new TextEncoder();
          writer.write(encoder.encode(sseEvent('endpoint', { uri: `${origin}/mcp` }))).catch(() => {});
          const keepAlive = setInterval(() => {
            writer.write(encoder.encode(': ping\n\n')).catch(() => clearInterval(keepAlive));
          }, 20000);
          return new Response(readable, {
            headers: {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
              'Access-Control-Allow-Origin': '*',
            },
          });
        }

        if (request.method === 'POST') {
          const authorizationHeader = request.headers.get('Authorization') ?? request.headers.get('authorization');
          const apiKeyHeader = request.headers.get('X-API-Key') ?? request.headers.get('x-api-key');
          const authCandidates = [
            authorizationHeader?.trim().replace(/^Bearer\s+/i, '').trim() ?? '',
            apiKeyHeader?.trim() ?? '',
          ].filter(Boolean);
          const uniqueAuthCandidates = [...new Set(authCandidates)];
          if (uniqueAuthCandidates.length === 0) {
            return new Response(JSON.stringify({ error: "Missing authentication token. Use Authorization: Bearer <token>, Authorization: <token>, or X-API-Key: <token>." }), {
              status: 401,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'WWW-Authenticate': 'Bearer realm="poke-ical"',
                'Access-Control-Allow-Origin': '*',
              },
            });
          }
          let credentials: Awaited<ReturnType<typeof loadStoredCredentials>> = null;
          for (const candidate of uniqueAuthCandidates) {
            credentials = await loadStoredCredentials(env, candidate);
            if (credentials) break;
          }
          if (!credentials) {
            return new Response(JSON.stringify({ error: "Invalid authentication token. Open /auth to save credentials and use the token shown there." }), {
              status: 401,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'WWW-Authenticate': 'Bearer realm="poke-ical"',
                'Access-Control-Allow-Origin': '*',
              },
            });
          }
          let body: JsonRpcRequest;
          try { body = (await request.json()) as JsonRpcRequest; } catch {
            return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          const bearerToken = uniqueAuthCandidates[0];
          const response = await handleJsonRpc(body, env, bearerToken);
          if (response === null) {
            return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*" } });
          }
          const acceptsSse = (request.headers.get("Accept") ?? "").includes("text/event-stream");
          if (acceptsSse) {
            return new Response(sseEvent("message", response), { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Access-Control-Allow-Origin": "*" } });
          }
          return new Response(JSON.stringify(response), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
      }
      return new Response('Not Found', { status: 404 });
    }

    return new Response('Not Found', { status: 404 });
  },
};