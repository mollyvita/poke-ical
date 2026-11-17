/**
 * Shared CalDAV HTTP helpers.
 *
 * Credentials are passed explicitly so the same code path works for
 * per-user OAuth credentials and the legacy env-secret fallback.
 */

export interface CalCreds {
  username: string;
  password: string;
}

export function basicAuth(creds: CalCreds): string {
  return 'Basic ' + btoa(`${creds.username}:${creds.password}`);
}

/**
 * Perform a raw CalDAV / WebDAV request.
 * Throws (and logs) on network-level errors; returns status + body text for
 * HTTP-level errors so callers can decide how to handle them.
 */
export async function caldavRequest(
  creds: CalCreds,
  url: string,
  method: string,
  body?: string,
  extraHeaders?: Record<string, string>,
): Promise<{ status: number; text: string }> {
  const headers: Record<string, string> = {
    Authorization: basicAuth(creds),
    'Content-Type': 'application/xml; charset=utf-8',
    ...extraHeaders,
  };
  let res: Response;
  try {
    res = await fetch(url, { method, headers, body });
  } catch (err) {
    console.error(`[poke-ical] fetch failed — ${method} ${url}:`, err);
    throw err;
  }
  const text = await res.text();
  if (res.status >= 400) {
    console.error(
      `[poke-ical] HTTP error — ${method} ${url} → ${res.status}\n`,
      text.slice(0, 500),
    );
  }
  return { status: res.status, text };
}
