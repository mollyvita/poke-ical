/**
 * poke-ical: iCloud Calendar MCP Server (Cloudflare Worker)
 *
 * Exposes 9 CalDAV tools via the Model Context Protocol over SSE.
 * Endpoint: /mcp (Bearer-token authenticated via the built-in OAuth 2.1 AS)
 *
 * OAuth flow: clients discover /.well-known/oauth-protected-resource, register
 * via /oauth/register, and complete an authorization-code + PKCE flow at
 * /oauth/authorize — which renders a login page collecting the user's iCloud
 * email + app-specific password. Credentials are stored AES-GCM-encrypted in KV.
 *
 * Required bindings/secrets:
 *   OAUTH_KV        — KV namespace (see wrangler.toml)
 *   TOKEN_ENC_KEY   — secret used to encrypt stored credentials
 *
 * Optional legacy fallback (single shared account, no OAuth):
 *   CALDAV_USERNAME  — Apple ID email (e.g. user@icloud.com)
 *   CALDAV_PASSWORD  — App-specific password from appleid.apple.com
 *
 * iCloud CalDAV discovery is a 2-step process:
 *   1. PROPFIND https://caldav.icloud.com/ → current-user-principal href
 *   2. PROPFIND {principal} → calendar-home-set href
 *   3. PROPFIND {home-set} → enumerate individual calendars
 */

import { caldavRequest, type CalCreds } from './caldav-http';
import { authenticateRequest, handleOAuthRequest, type OAuthEnv } from './oauth';

export interface Env extends OAuthEnv {
  CALDAV_USERNAME?: string;
  CALDAV_PASSWORD?: string;
}

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

// ---------------------------------------------------------------------------
// XML helpers  (no dependency on a full XML parser)
// ---------------------------------------------------------------------------

/** Return ALL text contents of every element matching `localName` (namespace-agnostic). */
function xmlAll(xml: string, localName: string): string[] {
  const out: string[] = [];
  // matches both <D:foo> … </D:foo>  and  <foo> … </foo>
  const re = new RegExp(
    `<(?:[^:>]+:)?${localName}(?:\\s[^>]*)?>([\\s\\S]*?)<\/(?:[^:>]+:)?${localName}>`,
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
async function fetchPrincipalUrl(creds: CalCreds): Promise<string> {
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(
    creds,
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
async function fetchCalendarHomeSet(creds: CalCreds, principalUrl: string): Promise<string> {
  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-home-set/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(
    creds,
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
async function resolveHomeSet(creds: CalCreds): Promise<string> {
  const principalUrl = await fetchPrincipalUrl(creds);
  return fetchCalendarHomeSet(creds, principalUrl);
}

// ---------------------------------------------------------------------------
// Step 3 – list calendars under the home-set URL
// ---------------------------------------------------------------------------
async function discoverCalendars(
  creds: CalCreds,
): Promise<Array<{ url: string; displayName: string; ctag: string }>> {
  const homeSetUrl = await resolveHomeSet(creds);

  const body = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
            xmlns:CS="http://calendarserver.org/ns/">
  <D:prop>
    <D:displayname/>
    <D:resourcetype/>
    <CS:getctag/>
  </D:prop>
</D:propfind>`;

  const { status, text } = await caldavRequest(creds, homeSetUrl, 'PROPFIND', body, { Depth: '1' });
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
  creds: CalCreds,
  calendarUrl: string,
  start?: string,
  end?: string,
): Promise<Array<Record<string, string>>> {
  let timeFilter = '';
  if (start || end) {
    const s = start ?? '19700101T000000Z';
    const e = end ?? '20991231T235959Z';
    timeFilter = `\n      <C:time-range start="${s}" end="${e}"/>`;
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

  const { status, text } = await caldavRequest(creds, calendarUrl, 'REPORT', body, {
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
  creds: CalCreds,
): Promise<unknown> {
  switch (name) {
    // ---- list_calendars ---------------------------------------------------
    case 'list_calendars': {
      const calendars = await discoverCalendars(creds);
      return { calendars };
    }

    // ---- list_events ------------------------------------------------------
    case 'list_events': {
      const events = await fetchEvents(
        creds,
        args.calendar_url as string,
        args.start as string | undefined,
        args.end as string | undefined,
      );
      return { events };
    }

    // ---- get_event --------------------------------------------------------
    case 'get_event': {
      const { status, text } = await caldavRequest(creds, args.event_url as string, 'GET');
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
      const { status } = await caldavRequest(creds, eventUrl, 'PUT', ical, {
        'Content-Type': 'text/calendar; charset=utf-8',
        'If-None-Match': '*',
      });
      if (status >= 400) throw new Error(`PUT new event returned ${status}`);
      return { uid, event_url: eventUrl, status };
    }

    // ---- update_event -----------------------------------------------------
    case 'update_event': {
      const eventUrl = args.event_url as string;
      const { status: gs, text: existing } = await caldavRequest(creds, eventUrl, 'GET');
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

      const { status } = await caldavRequest(creds, eventUrl, 'PUT', updated, putHeaders);
      if (status >= 400) throw new Error(`PUT update returned ${status}`);
      return { event_url: eventUrl, status };
    }

    // ---- delete_event -----------------------------------------------------
    case 'delete_event': {
      const eventUrl = args.event_url as string;
      const headers: Record<string, string> = {};
      if (args.etag) headers['If-Match'] = args.etag as string;
      const { status } = await caldavRequest(creds, eventUrl, 'DELETE', undefined, headers);
      if (status >= 400 && status !== 404)
        throw new Error(`DELETE returned ${status}`);
      return { deleted: true, status };
    }

    // ---- search_events ----------------------------------------------------
    case 'search_events': {
      const q = (args.query as string).toLowerCase();
      const events = await fetchEvents(
        creds,
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
        creds,
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
      const events = await fetchEvents(creds, args.calendar_url as string);
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

async function handleJsonRpc(req: JsonRpcRequest, creds: CalCreds): Promise<JsonRpcResponse | null> {
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
      const toolResult = await executeTool(p.name, p.arguments ?? {}, creds);
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
    const url = new URL(request.url);

    // -----------------------------------------------------------------------
    // OAuth 2.1 authorization server — metadata, DCR, authorize, token, revoke
    // -----------------------------------------------------------------------
    const oauthResponse = await handleOAuthRequest(request, env, url);
    if (oauthResponse) return oauthResponse;

    // -----------------------------------------------------------------------
    // /mcp  — MCP over SSE (Bearer-token authenticated)
    // -----------------------------------------------------------------------
    if (url.pathname === '/mcp') {
      // CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
          },
        });
      }

      // Resolve per-user credentials from the Bearer token (or legacy secrets)
      const auth = await authenticateRequest(request, env);
      if (auth instanceof Response) return auth;
      const creds = auth;

      // ---- GET: SSE stream — sends endpoint event so clients know where to POST
      if (request.method === 'GET') {
        const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
        const writer = writable.getWriter();
        const encoder = new TextEncoder();

        // Send endpoint event immediately
        writer.write(encoder.encode(
          sseEvent('endpoint', { uri: `${url.origin}/mcp` }),
        )).catch(() => {});

        // Periodic comment-based keepalive (CF Workers can't use setInterval
        // reliably in long-lived streams, but this is fine for most clients)
        const keepAlive = setInterval(() => {
          writer.write(encoder.encode(': ping\n\n')).catch(() => {
            clearInterval(keepAlive);
          });
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

      // ---- POST: JSON-RPC message
      if (request.method === 'POST') {
        let body: JsonRpcRequest;
        try {
          body = (await request.json()) as JsonRpcRequest;
        } catch {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Parse error' },
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } },
          );
        }

        const response = await handleJsonRpc(body, creds);

        // Notification — 204 no content
        if (response === null) {
          return new Response(null, {
            status: 204,
            headers: { 'Access-Control-Allow-Origin': '*' },
          });
        }

        const acceptsSse = (request.headers.get('Accept') ?? '').includes('text/event-stream');
        if (acceptsSse) {
          return new Response(sseEvent('message', response), {
            headers: {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache',
              'Access-Control-Allow-Origin': '*',
            },
          });
        }

        return new Response(JSON.stringify(response), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
    }

    // -----------------------------------------------------------------------
    // /health
    // -----------------------------------------------------------------------
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true, version: '2.0.0' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
