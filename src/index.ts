interface Env {
  STATE: KVNamespace;
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  GCHAT_WEBHOOK_URL: string;
  GCHAT_WEBHOOK_SECURITY?: string;
  GCHAT_WEBHOOK_CONFIG?: string;
  ALERT_MODE?: string;
  ALERT_ACTION_ALLOWLIST?: string;
}

type AuditEvent = {
  id?: string;
  when?: string;
  interface?: string;
  account?: {
    id?: string;
    name?: string;
  };
  owner?: {
    id?: string;
  };
  zone?: {
    id?: string;
    name?: string;
  };
  actor?: {
    id?: string;
    type?: string;
    email?: string;
    ip?: string;
    ip_address?: string;
    context?: string;
    token_id?: string;
    token_name?: string;
  };
  action?:
    | {
        type?: string;
        description?: string;
        result?: string;
        time?: string;
      }
    | string;
  resource?: {
    id?: string;
    name?: string;
    type?: string;
    product?: string;
    request?: unknown;
    response?: unknown;
    scope?: unknown;
  };
  resources?: {
    resource_id?: string;
    resource_type?: string;
  }[];
  raw?: {
    cf_ray_id?: string;
    method?: string;
    status_code?: number;
    uri?: string;
    user_agent?: string;
  };
  metadata?: {
    key?: string;
    value?: string;
  }[];
  oldValue?: unknown;
  newValue?: unknown;
};

type AuditLogsResponse = {
  success: boolean;
  errors?: { message?: string }[];
  result?: AuditEvent[];
  result_info?: {
    count?: string;
    cursor?: string;
  };
};

type GchatPayload = {
  text: string;
  cardsV2: {
    cardId: string;
    card: {
      header: {
        title: string;
        subtitle?: string;
      };
      sections: {
        widgets: Array<
          | {
              decoratedText: {
                topLabel: string;
                text: string;
              };
            }
          | {
              textParagraph: {
                text: string;
              };
            }
        >;
      }[];
    };
  }[];
};

type EventProfile = {
  severity: "HIGH" | "MEDIUM" | "LOW";
  category: "security" | "config" | "general";
};

type LedgerEntry = {
  event_id: string;
  sent_at: string;
  event_time: string;
  webhook: string;
  severity: EventProfile["severity"];
  category: EventProfile["category"];
  action: string;
  actor: string;
  resource: string;
  result: string;
  status: "sent";
};

const CURSOR_KEY = "cursor:last_seen_iso";
const DEDUPE_PREFIX = "dedupe:";
const DEDUPE_TTL_SECONDS = 7 * 24 * 60 * 60;
const LEDGER_EVENT_PREFIX = "ledger:event:";
const LEDGER_RECENT_PREFIX = "ledger:recent:";
const LEDGER_RETENTION_SECONDS = 180 * 24 * 60 * 60;
const REVERSE_TS_MAX = 9_999_999_999_999;
const MAIN_CRON = "*/1 * * * *";
const DAILY_SUMMARY_CRON = "0 0 * * *";
const IMPORTANT_KEYWORDS = [
  "member",
  "token",
  "auth",
  "login",
  "mfa",
  "sso",
  "access",
  "firewall",
  "waf",
  "dns",
  "ssl",
  "certificate",
  "worker",
  "route",
  "ruleset",
  "apikey",
  "api_key",
  "secret",
];

export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    if (event.cron === DAILY_SUMMARY_CRON) {
      ctx.waitUntil(
        sendDailySummary(env).catch((error) => {
          console.error("daily summary failed", toErrorMessage(error));
        }),
      );
      return;
    }

    if (event.cron === MAIN_CRON) {
      ctx.waitUntil(
        syncAuditToGoogleChat(env).catch((error) => {
          console.error("scheduled sync failed", toErrorMessage(error));
        }),
      );
      return;
    }

    ctx.waitUntil(Promise.resolve());
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true, service: "cf-audit-gchat-webhook" });
    }

    if ((request.method === "POST" || request.method === "GET") && url.pathname === "/run") {
      try {
        await syncAuditToGoogleChat(env);
        return Response.json({ ok: true });
      } catch (error) {
        return Response.json({ ok: false, error: toErrorMessage(error) }, { status: 500 });
      }
    }

    if ((request.method === "POST" || request.method === "GET") && url.pathname === "/summary") {
      try {
        await sendDailySummary(env);
        return Response.json({ ok: true });
      } catch (error) {
        return Response.json({ ok: false, error: toErrorMessage(error) }, { status: 500 });
      }
    }

    if (request.method === "GET" && url.pathname === "/ledger") {
      try {
        const eventId = url.searchParams.get("event_id") ?? undefined;
        const limit = toPositiveInt(url.searchParams.get("limit"), 20, 100);

        if (eventId) {
          const entry = await getLedgerByEventId(env, eventId);
          return Response.json({ ok: true, event_id: eventId, entry });
        }

        const entries = await listRecentLedgerEntries(env, limit);
        return Response.json({ ok: true, count: entries.length, entries });
      } catch (error) {
        return Response.json({ ok: false, error: toErrorMessage(error) }, { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function syncAuditToGoogleChat(env: Env): Promise<void> {
  const now = Date.now();
  const defaultSince = new Date(now - 5 * 60 * 1000).toISOString();
  const since = (await env.STATE.get(CURSOR_KEY)) ?? defaultSince;
  const before = new Date().toISOString();

  const events = await listAuditEvents(env, since, before);
  if (events.length === 0) {
    return;
  }

  const sorted = [...events].sort((a, b) => getEventTimestamp(a).localeCompare(getEventTimestamp(b)));

  let newestIso = since;
  const unsent: AuditEvent[] = [];

  for (const event of sorted) {
    const eventTime = getEventTimestamp(event);
    if (eventTime > newestIso) {
      newestIso = eventTime;
    }

    const eventId = toEventId(event);
    const dedupeKey = `${DEDUPE_PREFIX}${eventId}`;
    const alreadySent = await env.STATE.get(dedupeKey);
    if (alreadySent) {
      continue;
    }

    unsent.push(event);
  }

  const filtered = unsent.filter((event) => shouldAlertEvent(event, env));
  const routed = routeByWebhook(filtered, env);

  for (const [webhookUrl, webhookEvents] of routed.entries()) {
    for (const batch of chunk(webhookEvents, 5)) {
      const payload = formatGchatMessage(batch);
      await postToGoogleChat(webhookUrl, payload);
      await markBatchAsSent(env, webhookUrl, batch);
    }
  }

  await env.STATE.put(CURSOR_KEY, newestIso);
}

async function sendDailySummary(env: Env): Promise<void> {
  const before = new Date();
  const since = new Date(before.getTime() - 24 * 60 * 60 * 1000);
  const events = await listAuditEvents(env, since.toISOString(), before.toISOString());
  const payload = formatDailySummary(events, since.toISOString(), before.toISOString());
  await postToGoogleChat(env.GCHAT_WEBHOOK_URL, payload);
}

async function listAuditEvents(env: Env, sinceIso: string, beforeIso: string): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];
  let cursor: string | undefined;

  while (true) {
    const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/logs/audit`);
    url.searchParams.set("since", sinceIso);
    url.searchParams.set("before", beforeIso);
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Cloudflare audit API request failed (${response.status}): ${body}`);
    }

    const payload = (await response.json()) as AuditLogsResponse;
    if (!payload.success) {
      const errorMessage = (payload.errors ?? [])
        .map((item) => item.message ?? "unknown error")
        .join("; ");
      throw new Error(`Cloudflare audit API error: ${errorMessage}`);
    }

    events.push(...(payload.result ?? []));
    const nextCursor = payload.result_info?.cursor;
    if (!nextCursor || nextCursor === cursor) {
      break;
    }
    cursor = nextCursor;
  }

  return events;
}

async function postToGoogleChat(webhookUrl: string, payload: GchatPayload): Promise<void> {
  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Google Chat webhook failed (${response.status}): ${body}`);
  }
}

function formatGchatMessage(events: AuditEvent[]): GchatPayload {
  const cards = events.map((event, index) => buildEventCard(event, index));

  return {
    text: `Cloudflare audit logs: ${events.length} new event(s)`,
    cardsV2: cards,
  };
}

function formatDailySummary(events: AuditEvent[], sinceIso: string, beforeIso: string): GchatPayload {
  const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const categoryCounts = { security: 0, config: 0, general: 0 };
  const byAction = new Map<string, number>();
  const byActor = new Map<string, number>();

  for (const event of events) {
    const profile = getEventProfile(event);
    severityCounts[profile.severity] += 1;
    categoryCounts[profile.category] += 1;

    const actionType = getAction(event).type ?? "unknown-action";
    byAction.set(actionType, (byAction.get(actionType) ?? 0) + 1);

    const actor = event.actor?.email ?? event.actor?.id ?? event.actor?.type ?? "unknown-actor";
    byActor.set(actor, (byActor.get(actor) ?? 0) + 1);
  }

  const topActions = sortMapDesc(byAction).slice(0, 8);
  const topActors = sortMapDesc(byActor).slice(0, 8);
  const widgets: GchatPayload["cardsV2"][number]["card"]["sections"][number]["widgets"] = [
    {
      decoratedText: {
        topLabel: "Window",
        text: `${escapeForChat(sinceIso)} to ${escapeForChat(beforeIso)}`,
      },
    },
    {
      decoratedText: {
        topLabel: "Total Events",
        text: String(events.length),
      },
    },
    {
      decoratedText: {
        topLabel: "Severity",
        text: `HIGH=${severityCounts.HIGH}, MEDIUM=${severityCounts.MEDIUM}, LOW=${severityCounts.LOW}`,
      },
    },
    {
      decoratedText: {
        topLabel: "Categories",
        text: `security=${categoryCounts.security}, config=${categoryCounts.config}, general=${categoryCounts.general}`,
      },
    },
    {
      textParagraph: {
        text: `<b>Top Actions</b><br>${escapeForChat(formatKeyValueList(topActions))}`,
      },
    },
    {
      textParagraph: {
        text: `<b>Top Actors</b><br>${escapeForChat(formatKeyValueList(topActors))}`,
      },
    },
  ];

  return {
    text: `Cloudflare audit logs daily summary: ${events.length} event(s)`,
    cardsV2: [
      {
        cardId: "daily-summary",
        card: {
          header: {
            title: "Cloudflare Audit Daily Summary",
            subtitle: "Last 24 hours",
          },
          sections: [{ widgets }],
        },
      },
    ],
  };
}

function buildEventCard(event: AuditEvent, index: number): GchatPayload["cardsV2"][number] {
  const action = getAction(event);
  const eventTime = getEventTimestamp(event);
  const actorIp = event.actor?.ip ?? event.actor?.ip_address ?? "unknown-ip";
  const actorIdentity = [event.actor?.email, event.actor?.id, event.actor?.type]
    .filter((value): value is string => Boolean(value))
    .join(" | ");
  const resourceName = event.resource?.name ?? "unknown-resource-name";
  const resourceId = event.resource?.id ?? "unknown-resource-id";
  const resourceType = event.resource?.type ?? event.resource?.product ?? "unknown-resource-type";
  const profile = getEventProfile(event);
  const what = `${action.type ?? "unknown-action"} on ${resourceName} (${resourceType}:${resourceId})`;

  const widgets: GchatPayload["cardsV2"][number]["card"]["sections"][number]["widgets"] = [
    { decoratedText: { topLabel: "Severity", text: profile.severity } },
    { decoratedText: { topLabel: "When", text: escapeForChat(eventTime) } },
    { decoratedText: { topLabel: "Who", text: escapeForChat(actorIdentity || "unknown-actor") } },
    { decoratedText: { topLabel: "Who IP", text: escapeForChat(actorIp) } },
    { decoratedText: { topLabel: "What", text: escapeForChat(what) } },
    { decoratedText: { topLabel: "Action Result", text: escapeForChat(action.result ?? "unknown-result") } },
    { decoratedText: { topLabel: "Event ID", text: escapeForChat(event.id ?? "unknown") } },
  ];

  if (action.description) {
    widgets.push({ decoratedText: { topLabel: "Action Description", text: escapeForChat(action.description) } });
  }
  if (event.account?.id || event.account?.name) {
    widgets.push({
      decoratedText: {
        topLabel: "Account",
        text: escapeForChat(`${event.account?.name ?? "unknown-account-name"} | ${event.account?.id ?? "unknown-account-id"}`),
      },
    });
  }
  if (event.zone?.id || event.zone?.name) {
    widgets.push({
      decoratedText: {
        topLabel: "Zone",
        text: escapeForChat(`${event.zone?.name ?? "unknown-zone-name"} | ${event.zone?.id ?? "unknown-zone-id"}`),
      },
    });
  }
  const changeLines = extractChangeDetails(event);
  if (changeLines.length > 0) {
    widgets.push({
      textParagraph: {
        text: `<b>Change Details</b><br>${escapeForChat(changeLines.join("\n"))}`,
      },
    });
  }

  return {
    cardId: `audit-${index + 1}`,
    card: {
      header: {
        title: "Cloudflare Audit (Auditor View)",
        subtitle: escapeForChat(`${action.type ?? "unknown-action"} | ${profile.severity}`),
      },
      sections: [
        {
          widgets,
        },
      ],
    },
  };
}

function routeByWebhook(events: AuditEvent[], env: Env): Map<string, AuditEvent[]> {
  const mapped = new Map<string, AuditEvent[]>();

  for (const event of events) {
    const webhookUrl = resolveWebhook(event, env);
    if (!mapped.has(webhookUrl)) {
      mapped.set(webhookUrl, []);
    }
    mapped.get(webhookUrl)?.push(event);
  }

  return mapped;
}

function resolveWebhook(event: AuditEvent, env: Env): string {
  const profile = getEventProfile(event);

  if (profile.category === "security" && env.GCHAT_WEBHOOK_SECURITY) {
    return env.GCHAT_WEBHOOK_SECURITY;
  }

  if (profile.category === "config" && env.GCHAT_WEBHOOK_CONFIG) {
    return env.GCHAT_WEBHOOK_CONFIG;
  }

  return env.GCHAT_WEBHOOK_URL;
}

function shouldAlertEvent(event: AuditEvent, env: Env): boolean {
  const action = getAction(event);
  const actionBlob = [
    action.type,
    action.description,
    event.resource?.product,
    event.resource?.type,
    event.raw?.uri,
    event.raw?.method,
  ]
    .filter((item): item is string => Boolean(item))
    .join(" ")
    .toLowerCase();

  const allowlist = parseAllowlist(env.ALERT_ACTION_ALLOWLIST);
  if (allowlist.length > 0) {
    return allowlist.some((item) => actionBlob.includes(item));
  }

  const mode = (env.ALERT_MODE ?? "all").toLowerCase();
  if (mode === "all") {
    return true;
  }

  if ((action.result ?? "").toLowerCase() === "failure") {
    return true;
  }

  return IMPORTANT_KEYWORDS.some((keyword) => actionBlob.includes(keyword));
}

function getEventProfile(event: AuditEvent): EventProfile {
  const action = getAction(event);
  const text = [action.type, action.description, event.resource?.product, event.resource?.type, event.raw?.uri]
    .filter((item): item is string => Boolean(item))
    .join(" ")
    .toLowerCase();
  const result = (action.result ?? "").toLowerCase();

  const isSecurity =
    text.includes("token") ||
    text.includes("member") ||
    text.includes("auth") ||
    text.includes("login") ||
    text.includes("mfa") ||
    text.includes("sso") ||
    text.includes("access") ||
    text.includes("firewall") ||
    text.includes("waf") ||
    text.includes("apikey") ||
    text.includes("api_key") ||
    text.includes("secret");

  if (isSecurity) {
    if (result === "failure") {
      return { severity: "HIGH", category: "security" };
    }
    if (text.includes("delete") || text.includes("revoke") || text.includes("disable")) {
      return { severity: "HIGH", category: "security" };
    }
    return { severity: "MEDIUM", category: "security" };
  }

  const isConfig =
    text.includes("zone") ||
    text.includes("dns") ||
    text.includes("ssl") ||
    text.includes("certificate") ||
    text.includes("ruleset") ||
    text.includes("worker") ||
    text.includes("route") ||
    text.includes("setting");

  if (isConfig) {
    if (result === "failure") {
      return { severity: "HIGH", category: "config" };
    }
    return { severity: "MEDIUM", category: "config" };
  }

  if (result === "failure") {
    return { severity: "MEDIUM", category: "general" };
  }

  return { severity: "LOW", category: "general" };
}

function extractChangeDetails(event: AuditEvent): string[] {
  const lines: string[] = [];
  const diff = buildDiff(event.oldValue, event.newValue);

  if (diff.length > 0) {
    lines.push(...diff);
  } else {
    if (event.oldValue !== undefined) {
      lines.push(`old=${truncateText(toCompactJson(event.oldValue), 400)}`);
    }
    if (event.newValue !== undefined) {
      lines.push(`new=${truncateText(toCompactJson(event.newValue), 400)}`);
    }
  }

  if (lines.length > 6) {
    return [...lines.slice(0, 6), "...truncated..."];
  }
  return lines;
}

async function markBatchAsSent(env: Env, webhookUrl: string, events: AuditEvent[]): Promise<void> {
  const nowIso = new Date().toISOString();

  await Promise.all(
    events.map(async (event) => {
      const eventId = toEventId(event);
      const dedupeKey = `${DEDUPE_PREFIX}${eventId}`;
      const profile = getEventProfile(event);
      const action = getAction(event).type ?? "unknown-action";
      const actor = event.actor?.email ?? event.actor?.id ?? event.actor?.type ?? "unknown-actor";
      const resource = event.resource?.name ?? event.resource?.id ?? event.resource?.type ?? "unknown-resource";
      const result = getAction(event).result ?? "unknown-result";

      const entry: LedgerEntry = {
        event_id: eventId,
        sent_at: nowIso,
        event_time: getEventTimestamp(event),
        webhook: redactWebhook(webhookUrl),
        severity: profile.severity,
        category: profile.category,
        action,
        actor,
        resource,
        result,
        status: "sent",
      };

      await env.STATE.put(dedupeKey, "1", { expirationTtl: DEDUPE_TTL_SECONDS });
      await writeLedgerEntry(env, entry);
    }),
  );
}

async function writeLedgerEntry(env: Env, entry: LedgerEntry): Promise<void> {
  const eventKey = `${LEDGER_EVENT_PREFIX}${entry.event_id}`;
  const recentKey = `${LEDGER_RECENT_PREFIX}${toReverseTimestamp(entry.sent_at)}:${entry.event_id}`;
  const payload = JSON.stringify(entry);

  await Promise.all([
    env.STATE.put(eventKey, payload, { expirationTtl: LEDGER_RETENTION_SECONDS }),
    env.STATE.put(recentKey, payload, { expirationTtl: LEDGER_RETENTION_SECONDS }),
  ]);
}

async function getLedgerByEventId(env: Env, eventId: string): Promise<LedgerEntry | null> {
  const key = `${LEDGER_EVENT_PREFIX}${eventId}`;
  const raw = await env.STATE.get(key);
  if (!raw) {
    return null;
  }
  return parseLedgerEntry(raw);
}

async function listRecentLedgerEntries(env: Env, limit: number): Promise<LedgerEntry[]> {
  const results = await env.STATE.list({ prefix: LEDGER_RECENT_PREFIX, limit });
  const entries: LedgerEntry[] = [];

  for (const key of results.keys) {
    const raw = await env.STATE.get(key.name);
    if (!raw) {
      continue;
    }

    const parsed = parseLedgerEntry(raw);
    if (parsed) {
      entries.push(parsed);
    }
  }

  return entries;
}

function parseLedgerEntry(raw: string): LedgerEntry | null {
  try {
    return JSON.parse(raw) as LedgerEntry;
  } catch {
    return null;
  }
}

function buildDiff(oldValue: unknown, newValue: unknown): string[] {
  if (!isRecord(oldValue) || !isRecord(newValue)) {
    return [];
  }

  const keys = new Set<string>([...Object.keys(oldValue), ...Object.keys(newValue)]);
  const lines: string[] = [];

  for (const key of [...keys].sort()) {
    const oldItem = oldValue[key];
    const newItem = newValue[key];
    if (isEqual(oldItem, newItem)) {
      continue;
    }

    lines.push(
      `${key}: ${truncateText(toCompactJson(oldItem), 120)} -> ${truncateText(toCompactJson(newItem), 120)}`,
    );
  }

  return lines;
}

function toEventId(event: AuditEvent): string {
  if (event.id && event.id.length > 0) {
    return event.id;
  }

  return [
    getEventTimestamp(event),
    event.actor?.email ?? "unknown-actor",
    getAction(event).type ?? "unknown-action",
    event.resource?.id ?? event.resource?.name ?? "unknown-resource",
  ].join("|");
}

function chunk<T>(items: T[], size: number): T[][] {
  const output: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    output.push(items.slice(index, index + size));
  }
  return output;
}

function parseAllowlist(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  return raw
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length > 0);
}

function sortMapDesc(input: Map<string, number>): Array<[string, number]> {
  return [...input.entries()].sort((a, b) => b[1] - a[1]);
}

function toReverseTimestamp(iso: string): string {
  const ms = Date.parse(iso);
  const safeMs = Number.isFinite(ms) ? ms : 0;
  const reverse = Math.max(0, REVERSE_TS_MAX - safeMs);
  return String(reverse).padStart(13, "0");
}

function redactWebhook(webhook: string): string {
  try {
    const url = new URL(webhook);
    return `${url.origin}${url.pathname}`;
  } catch {
    return "invalid-webhook";
  }
}

function toPositiveInt(raw: string | null, fallback: number, max: number): number {
  if (!raw) {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  return Math.min(parsed, max);
}

function formatKeyValueList(items: Array<[string, number]>): string {
  if (items.length === 0) {
    return "none";
  }
  return items.map(([key, value]) => `${key}: ${value}`).join("\n");
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return "unknown error";
}

function toCompactJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "[unserializable]";
  }
}

function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength - 3)}...`;
}

function escapeForChat(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function getAction(event: AuditEvent): { type?: string; description?: string; result?: string } {
  if (typeof event.action === "string") {
    return { type: event.action };
  }

  return {
    type: event.action?.type,
    description: event.action?.description,
    result: event.action?.result,
  };
}

function getEventTimestamp(event: AuditEvent): string {
  if (typeof event.action !== "string" && event.action?.time) {
    return event.action.time;
  }

  return event.when ?? "unknown-time";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEqual(a: unknown, b: unknown): boolean {
  return toCompactJson(a) === toCompactJson(b);
}
