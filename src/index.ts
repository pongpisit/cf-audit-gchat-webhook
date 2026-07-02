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
    const fallbackSent = await tryPostFallbackText(webhookUrl, payload.text);
    if (fallbackSent) {
      return;
    }
    throw new Error(`Google Chat webhook failed (${response.status}): ${body}`);
  }
}

async function tryPostFallbackText(webhookUrl: string, text: string): Promise<boolean> {
  const fallbackResponse = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
    },
    body: JSON.stringify({ text: truncateText(text, 3500) }),
  });

  return fallbackResponse.ok;
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
  const bkkTime = toBangkokTime(eventTime);
  const actorIp = event.actor?.ip ?? event.actor?.ip_address ?? "unknown-ip";
  const username = event.actor?.email ?? event.actor?.type ?? "unknown-actor";
  const resourceName = event.resource?.name ?? "unknown-resource-name";
  const resourceId = event.resource?.id ?? "unknown-resource-id";
  const resourceType = event.resource?.type ?? event.resource?.product ?? "unknown-resource-type";
  const profile = getEventProfile(event);
  const what = `${action.type ?? "unknown-action"} on ${resourceName} (${resourceType}:${resourceId})`;
  const who = `username=${username}`;

  const widgets: GchatPayload["cardsV2"][number]["card"]["sections"][number]["widgets"] = [
    { decoratedText: { topLabel: "Severity", text: profile.severity } },
    { decoratedText: { topLabel: "When (BKK +07)", text: escapeForChat(bkkTime) } },
    { decoratedText: { topLabel: "Who", text: escapeForChat(who) } },
    { decoratedText: { topLabel: "IP", text: escapeForChat(actorIp) } },
    { decoratedText: { topLabel: "What", text: escapeForChat(what) } },
    { decoratedText: { topLabel: "Action Result", text: escapeForChat(action.result ?? "unknown-result") } },
  ];

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
        subtitle: escapeForChat(`${action.type ?? "unknown-action"}`),
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
  const lines: string[] = ["field | old | new"];
  const diff = buildDiff(event.oldValue, event.newValue);
  const ruleDetails = extractRuleDetails(event);

  if (ruleDetails.length > 0) {
    lines.push(...ruleDetails);
  }

  if (diff.length > 0) {
    lines.push(...diff);
  } else {
    if (event.oldValue !== undefined) {
      lines.push(formatChangeRow("value", event.oldValue, event.newValue));
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
  if (oldValue === undefined && newValue === undefined) {
    return [];
  }

  const oldFlat = flattenValue(oldValue, "old");
  const newFlat = flattenValue(newValue, "new");
  const comparableKeys = new Set<string>();

  for (const key of oldFlat.keys()) {
    if (key.startsWith("old.")) {
      comparableKeys.add(key.slice(4));
    }
  }
  for (const key of newFlat.keys()) {
    if (key.startsWith("new.")) {
      comparableKeys.add(key.slice(4));
    }
  }

  const lines: string[] = [];

  for (const key of sortDiffKeys([...comparableKeys])) {
    const oldItem = oldFlat.get(`old.${key}`);
    const newItem = newFlat.get(`new.${key}`);
    if (isEqual(oldItem, newItem)) {
      continue;
    }

    lines.push(formatChangeRow(key, oldItem, newItem));

    if (lines.length >= 20) {
      lines.push("...more fields changed...");
      break;
    }
  }

  return lines;
}

function extractRuleDetails(event: AuditEvent): string[] {
  const action = (getAction(event).type ?? "").toLowerCase();
  const resourceType = (event.resource?.type ?? event.resource?.product ?? "").toLowerCase();
  const rawUri = (event.raw?.uri ?? "").toLowerCase();

  const isRulesEvent =
    resourceType.includes("rule") ||
    action.includes("rule") ||
    rawUri.includes("rules") ||
    rawUri.includes("rulesets");

  if (!isRulesEvent) {
    return [];
  }

  const oldRule = findRuleObject(event.oldValue);
  const newRule = findRuleObject(event.newValue);
  const oldRuleOrFallback = oldRule ?? (isRecord(event.oldValue) ? event.oldValue : undefined);
  const newRuleOrFallback = newRule ?? (isRecord(event.newValue) ? event.newValue : undefined);

  const lines: string[] = [];
  const oldRuleId = readRecordString(oldRuleOrFallback, "id") ?? readRecordString(oldRuleOrFallback, "ref");
  const newRuleId = readRecordString(newRuleOrFallback, "id") ?? readRecordString(newRuleOrFallback, "ref");
  const oldExpression = readRecordString(oldRuleOrFallback, "expression");
  const newExpression = readRecordString(newRuleOrFallback, "expression");
  const oldAction = readRecordString(oldRuleOrFallback, "action");
  const newAction = readRecordString(newRuleOrFallback, "action");
  const oldDescription = readRecordString(oldRuleOrFallback, "description");
  const newDescription = readRecordString(newRuleOrFallback, "description");

  if (!isEqual(oldRuleId, newRuleId)) {
    lines.push(formatChangeRow("rule.id", oldRuleId, newRuleId));
  }
  if (!isEqual(oldAction, newAction)) {
    lines.push(formatChangeRow("rule.action", oldAction, newAction));
  }
  if (!isEqual(oldDescription, newDescription)) {
    lines.push(formatChangeRow("rule.description", oldDescription, newDescription));
  }
  if (!isEqual(oldExpression, newExpression)) {
    lines.push(formatChangeRow("rule.expression", oldExpression, newExpression));
  }

  if (action.includes("delete")) {
    if (oldRuleOrFallback) {
      lines.push(formatChangeRow("deleted.rule", oldRuleOrFallback, newRuleOrFallback));
    }
  }

  return lines;
}

function findRuleObject(value: unknown): Record<string, unknown> | undefined {
  if (isRuleShape(value)) {
    return value;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findRuleObject(item);
      if (found) {
        return found;
      }
    }
    return undefined;
  }

  if (!isRecord(value)) {
    return undefined;
  }

  for (const nested of Object.values(value)) {
    const found = findRuleObject(nested);
    if (found) {
      return found;
    }
  }

  return undefined;
}

function isRuleShape(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.id === "string" ||
    typeof value.ref === "string" ||
    typeof value.expression === "string" ||
    typeof value.action === "string"
  );
}

function readRecordString(value: Record<string, unknown> | undefined, key: string): string | undefined {
  if (!value) {
    return undefined;
  }

  const item = value[key];
  if (typeof item === "string" && item.length > 0) {
    return item;
  }
  return undefined;
}

function flattenValue(
  value: unknown,
  prefix: string,
  maxDepth = 4,
  maxEntries = 120,
): Map<string, unknown> {
  const out = new Map<string, unknown>();

  const walk = (node: unknown, path: string, depth: number): void => {
    if (out.size >= maxEntries) {
      return;
    }

    if (depth > maxDepth) {
      out.set(path, "[max-depth]");
      return;
    }

    if (Array.isArray(node)) {
      if (node.length === 0) {
        out.set(path, []);
        return;
      }

      for (let index = 0; index < node.length; index += 1) {
        walk(node[index], `${path}[${index}]`, depth + 1);
        if (out.size >= maxEntries) {
          return;
        }
      }
      return;
    }

    if (isRecord(node)) {
      const keys = Object.keys(node);
      if (keys.length === 0) {
        out.set(path, {});
        return;
      }

      for (const key of keys.sort()) {
        walk(node[key], `${path}.${key}`, depth + 1);
        if (out.size >= maxEntries) {
          return;
        }
      }
      return;
    }

    out.set(path, node);
  };

  walk(value, prefix, 0);
  return out;
}

function sortDiffKeys(keys: string[]): string[] {
  const priorityPrefixes = [
    "id",
    "ref",
    "action",
    "description",
    "expression",
    "enabled",
    "paused",
    "priority",
    "phase",
    "value",
  ];

  const score = (key: string): number => {
    for (let index = 0; index < priorityPrefixes.length; index += 1) {
      if (key.startsWith(priorityPrefixes[index])) {
        return index;
      }
    }
    return priorityPrefixes.length;
  };

  return [...keys].sort((a, b) => {
    const scoreA = score(a);
    const scoreB = score(b);
    if (scoreA !== scoreB) {
      return scoreA - scoreB;
    }
    return a.localeCompare(b);
  });
}

function formatChangeRow(field: string, oldValue: unknown, newValue: unknown): string {
  const oldText = truncateText(toCompactJson(oldValue), 120);
  const newText = truncateText(toCompactJson(newValue), 120);
  return `${field} | ${oldText} | ${newText}`;
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

function toBangkokTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }

  return new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Bangkok",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
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
