// This module provides browser UI routes with session auth for admin and user operations.

import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { executeTool, undoChangesByIds } from '../mcp/tools.js';
import { getLink404MonitorStatus } from '../services/link-404-routine.js';
import { getNewLinksRoutineStatus } from '../services/new-links-routine.js';
import type { AiChangeActionType, AuthenticatedPrincipal, SessionPrincipal, UserRole } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { sanitizeForLog } from '../utils/logger.js';
import {
  generateApiToken,
  generateCsrfToken,
  generateSessionToken,
  hashApiToken,
  hashPassword,
  parseCookies,
  serializeCookie,
  serializeExpiredCookie,
  verifyPassword
} from '../utils/security.js';
import { authenticateSession, requireAdminSession, requireCsrf, requireSession } from './auth.js';

interface LoginAttemptState {
  failures: number;
  firstFailureAt: number;
  blockedUntil: number;
}

const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_BLOCK_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 5;
const ALLOWED_AI_CHANGE_ACTION_TYPES: AiChangeActionType[] = [
  'create_link',
  'update_link',
  'delete_link',
  'move_collection',
  'tag_add',
  'tag_remove',
  'normalize_url',
  'archive',
  'unarchive',
  'merge'
];
const AI_LOG_PRUNE_THROTTLE_MS = 5 * 60 * 1000;
const aiLogPruneLastRunByUser = new Map<number, number>();

const loginSchema = z.object({
  username: z.string().min(1).max(80),
  password: z.string().min(1).max(200)
});

const createUserSchema = z.object({
  username: z.string().min(3).max(50),
  password: z.string().min(12).max(200),
  role: z.enum(['admin', 'user']).default('user'),
  writeModeEnabled: z.boolean().default(false),
  issueApiKey: z.boolean().default(false),
  apiKeyLabel: z.string().min(2).max(100).default('default')
});

const toggleUserActiveSchema = z.object({
  active: z.boolean()
});

const toggleWriteModeSchema = z.object({
  writeModeEnabled: z.boolean()
});

const setOfflinePolicySchema = z
  .object({
    offlineDays: z.number().int().min(1).max(365),
    minConsecutiveFailures: z.number().int().min(1).max(30),
    action: z.enum(['archive', 'delete', 'none']),
    archiveCollectionId: z.number().int().positive().nullable().optional()
  })
  .superRefine((payload, ctx) => {
    // This validation requires a destination collection only when archive action is selected.
    if (payload.action === 'archive' && !payload.archiveCollectionId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['archiveCollectionId'],
        message: 'archiveCollectionId is required when action=archive.'
      });
    }
  });

const setTaggingPolicySchema = z
  .object({
    fetchMode: z.enum(['never', 'optional', 'always']).optional(),
    allowUserFetchModeOverride: z.boolean().optional(),
    inferenceProvider: z.enum(['builtin', 'perplexity', 'mistral', 'huggingface']).optional(),
    inferenceModel: z.string().trim().max(200).nullable().optional(),
    blockedTagNames: z.array(z.string().trim().min(1).max(80)).max(400).optional(),
    similarityThreshold: z.number().min(0).max(1).optional(),
    fetchTimeoutMs: z.number().int().min(500).max(20000).optional(),
    fetchMaxBytes: z.number().int().min(8192).max(1048576).optional()
  })
  .refine((payload) => Object.keys(payload).length > 0, {
    message: 'At least one tagging policy field must be updated.'
  });

// This helper validates IANA timezone inputs for admin/user preference payloads.
function isValidIanaTimeZone(value: string): boolean {
  try {
    Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

const setTaggingPreferencesSchema = z
  .object({
    taggingStrictness: z.enum(['very_strict', 'medium', 'relaxed']).optional(),
    fetchMode: z.enum(['never', 'optional', 'always']).optional(),
    queryTimeZone: z.string().trim().min(1).max(100).nullable().optional()
  })
  .superRefine((payload, ctx) => {
    // This validation keeps timezone preference values strict and deterministic.
    if (payload.queryTimeZone && !isValidIanaTimeZone(payload.queryTimeZone)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['queryTimeZone'],
        message: 'queryTimeZone must be a valid IANA timezone.'
      });
    }
  })
  .refine((payload) => Object.keys(payload).length > 0, {
    message: 'At least one tagging preference field must be updated.'
  });

const setNewLinksRoutineSchema = z
  .object({
    enabled: z.boolean().optional(),
    intervalMinutes: z.number().int().min(1).max(1440).optional(),
    modules: z.array(z.enum(['governed_tagging', 'normalize_urls', 'dedupe'])).min(1).max(3).optional(),
    batchSize: z.number().int().min(1).max(1000).optional(),
    requestBackfill: z.boolean().optional(),
    confirmBackfill: z.boolean().optional()
  })
  .refine((payload) => Object.keys(payload).length > 0, {
    message: 'At least one new-links routine field must be updated.'
  });

const setLink404MonitorSchema = z
  .object({
    enabled: z.boolean().optional(),
    interval: z.enum(['daily', 'weekly', 'biweekly', 'monthly', 'semiannual', 'yearly']).optional(),
    toDeleteAfter: z.enum(['after_1_month', 'after_6_months', 'after_1_year']).optional()
  })
  .refine((payload) => Object.keys(payload).length > 0, {
    message: 'At least one 404-monitor field must be updated.'
  });

const setChatControlSchema = z
  .object({
    // This transform keeps empty user input compatible with the backend default archive collection name.
    archiveCollectionName: z
      .preprocess(
        (value) => (typeof value === 'string' ? value.trim() : value),
        z.string().max(120).transform((value) => value || 'Archive')
      )
      .optional(),
    archiveCollectionParentId: z.number().int().positive().nullable().optional(),
    // This transform keeps empty user input compatible with the backend default chat capture tag name.
    chatCaptureTagName: z
      .preprocess(
        (value) => (typeof value === 'string' ? value.trim() : value),
        z.string().max(80).transform((value) => value || 'AI Chat')
      )
      .optional(),
    chatCaptureTagAiChatEnabled: z.boolean().optional(),
    chatCaptureTagAiNameEnabled: z.boolean().optional(),
    aiActivityRetentionDays: z.union([z.literal(30), z.literal(90), z.literal(180), z.literal(365)]).optional()
  })
  .refine((payload) => Object.keys(payload).length > 0, {
    message: 'At least one chat-control field must be updated.'
  });

// This helper normalizes query-string fields into deterministic string arrays.
const stringArrayQuerySchema = z.preprocess((value) => {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }
  return [];
}, z.array(z.string().trim().min(1).max(120)).max(100));

// This helper parses query booleans from native or string-encoded values.
const queryBooleanSchema = z.preprocess((value) => {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1' || normalized === 'yes') {
      return true;
    }
    if (normalized === 'false' || normalized === '0' || normalized === 'no') {
      return false;
    }
  }
  return undefined;
}, z.boolean().optional());

const listAiLogQuerySchema = z.object({
  q: z.string().trim().max(300).optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional(),
  actionType: stringArrayQuerySchema.optional(),
  toolName: stringArrayQuerySchema.optional(),
  linkId: z.coerce.number().int().positive().optional(),
  collectionFromId: z.coerce.number().int().positive().optional(),
  collectionToId: z.coerce.number().int().positive().optional(),
  tagName: z.string().trim().max(120).optional(),
  trackingTrimmed: queryBooleanSchema,
  undoStatus: z.enum(['pending', 'applied', 'conflict', 'failed']).optional(),
  page: z.coerce.number().int().min(1).max(500000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  sortBy: z.enum(['changedAt', 'linkId', 'actionType', 'toolName']).default('changedAt'),
  sortDir: z.enum(['asc', 'desc']).default('desc')
});

const aiLogFacetQuerySchema = z.object({
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional()
});

const aiLogUndoSchema = z
  .object({
    mode: z.enum(['changes', 'operations']),
    changeIds: z.array(z.number().int().positive()).max(200).optional(),
    operationIds: z.array(z.string().trim().min(8).max(100)).max(200).optional()
  })
  .superRefine((payload, ctx) => {
    // This validation enforces explicit target identifiers for both undo modes.
    if (payload.mode === 'changes' && (!payload.changeIds || payload.changeIds.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['changeIds'],
        message: 'changeIds are required when mode=changes.'
      });
    }
    if (payload.mode === 'operations' && (!payload.operationIds || payload.operationIds.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['operationIds'],
        message: 'operationIds are required when mode=operations.'
      });
    }
  });

const aiLogSettingsSchema = z.object({
  retentionDays: z.union([z.literal(30), z.literal(90), z.literal(180), z.literal(365)])
});

// This schema limits admin OAuth session-lifetime updates to deterministic supported presets.
const oauthSessionLifetimeSchema = z.union([
  z.literal('permanent'),
  z.literal(1),
  z.literal(7),
  z.literal(30),
  z.literal(180),
  z.literal(365)
]);

const setOauthSessionSchema = z.object({
  sessionLifetime: oauthSessionLifetimeSchema
});

const createApiKeySchema = z.object({
  userId: z.number().int().positive(),
  label: z.string().min(2).max(100).default('default')
});

const createOwnApiKeySchema = z.object({
  label: z.string().min(2).max(100).default('default')
});

const updateLinkwardenSchema = z
  .object({
    baseUrl: z.string().url().optional()
  })
  .refine((payload) => Boolean(payload.baseUrl), {
    message: 'At least one field must be updated.'
  });

const setLinkwardenTokenSchema = z.object({
  token: z.string().min(20).max(500)
});

const userIdParamSchema = z.object({
  userId: z.coerce.number().int().positive()
});

const keyIdParamSchema = z.object({
  keyId: z.string().min(3).max(128)
});

// This helper writes one structured info-level UI event with request metadata.
function logUiInfo(request: FastifyRequest, event: string, details?: Record<string, unknown>): void {
  const sanitizedDetails = (sanitizeForLog(details) ?? {}) as Record<string, unknown>;
  request.log.info(
    {
      event,
      requestId: request.id,
      ip: request.ip,
      ...sanitizedDetails
    },
    event
  );
}

// This helper writes one structured warning-level UI event with sanitized details.
function logUiWarn(request: FastifyRequest, event: string, details?: Record<string, unknown>): void {
  const sanitizedDetails = (sanitizeForLog(details) ?? {}) as Record<string, unknown>;
  request.log.warn(
    {
      event,
      requestId: request.id,
      ip: request.ip,
      ...sanitizedDetails
    },
    event
  );
}

// This helper writes one structured debug-level UI event with sanitized details.
function logUiDebug(request: FastifyRequest, event: string, details?: Record<string, unknown>): void {
  const sanitizedDetails = (sanitizeForLog(details) ?? {}) as Record<string, unknown>;
  request.log.debug(
    {
      event,
      requestId: request.id,
      ip: request.ip,
      ...sanitizedDetails
    },
    event
  );
}

// This map tracks login failures to throttle brute-force attempts per ip+username pair.
const loginAttempts = new Map<string, LoginAttemptState>();

// This helper returns true when secure cookies should be set on this request.
function shouldUseSecureCookies(request: FastifyRequest): boolean {
  const envSetting = (process.env.COOKIE_SECURE ?? 'auto').toLowerCase();

  if (envSetting === 'true') {
    return true;
  }

  if (envSetting === 'false') {
    return false;
  }

  return request.protocol === 'https';
}

// This helper returns configured session ttl with bounded sane defaults.
function getSessionTtlSeconds(): number {
  const configured = Number(process.env.SESSION_TTL_HOURS ?? '12');
  const safeHours = Number.isFinite(configured) ? Math.min(Math.max(configured, 1), 168) : 12;
  return Math.floor(safeHours * 3600);
}

// This helper creates one deterministic key for the login rate limiter state map.
function buildLoginLimitKey(request: FastifyRequest, username: string): string {
  const ip = request.ip || 'unknown';
  return `${ip.toLowerCase()}|${username.trim().toLowerCase()}`;
}

// This helper periodically removes stale limiter entries to keep memory bounded.
function cleanupLoginLimiter(now: number): void {
  for (const [key, state] of loginAttempts.entries()) {
    if (state.blockedUntil < now - LOGIN_BLOCK_MS && state.firstFailureAt < now - LOGIN_WINDOW_MS) {
      loginAttempts.delete(key);
    }
  }
}

// This helper enforces login rate limits before credential checks run.
function assertLoginAllowed(key: string): void {
  const now = Date.now();
  cleanupLoginLimiter(now);

  const state = loginAttempts.get(key);
  if (!state) {
    return;
  }

  if (state.blockedUntil > now) {
    throw new AppError(429, 'too_many_attempts', 'Too many login attempts. Please try again later.');
  }
}

// This helper records one failed login and blocks when thresholds are reached.
function registerLoginFailure(key: string): void {
  const now = Date.now();
  const previous = loginAttempts.get(key);

  if (!previous || now - previous.firstFailureAt > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, {
      failures: 1,
      firstFailureAt: now,
      blockedUntil: 0
    });
    return;
  }

  const nextFailures = previous.failures + 1;
  const blockedUntil = nextFailures >= LOGIN_MAX_FAILURES ? now + LOGIN_BLOCK_MS : 0;

  loginAttempts.set(key, {
    failures: nextFailures,
    firstFailureAt: previous.firstFailureAt,
    blockedUntil
  });
}

// This helper clears failed login counters after successful authentication.
function clearLoginFailures(key: string): void {
  loginAttempts.delete(key);
}

// This helper issues one API token for a user and stores only its hash.
function issueApiKey(db: SqliteStore, userId: number, label: string): { token: string; keyId: string } {
  const generated = generateApiToken();
  db.createApiKey(userId, label, generated.keyId, hashApiToken(generated.token));
  return generated;
}

// This helper ensures one CSRF cookie exists and returns its value for page rendering.
function ensureCsrfCookie(request: FastifyRequest, reply: FastifyReply): { csrfToken: string; secure: boolean } {
  const secure = shouldUseSecureCookies(request);
  const cookies = parseCookies(request.headers.cookie);
  const existing = cookies.mcp_csrf;
  const csrfToken = existing && existing.length > 0 ? existing : generateCsrfToken();

  if (!existing) {
    reply.header('set-cookie', serializeCookie('mcp_csrf', csrfToken, { secure, maxAgeSeconds: 24 * 3600 }));
  }

  return { csrfToken, secure };
}

// This helper normalizes one optional post-login redirect path and prevents open redirects.
function sanitizeNextPath(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) {
    return null;
  }

  return trimmed;
}

// This helper renders one early theme boot script to avoid flashes before CSS variables are applied.
function renderThemeHead(): string {
  return `<script>
(() => {
  const storageKey = 'lwmcp.themePreference';
  const allowed = new Set(['system', 'light', 'dark']);
  const media = typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-color-scheme: dark)')
    : null;

  const readPreference = () => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      return allowed.has(raw || '') ? raw : 'system';
    } catch {
      return 'system';
    }
  };

  const writePreference = (preference) => {
    if (!allowed.has(preference)) {
      return;
    }
    try {
      window.localStorage.setItem(storageKey, preference);
    } catch {
      // This no-op keeps theme switching functional even when localStorage is unavailable.
    }
  };

  const resolveTheme = (preference) => {
    if (preference === 'dark' || preference === 'light') {
      return preference;
    }
    return media && media.matches ? 'dark' : 'light';
  };

  const applyResolvedTheme = (theme) => {
    const normalized = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.theme = normalized;
    document.documentElement.style.colorScheme = normalized;
  };

  const applyFromPreference = (preference) => {
    applyResolvedTheme(resolveTheme(preference));
  };

  const syncSwitchers = () => {
    const preference = readPreference();
    document.querySelectorAll('[data-theme-switcher]').forEach((element) => {
      if (element && element.tagName === 'SELECT') {
        element.value = preference;
      }
    });
  };

  const bindSwitcher = (switcher) => {
    if (!switcher || switcher.dataset.themeBound === '1') {
      return;
    }
    switcher.dataset.themeBound = '1';
    switcher.addEventListener('change', (event) => {
      const nextPreference = event?.target?.value;
      if (!allowed.has(nextPreference)) {
        return;
      }
      writePreference(nextPreference);
      applyFromPreference(nextPreference);
      syncSwitchers();
    });
  };

  const initSwitchers = () => {
    document.querySelectorAll('[data-theme-switcher]').forEach((element) => {
      if (element && element.tagName === 'SELECT') {
        bindSwitcher(element);
      }
    });
    syncSwitchers();
  };

  // This initial apply ensures the first paint already uses the persisted/system theme.
  applyFromPreference(readPreference());
  if (media && typeof media.addEventListener === 'function') {
    media.addEventListener('change', () => {
      if (readPreference() === 'system') {
        applyFromPreference('system');
        syncSwitchers();
      }
    });
  } else if (media && typeof media.addListener === 'function') {
    media.addListener(() => {
      if (readPreference() === 'system') {
        applyFromPreference('system');
        syncSwitchers();
      }
    });
  }

  window.lwmcpTheme = {
    initSwitchers,
    readPreference,
    applyFromPreference
  };
})();
</script>`;
}

// This helper renders shared theme tokens and base component styles for every /admin page.
function renderThemeStyles(): string {
  return `<style>
  :root {
    --bg: #f4f5f7;
    --surface: #ffffff;
    --text: #111319;
    --text-muted: #4b5563;
    --border: #d1d5db;
    --accent: #E94C16;
    --accent-strong: #9e2c0a;
    --accent-soft: #fde8df;
    --focus-ring: rgba(233, 76, 22, 0.45);
    --input-bg: #ffffff;
    --pre-bg: #f5f7fb;
  }

  :root[data-theme="dark"] {
    --bg: #12161b;
    --surface: #1b222b;
    --text: #eef2f7;
    --text-muted: #b8c3cf;
    --border: #354252;
    --accent: #E94C16;
    --accent-strong: #bf3a0f;
    --accent-soft: #3b241d;
    --focus-ring: rgba(233, 76, 22, 0.55);
    --input-bg: #1a2028;
    --pre-bg: #151b22;
  }

  html, body {
    background: var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
    margin: 0;
    padding: 0;
  }

  .page {
    max-width: 980px;
    margin: 2rem auto;
    padding: 0 1rem;
  }

  .page.page-narrow { max-width: 760px; }
  .page.page-medium { max-width: 860px; }
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .theme-control {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-muted);
    font-size: 0.95rem;
    white-space: nowrap;
  }

  .theme-control label {
    display: inline;
    margin: 0;
    font-weight: 600;
  }

  .theme-control select {
    width: auto;
    min-width: 9rem;
    margin: 0;
    padding: 0.42rem 0.55rem;
    border-radius: 8px;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--surface);
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
    color: var(--text);
  }

  label { display: block; font-weight: 600; margin-top: 0.8rem; }

  input, select, textarea, button {
    width: 100%;
    padding: 0.6rem;
    margin-top: 0.35rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--input-bg);
    color: var(--text);
  }

  button {
    cursor: pointer;
    font-weight: 700;
    background: var(--accent-strong);
    border-color: var(--accent-strong);
    color: #ffffff;
    transition: filter 0.15s ease-in-out, transform 0.05s ease-in-out;
  }

  button:hover { filter: brightness(1.06); }
  button:active { transform: translateY(1px); }

  input:focus, select:focus, textarea:focus, button:focus {
    outline: 3px solid var(--focus-ring);
    outline-offset: 1px;
  }

  textarea { min-height: 120px; }
  pre {
    background: var(--pre-bg);
    border-radius: 10px;
    padding: 0.8rem;
    overflow: auto;
    border: 1px solid var(--border);
  }

  p { color: var(--text); }
  h1, h2, h3 { color: var(--text); }

  a {
    color: var(--accent);
  }

  .tabs-shell {
    margin-bottom: 1rem;
    padding: 0.75rem;
  }

  .top-tabs,
  .sub-tabs {
    display: flex;
    gap: 0.5rem;
    flex-wrap: nowrap;
    overflow-x: auto;
    padding-bottom: 0.2rem;
  }

  .top-tabs {
    position: sticky;
    top: 0;
    z-index: 30;
    background: var(--surface);
  }

  .top-tab-btn,
  .sub-tab-btn {
    flex: 0 0 auto;
    width: auto;
    margin: 0;
    padding: 0.5rem 0.85rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text);
    font-weight: 700;
  }

  .top-tab-btn[aria-selected="true"],
  .sub-tab-btn[aria-selected="true"] {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--text);
  }

  .sub-tabs {
    margin-top: 0.55rem;
    border-top: 1px solid var(--border);
    padding-top: 0.6rem;
  }

  .tab-panel-card[hidden] {
    display: none !important;
  }

  .status-inline {
    margin-top: 0.6rem;
    font-size: 0.9rem;
    color: var(--text-muted);
  }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
    gap: 0.6rem;
    margin: 0.7rem 0 0.4rem;
  }

  .kpi-item {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.55rem 0.65rem;
    background: var(--pre-bg);
  }

  .kpi-label {
    display: block;
    font-size: 0.76rem;
    color: var(--text-muted);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .kpi-value {
    display: block;
    margin-top: 0.2rem;
    font-size: 0.92rem;
    font-weight: 700;
    color: var(--text);
  }

  .form-block {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.7rem 0.8rem;
    margin-top: 0.8rem;
    background: var(--pre-bg);
  }

  .form-block h3 {
    margin: 0;
    font-size: 1rem;
  }

  .help-text {
    margin: 0.35rem 0 0.15rem;
    color: var(--text-muted);
    font-size: 0.88rem;
  }

  .inline-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.7rem;
  }

  .inline-actions button {
    width: auto;
    min-width: 11rem;
    margin-top: 0;
  }

  .ai-log-table-wrap {
    margin-top: 0.85rem;
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--pre-bg);
  }

  .ai-log-table {
    width: 100%;
    border-collapse: collapse;
    min-width: 1100px;
  }

  .ai-log-table th,
  .ai-log-table td {
    border-bottom: 1px solid var(--border);
    padding: 0.5rem 0.55rem;
    text-align: left;
    vertical-align: top;
    color: var(--text);
    font-size: 0.86rem;
  }

  .ai-log-table thead th {
    position: sticky;
    top: 0;
    background: var(--surface);
    z-index: 2;
  }

  .ai-log-table tbody tr:last-child td {
    border-bottom: none;
  }

  .mono {
    font-family: "JetBrains Mono", "Fira Mono", "SFMono-Regular", Consolas, monospace;
    word-break: break-word;
  }

  .field-error {
    margin: 0.28rem 0 0;
    color: #b42318;
    font-size: 0.86rem;
    font-weight: 600;
  }

  :root[data-theme="dark"] .field-error {
    color: #ff8a66;
  }

  .field-invalid {
    border-color: #b42318 !important;
  }

  :root[data-theme="dark"] .field-invalid {
    border-color: #ff8a66 !important;
  }

  .toast-stack {
    position: fixed;
    right: 1rem;
    bottom: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    z-index: 1200;
    max-width: min(94vw, 30rem);
  }

  .toast {
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    border-radius: 10px;
    padding: 0.66rem 0.78rem;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.22);
    font-size: 0.92rem;
  }

  .toast.success { border-color: #1f883d; }
  .toast.error { border-color: #b42318; }
  .toast.info { border-color: var(--accent); }

  .debug-details summary {
    cursor: pointer;
    font-weight: 700;
    color: var(--accent);
  }

  .debug-details[open] summary {
    margin-bottom: 0.6rem;
  }

  @media (max-width: 720px) {
    .page-header {
      flex-direction: column;
      align-items: flex-start;
    }
  }
  </style>`;
}

// This helper renders one reusable theme switcher control for all /admin pages.
function renderThemeSwitcher(): string {
  return `<div class="theme-control">
    <label for="themePreference">Darstellung</label>
    <select id="themePreference" data-theme-switcher>
      <option value="system">System</option>
      <option value="light">Hell</option>
      <option value="dark">Dunkel</option>
    </select>
  </div>`;
}

// This helper initializes switcher bindings after page-specific scripts are loaded.
function renderThemeInitScript(): string {
  return `
if (window.lwmcpTheme && typeof window.lwmcpTheme.initSwitchers === 'function') {
  window.lwmcpTheme.initSwitchers();
}
`;
}

// This helper sends the standard login page for initialized systems without session.
function renderLoginPage(csrfToken: string, nextPath: string | null): string {
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp Login</title>
  ${renderThemeHead()}
  ${renderThemeStyles()}
</head>
<body>
  <div class="page page-narrow">
  <div class="page-header">
    <h1>linkwarden-mcp</h1>
    ${renderThemeSwitcher()}
  </div>
  <div class="card tab-panel-card" data-top-tab="administration" data-sub-tab="benutzer">
    <h2>Login</h2>
    <label for="username">Benutzername</label>
    <input id="username" autocomplete="username" />
    <label for="password">Passwort</label>
    <input id="password" type="password" autocomplete="current-password" />
    <button onclick="login()">Einloggen</button>
  </div>
  <div class="card tab-panel-card" data-top-tab="governance" data-sub-tab="tagging-policy">
    <h3>Antwort</h3>
    <pre id="result">Warte auf Aktion ...</pre>
  </div>
<script>
const csrfToken = ${JSON.stringify(csrfToken)};
const nextPath = ${JSON.stringify(nextPath)};

async function login() {
  const payload = {
    username: document.getElementById('username').value,
    password: document.getElementById('password').value
  };

  const res = await fetch('/admin/auth/login', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrfToken
    },
    body: JSON.stringify(payload)
  });

  const json = await res.json();
  document.getElementById('result').textContent = JSON.stringify(json, null, 2);

  if (res.ok) {
    window.location.href = nextPath || '/admin';
  }
}
${renderThemeInitScript()}
</script>
  </div>
</body>
</html>`;
}

// This helper renders first-run setup UI when the service has not been initialized yet.
function renderFirstRunPage(csrfToken: string): string {
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp First-Run Setup</title>
  ${renderThemeHead()}
  ${renderThemeStyles()}
</head>
<body>
  <div class="page page-medium">
  <div class="page-header">
    <h1>linkwarden-mcp First-Run Setup</h1>
    ${renderThemeSwitcher()}
  </div>
  <div class="card tab-panel-card" data-top-tab="administration" data-sub-tab="admin-keys">
    <p>Richte hier den ersten Admin und das Linkwarden-Ziel ein.</p>
    <label for="masterPassphrase">Master-Passphrase</label>
    <input id="masterPassphrase" type="password" />
    <label for="adminUsername">Admin-Benutzername</label>
    <input id="adminUsername" value="admin" />
    <label for="adminPassword">Admin-Passwort</label>
    <input id="adminPassword" type="password" />
    <label for="baseUrl">Linkwarden Base URL</label>
    <input id="baseUrl" placeholder="http://linkwarden:3000" />
    <label for="apiToken">Linkwarden API Key -> MCP</label>
    <input id="apiToken" type="password" />
    <label for="oauthClientId">OAuth Client ID (optional)</label>
    <input id="oauthClientId" placeholder="chatgpt-client-id" />
    <label for="oauthClientSecret">OAuth Client Secret (optional)</label>
    <input id="oauthClientSecret" type="password" />
    <label><input id="adminWriteModeDefault" type="checkbox" /> Admin Write-Mode initial aktivieren</label>
    <label><input id="issueAdminApiKey" type="checkbox" checked /> Initialen Admin-MCP-Key erzeugen (einmalig anzeigen)</label>
    <button onclick="initializeSetup()">Setup abschließen</button>
  </div>
  <div class="card tab-panel-card" data-top-tab="integrationen" data-sub-tab="user-linkwarden-token">
    <h3>Antwort</h3>
    <pre id="result">Warte auf Aktion ...</pre>
  </div>
<script>
const csrfToken = ${JSON.stringify(csrfToken)};

async function initializeSetup() {
  const payload = {
    masterPassphrase: document.getElementById('masterPassphrase').value,
    adminUsername: document.getElementById('adminUsername').value,
    adminPassword: document.getElementById('adminPassword').value,
    linkwardenBaseUrl: document.getElementById('baseUrl').value,
    linkwardenApiToken: document.getElementById('apiToken').value,
    oauthClientId: document.getElementById('oauthClientId').value || undefined,
    oauthClientSecret: document.getElementById('oauthClientSecret').value || undefined,
    adminWriteModeDefault: document.getElementById('adminWriteModeDefault').checked,
    issueAdminApiKey: document.getElementById('issueAdminApiKey').checked
  };

  const res = await fetch('/admin/setup/initialize', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrfToken
    },
    body: JSON.stringify(payload)
  });

  const json = await res.json();
  document.getElementById('result').textContent = JSON.stringify(json, null, 2);

  if (res.ok) {
    window.location.href = '/admin';
  }
}
${renderThemeInitScript()}
</script>
  </div>
</body>
</html>`;
}

// This helper renders fallback unlock UI when encrypted runtime config is still locked.
function renderUnlockPage(csrfToken: string): string {
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp Unlock</title>
  ${renderThemeHead()}
  ${renderThemeStyles()}
</head>
<body>
  <div class="page page-narrow">
  <div class="page-header">
    <h1>linkwarden-mcp Unlock</h1>
    ${renderThemeSwitcher()}
  </div>
  <div class="card tab-panel-card" data-top-tab="integrationen" data-sub-tab="linkwarden-ziel">
    <p>Der Server ist initialisiert, aber aktuell gesperrt. Normalerweise übernimmt Auto-Unlock das beim Start.</p>
    <label for="passphrase">Master-Passphrase</label>
    <input id="passphrase" type="password" />
    <button onclick="unlockConfig()">Entsperren</button>
  </div>
  <div class="card">
    <h3>Antwort</h3>
    <pre id="result">Warte auf Aktion ...</pre>
  </div>
<script>
const csrfToken = ${JSON.stringify(csrfToken)};

async function unlockConfig() {
  const res = await fetch('/admin/setup/unlock', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrfToken
    },
    body: JSON.stringify({
      passphrase: document.getElementById('passphrase').value
    })
  });

  const json = await res.json();
  document.getElementById('result').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    window.location.href = '/admin';
  }
}
${renderThemeInitScript()}
</script>
  </div>
</body>
</html>`;
}

// This helper renders a shared dashboard shell used for admin and standard users.
export function renderDashboardPage(principal: SessionPrincipal, csrfToken: string): string {
  const adminSections =
    principal.role === 'admin'
      ? `
  <div class="card tab-panel-card" data-top-tab="administration" data-sub-tab="benutzer">
    <h2>Admin: Benutzer verwalten</h2>
    <button onclick="loadUsers()">Benutzer laden</button>
    <pre id="usersResult">Noch nicht geladen</pre>

    <div class="form-block" data-form-section="benutzer-anlegen" data-form-section-label="Benutzer anlegen">
      <h3>Anlegen</h3>
      <p class="help-text">Erstellt einen neuen Benutzer mit initialer Rolle und optional aktivem Write-Mode.</p>
      <label for="newUsername">Neuer Benutzername</label>
      <input id="newUsername" />
      <label for="newPassword">Neues Passwort</label>
      <input id="newPassword" type="password" />
      <label for="newRole">Rolle</label>
      <select id="newRole"><option value="user">user</option><option value="admin">admin</option></select>
      <label><input id="newWriteMode" type="checkbox" /> Write-Mode aktiv</label>
      <button onclick="createUser()">Benutzer anlegen</button>
    </div>

    <div class="form-block" data-form-section="benutzer-status" data-form-section-label="Aktiv und Write-Mode">
      <h3>Aktiv / Write-Mode</h3>
      <p class="help-text">Steuert Login-Zugriff und Bearbeitungsrechte pro Benutzer.</p>
      <label for="toggleUserSelect">Benutzer für Aktiv/Deaktiv</label>
      <select id="toggleUserSelect"></select>
      <label><input id="toggleUserActive" type="checkbox" checked /> Aktiv</label>
      <button onclick="setUserActive()">Aktiv-Status setzen</button>
      <label for="writeModeUserSelect">Benutzer für Write-Mode</label>
      <select id="writeModeUserSelect"></select>
      <label><input id="writeModeForUser" type="checkbox" /> Write-Mode aktiv</label>
      <button onclick="setUserWriteMode()">Write-Mode pro User setzen</button>
    </div>

    <div class="form-block" data-form-section="benutzer-offline-policy" data-form-section-label="404-Policy">
      <h3>404-Policy</h3>
      <p class="help-text">Definiert, wann bei länger offline erreichbaren Links archiviert, gelöscht oder nichts getan wird.</p>
      <label for="offlinePolicyUserSelect">Benutzer für 404-Policy</label>
      <select id="offlinePolicyUserSelect"></select>
      <label for="offlineDaysForUser">Offline-Tage bis Aktion</label>
      <input id="offlineDaysForUser" type="number" min="1" max="365" value="14" />
      <label for="offlineFailuresForUser">Min. aufeinanderfolgende Fehler</label>
      <input id="offlineFailuresForUser" type="number" min="1" max="30" value="3" />
      <label for="offlineActionForUser">Aktion bei dauerhaftem 404</label>
      <select id="offlineActionForUser">
        <option value="archive">archive</option>
        <option value="delete">delete</option>
        <option value="none">none</option>
      </select>
      <label for="offlineArchiveCollectionIdForUser">Archive Collection ID (nur bei archive)</label>
      <input id="offlineArchiveCollectionIdForUser" type="number" min="1" />
      <button onclick="setUserOfflinePolicy()">404-Policy pro User setzen</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="governance" data-sub-tab="tagging-policy">
    <h2>Admin: Governed Tagging Policy</h2>
    <button onclick="loadTaggingPolicy()">Tagging-Policy laden</button>
    <pre id="taggingPolicyResult">Noch nicht geladen</pre>

    <div class="form-block" data-form-section="tagging-global" data-form-section-label="Tagging global">
      <h3>Global</h3>
      <p class="help-text">Definiert die globale Tagging-Strategie für alle Benutzer.</p>
      <label for="policyFetchMode">Globaler Fetch-Mode</label>
      <select id="policyFetchMode">
        <option value="never">never</option>
        <option value="optional">optional</option>
        <option value="always">always</option>
      </select>
      <label><input id="policyAllowUserFetchOverride" type="checkbox" /> User dürfen eigenen Fetch-Mode setzen</label>
      <label for="policyBlockedTags">Blockierte Tags (Komma-separiert)</label>
      <input id="policyBlockedTags" placeholder="spam, tracking, misc" />
      <label for="policySimilarityThreshold">Similarity Threshold (0-1)</label>
      <input id="policySimilarityThreshold" type="number" min="0" max="1" step="0.01" value="0.88" />
      <label for="policyFetchTimeoutMs">Fetch Timeout (ms)</label>
      <input id="policyFetchTimeoutMs" type="number" min="500" max="20000" value="3000" />
      <label for="policyFetchMaxBytes">Fetch Max Bytes</label>
      <input id="policyFetchMaxBytes" type="number" min="8192" max="1048576" value="131072" />
    </div>

    <div class="form-block" data-form-section="tagging-provider" data-form-section-label="Tagging Provider">
      <h3>Provider</h3>
      <p class="help-text">Steuert, welcher AI-Provider für Tag-Kontext verwendet wird.</p>
      <label for="policyInferenceProvider">AI Provider für Tag-Kontext</label>
      <select id="policyInferenceProvider">
        <option value="builtin">builtin (lokal, ohne externes LLM)</option>
        <option value="perplexity">perplexity</option>
        <option value="mistral">mistral</option>
        <option value="huggingface">huggingface</option>
      </select>
      <label for="policyInferenceModel">AI Modell (optional; bei huggingface empfohlen/üblich erforderlich)</label>
      <input id="policyInferenceModel" placeholder="z. B. sonar, mistral-small-latest, meta-llama/Llama-3.1-8B-Instruct" />
      <button onclick="setTaggingPolicy()">Tagging-Policy speichern</button>
    </div>

    <div class="form-block" data-form-section="tagging-user-preferences" data-form-section-label="Tagging Benutzerpräferenzen">
      <h3>Benutzerpräferenzen</h3>
      <p class="help-text">Setzt Tagging-Parameter gezielt für ausgewählte Benutzer.</p>
      <label for="taggingPreferenceUserSelect">Benutzer für Tagging-Preferences</label>
      <select id="taggingPreferenceUserSelect"></select>
      <label for="taggingStrictnessForUser">Strenge pro User</label>
      <select id="taggingStrictnessForUser">
        <option value="very_strict">very_strict</option>
        <option value="medium">medium</option>
        <option value="relaxed">relaxed</option>
      </select>
      <label for="fetchModeForUser">Fetch-Mode pro User</label>
      <select id="fetchModeForUser">
        <option value="never">never</option>
        <option value="optional">optional</option>
        <option value="always">always</option>
      </select>
      <label for="queryTimeZoneForUser">Query-Zeitzone pro User (IANA)</label>
      <input id="queryTimeZoneForUser" placeholder="Europe/Berlin" />
      <button onclick="setUserTaggingPreferences()">Tagging-Preferences pro User speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="administration" data-sub-tab="admin-keys">
    <h2>Admin: MCP API Keys -> AI</h2>
    <button onclick="loadAdminKeys()">Alle MCP API Keys laden</button>
    <pre id="adminKeysResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="admin-key-issue" data-form-section-label="Admin-Key ausstellen">
      <label for="apiKeyUserSelect">Benutzer für neuen MCP API Key</label>
      <select id="apiKeyUserSelect"></select>
      <label for="apiKeyLabel">Key Label</label>
      <input id="apiKeyLabel" value="default" />
      <button onclick="issueAdminKey()">API Key ausstellen</button>
    </div>
    <div class="form-block" data-form-section="admin-key-revoke" data-form-section-label="Admin-Key revoken">
      <label for="revokeKeyId">Key ID zum Revoken</label>
      <input id="revokeKeyId" />
      <button onclick="revokeAdminKey()">API Key revoken</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="integrationen" data-sub-tab="user-linkwarden-token">
    <h2>Admin: Linkwarden API Key -> MCP (pro User)</h2>
    <div class="form-block" data-form-section="user-linkwarden-token-set" data-form-section-label="User Linkwarden-Key">
      <label for="linkwardenTokenUserSelect">Benutzer</label>
      <select id="linkwardenTokenUserSelect"></select>
      <label for="linkwardenTokenValue">Linkwarden API Key</label>
      <input id="linkwardenTokenValue" type="password" />
      <button onclick="setUserLinkwardenToken()">Linkwarden API Key speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="integrationen" data-sub-tab="linkwarden-ziel">
    <h2>Admin: Linkwarden Ziel</h2>
    <button onclick="loadLinkwardenConfig()">Aktuelle Konfiguration laden</button>
    <pre id="linkwardenConfigResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="linkwarden-ziel-update" data-form-section-label="Linkwarden Ziel">
      <label for="lwBaseUrl">Neue Base URL</label>
      <input id="lwBaseUrl" placeholder="http://linkwarden:3000" />
      <button onclick="updateLinkwardenConfig()">Linkwarden Konfiguration speichern</button>
    </div>
    <div class="form-block" data-form-section="oauth-session-lifetime" data-form-section-label="OAuth Session-Laufzeit">
      <label for="oauthSessionLifetime">OAuth Session-Laufzeit (Refresh-Token)</label>
      <select id="oauthSessionLifetime">
        <option value="permanent">Dauerhaft</option>
        <option value="1">Täglich</option>
        <option value="7">Wöchentlich</option>
        <option value="30">30 Tage</option>
        <option value="180">180 Tage</option>
        <option value="365">365 Tage</option>
      </select>
      <button onclick="setOAuthSessionLifetime()">Session-Laufzeit speichern</button>
      <p class="status-inline" id="oauthSessionLifetimeStatus"></p>
    </div>
  </div>
      `
      : '';

  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp Dashboard</title>
  ${renderThemeHead()}
  ${renderThemeStyles()}
</head>
<body>
  <div class="page">
  <div class="page-header">
    <h1>linkwarden-mcp Dashboard</h1>
    ${renderThemeSwitcher()}
  </div>
  <div class="card tabs-shell">
    <nav class="top-tabs" id="topTabsNav" role="tablist" aria-label="Hauptnavigation"></nav>
    <nav class="sub-tabs" id="subTabsNav" role="tablist" aria-label="Unterbereiche"></nav>
  </div>
  <div class="card tab-panel-card" data-top-tab="uebersicht" data-sub-tab="status">
    <p>Angemeldet als <strong>${principal.username}</strong> (Rolle: <strong>${principal.role}</strong>)</p>
    <button onclick="logout()">Logout</button>
    <div class="kpi-grid" id="overviewKpis">
      <div class="kpi-item"><span class="kpi-label">Rolle</span><span class="kpi-value" id="kpiRole">${principal.role}</span></div>
      <div class="kpi-item"><span class="kpi-label">Write-Mode</span><span class="kpi-value" id="kpiWriteMode">unbekannt</span></div>
      <div class="kpi-item"><span class="kpi-label">Linkwarden-Token</span><span class="kpi-value" id="kpiToken">unbekannt</span></div>
      <div class="kpi-item"><span class="kpi-label">Routine</span><span class="kpi-value" id="kpiRoutine">unbekannt</span></div>
      <div class="kpi-item"><span class="kpi-label">Letzte Aktion</span><span class="kpi-value" id="kpiLastAction">Noch keine</span></div>
    </div>
    <p class="status-inline" id="statusOverview" aria-live="polite"></p>
    <details class="debug-details" id="debugDrawer">
      <summary>Antwortdetails anzeigen</summary>
      <pre id="actionResult">Warte auf Aktion ...</pre>
    </details>
  </div>

  <div class="card tab-panel-card" data-top-tab="uebersicht" data-sub-tab="ai-log">
    <h2>AI-Log</h2>
    <button onclick="refreshAiLog()">AI-Log laden</button>
    <pre id="aiLogResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="ai-log-filters" data-form-section-label="AI-Log Filter">
      <h3>Filter</h3>
      <p class="help-text">Filtere nach Link, Collection, Tags, Zeitraum und Änderungsstatus.</p>
      <label for="aiLogQuery">Suche (Titel/URL/Collection/Tag)</label>
      <input id="aiLogQuery" placeholder="z. B. serverfault.com oder AI Chat" />
      <label for="aiLogDateFrom">Von (Datum/Zeit)</label>
      <input id="aiLogDateFrom" type="datetime-local" />
      <label for="aiLogDateTo">Bis (Datum/Zeit)</label>
      <input id="aiLogDateTo" type="datetime-local" />
      <label for="aiLogActionTypes">Aktionstypen (Mehrfachauswahl)</label>
      <select id="aiLogActionTypes" multiple size="6"></select>
      <label for="aiLogToolNames">Tools (Mehrfachauswahl)</label>
      <select id="aiLogToolNames" multiple size="6"></select>
      <label for="aiLogCollectionFrom">Collection von</label>
      <select id="aiLogCollectionFrom"></select>
      <label for="aiLogCollectionTo">Collection nach</label>
      <select id="aiLogCollectionTo"></select>
      <label for="aiLogLinkId">Link-ID</label>
      <input id="aiLogLinkId" type="number" min="1" />
      <label for="aiLogTagName">Tag enthält</label>
      <input id="aiLogTagName" placeholder="z. B. ChatGPT" />
      <label for="aiLogTrackingTrimmed">Tracking gekürzt</label>
      <select id="aiLogTrackingTrimmed">
        <option value="">alle</option>
        <option value="true">ja</option>
        <option value="false">nein</option>
      </select>
      <label for="aiLogUndoStatus">Undo-Status</label>
      <select id="aiLogUndoStatus">
        <option value="">alle</option>
        <option value="pending">pending</option>
        <option value="applied">applied</option>
        <option value="conflict">conflict</option>
        <option value="failed">failed</option>
      </select>
      <label for="aiLogSortBy">Sortierung</label>
      <select id="aiLogSortBy">
        <option value="changedAt">Datum</option>
        <option value="actionType">Aktion</option>
        <option value="toolName">Tool</option>
        <option value="linkId">Link-ID</option>
      </select>
      <label for="aiLogSortDir">Richtung</label>
      <select id="aiLogSortDir">
        <option value="desc">absteigend</option>
        <option value="asc">aufsteigend</option>
      </select>
      <label for="aiLogPageSize">Einträge pro Seite</label>
      <select id="aiLogPageSize">
        <option value="10">10</option>
        <option value="25" selected>25</option>
        <option value="50">50</option>
        <option value="100">100</option>
      </select>
      <div class="inline-actions">
        <button onclick="applyAiLogFilters()">Filter anwenden</button>
        <button onclick="resetAiLogFilters()">Filter zurücksetzen</button>
        <button onclick="loadAiLogFacets()">Filterlisten aktualisieren</button>
      </div>
    </div>
    <div class="form-block" data-form-section="ai-log-actions" data-form-section-label="AI-Log Aktionen">
      <h3>Aktionen</h3>
      <p class="help-text">Markiere Einträge und führe selektives oder operation-basiertes Undo aus.</p>
      <div class="inline-actions">
        <button onclick="undoSelectedAiLogChanges()">Ausgewählte Änderungen rückgängig</button>
        <button onclick="undoSelectedAiLogOperations()">Ausgewählte Operationen rückgängig</button>
      </div>
      <p class="status-inline" id="aiLogSelectionSummary">Keine Einträge ausgewählt.</p>
      <p class="status-inline" id="aiLogPagingInfo">Seite 1</p>
      <div class="inline-actions">
        <button onclick="prevAiLogPage()">Vorherige Seite</button>
        <button onclick="nextAiLogPage()">Nächste Seite</button>
      </div>
    </div>
    <div class="form-block" data-form-section="ai-log-retention" data-form-section-label="AI-Log Aufbewahrung">
      <h3>Aufbewahrung</h3>
      <p class="help-text">Lege fest, wie lange AI-Log-Einträge pro User aufbewahrt werden.</p>
      <label for="selfAiActivityRetentionDays">Retention (Tage)</label>
      <select id="selfAiActivityRetentionDays">
        <option value="30">30</option>
        <option value="90">90</option>
        <option value="180" selected>180</option>
        <option value="365">365</option>
      </select>
      <button onclick="setOwnAiLogSettings()">Retention speichern</button>
    </div>
    <div class="ai-log-table-wrap">
      <table class="ai-log-table" id="aiLogTable" aria-label="AI Aktivitätslog">
        <thead>
          <tr>
            <th><input id="aiLogSelectAll" type="checkbox" onchange="toggleAiLogSelectAll()" aria-label="Alle auswählen" /></th>
            <th>Datum</th>
            <th>Aktion</th>
            <th>Link</th>
            <th>Collection von -> nach</th>
            <th>Tags + / -</th>
            <th>URL vorher -> nachher</th>
            <th>Tool</th>
            <th>Undo</th>
          </tr>
        </thead>
        <tbody id="aiLogTableBody">
          <tr><td colspan="9">Noch keine Daten geladen.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="mein-konto" data-sub-tab="profil">
    <h2>Mein Profil</h2>
    <button onclick="loadMe()">Profil neu laden</button>
    <pre id="meResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="profil-write-mode" data-form-section-label="Profil Write-Mode">
      <label><input id="selfWriteMode" type="checkbox" /> Eigener Write-Mode aktiv</label>
      <button onclick="setOwnWriteMode()">Meinen Write-Mode speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="governance" data-sub-tab="mein-tagging">
    <h2>Mein Tagging</h2>
    <button onclick="loadOwnTaggingPreferences()">Tagging-Einstellungen laden</button>
    <pre id="ownTaggingPreferencesResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="mein-tagging-preferences" data-form-section-label="Mein Tagging">
      <label for="selfTaggingStrictness">Tagging-Strenge</label>
      <select id="selfTaggingStrictness">
        <option value="very_strict">very_strict</option>
        <option value="medium">medium</option>
        <option value="relaxed">relaxed</option>
      </select>
      <label for="selfFetchMode">Fetch-Mode</label>
      <select id="selfFetchMode">
        <option value="never">never</option>
        <option value="optional">optional</option>
        <option value="always">always</option>
      </select>
      <label for="selfQueryTimeZone">Query-Zeitzone (IANA)</label>
      <input id="selfQueryTimeZone" placeholder="Europe/Berlin" />
      <button onclick="setOwnTaggingPreferences()">Meine Tagging-Einstellungen speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="automationen" data-sub-tab="routine">
    <h2>Meine New-Links-Routine</h2>
    <button onclick="loadOwnNewLinksRoutine()">Routine-Status laden</button>
    <pre id="ownNewLinksRoutineResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="routine-settings" data-form-section-label="Routine-Einstellungen">
      <label><input id="selfRoutineEnabled" type="checkbox" /> Routine aktiviert</label>
      <label for="selfRoutineInterval">Intervall (Minuten)</label>
      <input id="selfRoutineInterval" type="number" min="1" max="1440" value="15" />
      <label for="selfRoutineBatchSize">Batch-Größe</label>
      <input id="selfRoutineBatchSize" type="number" min="1" max="1000" value="200" />
      <label><input id="selfRoutineModuleTagging" type="checkbox" checked /> Modul: governed_tagging</label>
      <label><input id="selfRoutineModuleNormalize" type="checkbox" checked /> Modul: normalize_urls</label>
      <label><input id="selfRoutineModuleDedupe" type="checkbox" checked /> Modul: dedupe</label>
      <label><input id="selfRoutineRequestBackfill" type="checkbox" /> Backfill für Altbestand anfordern</label>
      <label><input id="selfRoutineConfirmBackfill" type="checkbox" /> Backfill ausdrücklich bestätigen</label>
      <button onclick="setOwnNewLinksRoutine()">Routine-Einstellungen speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="automationen" data-sub-tab="link-404-monitor">
    <h2>Mein 404-Monitor</h2>
    <button onclick="loadOwnLink404Monitor()">404-Monitor laden</button>
    <pre id="ownLink404MonitorResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="link-404-monitor-settings" data-form-section-label="404-Monitor">
      <label><input id="selfLink404MonitorEnabled" type="checkbox" /> 404-Monitor aktiviert</label>
      <label for="selfLink404MonitorInterval">Prüfintervall</label>
      <select id="selfLink404MonitorInterval">
        <option value="daily">Täglich</option>
        <option value="weekly">Wöchentlich</option>
        <option value="biweekly">Alle zwei Wochen</option>
        <option value="monthly" selected>Monatlich</option>
        <option value="semiannual">Halbjährlich</option>
        <option value="yearly">Jährlich</option>
      </select>
      <label for="selfLink404MonitorToDeleteAfter">to-delete nach</label>
      <select id="selfLink404MonitorToDeleteAfter">
        <option value="after_1_month">Nach einem Monat</option>
        <option value="after_6_months">Nach einem halben Jahr</option>
        <option value="after_1_year" selected>Nach einem Jahr</option>
      </select>
      <button onclick="setOwnLink404Monitor()">404-Monitor speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="automationen" data-sub-tab="chat-control">
    <h2>Mein Chat-Control</h2>
    <button onclick="loadOwnChatControl()">Chat-Control laden</button>
    <pre id="ownChatControlResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="chat-control-settings" data-form-section-label="Chat-Control">
      <label for="selfArchiveCollectionName">Archiv-Collection-Name</label>
      <input id="selfArchiveCollectionName" value="Archive" />
      <label for="selfArchiveCollectionParentId">Archiv Parent Collection ID (optional)</label>
      <input id="selfArchiveCollectionParentId" type="number" min="1" />
      <label for="selfChatCaptureTagName">Chat-Link-Tag-Name</label>
      <input id="selfChatCaptureTagName" value="AI Chat" />
      <label><input id="selfChatCaptureTagAiChatEnabled" type="checkbox" checked /> AI Chat-Tag setzen</label>
      <label><input id="selfChatCaptureTagAiNameEnabled" type="checkbox" checked /> AI Name-Tag setzen</label>
      <button onclick="setOwnChatControl()">Chat-Control speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="integrationen" data-sub-tab="linkwarden-token">
    <h2>Mein Linkwarden API Key -> MCP</h2>
    <p id="selfLinkwardenStatus">Status: unbekannt</p>
    <div class="form-block" data-form-section="linkwarden-token-set" data-form-section-label="Mein Linkwarden-Key">
      <label for="selfLinkwardenToken">Linkwarden API Key</label>
      <input id="selfLinkwardenToken" type="password" />
      <button onclick="setOwnLinkwardenToken()">Linkwarden API Key speichern</button>
    </div>
  </div>

  <div class="card tab-panel-card" data-top-tab="mein-konto" data-sub-tab="api-keys">
    <h2>Meine MCP API Keys -> AI</h2>
    <button onclick="loadOwnKeys()">Meine MCP API Keys laden</button>
    <pre id="ownKeysResult">Noch nicht geladen</pre>
    <div class="form-block" data-form-section="own-key-issue" data-form-section-label="Eigenen API-Key erzeugen">
      <label for="ownKeyLabel">Key Label</label>
      <input id="ownKeyLabel" value="default" />
      <button onclick="issueOwnKey()">Eigenen API Key erzeugen</button>
    </div>
    <div class="form-block" data-form-section="own-key-revoke" data-form-section-label="Eigenen API-Key revoken">
      <label for="ownRevokeKeyId">Key ID zum Revoken</label>
      <input id="ownRevokeKeyId" />
      <button onclick="revokeOwnKey()">Eigenen API Key revoken</button>
    </div>
  </div>

  ${adminSections}

  <div id="toastStack" class="toast-stack" aria-live="polite" aria-atomic="false"></div>

<script>
const csrfToken = ${JSON.stringify(csrfToken)};
const isAdmin = ${JSON.stringify(principal.role === 'admin')};
const currentRole = isAdmin ? 'admin' : 'user';
let usersCache = [];

/**
 * This typedef declares the supported top-level tab keys for the admin dashboard shell.
 * @typedef {'uebersicht'|'mein-konto'|'automationen'|'integrationen'|'governance'|'administration'} TabKey
 */

/**
 * This typedef declares subtab keys as free-form strings constrained by per-tab registries below.
 * @typedef {string} SubTabKey
 */

/**
 * This typedef defines one role-aware top-level tab descriptor used by the tab renderer.
 * @typedef {{ key: TabKey, label: string, adminOnly: boolean }} TabDefinition
 */

/**
 * This typedef describes panel loading state used by lazy-loading and stale invalidation.
 * @typedef {{ loadedPanels:Set<string>, stalePanels:Set<string>, inflightPanelLoads:Map<string, Promise<void>> }} LoadState
 */

/**
 * This typedef describes deduplicated request state for inflight API calls.
 * @typedef {{ inflightRequests:Map<string, Promise<{res:Response, json:any}>> }} RequestState
 */

const loadedPanels = new Set();
const stalePanels = new Set();

// This map tracks known form sections per panel and drives section-level dirty guards.
const sectionRegistry = new Map();

// This set tracks dirty form sections using keys composed from panel and section ids.
const dirtySections = new Set();
const debugDrawerStorageKey = 'lwmcp.debugDrawerOpen';

/** @type {RequestState['inflightRequests']} */
const inflightRequests = new Map();

/** @type {LoadState['inflightPanelLoads']} */
const inflightPanelLoads = new Map();
let activeTopTab = 'uebersicht';
let activeSubTab = 'status';
const topNavFocusMode = 'tab-button';
const subNavFocusMode = 'tab-button';
let aiLogPage = 1;
let aiLogTotal = 0;
let aiLogPageSize = 25;
let aiLogEntries = [];

/** @type {TabDefinition[]} */
const topTabDefinitions = [
  { key: 'uebersicht', label: 'Übersicht', adminOnly: false },
  { key: 'mein-konto', label: 'Mein Konto', adminOnly: false },
  { key: 'automationen', label: 'Automationen', adminOnly: false },
  { key: 'integrationen', label: 'Integrationen', adminOnly: false },
  { key: 'governance', label: 'Governance', adminOnly: false },
  { key: 'administration', label: 'Administration', adminOnly: true }
];

// This registry documents allowed subtab keys for each top-level tab key.
/** @type {Record<TabKey, Array<{ key: SubTabKey, label: string, adminOnly: boolean }>>} */
const subTabDefinitions = {
  'uebersicht': [
    { key: 'status', label: 'Status', adminOnly: false },
    { key: 'ai-log', label: 'AI-Log', adminOnly: false }
  ],
  'mein-konto': [
    { key: 'profil', label: 'Profil', adminOnly: false },
    { key: 'api-keys', label: 'MCP API Keys', adminOnly: false }
  ],
  'automationen': [
    { key: 'routine', label: 'New-Links-Routine', adminOnly: false },
    { key: 'link-404-monitor', label: '404-Monitor', adminOnly: false },
    { key: 'chat-control', label: 'Chat-Control', adminOnly: false }
  ],
  'integrationen': [
    { key: 'linkwarden-token', label: 'Mein Linkwarden-Key', adminOnly: false },
    { key: 'user-linkwarden-token', label: 'User Linkwarden-Keys', adminOnly: true },
    { key: 'linkwarden-ziel', label: 'Linkwarden Ziel', adminOnly: true }
  ],
  'governance': [
    { key: 'mein-tagging', label: 'Mein Tagging', adminOnly: false },
    { key: 'tagging-policy', label: 'Tagging-Policy', adminOnly: true }
  ],
  'administration': [
    { key: 'benutzer', label: 'Benutzer', adminOnly: true },
    { key: 'admin-keys', label: 'Admin API Keys', adminOnly: true }
  ]
};

const panelLoaders = {
  'uebersicht:status': async () => {
    await loadMe();
    await loadOwnNewLinksRoutine();
  },
  'uebersicht:ai-log': async () => {
    await loadAiLogFacets();
    await loadOwnAiLogSettings();
    await loadAiLog();
  },
  'mein-konto:profil': async () => { await loadMe(); },
  'mein-konto:api-keys': async () => { await loadOwnKeys(); },
  'automationen:routine': async () => { await loadOwnNewLinksRoutine(); },
  'automationen:link-404-monitor': async () => { await loadOwnLink404Monitor(); },
  'automationen:chat-control': async () => { await loadOwnChatControl(); },
  'integrationen:linkwarden-token': async () => { await loadMe(); },
  'integrationen:user-linkwarden-token': async () => { await loadUsers(); },
  'integrationen:linkwarden-ziel': async () => {
    await loadLinkwardenConfig();
    await loadOAuthSessionSettings();
  },
  'governance:mein-tagging': async () => { await loadOwnTaggingPreferences(); },
  'governance:tagging-policy': async () => {
    await loadTaggingPolicy();
    await loadUsers();
  },
  'administration:benutzer': async () => { await loadUsers(); },
  'administration:admin-keys': async () => {
    await loadUsers();
    await loadAdminKeys();
  }
};

const mutationInvalidationMap = {
  createUser: ['administration:*', 'integrationen:user-linkwarden-token', 'governance:tagging-policy'],
  setUserActive: ['administration:*', 'integrationen:user-linkwarden-token', 'governance:tagging-policy'],
  setUserWriteMode: ['administration:*', 'integrationen:user-linkwarden-token', 'governance:tagging-policy'],
  setUserOfflinePolicy: ['administration:*', 'integrationen:user-linkwarden-token', 'governance:tagging-policy'],
  setOwnWriteMode: ['mein-konto:profil', 'uebersicht:status'],
  setOwnTaggingPreferences: ['governance:mein-tagging', 'uebersicht:status'],
  setOwnNewLinksRoutine: ['automationen:routine', 'uebersicht:status'],
  setOwnLink404Monitor: ['automationen:link-404-monitor', 'uebersicht:status'],
  setOwnChatControl: ['automationen:chat-control', 'uebersicht:ai-log'],
  setOwnLinkwardenToken: ['integrationen:linkwarden-token', 'uebersicht:status'],
  issueOwnKey: ['mein-konto:api-keys'],
  revokeOwnKey: ['mein-konto:api-keys'],
  issueAdminKey: ['administration:admin-keys'],
  revokeAdminKey: ['administration:admin-keys'],
  setUserLinkwardenToken: ['integrationen:user-linkwarden-token', 'administration:benutzer'],
  setTaggingPolicy: ['governance:*'],
  setUserTaggingPreferences: ['governance:*'],
  updateLinkwardenConfig: ['integrationen:linkwarden-ziel'],
  setOAuthSessionLifetime: ['integrationen:linkwarden-ziel', 'uebersicht:status'],
  undoAiLogChanges: ['uebersicht:ai-log', 'uebersicht:status'],
  undoAiLogOperations: ['uebersicht:ai-log', 'uebersicht:status'],
  setOwnAiLogSettings: ['uebersicht:ai-log']
};

// This helper creates a deterministic key for tab/subtab addressed panel state.
function panelKey(topTab, subTab) {
  return topTab + ':' + subTab;
}

// This helper composes one unique dirty-section key for a panel and local form section id.
function sectionKey(topTab, subTab, sectionId) {
  return panelKey(topTab, subTab) + '#' + sectionId;
}

// This helper normalizes section labels into deterministic, user-readable guard text.
function normalizeSectionLabel(value, fallback) {
  const normalized = String(value || '').trim();
  if (normalized.length > 0) {
    return normalized;
  }
  return String(fallback || 'Abschnitt');
}

// This helper registers one section descriptor for section-level dirty tracking.
function registerSection(topTab, subTab, sectionId, sectionLabel) {
  const key = panelKey(topTab, subTab);
  if (!sectionRegistry.has(key)) {
    sectionRegistry.set(key, []);
  }
  const sections = sectionRegistry.get(key);
  const existing = sections.find((item) => item.id === sectionId);
  const next = {
    id: sectionId,
    label: normalizeSectionLabel(sectionLabel, sectionId)
  };
  if (existing) {
    existing.label = next.label;
    return;
  }
  sections.push(next);
}

// This helper initializes section registry entries from data-form-section markers and panel defaults.
function initializeSectionRegistry() {
  sectionRegistry.clear();
  const cards = document.querySelectorAll('.tab-panel-card');
  cards.forEach((card) => {
    const topTab = card.getAttribute('data-top-tab') || '';
    const subTab = card.getAttribute('data-sub-tab') || '';
    if (!topTab || !subTab) {
      return;
    }

    const panelLabel = card.querySelector('h2')?.textContent || panelKey(topTab, subTab);
    const defaultSectionId = (card.getAttribute('data-panel-default-section') || 'main').trim() || 'main';
    const explicitSections = card.querySelectorAll('[data-form-section]');
    if (explicitSections.length === 0) {
      registerSection(topTab, subTab, defaultSectionId, panelLabel);
      return;
    }

    explicitSections.forEach((section) => {
      const sectionId = (section.getAttribute('data-form-section') || '').trim();
      if (!sectionId) {
        return;
      }
      const sectionLabel = section.getAttribute('data-form-section-label') || sectionId;
      registerSection(topTab, subTab, sectionId, sectionLabel);
    });
  });
}

// This helper resolves the owning section for one input control using explicit markers and panel fallback.
function resolveSectionFromControl(control) {
  if (!control || typeof control.closest !== 'function') {
    return null;
  }

  const panel = control.closest('.tab-panel-card');
  if (!panel) {
    return null;
  }

  const topTab = panel.getAttribute('data-top-tab') || '';
  const subTab = panel.getAttribute('data-sub-tab') || '';
  if (!topTab || !subTab) {
    return null;
  }

  const sectionElement = control.closest('[data-form-section]');
  const sectionId = sectionElement
    ? (sectionElement.getAttribute('data-form-section') || '').trim()
    : ((panel.getAttribute('data-panel-default-section') || 'main').trim() || 'main');
  const defaultLabel = sectionId || 'main';
  const sectionLabel = sectionElement
    ? (sectionElement.getAttribute('data-form-section-label') || defaultLabel)
    : (panel.querySelector('h2')?.textContent || defaultLabel);
  const normalizedId = sectionId || 'main';
  registerSection(topTab, subTab, normalizedId, sectionLabel);

  return {
    topTab,
    subTab,
    sectionId: normalizedId,
    sectionLabel: normalizeSectionLabel(sectionLabel, normalizedId)
  };
}

// This helper returns all dirty sections for one panel with labels for guard messaging.
function getDirtySectionsForPanel(topTab, subTab) {
  const key = panelKey(topTab, subTab);
  const sections = Array.isArray(sectionRegistry.get(key)) ? sectionRegistry.get(key) : [];
  return sections
    .filter((section) => dirtySections.has(sectionKey(topTab, subTab, section.id)))
    .map((section) => ({
      id: section.id,
      label: section.label
    }));
}

// This helper clears dirty state for one section inside a panel after a successful targeted mutation.
function clearDirtySection(topTab, subTab, sectionId) {
  dirtySections.delete(sectionKey(topTab, subTab, sectionId));
}

// This helper clears dirty state for the default section in the currently active panel.
function clearDirtyDefaultForActivePanel() {
  const panel = document.getElementById(panelDomId(activeTopTab, activeSubTab));
  const defaultSectionId = panel
    ? ((panel.getAttribute('data-panel-default-section') || 'main').trim() || 'main')
    : 'main';
  clearDirtySection(activeTopTab, activeSubTab, defaultSectionId);
}

// This helper clears dirty sections selectively based on explicitly declared mutation section ids.
function clearDirtySectionsForMutation(mutationSections) {
  if (!Array.isArray(mutationSections) || mutationSections.length === 0) {
    clearDirtyDefaultForActivePanel();
    return;
  }

  mutationSections.forEach((sectionId) => {
    const normalized = String(sectionId || '').trim();
    if (normalized.length === 0) {
      return;
    }
    clearDirtySection(activeTopTab, activeSubTab, normalized);
  });
}

// This helper maps one top/subtab pair to a deterministic DOM id for ARIA bindings.
function panelDomId(topTab, subTab) {
  return 'panel-' + topTab + '-' + subTab;
}

// This helper builds one deterministic DOM id for top-level tab buttons.
function topTabDomId(topTab) {
  return 'tab-top-' + topTab;
}

// This helper builds one deterministic DOM id for sub-tab buttons.
function subTabDomId(topTab, subTab) {
  return 'tab-sub-' + topTab + '-' + subTab;
}

/**
 * This helper centralizes role checks for top and subtab visibility.
 * @param {{ adminOnly?: boolean }} tab
 * @param {'admin'|'user'|string} role
 * @returns {boolean}
 */
function isTabAllowedForRole(tab, role) {
  return !tab.adminOnly || role === 'admin';
}

// This helper returns tab definitions allowed for the current principal role.
function getAllowedTopTabs() {
  return topTabDefinitions.filter((item) => isTabAllowedForRole(item, currentRole));
}

// This helper returns subtab definitions allowed for one top-level tab.
function getAllowedSubTabs(topTab) {
  const candidates = Array.isArray(subTabDefinitions[topTab]) ? subTabDefinitions[topTab] : [];
  return candidates.filter((item) => isTabAllowedForRole(item, currentRole));
}

/**
 * This helper parses tab state from hash format #tab=<top>&sub=<sub>.
 * @returns {{ topTab: TabKey | string, subTab: SubTabKey }}
 */
function parseTabState() {
  const raw = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
  const params = new URLSearchParams(raw);
  return {
    topTab: params.get('tab') || '',
    subTab: params.get('sub') || ''
  };
}

/**
 * This helper serializes one tab state into the public hash deep-link contract.
 * @param {TabKey | string} topTab
 * @param {SubTabKey} subTab
 * @returns {string}
 */
function serializeTabState(topTab, subTab) {
  const params = new URLSearchParams();
  params.set('tab', topTab);
  params.set('sub', subTab);
  return '#' + params.toString();
}

// This helper writes tab state to URL hash using push or replace semantics.
function writeTabStateToHash(topTab, subTab, historyMode) {
  if (historyMode === 'skip') {
    return;
  }

  const nextHash = serializeTabState(topTab, subTab);
  if (window.location.hash === nextHash) {
    return;
  }

  if (historyMode === 'push') {
    window.location.hash = nextHash;
    return;
  }

  window.history.replaceState(null, '', nextHash);
}

// This helper ensures a requested tab/subtab pair is valid for the current role.
function normalizeTabState(state) {
  const requestedTop = state && typeof state === 'object' ? String(state.topTab || '') : '';
  const requestedSub = state && typeof state === 'object' ? String(state.subTab || '') : '';
  const allowedTopTabs = getAllowedTopTabs();
  const fallbackTop = allowedTopTabs.length > 0 ? allowedTopTabs[0].key : 'uebersicht';
  const safeTop = allowedTopTabs.some((item) => item.key === requestedTop) ? requestedTop : fallbackTop;
  const allowedSubTabs = getAllowedSubTabs(safeTop);
  const fallbackSub = allowedSubTabs.length > 0 ? allowedSubTabs[0].key : 'status';
  const safeSub = allowedSubTabs.some((item) => item.key === requestedSub) ? requestedSub : fallbackSub;
  return { topTab: safeTop, subTab: safeSub };
}

// This helper renders role-aware top-level tab buttons with ARIA selected state.
function renderTopTabs() {
  const container = document.getElementById('topTabsNav');
  if (!container) {
    return;
  }
  const allowedTopTabs = getAllowedTopTabs();
  container.innerHTML = allowedTopTabs
    .map((item) => {
      const selected = item.key === activeTopTab;
      const firstSubTab = getAllowedSubTabs(item.key)[0];
      const controlledPanel = panelDomId(item.key, firstSubTab ? firstSubTab.key : 'status');
      return '<button class="top-tab-btn" id="' + topTabDomId(item.key) + '" type="button" data-top-tab-btn="' + item.key + '" role="tab" aria-controls="' + controlledPanel + '" aria-selected="' + String(selected) + '" tabindex="' + String(selected ? 0 : -1) + '">' + item.label + '</button>';
    })
    .join('');
}

// This helper renders role-aware subtab buttons for the active top-level tab.
function renderSubTabs() {
  const container = document.getElementById('subTabsNav');
  if (!container) {
    return;
  }
  const allowedSubTabs = getAllowedSubTabs(activeTopTab);
  container.innerHTML = allowedSubTabs
    .map((item) => {
      const selected = item.key === activeSubTab;
      const controlledPanel = panelDomId(activeTopTab, item.key);
      return '<button class="sub-tab-btn" id="' + subTabDomId(activeTopTab, item.key) + '" type="button" data-sub-tab-btn="' + item.key + '" role="tab" aria-controls="' + controlledPanel + '" aria-selected="' + String(selected) + '" tabindex="' + String(selected ? 0 : -1) + '">' + item.label + '</button>';
    })
    .join('');
}

// This helper configures panel ids and ARIA panel metadata from existing data attributes.
function initializePanelA11y() {
  const cards = document.querySelectorAll('.tab-panel-card');
  cards.forEach((card) => {
    const topTab = card.getAttribute('data-top-tab') || '';
    const subTab = card.getAttribute('data-sub-tab') || '';
    if (!topTab || !subTab) {
      return;
    }
    if (!card.getAttribute('data-panel-default-section')) {
      card.setAttribute('data-panel-default-section', 'main');
    }
    card.id = panelDomId(topTab, subTab);
    card.setAttribute('role', 'tabpanel');
    card.setAttribute('aria-labelledby', subTabDomId(topTab, subTab));
  });
}

// This helper toggles panel visibility based on active top tab and subtab.
function applyPanelVisibility() {
  const cards = document.querySelectorAll('.tab-panel-card');
  cards.forEach((card) => {
    const topTab = card.getAttribute('data-top-tab') || '';
    const subTab = card.getAttribute('data-sub-tab') || '';
    const visible = topTab === activeTopTab && subTab === activeSubTab;
    card.hidden = !visible;
    card.setAttribute('aria-hidden', String(!visible));
    if (visible) {
      card.setAttribute('aria-labelledby', subTabDomId(activeTopTab, activeSubTab));
    } else if (topTab) {
      card.setAttribute('aria-labelledby', topTabDomId(topTab));
    }
  });
}

// This helper marks one form section as dirty when inputs inside that section are edited.
function markDirtyFromInput(event) {
  const target = event.target;
  const meta = resolveSectionFromControl(target);
  if (!meta) {
    return;
  }
  dirtySections.add(sectionKey(meta.topTab, meta.subTab, meta.sectionId));
}

// This helper adds dirty tracking listeners to all editable controls inside tabbed panels.
function initDirtyTracking() {
  const controls = document.querySelectorAll('.tab-panel-card input, .tab-panel-card select, .tab-panel-card textarea');
  controls.forEach((control) => {
    control.addEventListener('input', markDirtyFromInput);
    control.addEventListener('change', markDirtyFromInput);
  });
}

// This helper renders one toast message with optional custom timeout behavior.
function showToast(type, message, options = {}) {
  const stack = document.getElementById('toastStack');
  if (!stack) {
    return;
  }
  const toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.textContent = message;
  stack.appendChild(toast);
  const durationMs = Number(options.durationMs);
  const autoDismissMs = Number.isFinite(durationMs) ? durationMs : (type === 'error' ? 0 : 3500);
  if (autoDismissMs > 0) {
    setTimeout(() => {
      toast.remove();
    }, autoDismissMs);
  }
}

// This helper writes one compact status line under the overview session card.
function setOverviewStatus(message) {
  const element = document.getElementById('statusOverview');
  if (!element) {
    return;
  }
  element.textContent = message;
  const kpiLastAction = document.getElementById('kpiLastAction');
  if (kpiLastAction) {
    kpiLastAction.textContent = message;
  }
}

// This helper updates one overview KPI value by element id when the target exists.
function setKpiValue(id, value) {
  const element = document.getElementById(id);
  if (!element) {
    return;
  }
  element.textContent = String(value);
}

// This helper writes one formatted payload into the debug drawer and optionally opens it.
function openDebugDrawer(payload, options = {}) {
  const pre = document.getElementById('actionResult');
  if (!pre) {
    return;
  }
  pre.textContent = JSON.stringify(payload, null, 2);
  if (options.autoOpenOnError) {
    const drawer = document.getElementById('debugDrawer');
    if (drawer && typeof drawer.open !== 'undefined') {
      drawer.open = true;
      try {
        window.sessionStorage.setItem(debugDrawerStorageKey, '1');
      } catch {
        // This no-op keeps debug rendering stable when sessionStorage is unavailable.
      }
    }
  }
}

// This helper restores debug drawer visibility preference and keeps it synced in sessionStorage.
function initDebugDrawerState() {
  const drawer = document.getElementById('debugDrawer');
  if (!drawer) {
    return;
  }

  try {
    drawer.open = window.sessionStorage.getItem(debugDrawerStorageKey) === '1';
  } catch {
    // This no-op keeps drawer behavior stable when sessionStorage is unavailable.
  }

  drawer.addEventListener('toggle', () => {
    try {
      if (drawer.open) {
        window.sessionStorage.setItem(debugDrawerStorageKey, '1');
      } else {
        window.sessionStorage.removeItem(debugDrawerStorageKey);
      }
    } catch {
      // This no-op keeps drawer toggling stable when sessionStorage is unavailable.
    }
  });
}

// This helper removes previous inline field validation hints before applying new ones.
function clearFieldErrors() {
  document.querySelectorAll('.field-error').forEach((node) => node.remove());
  document.querySelectorAll('.field-invalid').forEach((node) => node.classList.remove('field-invalid'));
}

// This helper normalizes field names for robust zod-to-dom matching.
function normalizeFieldName(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

// This helper resolves a likely form control for one zod field error key.
function findControlForField(fieldName) {
  const controls = Array.from(document.querySelectorAll('input[id], select[id], textarea[id]'));
  const normalizedField = normalizeFieldName(fieldName);
  if (!normalizedField) {
    return null;
  }

  const exact = controls.find((control) => normalizeFieldName(control.id) === normalizedField);
  if (exact) {
    return exact;
  }

  const suffix = normalizedField.split(/(?:dot|_)/).pop() || normalizedField;
  return controls.find((control) => {
    const normalizedId = normalizeFieldName(control.id);
    return normalizedId.endsWith(suffix) || suffix.endsWith(normalizedId);
  }) || null;
}

// This helper attaches one inline validation message directly behind a field.
function showFieldError(control, message) {
  if (!control || typeof control.insertAdjacentElement !== 'function') {
    return;
  }
  control.classList.add('field-invalid');
  const error = document.createElement('p');
  error.className = 'field-error';
  error.textContent = String(message);
  control.insertAdjacentElement('afterend', error);
}

// This helper renders zod-style fieldErrors inline while keeping toast-level feedback.
function applyFieldErrors(details) {
  const fieldErrors = details && typeof details === 'object' ? details.fieldErrors : null;
  if (!fieldErrors || typeof fieldErrors !== 'object') {
    return 0;
  }

  let count = 0;
  Object.entries(fieldErrors).forEach(([field, messages]) => {
    if (!Array.isArray(messages) || messages.length === 0) {
      return;
    }
    const control = findControlForField(field);
    if (!control) {
      return;
    }
    showFieldError(control, messages[0]);
    count += 1;
  });
  return count;
}

// This helper serializes nested values deterministically to build stable request dedupe keys.
function stableSerialize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return '[' + value.map((entry) => stableSerialize(entry)).join(',') + ']';
  }

  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + stableSerialize(value[key])).join(',') + '}';
}

// This helper normalizes request bodies so semantically identical JSON payloads dedupe correctly.
function normalizeBodyForRequestKey(body) {
  if (body == null) {
    return '';
  }

  if (typeof body === 'string') {
    const trimmed = body.trim();
    if (trimmed.length === 0) {
      return '';
    }
    try {
      return stableSerialize(JSON.parse(trimmed));
    } catch {
      return trimmed;
    }
  }

  if (body instanceof URLSearchParams) {
    return body.toString();
  }

  return stableSerialize(body);
}

// This helper builds one deterministic request key used for inflight request dedupe.
function buildRequestKey(url, options) {
  const method = String(options?.method || 'GET').toUpperCase();
  const bodyKey = normalizeBodyForRequestKey(options?.body);
  return method + ' ' + String(url) + ' ' + bodyKey;
}

// This helper deduplicates inflight HTTP requests with identical method/url/body signatures.
async function requestJson(url, options = {}) {
  const key = buildRequestKey(url, options);
  if (inflightRequests.has(key)) {
    return inflightRequests.get(key);
  }

  const promise = (async () => {
    const res = await fetch(url, options);
    let json = {};
    try {
      json = await res.json();
    } catch {
      json = {};
    }
    return { res, json };
  })();

  inflightRequests.set(key, promise);
  try {
    return await promise;
  } finally {
    inflightRequests.delete(key);
  }
}

// This helper resolves invalidation targets from explicit panel keys and wildcard groups.
function resolveInvalidationTargets(actionKey) {
  const targets = mutationInvalidationMap[actionKey];
  if (!Array.isArray(targets)) {
    return [];
  }

  const knownPanels = Object.keys(panelLoaders);
  const resolved = new Set();
  targets.forEach((target) => {
    if (target.endsWith(':*')) {
      const prefix = target.slice(0, -1);
      knownPanels.forEach((panel) => {
        if (panel.startsWith(prefix)) {
          resolved.add(panel);
        }
      });
      return;
    }

    if (knownPanels.includes(target)) {
      resolved.add(target);
    }
  });

  return Array.from(resolved);
}

// This helper marks panel caches stale and refreshes the active panel immediately when affected.
async function invalidateAfterMutation(actionKey) {
  if (!actionKey) {
    return;
  }

  const panelTargets = resolveInvalidationTargets(actionKey);
  if (panelTargets.length === 0) {
    showToast('info', 'Keine Panel-Aktualisierung erforderlich.', { durationMs: 2200 });
    return;
  }
  panelTargets.forEach((target) => stalePanels.add(target));
  const activeKey = panelKey(activeTopTab, activeSubTab);
  if (stalePanels.has(activeKey)) {
    await ensurePanelLoaded(activeTopTab, activeSubTab, { force: true });
  }
}

/**
 * This helper loads one panel lazily with inflight dedupe and stale-aware refresh behavior.
 * @param {TabKey | string} topTab
 * @param {SubTabKey} subTab
 * @param {{ force?: boolean }} [options]
 * @returns {Promise<void>}
 */
async function ensurePanelLoaded(topTab, subTab, options = {}) {
  const key = panelKey(topTab, subTab);
  const force = Boolean(options.force);
  const needsLoad = force || !loadedPanels.has(key) || stalePanels.has(key);
  if (!needsLoad) {
    return;
  }

  if (inflightPanelLoads.has(key)) {
    await inflightPanelLoads.get(key);
    return;
  }

  const loader = panelLoaders[key];
  const loadPromise = (async () => {
    if (typeof loader === 'function') {
      await loader();
    }
    loadedPanels.add(key);
    stalePanels.delete(key);
  })();

  inflightPanelLoads.set(key, loadPromise);
  try {
    await loadPromise;
  } finally {
    inflightPanelLoads.delete(key);
  }
}

// This helper focuses either the active tab button or the first control in the active panel.
function focusAfterTabChange(focusMode) {
  const normalizedFocusMode = focusMode || 'tab-button';
  if (normalizedFocusMode === 'none') {
    return;
  }

  if (normalizedFocusMode === 'first-input') {
    const panel = document.getElementById(panelDomId(activeTopTab, activeSubTab));
    const control = panel
      ? panel.querySelector('input, select, textarea, button')
      : null;
    if (control && typeof control.focus === 'function') {
      control.focus();
      return;
    }
  }

  const activeSubButton = document.getElementById(subTabDomId(activeTopTab, activeSubTab));
  if (activeSubButton && typeof activeSubButton.focus === 'function') {
    activeSubButton.focus();
    return;
  }

  const activeTopButton = document.getElementById(topTabDomId(activeTopTab));
  if (activeTopButton && typeof activeTopButton.focus === 'function') {
    activeTopButton.focus();
  }
}

/**
 * This helper activates one panel, applies guards, syncs hash state, and triggers lazy loading.
 * @param {{ topTab?: TabKey | string, subTab?: SubTabKey } | null | undefined} state
 * @param {{ skipGuard?: boolean, historyMode?: 'push'|'replace'|'skip', focusMode?: 'tab-button'|'first-input'|'none', notifyNoChange?: boolean }} [options]
 * @returns {Promise<{ changed: boolean, blocked: boolean, normalized: { topTab: string, subTab: string } }>}
 */
async function applyTabState(state, options = {}) {
  const normalized = normalizeTabState(state);
  const current = panelKey(activeTopTab, activeSubTab);
  const next = panelKey(normalized.topTab, normalized.subTab);
  if (!options.skipGuard && current !== next) {
    const dirtyInCurrentPanel = getDirtySectionsForPanel(activeTopTab, activeSubTab);
    if (dirtyInCurrentPanel.length > 0) {
      const uniqueLabels = Array.from(new Set(dirtyInCurrentPanel.map((section) => section.label)));
      const sectionHint = uniqueLabels.join(', ');
      const proceed = window.confirm(
        'Du hast ungespeicherte Änderungen in: ' + sectionHint + '. Trotzdem Tab wechseln?'
      );
      if (!proceed) {
        return {
          changed: false,
          blocked: true,
          normalized
        };
      }
    }
  }

  if (current === next && options.notifyNoChange) {
    showToast('info', 'Tab ist bereits aktiv.', { durationMs: 2000 });
  }

  activeTopTab = normalized.topTab;
  activeSubTab = normalized.subTab;
  renderTopTabs();
  renderSubTabs();
  applyPanelVisibility();
  await ensurePanelLoaded(activeTopTab, activeSubTab);
  writeTabStateToHash(activeTopTab, activeSubTab, options.historyMode || 'replace');
  focusAfterTabChange(options.focusMode || 'tab-button');

  return {
    changed: current !== next,
    blocked: false,
    normalized
  };
}

// This helper handles keyboard navigation for tablists (Arrow/Home/End/Enter/Space).
function bindKeyboardNavigation(container, selector, resolveStateFromButton, focusMode) {
  if (!container) {
    return;
  }

  container.addEventListener('keydown', async (event) => {
    const target = event.target && typeof event.target.closest === 'function'
      ? event.target.closest(selector)
      : null;
    if (!target) {
      return;
    }

    const buttons = Array.from(container.querySelectorAll(selector));
    if (buttons.length === 0) {
      return;
    }

    const currentIndex = buttons.indexOf(target);
    if (currentIndex < 0) {
      return;
    }

    const key = String(event.key || '');
    let nextIndex = currentIndex;
    let shouldActivate = false;

    if (key === 'ArrowRight') {
      nextIndex = (currentIndex + 1) % buttons.length;
      shouldActivate = true;
    } else if (key === 'ArrowLeft') {
      nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
      shouldActivate = true;
    } else if (key === 'Home') {
      nextIndex = 0;
      shouldActivate = true;
    } else if (key === 'End') {
      nextIndex = buttons.length - 1;
      shouldActivate = true;
    } else if (key === 'Enter' || key === ' ' || key === 'Spacebar') {
      shouldActivate = true;
    } else {
      return;
    }

    event.preventDefault();
    const nextButton = buttons[nextIndex];
    if (!shouldActivate || !nextButton) {
      return;
    }

    const nextState = resolveStateFromButton(nextButton);
    await applyTabState(nextState, { historyMode: 'push', focusMode: focusMode || 'tab-button', notifyNoChange: true });
  });
}

// This helper wires tab navigation click handlers for both top tabs and subtabs.
function bindTabNavigation() {
  const topNav = document.getElementById('topTabsNav');
  if (topNav) {
    topNav.addEventListener('click', async (event) => {
      const target = event.target?.closest ? event.target.closest('[data-top-tab-btn]') : null;
      if (!target) {
        return;
      }
      const topTab = target.getAttribute('data-top-tab-btn') || '';
      const subTabs = getAllowedSubTabs(topTab);
      const defaultSubTab = subTabs.length > 0 ? subTabs[0].key : 'status';
      await applyTabState(
        {
          topTab,
          subTab: defaultSubTab
        },
        { historyMode: 'push', focusMode: topNavFocusMode, notifyNoChange: true }
      );
    });
    bindKeyboardNavigation(topNav, '[data-top-tab-btn]', (button) => {
      const topTab = button.getAttribute('data-top-tab-btn') || '';
      const subTabs = getAllowedSubTabs(topTab);
      return {
        topTab,
        subTab: subTabs.length > 0 ? subTabs[0].key : 'status'
      };
    }, topNavFocusMode);
  }

  const subNav = document.getElementById('subTabsNav');
  if (subNav) {
    subNav.addEventListener('click', async (event) => {
      const target = event.target?.closest ? event.target.closest('[data-sub-tab-btn]') : null;
      if (!target) {
        return;
      }
      const subTab = target.getAttribute('data-sub-tab-btn') || '';
      await applyTabState(
        {
          topTab: activeTopTab,
          subTab
        },
        { historyMode: 'push', focusMode: subNavFocusMode, notifyNoChange: true }
      );
    });
    bindKeyboardNavigation(subNav, '[data-sub-tab-btn]', (button) => ({
      topTab: activeTopTab,
      subTab: button.getAttribute('data-sub-tab-btn') || ''
    }), subNavFocusMode);
  }
}

// This helper synchronizes UI state from URL hash while preserving deterministic fallback behavior.
async function syncTabStateFromLocation() {
  const requested = parseTabState();
  const outcome = await applyTabState(requested, { historyMode: 'skip', focusMode: 'none' });
  if (outcome.blocked) {
    writeTabStateToHash(activeTopTab, activeSubTab, 'replace');
    return;
  }

  const normalizedHash = serializeTabState(outcome.normalized.topTab, outcome.normalized.subTab);
  const requestedHash = serializeTabState(requested.topTab, requested.subTab);
  if (normalizedHash !== requestedHash) {
    writeTabStateToHash(outcome.normalized.topTab, outcome.normalized.subTab, 'replace');
  }
}

// This helper initializes A11y metadata and tab state wiring for click/hash/history flows.
async function initTabState() {
  initializePanelA11y();
  await syncTabStateFromLocation();
  window.addEventListener('hashchange', async () => {
    await syncTabStateFromLocation();
  });
  window.addEventListener('popstate', async () => {
    await syncTabStateFromLocation();
  });
}

function updateUserSelect(selectId) {
  const select = document.getElementById(selectId);
  if (!select) {
    return;
  }

  select.innerHTML = '';
  for (const user of usersCache) {
    const option = document.createElement('option');
    option.value = String(user.id);
    option.textContent = user.username;
    select.appendChild(option);
  }
}

function refreshAdminUserSelects() {
  updateUserSelect('toggleUserSelect');
  updateUserSelect('writeModeUserSelect');
  updateUserSelect('offlinePolicyUserSelect');
  updateUserSelect('taggingPreferenceUserSelect');
  updateUserSelect('apiKeyUserSelect');
  updateUserSelect('linkwardenTokenUserSelect');
  syncOfflinePolicyFromSelectedUser();
  syncTaggingPreferencesFromSelectedUser();
}

// This helper maps one selected user id back to cached user objects for policy prefilling.
function getSelectedUser(selectId) {
  const select = document.getElementById(selectId);
  if (!select) {
    return null;
  }

  const selectedId = Number(select.value);
  if (!Number.isFinite(selectedId)) {
    return null;
  }

  return usersCache.find((user) => Number(user.id) === selectedId) || null;
}

// This helper prefills offline policy form controls from currently selected user settings.
function syncOfflinePolicyFromSelectedUser() {
  const user = getSelectedUser('offlinePolicyUserSelect');
  if (!user || !user.settings) {
    return;
  }

  document.getElementById('offlineDaysForUser').value = String(user.settings.offlineDays ?? 14);
  document.getElementById('offlineFailuresForUser').value = String(user.settings.offlineMinConsecutiveFailures ?? 3);
  document.getElementById('offlineActionForUser').value = String(user.settings.offlineAction ?? 'archive');
  document.getElementById('offlineArchiveCollectionIdForUser').value =
    user.settings.offlineArchiveCollectionId != null ? String(user.settings.offlineArchiveCollectionId) : '';
}

// This helper prefills governed-tagging preference controls from currently selected user settings.
function syncTaggingPreferencesFromSelectedUser() {
  const user = getSelectedUser('taggingPreferenceUserSelect');
  if (!user || !user.settings) {
    return;
  }

  document.getElementById('taggingStrictnessForUser').value = String(user.settings.taggingStrictness ?? 'very_strict');
  document.getElementById('fetchModeForUser').value = String(user.settings.fetchMode ?? 'optional');
  document.getElementById('queryTimeZoneForUser').value = String(user.settings.queryTimeZone ?? '');
}

// This helper converts empty timezone inputs into null so the backend can clear per-user overrides deterministically.
function readOptionalTimeZoneInput(inputId) {
  const raw = document.getElementById(inputId).value.trim();
  return raw.length > 0 ? raw : null;
}

// This helper converts empty text inputs into null for optional backend string fields.
function readOptionalTextInput(inputId) {
  const raw = document.getElementById(inputId).value.trim();
  return raw.length > 0 ? raw : null;
}

// This helper reads module toggles and returns the deterministic module list used by the new-links routine API.
function readRoutineModules() {
  const modules = [];
  if (document.getElementById('selfRoutineModuleTagging').checked) {
    modules.push('governed_tagging');
  }
  if (document.getElementById('selfRoutineModuleNormalize').checked) {
    modules.push('normalize_urls');
  }
  if (document.getElementById('selfRoutineModuleDedupe').checked) {
    modules.push('dedupe');
  }
  return modules;
}

// This helper applies routine settings payload values to dashboard controls after API reads.
function applyRoutineSettingsToForm(settings) {
  document.getElementById('selfRoutineEnabled').checked = Boolean(settings?.enabled);
  document.getElementById('selfRoutineInterval').value = String(settings?.intervalMinutes ?? 15);
  document.getElementById('selfRoutineBatchSize').value = String(settings?.batchSize ?? 200);
  const modules = new Set(Array.isArray(settings?.modules) ? settings.modules : []);
  document.getElementById('selfRoutineModuleTagging').checked = modules.has('governed_tagging');
  document.getElementById('selfRoutineModuleNormalize').checked = modules.has('normalize_urls');
  document.getElementById('selfRoutineModuleDedupe').checked = modules.has('dedupe');
}

// This helper applies 404-monitor settings payload values to dashboard controls after API reads.
function applyLink404MonitorSettingsToForm(settings) {
  document.getElementById('selfLink404MonitorEnabled').checked = Boolean(settings?.enabled);
  document.getElementById('selfLink404MonitorInterval').value = String(settings?.interval ?? 'monthly');
  document.getElementById('selfLink404MonitorToDeleteAfter').value = String(
    settings?.toDeleteAfter ?? 'after_1_year'
  );
}

// This helper escapes dynamic text content before composing HTML strings for table cells.
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// This helper formats one ISO timestamp into localized dashboard date/time output.
function formatAiLogTimestamp(iso) {
  if (!iso) {
    return '-';
  }
  const parsed = new Date(String(iso));
  if (Number.isNaN(parsed.getTime())) {
    return String(iso);
  }
  return parsed.toLocaleString('de-DE');
}

// This helper parses optional datetime-local input values into ISO timestamps for backend filtering.
function readOptionalDateTimeIso(inputId) {
  const raw = document.getElementById(inputId)?.value?.trim() || '';
  if (raw.length === 0) {
    return null;
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

// This helper parses optional positive integer inputs and returns null for empty values.
function readOptionalPositiveInt(inputId) {
  const raw = document.getElementById(inputId)?.value?.trim() || '';
  if (raw.length === 0) {
    return null;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

// This helper reads selected values from a multiple-select control in deterministic order.
function getSelectedValues(selectId) {
  const select = document.getElementById(selectId);
  if (!select) {
    return [];
  }
  return Array.from(select.selectedOptions || [])
    .map((option) => option.value)
    .filter((value) => String(value).trim().length > 0);
}

// This helper keeps selection state stable when select options are refreshed from facet payloads.
function replaceSelectOptions(selectId, options, includeAllOption = false) {
  const select = document.getElementById(selectId);
  if (!select) {
    return;
  }
  const previous = new Set(Array.from(select.selectedOptions || []).map((option) => option.value));
  select.innerHTML = '';
  if (includeAllOption) {
    const allOption = document.createElement('option');
    allOption.value = '';
    allOption.textContent = 'alle';
    select.appendChild(allOption);
  }
  options.forEach((option) => {
    const element = document.createElement('option');
    element.value = String(option.value);
    element.textContent = String(option.label);
    if (previous.has(element.value)) {
      element.selected = true;
    }
    select.appendChild(element);
  });
}

// This helper builds deterministic query parameters from current AI-log filter controls.
function buildAiLogQueryParams() {
  const params = new URLSearchParams();
  const query = document.getElementById('aiLogQuery')?.value?.trim() || '';
  const dateFrom = readOptionalDateTimeIso('aiLogDateFrom');
  const dateTo = readOptionalDateTimeIso('aiLogDateTo');
  const actionTypes = getSelectedValues('aiLogActionTypes');
  const toolNames = getSelectedValues('aiLogToolNames');
  const collectionFromId = document.getElementById('aiLogCollectionFrom')?.value || '';
  const collectionToId = document.getElementById('aiLogCollectionTo')?.value || '';
  const linkId = readOptionalPositiveInt('aiLogLinkId');
  const tagName = document.getElementById('aiLogTagName')?.value?.trim() || '';
  const trackingTrimmed = document.getElementById('aiLogTrackingTrimmed')?.value || '';
  const undoStatus = document.getElementById('aiLogUndoStatus')?.value || '';
  const sortBy = document.getElementById('aiLogSortBy')?.value || 'changedAt';
  const sortDir = document.getElementById('aiLogSortDir')?.value || 'desc';
  aiLogPageSize = Number(document.getElementById('aiLogPageSize')?.value || '25');

  if (query.length > 0) {
    params.set('q', query);
  }
  if (dateFrom) {
    params.set('dateFrom', dateFrom);
  }
  if (dateTo) {
    params.set('dateTo', dateTo);
  }
  actionTypes.forEach((actionType) => params.append('actionType', actionType));
  toolNames.forEach((toolName) => params.append('toolName', toolName));
  if (collectionFromId) {
    params.set('collectionFromId', collectionFromId);
  }
  if (collectionToId) {
    params.set('collectionToId', collectionToId);
  }
  if (linkId) {
    params.set('linkId', String(linkId));
  }
  if (tagName.length > 0) {
    params.set('tagName', tagName);
  }
  if (trackingTrimmed === 'true' || trackingTrimmed === 'false') {
    params.set('trackingTrimmed', trackingTrimmed);
  }
  if (undoStatus.length > 0) {
    params.set('undoStatus', undoStatus);
  }
  params.set('sortBy', sortBy);
  params.set('sortDir', sortDir);
  params.set('page', String(aiLogPage));
  params.set('pageSize', String(aiLogPageSize));
  return params;
}

// This helper updates paging labels and selection summary for the AI-log table.
function updateAiLogSelectionSummary() {
  const selectedRows = Array.from(document.querySelectorAll('#aiLogTableBody input[data-ai-log-select]:checked'));
  const selectedCount = selectedRows.length;
  const operationIds = new Set(
    selectedRows
      .map((row) => row.getAttribute('data-operation-id') || '')
      .filter((value) => value.length > 0)
  );
  const summaryElement = document.getElementById('aiLogSelectionSummary');
  if (summaryElement) {
    summaryElement.textContent = selectedCount > 0
      ? String(selectedCount) + ' Einträge ausgewählt (' + String(operationIds.size) + ' Operationen).'
      : 'Keine Einträge ausgewählt.';
  }
}

// This helper renders one paged AI-log table body from API response rows.
function renderAiLogRows(rows) {
  const body = document.getElementById('aiLogTableBody');
  if (!body) {
    return;
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    body.innerHTML = '<tr><td colspan="9">Keine passenden Einträge gefunden.</td></tr>';
    updateAiLogSelectionSummary();
    return;
  }

  body.innerHTML = rows
    .map((row) => {
      const tagsAdded = Array.isArray(row.tagsAdded) ? row.tagsAdded.join(', ') : '';
      const tagsRemoved = Array.isArray(row.tagsRemoved) ? row.tagsRemoved.join(', ') : '';
      const collectionFrom = row.collectionFromName || (row.collectionFromId ? '#' + String(row.collectionFromId) : '-');
      const collectionTo = row.collectionToName || (row.collectionToId ? '#' + String(row.collectionToId) : '-');
      const urlBefore = row.urlBefore || '-';
      const urlAfter = row.urlAfter || '-';
      const trackingNote = row.trackingTrimmed ? ' (tracking gekürzt)' : '';
      return (
        '<tr>' +
        '<td>' +
        '<input ' +
        'type="checkbox" ' +
        'data-ai-log-select="1" ' +
        'data-change-id="' + escapeHtml(row.id) + '" ' +
        'data-operation-id="' + escapeHtml(row.operationId || '') + '" ' +
        'onchange="updateAiLogSelectionSummary()" ' +
        'aria-label="Eintrag ' + escapeHtml(row.id) + ' auswählen" ' +
        '/>' +
        '</td>' +
        '<td>' + escapeHtml(formatAiLogTimestamp(row.changedAt)) + '</td>' +
        '<td class="mono">' + escapeHtml(row.actionType) + '</td>' +
        '<td>' +
        '<div>' + escapeHtml(row.linkTitle || '-') + '</div>' +
        '<div class="mono">#' + escapeHtml(row.linkId || '-') + '</div>' +
        '</td>' +
        '<td>' + escapeHtml(collectionFrom) + ' -> ' + escapeHtml(collectionTo) + '</td>' +
        '<td><strong>+</strong> ' + escapeHtml(tagsAdded || '-') + '<br /><strong>-</strong> ' + escapeHtml(tagsRemoved || '-') + '</td>' +
        '<td class="mono">' + escapeHtml(urlBefore) + '<br />-> ' + escapeHtml(urlAfter) + escapeHtml(trackingNote) + '</td>' +
        '<td class="mono">' + escapeHtml(row.toolName || '-') + '</td>' +
        '<td class="mono">' + escapeHtml(row.undoStatus || '-') + '</td>' +
        '</tr>'
      );
    })
    .join('');
  updateAiLogSelectionSummary();
}

// This helper loads AI-log facets so filter lists stay aligned with available records.
async function loadAiLogFacets() {
  const params = new URLSearchParams();
  const dateFrom = readOptionalDateTimeIso('aiLogDateFrom');
  const dateTo = readOptionalDateTimeIso('aiLogDateTo');
  if (dateFrom) {
    params.set('dateFrom', dateFrom);
  }
  if (dateTo) {
    params.set('dateTo', dateTo);
  }

  const query = params.toString();
  const path = query.length > 0 ? '/admin/ui/user/ai-log/facets?' + query : '/admin/ui/user/ai-log/facets';
  const { res, json } = await requestJson(path);
  if (!res.ok) {
    showToast('error', json?.error?.message || 'AI-Log Filterlisten konnten nicht geladen werden.');
    openDebugDrawer(json, { autoOpenOnError: true });
    return;
  }

  const facets = json?.facets || {};
  replaceSelectOptions(
    'aiLogActionTypes',
    (Array.isArray(facets.actionTypes) ? facets.actionTypes : []).map((entry) => ({ value: entry, label: entry })),
    false
  );
  replaceSelectOptions(
    'aiLogToolNames',
    (Array.isArray(facets.toolNames) ? facets.toolNames : []).map((entry) => ({ value: entry, label: entry })),
    false
  );
  replaceSelectOptions(
    'aiLogCollectionFrom',
    (Array.isArray(facets.collectionFrom) ? facets.collectionFrom : []).map((entry) => ({
      value: String(entry.id),
      label: String(entry.name) + ' (#' + String(entry.id) + ')'
    })),
    true
  );
  replaceSelectOptions(
    'aiLogCollectionTo',
    (Array.isArray(facets.collectionTo) ? facets.collectionTo : []).map((entry) => ({
      value: String(entry.id),
      label: String(entry.name) + ' (#' + String(entry.id) + ')'
    })),
    true
  );
}

// This helper loads per-user AI-log retention settings into dashboard controls.
async function loadOwnAiLogSettings() {
  const { res, json } = await requestJson('/admin/ui/user/ai-log/settings');
  if (!res.ok) {
    showToast('error', json?.error?.message || 'AI-Log Einstellungen konnten nicht geladen werden.');
    openDebugDrawer(json, { autoOpenOnError: true });
    return;
  }
  const retentionDays = Number(json?.settings?.retentionDays ?? 180);
  document.getElementById('selfAiActivityRetentionDays').value = String(retentionDays);
}

// This helper persists per-user AI-log retention settings.
async function setOwnAiLogSettings() {
  await api('/admin/ui/user/ai-log/settings', {
    method: 'POST',
    body: JSON.stringify({
      retentionDays: Number(document.getElementById('selfAiActivityRetentionDays').value)
    }),
    mutationAction: 'setOwnAiLogSettings',
    mutationSections: ['ai-log-retention'],
    successMessage: 'AI-Log Retention gespeichert.'
  });
  await loadAiLog();
}

// This helper loads one AI-log page using current filters and updates table + paging state.
async function loadAiLog() {
  const params = buildAiLogQueryParams();
  const path = '/admin/ui/user/ai-log?' + params.toString();
  const { res, json } = await requestJson(path);
  document.getElementById('aiLogResult').textContent = JSON.stringify(json, null, 2);
  openDebugDrawer(json, { autoOpenOnError: !res.ok });
  if (!res.ok) {
    const message = json?.error?.message || 'AI-Log konnte nicht geladen werden.';
    showToast('error', message);
    setOverviewStatus('Fehler: ' + message);
    renderAiLogRows([]);
    return;
  }

  aiLogEntries = Array.isArray(json?.items) ? json.items : [];
  aiLogTotal = Number(json?.paging?.total ?? aiLogEntries.length);
  renderAiLogRows(aiLogEntries);
  const totalPages = Math.max(1, Math.ceil(aiLogTotal / Math.max(1, aiLogPageSize)));
  const pagingInfo = document.getElementById('aiLogPagingInfo');
  if (pagingInfo) {
    pagingInfo.textContent = 'Seite ' + String(aiLogPage) + ' / ' + String(totalPages) + ' (' + String(aiLogTotal) + ' Einträge)';
  }
  const selectAll = document.getElementById('aiLogSelectAll');
  if (selectAll) {
    selectAll.checked = false;
  }
}

// This helper refreshes AI-log data while keeping current page and filter state.
async function refreshAiLog() {
  await loadAiLog();
}

// This helper applies current AI-log filters from the first page.
async function applyAiLogFilters() {
  aiLogPage = 1;
  await loadAiLogFacets();
  await loadAiLog();
}

// This helper resets AI-log filters to defaults and reloads facets plus first page.
async function resetAiLogFilters() {
  document.getElementById('aiLogQuery').value = '';
  document.getElementById('aiLogDateFrom').value = '';
  document.getElementById('aiLogDateTo').value = '';
  document.getElementById('aiLogLinkId').value = '';
  document.getElementById('aiLogTagName').value = '';
  document.getElementById('aiLogTrackingTrimmed').value = '';
  document.getElementById('aiLogUndoStatus').value = '';
  document.getElementById('aiLogSortBy').value = 'changedAt';
  document.getElementById('aiLogSortDir').value = 'desc';
  document.getElementById('aiLogPageSize').value = '25';
  Array.from(document.getElementById('aiLogActionTypes').options).forEach((option) => {
    option.selected = false;
  });
  Array.from(document.getElementById('aiLogToolNames').options).forEach((option) => {
    option.selected = false;
  });
  document.getElementById('aiLogCollectionFrom').value = '';
  document.getElementById('aiLogCollectionTo').value = '';
  aiLogPage = 1;
  await loadAiLogFacets();
  await loadAiLog();
}

// This helper toggles all visible AI-log row selections from one header checkbox.
function toggleAiLogSelectAll() {
  const selectAll = document.getElementById('aiLogSelectAll');
  const checked = Boolean(selectAll?.checked);
  document.querySelectorAll('#aiLogTableBody input[data-ai-log-select]').forEach((checkbox) => {
    checkbox.checked = checked;
  });
  updateAiLogSelectionSummary();
}

// This helper returns currently selected AI-log table rows with normalized change/operation ids.
function getSelectedAiLogRows() {
  return Array.from(document.querySelectorAll('#aiLogTableBody input[data-ai-log-select]:checked')).map((checkbox) => ({
    changeId: Number(checkbox.getAttribute('data-change-id')),
    operationId: checkbox.getAttribute('data-operation-id') || ''
  }));
}

// This helper submits undo requests for selected AI-log change rows.
async function undoSelectedAiLogChanges() {
  const selectedRows = getSelectedAiLogRows();
  const changeIds = [...new Set(selectedRows.map((row) => row.changeId).filter((id) => Number.isInteger(id) && id > 0))];
  if (changeIds.length === 0) {
    showToast('info', 'Bitte mindestens einen AI-Log Eintrag auswählen.', { durationMs: 2200 });
    return;
  }
  const proceed = window.confirm('Soll(en) ' + String(changeIds.length) + ' Änderung(en) rückgängig gemacht werden?');
  if (!proceed) {
    return;
  }

  await api('/admin/ui/user/ai-log/undo', {
    method: 'POST',
    body: JSON.stringify({
      mode: 'changes',
      changeIds
    }),
    mutationAction: 'undoAiLogChanges',
    mutationSections: ['ai-log-actions'],
    successMessage: 'Ausgewählte Änderungen wurden rückgängig gemacht.'
  });
  await loadAiLog();
}

// This helper submits undo requests for unique operation ids from selected AI-log rows.
async function undoSelectedAiLogOperations() {
  const selectedRows = getSelectedAiLogRows();
  const operationIds = [...new Set(selectedRows.map((row) => row.operationId).filter((id) => id.length > 0))];
  if (operationIds.length === 0) {
    showToast('info', 'Bitte mindestens einen Eintrag mit Operation auswählen.', { durationMs: 2200 });
    return;
  }
  const proceed = window.confirm('Soll(en) ' + String(operationIds.length) + ' Operation(en) rückgängig gemacht werden?');
  if (!proceed) {
    return;
  }

  await api('/admin/ui/user/ai-log/undo', {
    method: 'POST',
    body: JSON.stringify({
      mode: 'operations',
      operationIds
    }),
    mutationAction: 'undoAiLogOperations',
    mutationSections: ['ai-log-actions'],
    successMessage: 'Ausgewählte Operationen wurden rückgängig gemacht.'
  });
  await loadAiLog();
}

// This helper moves to the previous AI-log page when available.
async function prevAiLogPage() {
  if (aiLogPage <= 1) {
    showToast('info', 'Bereits auf der ersten Seite.', { durationMs: 1800 });
    return;
  }
  aiLogPage -= 1;
  await loadAiLog();
}

// This helper moves to the next AI-log page when available.
async function nextAiLogPage() {
  const totalPages = Math.max(1, Math.ceil(aiLogTotal / Math.max(1, aiLogPageSize)));
  if (aiLogPage >= totalPages) {
    showToast('info', 'Keine weitere Seite vorhanden.', { durationMs: 1800 });
    return;
  }
  aiLogPage += 1;
  await loadAiLog();
}

async function api(url, options = {}) {
  clearFieldErrors();
  const mutationAction = options.mutationAction || '';
  const mutationSections = Array.isArray(options.mutationSections) ? options.mutationSections : [];
  const successMessage = options.successMessage || 'Aktion erfolgreich gespeichert.';
  const requestOptions = {
    ...options,
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrfToken,
      ...(options.headers || {})
    }
  };
  delete requestOptions.mutationAction;
  delete requestOptions.mutationSections;
  delete requestOptions.successMessage;

  const { res, json } = await requestJson(url, requestOptions);
  openDebugDrawer(json, { autoOpenOnError: !res.ok });
  if (!res.ok) {
    applyFieldErrors(json?.error?.details ?? null);
    const message = json?.error?.message || 'API Fehler';
    showToast('error', message);
    setOverviewStatus('Fehler: ' + message);
    throw new Error(message);
  }

  showToast('success', successMessage, { durationMs: 3200 });
  const successStatus = 'Letzte erfolgreiche Aktion: ' + new Date().toLocaleTimeString('de-DE');
  setOverviewStatus(successStatus);
  if (mutationAction || mutationSections.length > 0) {
    clearDirtySectionsForMutation(mutationSections);
  }
  await invalidateAfterMutation(mutationAction);
  return json;
}

async function logout() {
  await api('/admin/auth/logout', { method: 'POST', body: '{}' });
  window.location.href = '/admin';
}

async function loadMe() {
  const { res, json } = await requestJson('/admin/auth/me');
  document.getElementById('meResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    document.getElementById('selfWriteMode').checked = Boolean(json?.me?.settings?.writeModeEnabled);
    document.getElementById('selfTaggingStrictness').value = String(json?.me?.settings?.taggingStrictness ?? 'very_strict');
    document.getElementById('selfFetchMode').value = String(json?.me?.settings?.fetchMode ?? 'optional');
    document.getElementById('selfQueryTimeZone').value = String(json?.me?.settings?.queryTimeZone ?? '');
    document.getElementById('ownTaggingPreferencesResult').textContent = JSON.stringify(
      {
        ok: true,
        preferences: {
          taggingStrictness: json?.me?.settings?.taggingStrictness ?? 'very_strict',
          fetchMode: json?.me?.settings?.fetchMode ?? 'optional',
          queryTimeZone: json?.me?.settings?.queryTimeZone ?? null
        }
      },
      null,
      2
    );
    const status = json?.me?.linkwardenTokenConfigured ? 'Status: konfiguriert' : 'Status: fehlt';
    document.getElementById('selfLinkwardenStatus').textContent = status;
    setKpiValue('kpiRole', json?.me?.role || currentRole);
    setKpiValue('kpiWriteMode', json?.me?.settings?.writeModeEnabled ? 'aktiv' : 'aus');
    setKpiValue('kpiToken', json?.me?.linkwardenTokenConfigured ? 'konfiguriert' : 'fehlt');
  }
}

async function setOwnWriteMode() {
  await api('/admin/ui/user/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('selfWriteMode').checked }),
    mutationAction: 'setOwnWriteMode',
    mutationSections: ['profil-write-mode']
  });
}

async function loadOwnTaggingPreferences() {
  const { res, json } = await requestJson('/admin/ui/user/tagging-preferences');
  document.getElementById('ownTaggingPreferencesResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    document.getElementById('selfTaggingStrictness').value = String(json?.preferences?.taggingStrictness ?? 'very_strict');
    document.getElementById('selfFetchMode').value = String(json?.preferences?.fetchMode ?? 'optional');
    document.getElementById('selfQueryTimeZone').value = String(json?.preferences?.queryTimeZone ?? '');
  }
}

async function setOwnTaggingPreferences() {
  await api('/admin/ui/user/tagging-preferences', {
    method: 'POST',
    body: JSON.stringify({
      taggingStrictness: document.getElementById('selfTaggingStrictness').value,
      fetchMode: document.getElementById('selfFetchMode').value,
      queryTimeZone: readOptionalTimeZoneInput('selfQueryTimeZone')
    }),
    mutationAction: 'setOwnTaggingPreferences',
    mutationSections: ['mein-tagging-preferences']
  });
}

async function loadOwnNewLinksRoutine() {
  const { res, json } = await requestJson('/admin/ui/user/new-links-routine');
  document.getElementById('ownNewLinksRoutineResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    applyRoutineSettingsToForm(json?.status?.settings ?? {});
    setKpiValue('kpiRoutine', json?.status?.settings?.enabled ? 'aktiv' : 'aus');
  }
}

async function loadOwnLink404Monitor() {
  const { res, json } = await requestJson('/admin/ui/user/link-404-monitor');
  document.getElementById('ownLink404MonitorResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    applyLink404MonitorSettingsToForm(json?.status?.settings ?? {});
  }
}

async function loadOwnChatControl() {
  const { res, json } = await requestJson('/admin/ui/user/chat-control');
  document.getElementById('ownChatControlResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    document.getElementById('selfArchiveCollectionName').value = String(
      json?.chatControl?.archiveCollectionName ?? 'Archive'
    );
    document.getElementById('selfArchiveCollectionParentId').value =
      json?.chatControl?.archiveCollectionParentId != null
        ? String(json.chatControl.archiveCollectionParentId)
        : '';
    document.getElementById('selfChatCaptureTagName').value = String(
      json?.chatControl?.chatCaptureTagName ?? 'AI Chat'
    );
    document.getElementById('selfChatCaptureTagAiChatEnabled').checked =
      json?.chatControl?.chatCaptureTagAiChatEnabled !== false;
    document.getElementById('selfChatCaptureTagAiNameEnabled').checked =
      json?.chatControl?.chatCaptureTagAiNameEnabled !== false;
    const retentionInput = document.getElementById('selfAiActivityRetentionDays');
    if (retentionInput) {
      retentionInput.value = String(json?.chatControl?.aiActivityRetentionDays ?? 180);
    }
  }
}

async function setOwnNewLinksRoutine() {
  clearFieldErrors();
  const modules = readRoutineModules();
  if (modules.length === 0) {
    // This guard surfaces routine-module validation as inline and toast feedback without a backend round-trip.
    showFieldError(document.getElementById('selfRoutineModuleTagging'), 'Mindestens ein Routine-Modul muss aktiviert sein.');
    showToast('error', 'Mindestens ein Routine-Modul muss aktiviert sein.');
    openDebugDrawer({
      ok: false,
      error: {
        message: 'Mindestens ein Routine-Modul muss aktiviert sein.'
      }
    }, { autoOpenOnError: true });
    setOverviewStatus('Fehler: Mindestens ein Routine-Modul muss aktiviert sein.');
    return;
  }

  await api('/admin/ui/user/new-links-routine', {
    method: 'POST',
    body: JSON.stringify({
      enabled: document.getElementById('selfRoutineEnabled').checked,
      intervalMinutes: Number(document.getElementById('selfRoutineInterval').value),
      batchSize: Number(document.getElementById('selfRoutineBatchSize').value),
      modules,
      requestBackfill: document.getElementById('selfRoutineRequestBackfill').checked,
      confirmBackfill: document.getElementById('selfRoutineConfirmBackfill').checked
    }),
    mutationAction: 'setOwnNewLinksRoutine',
    mutationSections: ['routine-settings']
  });

  document.getElementById('selfRoutineRequestBackfill').checked = false;
  document.getElementById('selfRoutineConfirmBackfill').checked = false;
}

async function setOwnLink404Monitor() {
  await api('/admin/ui/user/link-404-monitor', {
    method: 'POST',
    body: JSON.stringify({
      enabled: document.getElementById('selfLink404MonitorEnabled').checked,
      interval: document.getElementById('selfLink404MonitorInterval').value,
      toDeleteAfter: document.getElementById('selfLink404MonitorToDeleteAfter').value
    }),
    mutationAction: 'setOwnLink404Monitor',
    mutationSections: ['link-404-monitor-settings']
  });
}

async function setOwnChatControl() {
  const archiveCollectionName = document.getElementById('selfArchiveCollectionName').value.trim();
  const archiveCollectionParentIdRaw = document.getElementById('selfArchiveCollectionParentId').value.trim();
  const chatCaptureTagName = document.getElementById('selfChatCaptureTagName').value.trim();
  await api('/admin/ui/user/chat-control', {
    method: 'POST',
    body: JSON.stringify({
      archiveCollectionName,
      archiveCollectionParentId:
        archiveCollectionParentIdRaw.length > 0 ? Number(archiveCollectionParentIdRaw) : null,
      chatCaptureTagName,
      chatCaptureTagAiChatEnabled: document.getElementById('selfChatCaptureTagAiChatEnabled').checked,
      chatCaptureTagAiNameEnabled: document.getElementById('selfChatCaptureTagAiNameEnabled').checked
    }),
    mutationAction: 'setOwnChatControl',
    mutationSections: ['chat-control-settings']
  });
}

async function setOwnLinkwardenToken() {
  await api('/admin/ui/user/linkwarden-token', {
    method: 'POST',
    body: JSON.stringify({ token: document.getElementById('selfLinkwardenToken').value }),
    mutationAction: 'setOwnLinkwardenToken',
    mutationSections: ['linkwarden-token-set']
  });
  document.getElementById('selfLinkwardenToken').value = '';
}

async function loadOwnKeys() {
  const { json } = await requestJson('/admin/ui/user/api-keys');
  document.getElementById('ownKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueOwnKey() {
  await api('/admin/ui/user/api-keys', {
    method: 'POST',
    body: JSON.stringify({ label: document.getElementById('ownKeyLabel').value }),
    mutationAction: 'issueOwnKey',
    mutationSections: ['own-key-issue']
  });
}

async function revokeOwnKey() {
  const keyId = document.getElementById('ownRevokeKeyId').value;
  await api('/admin/ui/user/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}',
    mutationAction: 'revokeOwnKey',
    mutationSections: ['own-key-revoke']
  });
}

async function loadUsers() {
  const { res, json } = await requestJson('/admin/ui/admin/users');
  document.getElementById('usersResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    usersCache = Array.isArray(json.users) ? json.users : [];
    refreshAdminUserSelects();
  }
}

async function createUser() {
  await api('/admin/ui/admin/users', {
    method: 'POST',
    body: JSON.stringify({
      username: document.getElementById('newUsername').value,
      password: document.getElementById('newPassword').value,
      role: document.getElementById('newRole').value,
      writeModeEnabled: document.getElementById('newWriteMode').checked
    }),
    mutationAction: 'createUser',
    mutationSections: ['benutzer-anlegen']
  });
}

async function setUserActive() {
  const userId = document.getElementById('toggleUserSelect').value;
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/active', {
    method: 'POST',
    body: JSON.stringify({ active: document.getElementById('toggleUserActive').checked }),
    mutationAction: 'setUserActive',
    mutationSections: ['benutzer-status']
  });
}

async function setUserWriteMode() {
  const userId = document.getElementById('writeModeUserSelect').value;
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('writeModeForUser').checked }),
    mutationAction: 'setUserWriteMode',
    mutationSections: ['benutzer-status']
  });
}

async function setUserOfflinePolicy() {
  const userId = Number(document.getElementById('offlinePolicyUserSelect').value);
  const action = document.getElementById('offlineActionForUser').value;
  const archiveCollectionIdRaw = document.getElementById('offlineArchiveCollectionIdForUser').value.trim();
  const archiveCollectionId = archiveCollectionIdRaw.length > 0 ? Number(archiveCollectionIdRaw) : null;

  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/offline-policy', {
    method: 'POST',
    body: JSON.stringify({
      offlineDays: Number(document.getElementById('offlineDaysForUser').value),
      minConsecutiveFailures: Number(document.getElementById('offlineFailuresForUser').value),
      action,
      archiveCollectionId: action === 'archive' ? archiveCollectionId : null
    }),
    mutationAction: 'setUserOfflinePolicy',
    mutationSections: ['benutzer-offline-policy']
  });
}

async function loadTaggingPolicy() {
  const { res, json } = await requestJson('/admin/ui/admin/tagging-policy');
  document.getElementById('taggingPolicyResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    const policy = json?.policy ?? {};
    document.getElementById('policyFetchMode').value = String(policy.fetchMode ?? 'optional');
    document.getElementById('policyAllowUserFetchOverride').checked = Boolean(policy.allowUserFetchModeOverride);
    document.getElementById('policyInferenceProvider').value = String(policy.inferenceProvider ?? 'builtin');
    document.getElementById('policyInferenceModel').value = String(policy.inferenceModel ?? '');
    document.getElementById('policyBlockedTags').value = Array.isArray(policy.blockedTagNames)
      ? policy.blockedTagNames.join(', ')
      : '';
    document.getElementById('policySimilarityThreshold').value = String(policy.similarityThreshold ?? 0.88);
    document.getElementById('policyFetchTimeoutMs').value = String(policy.fetchTimeoutMs ?? 3000);
    document.getElementById('policyFetchMaxBytes').value = String(policy.fetchMaxBytes ?? 131072);
  }
}

async function setTaggingPolicy() {
  const blockedRaw = document.getElementById('policyBlockedTags').value.trim();
  const blockedTagNames = blockedRaw.length === 0
    ? []
    : blockedRaw.split(',').map((item) => item.trim()).filter((item) => item.length > 0);

  await api('/admin/ui/admin/tagging-policy', {
    method: 'POST',
    body: JSON.stringify({
      fetchMode: document.getElementById('policyFetchMode').value,
      allowUserFetchModeOverride: document.getElementById('policyAllowUserFetchOverride').checked,
      inferenceProvider: document.getElementById('policyInferenceProvider').value,
      inferenceModel: readOptionalTextInput('policyInferenceModel'),
      blockedTagNames,
      similarityThreshold: Number(document.getElementById('policySimilarityThreshold').value),
      fetchTimeoutMs: Number(document.getElementById('policyFetchTimeoutMs').value),
      fetchMaxBytes: Number(document.getElementById('policyFetchMaxBytes').value)
    }),
    mutationAction: 'setTaggingPolicy',
    mutationSections: ['tagging-global', 'tagging-provider']
  });
}

async function setUserTaggingPreferences() {
  const userId = Number(document.getElementById('taggingPreferenceUserSelect').value);
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/tagging-preferences', {
    method: 'POST',
    body: JSON.stringify({
      taggingStrictness: document.getElementById('taggingStrictnessForUser').value,
      fetchMode: document.getElementById('fetchModeForUser').value,
      queryTimeZone: readOptionalTimeZoneInput('queryTimeZoneForUser')
    }),
    mutationAction: 'setUserTaggingPreferences',
    mutationSections: ['tagging-user-preferences']
  });
}

async function loadAdminKeys() {
  const { json } = await requestJson('/admin/ui/admin/api-keys');
  document.getElementById('adminKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueAdminKey() {
  await api('/admin/ui/admin/api-keys', {
    method: 'POST',
    body: JSON.stringify({
      userId: Number(document.getElementById('apiKeyUserSelect').value),
      label: document.getElementById('apiKeyLabel').value
    }),
    mutationAction: 'issueAdminKey',
    mutationSections: ['admin-key-issue']
  });
}

async function revokeAdminKey() {
  const keyId = document.getElementById('revokeKeyId').value;
  await api('/admin/ui/admin/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}',
    mutationAction: 'revokeAdminKey',
    mutationSections: ['admin-key-revoke']
  });
}

async function loadLinkwardenConfig() {
  const { json } = await requestJson('/admin/ui/admin/linkwarden');
  document.getElementById('linkwardenConfigResult').textContent = JSON.stringify(json, null, 2);
}

// This helper loads current OAuth session-lifetime settings for admin runtime policy controls.
async function loadOAuthSessionSettings() {
  const { res, json } = await requestJson('/admin/ui/admin/oauth-session');
  if (!res.ok) {
    const message = json?.error?.message || 'OAuth Session-Einstellungen konnten nicht geladen werden.';
    showToast('error', message);
    return;
  }

  const value = String(json?.settings?.sessionLifetime ?? 'permanent');
  document.getElementById('oauthSessionLifetime').value = value;
}

async function updateLinkwardenConfig() {
  const payload = {};
  const baseUrl = document.getElementById('lwBaseUrl').value.trim();

  if (baseUrl) {
    payload.baseUrl = baseUrl;
  }

  await api('/admin/ui/admin/linkwarden', {
    method: 'POST',
    body: JSON.stringify(payload),
    mutationAction: 'updateLinkwardenConfig',
    mutationSections: ['linkwarden-ziel-update']
  });
}

// This helper stores global OAuth session lifetime and immediately reapplies it to active refresh tokens.
async function setOAuthSessionLifetime() {
  const rawValue = document.getElementById('oauthSessionLifetime').value;
  const sessionLifetime = rawValue === 'permanent' ? 'permanent' : Number(rawValue);
  const json = await api('/admin/ui/admin/oauth-session', {
    method: 'POST',
    body: JSON.stringify({ sessionLifetime }),
    mutationAction: 'setOAuthSessionLifetime',
    mutationSections: ['oauth-session-lifetime']
  });
  const affectedCount = Number(json?.affectedCount ?? 0);
  document.getElementById('oauthSessionLifetimeStatus').textContent =
    'Aktive Sessions aktualisiert: ' + affectedCount;
}

async function setUserLinkwardenToken() {
  const userId = Number(document.getElementById('linkwardenTokenUserSelect').value);
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/linkwarden-token', {
    method: 'POST',
    body: JSON.stringify({ token: document.getElementById('linkwardenTokenValue').value }),
    mutationAction: 'setUserLinkwardenToken',
    mutationSections: ['user-linkwarden-token-set']
  });
  document.getElementById('linkwardenTokenValue').value = '';
}

${renderThemeInitScript()}
initializeSectionRegistry();
initDebugDrawerState();
bindTabNavigation();
initDirtyTracking();
if (isAdmin) {
  const offlinePolicySelect = document.getElementById('offlinePolicyUserSelect');
  if (offlinePolicySelect) {
    offlinePolicySelect.addEventListener('change', syncOfflinePolicyFromSelectedUser);
  }
  const taggingPreferenceSelect = document.getElementById('taggingPreferenceUserSelect');
  if (taggingPreferenceSelect) {
    taggingPreferenceSelect.addEventListener('change', syncTaggingPreferencesFromSelectedUser);
  }
}
initTabState();
</script>
  </div>
</body>
</html>`;
}

// This helper adapts one browser session principal to the internal authenticated-principal shape used by MCP services.
function toInternalPrincipal(principal: SessionPrincipal): AuthenticatedPrincipal {
  return {
    userId: principal.userId,
    username: principal.username,
    role: principal.role,
    apiKeyId: `session-${principal.sessionId}`,
    toolScopes: ['*'],
    collectionScopes: []
  };
}

// This helper throttles per-user AI-log pruning on read paths to avoid repeated expensive cleanup queries.
function pruneAiLogIfDue(db: SqliteStore, userId: number, retentionDays: 30 | 90 | 180 | 365): number {
  const now = Date.now();
  const lastRunAt = aiLogPruneLastRunByUser.get(userId) ?? 0;
  if (now - lastRunAt < AI_LOG_PRUNE_THROTTLE_MS) {
    return 0;
  }

  aiLogPruneLastRunByUser.set(userId, now);
  return db.pruneAiChangeLog(userId, retentionDays);
}

// This helper returns view data for one authenticated user including per-user settings.
function buildMePayload(db: SqliteStore, principal: SessionPrincipal): Record<string, unknown> {
  const user = db.getUserById(principal.userId);
  const settings = db.getUserSettings(principal.userId);
  const linkwardenTokenConfigured = db.hasUserLinkwardenToken(principal.userId);

  return {
    id: user.id,
    username: user.username,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    linkwardenTokenConfigured,
    settings
  };
}

// This function registers admin UI, auth/session routes, and admin/user JSON APIs.
export function registerUiRoutes(fastify: FastifyInstance, configStore: ConfigStore, db: SqliteStore): void {
  fastify.get('/admin', async (request, reply) => {
    const { csrfToken } = ensureCsrfCookie(request, reply);

    if (!configStore.isInitialized()) {
      logUiInfo(request, 'ui_render_first_run');
      reply.type('text/html').send(renderFirstRunPage(csrfToken));
      return;
    }

    if (!configStore.isUnlocked()) {
      logUiInfo(request, 'ui_render_unlock');
      reply.type('text/html').send(renderUnlockPage(csrfToken));
      return;
    }

    const principal = authenticateSession(request, db);
    if (!principal) {
      const query = (request.query ?? {}) as Record<string, unknown>;
      const nextPath = sanitizeNextPath(query.next);
      logUiInfo(request, 'ui_render_login');
      reply.type('text/html').send(renderLoginPage(csrfToken, nextPath));
      return;
    }

    logUiInfo(request, 'ui_render_dashboard', {
      userId: principal.userId,
      username: principal.username,
      role: principal.role
    });
    reply.type('text/html').send(renderDashboardPage(principal, csrfToken));
  });

  fastify.get('/admin/', async (_request, reply) => {
    reply.redirect('/admin');
  });

  fastify.get('/admin/setup', async (_request, reply) => {
    reply.redirect('/admin');
  });

  fastify.post('/admin/auth/login', async (request, reply) => {
    logUiInfo(request, 'ui_login_attempt');

    if (!configStore.isInitialized()) {
      logUiWarn(request, 'ui_login_rejected_not_initialized');
      throw new AppError(503, 'not_initialized', 'Server setup has not been completed.');
    }

    requireCsrf(request);

    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_login_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid login payload.', parsed.error.flatten());
    }

    const rateKey = buildLoginLimitKey(request, parsed.data.username);
    logUiDebug(request, 'ui_login_rate_limit_check', {
      username: parsed.data.username,
      rateKey
    });
    assertLoginAllowed(rateKey);

    const user = db.getUserForLogin(parsed.data.username);

    if (!user || user.is_active !== 1) {
      registerLoginFailure(rateKey);
      logUiWarn(request, 'ui_login_failed_invalid_credentials', {
        username: parsed.data.username
      });
      throw new AppError(401, 'invalid_credentials', 'Invalid username or password.');
    }

    const isPasswordValid = verifyPassword(parsed.data.password, {
      salt: user.password_salt,
      hash: user.password_hash,
      kdf: 'scrypt',
      params: 'N=16384,r=8,p=1,len=64'
    });

    if (!isPasswordValid) {
      registerLoginFailure(rateKey);
      logUiWarn(request, 'ui_login_failed_wrong_password', {
        username: parsed.data.username,
        userId: user.id
      });
      throw new AppError(401, 'invalid_credentials', 'Invalid username or password.');
    }

    clearLoginFailures(rateKey);

    const sessionId = randomUUID();
    const sessionToken = generateSessionToken();
    const csrfToken = generateCsrfToken();
    const ttlSeconds = getSessionTtlSeconds();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const secure = shouldUseSecureCookies(request);
    const userAgentHeader = request.headers['user-agent'];
    const userAgent = Array.isArray(userAgentHeader) ? userAgentHeader[0] : userAgentHeader;

    db.createSession({
      sessionId,
      userId: user.id,
      tokenHash: hashApiToken(sessionToken),
      expiresAt,
      ip: request.ip,
      userAgent
    });

    reply.header('set-cookie', [
      serializeCookie('mcp_session', sessionToken, { secure, maxAgeSeconds: ttlSeconds }),
      serializeCookie('mcp_csrf', csrfToken, { secure, maxAgeSeconds: ttlSeconds })
    ]);

    logUiInfo(request, 'ui_login_success', {
      userId: user.id,
      username: user.username,
      role: user.role,
      sessionId,
      ttlSeconds
    });

    reply.send({
      ok: true,
      me: buildMePayload(db, {
        sessionId,
        userId: user.id,
        username: user.username,
        role: user.role as UserRole
      })
    });
  });

  fastify.post('/admin/auth/logout', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    logUiInfo(request, 'ui_logout_requested', {
      userId: principal.userId,
      username: principal.username,
      role: principal.role,
      sessionId: principal.sessionId
    });
    db.invalidateSession(principal.sessionId);

    const secure = shouldUseSecureCookies(request);

    reply.header('set-cookie', [
      serializeExpiredCookie('mcp_session', secure),
      serializeExpiredCookie('mcp_csrf', secure)
    ]);

    logUiInfo(request, 'ui_logout_success', {
      userId: principal.userId,
      sessionId: principal.sessionId
    });

    reply.send({ ok: true });
  });

  fastify.get('/admin/auth/me', async (request, reply) => {
    const principal = requireSession(request, db);
    logUiDebug(request, 'ui_auth_me', {
      userId: principal.userId,
      username: principal.username,
      role: principal.role
    });

    reply.send({
      ok: true,
      me: buildMePayload(db, principal)
    });
  });

  fastify.get('/admin/ui/admin/users', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const users = db.listUsers();
    const usersWithSettings = users.map((user) => ({
      ...user,
      settings: db.getUserSettings(user.id),
      linkwardenTokenConfigured: db.hasUserLinkwardenToken(user.id)
    }));

    logUiInfo(request, 'ui_admin_list_users', {
      actorUserId: principal.userId,
      count: usersWithSettings.length
    });

    reply.send({
      ok: true,
      users: usersWithSettings
    });
  });

  fastify.post('/admin/ui/admin/users', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = createUserSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_create_user_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid create-user payload.', parsed.error.flatten());
    }

    const passwordRecord = hashPassword(parsed.data.password);

    const userId = db.createUser({
      username: parsed.data.username,
      role: parsed.data.role,
      passwordSalt: passwordRecord.salt,
      passwordHash: passwordRecord.hash,
      passwordKdf: passwordRecord.kdf,
      passwordIterations: 16384,
      writeModeEnabled: parsed.data.writeModeEnabled
    });

    const key = parsed.data.issueApiKey ? issueApiKey(db, userId, parsed.data.apiKeyLabel) : undefined;

    logUiInfo(request, 'ui_admin_create_user_success', {
      actorUserId: principal.userId,
      createdUserId: userId,
      username: parsed.data.username,
      role: parsed.data.role,
      writeModeEnabled: parsed.data.writeModeEnabled,
      apiKeyIssued: Boolean(key)
    });

    reply.code(201).send({
      ok: true,
      userId,
      username: parsed.data.username,
      role: parsed.data.role,
      apiKeyId: key?.keyId,
      apiKey: key?.token
    });
  });

  fastify.post('/admin/ui/admin/users/:userId/active', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    const body = toggleUserActiveSchema.safeParse(request.body);

    if (!params.success || !body.success) {
      logUiWarn(request, 'ui_admin_set_user_active_validation_failed', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid user active payload.', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
    }

    db.setUserActive(params.data.userId, body.data.active);

    logUiInfo(request, 'ui_admin_set_user_active_success', {
      actorUserId: principal.userId,
      targetUserId: params.data.userId,
      active: body.data.active
    });

    reply.send({
      ok: true,
      userId: params.data.userId,
      active: body.data.active
    });
  });

  fastify.post('/admin/ui/admin/users/:userId/write-mode', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    const body = toggleWriteModeSchema.safeParse(request.body);

    if (!params.success || !body.success) {
      logUiWarn(request, 'ui_admin_set_user_write_mode_validation_failed', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid write-mode payload.', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
    }

    db.setUserWriteMode(params.data.userId, body.data.writeModeEnabled);

    logUiInfo(request, 'ui_admin_set_user_write_mode_success', {
      actorUserId: principal.userId,
      targetUserId: params.data.userId,
      writeModeEnabled: body.data.writeModeEnabled
    });

    reply.send({
      ok: true,
      userId: params.data.userId,
      writeModeEnabled: body.data.writeModeEnabled
    });
  });

  fastify.post('/admin/ui/admin/users/:userId/offline-policy', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    const body = setOfflinePolicySchema.safeParse(request.body);

    if (!params.success || !body.success) {
      logUiWarn(request, 'ui_admin_set_user_offline_policy_validation_failed', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid offline policy payload.', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
    }

    db.setUserOfflinePolicy(params.data.userId, {
      offlineDays: body.data.offlineDays,
      offlineMinConsecutiveFailures: body.data.minConsecutiveFailures,
      offlineAction: body.data.action,
      offlineArchiveCollectionId: body.data.archiveCollectionId ?? null
    });

    logUiInfo(request, 'ui_admin_set_user_offline_policy_success', {
      actorUserId: principal.userId,
      targetUserId: params.data.userId,
      offlineDays: body.data.offlineDays,
      minConsecutiveFailures: body.data.minConsecutiveFailures,
      action: body.data.action,
      archiveCollectionId: body.data.archiveCollectionId ?? null
    });

    reply.send({
      ok: true,
      userId: params.data.userId,
      settings: db.getUserSettings(params.data.userId)
    });
  });

  fastify.get('/admin/ui/admin/users/:userId/tagging-preferences', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    if (!params.success) {
      logUiWarn(request, 'ui_admin_get_user_tagging_preferences_validation_failed', {
        params: params.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid user identifier.', params.error.flatten());
    }

    const policy = db.getGlobalTaggingPolicy();
    const settings = db.getUserSettings(params.data.userId);
    const effectiveFetchMode = policy.allowUserFetchModeOverride ? settings.fetchMode : policy.fetchMode;
    const effectiveInferenceProvider = policy.inferenceProvider;
    const effectiveInferenceModel = policy.inferenceModel;

    reply.send({
      ok: true,
      userId: params.data.userId,
      preferences: {
        taggingStrictness: settings.taggingStrictness,
        fetchMode: settings.fetchMode,
        queryTimeZone: settings.queryTimeZone,
        effectiveFetchMode,
        effectiveInferenceProvider,
        effectiveInferenceModel
      },
      policy: {
        allowUserFetchModeOverride: policy.allowUserFetchModeOverride,
        inferenceProvider: policy.inferenceProvider,
        inferenceModel: policy.inferenceModel
      }
    });
  });

  fastify.post('/admin/ui/admin/users/:userId/tagging-preferences', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    const body = setTaggingPreferencesSchema.safeParse(request.body);
    if (!params.success || !body.success) {
      logUiWarn(request, 'ui_admin_set_user_tagging_preferences_validation_failed', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid tagging preferences payload.', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
    }

    db.setUserTaggingPreferences(params.data.userId, {
      taggingStrictness: body.data.taggingStrictness,
      fetchMode: body.data.fetchMode,
      queryTimeZone: body.data.queryTimeZone
    });

    const policy = db.getGlobalTaggingPolicy();
    const settings = db.getUserSettings(params.data.userId);
    const effectiveFetchMode = policy.allowUserFetchModeOverride ? settings.fetchMode : policy.fetchMode;
    const effectiveInferenceProvider = policy.inferenceProvider;
    const effectiveInferenceModel = policy.inferenceModel;

    reply.send({
      ok: true,
      userId: params.data.userId,
      preferences: {
        taggingStrictness: settings.taggingStrictness,
        fetchMode: settings.fetchMode,
        queryTimeZone: settings.queryTimeZone,
        effectiveFetchMode,
        effectiveInferenceProvider,
        effectiveInferenceModel
      }
    });
  });

  fastify.post('/admin/ui/admin/users/:userId/linkwarden-token', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const params = userIdParamSchema.safeParse(request.params);
    const body = setLinkwardenTokenSchema.safeParse(request.body);

    if (!params.success || !body.success) {
      logUiWarn(request, 'ui_admin_set_linkwarden_token_validation_failed', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid Linkwarden token payload.', {
        params: params.success ? undefined : params.error.flatten(),
        body: body.success ? undefined : body.error.flatten()
      });
    }

    const encryptedToken = configStore.encryptSecret(body.data.token);
    db.setUserLinkwardenToken(params.data.userId, encryptedToken);

    logUiInfo(request, 'ui_admin_set_linkwarden_token_success', {
      actorUserId: principal.userId,
      targetUserId: params.data.userId
    });

    reply.send({
      ok: true,
      userId: params.data.userId,
      linkwardenTokenConfigured: true
    });
  });

  fastify.get('/admin/ui/admin/api-keys', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const apiKeys = db.listApiKeys();
    logUiInfo(request, 'ui_admin_list_api_keys', {
      actorUserId: principal.userId,
      count: apiKeys.length
    });

    reply.send({
      ok: true,
      apiKeys
    });
  });

  fastify.post('/admin/ui/admin/api-keys', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = createApiKeySchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_create_api_key_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid create-api-key payload.', parsed.error.flatten());
    }

    const key = issueApiKey(db, parsed.data.userId, parsed.data.label);

    logUiInfo(request, 'ui_admin_create_api_key_success', {
      actorUserId: principal.userId,
      targetUserId: parsed.data.userId,
      keyId: key.keyId,
      label: parsed.data.label
    });

    reply.code(201).send({
      ok: true,
      userId: parsed.data.userId,
      keyId: key.keyId,
      apiKey: key.token
    });
  });

  fastify.post('/admin/ui/admin/api-keys/:keyId/revoke', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = keyIdParamSchema.safeParse(request.params);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_revoke_api_key_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid revoke key payload.', parsed.error.flatten());
    }

    db.revokeApiKey(parsed.data.keyId);

    logUiInfo(request, 'ui_admin_revoke_api_key_success', {
      actorUserId: principal.userId,
      keyId: parsed.data.keyId
    });

    reply.send({
      ok: true,
      keyId: parsed.data.keyId,
      revoked: true
    });
  });

  fastify.get('/admin/ui/admin/linkwarden', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const target = db.getLinkwardenTarget();

    logUiInfo(request, 'ui_admin_get_linkwarden_config', {
      actorUserId: principal.userId,
      targetConfigured: Boolean(target)
    });

    reply.send({
      ok: true,
      target
    });
  });

  fastify.post('/admin/ui/admin/linkwarden', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = updateLinkwardenSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_update_linkwarden_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid Linkwarden update payload.', parsed.error.flatten());
    }

    if (!parsed.data.baseUrl) {
      logUiWarn(request, 'ui_admin_update_linkwarden_missing_target');
      throw new AppError(400, 'linkwarden_target_missing', 'Linkwarden base URL is not configured.');
    }

    db.setLinkwardenTarget(parsed.data.baseUrl);

    logUiInfo(request, 'ui_admin_update_linkwarden_success', {
      actorUserId: principal.userId,
      baseUrlUpdated: true
    });

    reply.send({
      ok: true,
      target: db.getLinkwardenTarget()
    });
  });

  fastify.get('/admin/ui/admin/oauth-session', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const runtime = configStore.getRuntimeConfig();

    logUiInfo(request, 'ui_admin_get_oauth_session_settings', {
      actorUserId: principal.userId,
      sessionLifetime: runtime.oauthSessionLifetime
    });

    reply.send({
      ok: true,
      settings: {
        sessionLifetime: runtime.oauthSessionLifetime
      }
    });
  });

  fastify.post('/admin/ui/admin/oauth-session', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = setOauthSessionSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_set_oauth_session_settings_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid OAuth session settings payload.', parsed.error.flatten());
    }

    configStore.updateConfig((current) => ({
      ...current,
      oauthSessionLifetime: parsed.data.sessionLifetime
    }));

    const affectedCount = db.rebaseActiveOAuthRefreshExpiries(parsed.data.sessionLifetime, new Date().toISOString());
    const runtime = configStore.getRuntimeConfig();

    logUiInfo(request, 'ui_admin_set_oauth_session_settings_success', {
      actorUserId: principal.userId,
      sessionLifetime: runtime.oauthSessionLifetime,
      affectedCount
    });

    reply.send({
      ok: true,
      settings: {
        sessionLifetime: runtime.oauthSessionLifetime
      },
      affectedCount
    });
  });

  fastify.get('/admin/ui/admin/tagging-policy', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    reply.send({
      ok: true,
      policy: db.getGlobalTaggingPolicy()
    });
  });

  fastify.post('/admin/ui/admin/tagging-policy', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = setTaggingPolicySchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_set_tagging_policy_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid tagging-policy payload.', parsed.error.flatten());
    }

    const current = db.getGlobalTaggingPolicy();
    const next = {
      ...current,
      ...parsed.data,
      inferenceModel:
        parsed.data.inferenceModel === undefined
          ? current.inferenceModel
          : parsed.data.inferenceModel === null
            ? null
            : parsed.data.inferenceModel.trim() || null,
      blockedTagNames:
        parsed.data.blockedTagNames?.map((name) => name.trim().toLocaleLowerCase()).filter((name) => name.length > 0) ??
        current.blockedTagNames
    };
    // This guard requires an explicit model id when Hugging Face router mode is enabled.
    if (next.inferenceProvider === 'huggingface' && !next.inferenceModel) {
      throw new AppError(
        400,
        'validation_error',
        'inferenceModel is required when inferenceProvider=huggingface.'
      );
    }
    db.setGlobalTaggingPolicy(next);

    let resetCount = 0;
    if (!next.allowUserFetchModeOverride) {
      resetCount = db.resetAllUserFetchModes(next.fetchMode);
    }

    logUiInfo(request, 'ui_admin_set_tagging_policy_success', {
      actorUserId: principal.userId,
      allowUserFetchModeOverride: next.allowUserFetchModeOverride,
      fetchMode: next.fetchMode,
      inferenceProvider: next.inferenceProvider,
      inferenceModel: next.inferenceModel,
      resetCount
    });

    reply.send({
      ok: true,
      policy: next,
      resetCount
    });
  });

  fastify.get('/admin/ui/user/me', async (request, reply) => {
    const principal = requireSession(request, db);
    logUiDebug(request, 'ui_user_me', {
      userId: principal.userId,
      username: principal.username
    });

    reply.send({
      ok: true,
      me: buildMePayload(db, principal)
    });
  });

  fastify.post('/admin/ui/user/write-mode', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = toggleWriteModeSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_write_mode_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid write-mode payload.', parsed.error.flatten());
    }

    db.setUserWriteMode(principal.userId, parsed.data.writeModeEnabled);

    logUiInfo(request, 'ui_user_set_write_mode_success', {
      userId: principal.userId,
      writeModeEnabled: parsed.data.writeModeEnabled
    });

    reply.send({
      ok: true,
      userId: principal.userId,
      writeModeEnabled: parsed.data.writeModeEnabled
    });
  });

  fastify.get('/admin/ui/user/tagging-preferences', async (request, reply) => {
    const principal = requireSession(request, db);
    const policy = db.getGlobalTaggingPolicy();
    const settings = db.getUserSettings(principal.userId);
    const effectiveFetchMode = policy.allowUserFetchModeOverride ? settings.fetchMode : policy.fetchMode;
    const effectiveInferenceProvider = policy.inferenceProvider;
    const effectiveInferenceModel = policy.inferenceModel;

    reply.send({
      ok: true,
      preferences: {
        taggingStrictness: settings.taggingStrictness,
        fetchMode: settings.fetchMode,
        queryTimeZone: settings.queryTimeZone,
        effectiveFetchMode,
        effectiveInferenceProvider,
        effectiveInferenceModel
      },
      policy: {
        allowUserFetchModeOverride: policy.allowUserFetchModeOverride,
        inferenceProvider: policy.inferenceProvider,
        inferenceModel: policy.inferenceModel
      }
    });
  });

  fastify.post('/admin/ui/user/tagging-preferences', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = setTaggingPreferencesSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_tagging_preferences_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid tagging-preferences payload.', parsed.error.flatten());
    }

    const policy = db.getGlobalTaggingPolicy();
    if (!policy.allowUserFetchModeOverride && parsed.data.fetchMode !== undefined) {
      throw new AppError(
        403,
        'forbidden',
        'User fetch-mode override is disabled by admin policy.'
      );
    }

    db.setUserTaggingPreferences(principal.userId, {
      taggingStrictness: parsed.data.taggingStrictness,
      fetchMode: parsed.data.fetchMode,
      queryTimeZone: parsed.data.queryTimeZone
    });

    const settings = db.getUserSettings(principal.userId);
    const effectiveFetchMode = policy.allowUserFetchModeOverride ? settings.fetchMode : policy.fetchMode;
    const effectiveInferenceProvider = policy.inferenceProvider;
    const effectiveInferenceModel = policy.inferenceModel;

    reply.send({
      ok: true,
      preferences: {
        taggingStrictness: settings.taggingStrictness,
        fetchMode: settings.fetchMode,
        queryTimeZone: settings.queryTimeZone,
        effectiveFetchMode,
        effectiveInferenceProvider,
        effectiveInferenceModel
      }
    });
  });

  fastify.get('/admin/ui/user/new-links-routine', async (request, reply) => {
    const principal = requireSession(request, db);
    const status = await getNewLinksRoutineStatus(
      {
        actor: `${principal.username}#${principal.sessionId}`,
        principal: toInternalPrincipal(principal),
        configStore,
        db,
        logger: request.log
      },
      {
        includeBacklogEstimate: true
      }
    );

    logUiInfo(request, 'ui_user_get_new_links_routine', {
      userId: principal.userId,
      enabled: status.settings.enabled,
      due: status.due
    });

    reply.send({
      ok: true,
      status
    });
  });

  fastify.post('/admin/ui/user/new-links-routine', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = setNewLinksRoutineSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_new_links_routine_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid new-links routine payload.', parsed.error.flatten());
    }

    const settings = db.setUserNewLinksRoutineSettings(principal.userId, {
      enabled: parsed.data.enabled,
      intervalMinutes: parsed.data.intervalMinutes,
      modules: parsed.data.modules,
      batchSize: parsed.data.batchSize,
      requestBackfill: parsed.data.requestBackfill,
      confirmBackfill: parsed.data.confirmBackfill
    });
    const status = await getNewLinksRoutineStatus(
      {
        actor: `${principal.username}#${principal.sessionId}`,
        principal: toInternalPrincipal(principal),
        configStore,
        db,
        logger: request.log
      },
      {
        includeBacklogEstimate: true
      }
    );

    logUiInfo(request, 'ui_user_set_new_links_routine_success', {
      userId: principal.userId,
      enabled: settings.enabled,
      intervalMinutes: settings.intervalMinutes,
      modules: settings.modules
    });

    reply.send({
      ok: true,
      settings,
      status
    });
  });

  fastify.get('/admin/ui/user/link-404-monitor', async (request, reply) => {
    const principal = requireSession(request, db);
    const status = await getLink404MonitorStatus(
      {
        actor: `${principal.username}#${principal.sessionId}`,
        principal: toInternalPrincipal(principal),
        configStore,
        db,
        logger: request.log
      },
      {}
    );

    logUiInfo(request, 'ui_user_get_link_404_monitor', {
      userId: principal.userId,
      enabled: status.settings.enabled,
      due: status.due,
      interval: status.settings.interval,
      toDeleteAfter: status.settings.toDeleteAfter
    });

    reply.send({
      ok: true,
      status
    });
  });

  fastify.post('/admin/ui/user/link-404-monitor', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = setLink404MonitorSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_link_404_monitor_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid 404-monitor payload.', parsed.error.flatten());
    }

    const settings = db.setUserLink404MonitorSettings(principal.userId, {
      enabled: parsed.data.enabled,
      interval: parsed.data.interval,
      toDeleteAfter: parsed.data.toDeleteAfter
    });
    const status = await getLink404MonitorStatus(
      {
        actor: `${principal.username}#${principal.sessionId}`,
        principal: toInternalPrincipal(principal),
        configStore,
        db,
        logger: request.log
      },
      {}
    );

    logUiInfo(request, 'ui_user_set_link_404_monitor_success', {
      userId: principal.userId,
      enabled: settings.enabled,
      interval: settings.interval,
      toDeleteAfter: settings.toDeleteAfter
    });

    reply.send({
      ok: true,
      settings,
      status
    });
  });

  fastify.get('/admin/ui/user/chat-control', async (request, reply) => {
    const principal = requireSession(request, db);
    const chatControl = db.getUserChatControlSettings(principal.userId);

    logUiInfo(request, 'ui_user_get_chat_control', {
      userId: principal.userId,
      archiveCollectionName: chatControl.archiveCollectionName,
      archiveCollectionParentId: chatControl.archiveCollectionParentId,
      chatCaptureTagName: chatControl.chatCaptureTagName,
      chatCaptureTagAiChatEnabled: chatControl.chatCaptureTagAiChatEnabled,
      chatCaptureTagAiNameEnabled: chatControl.chatCaptureTagAiNameEnabled,
      aiActivityRetentionDays: chatControl.aiActivityRetentionDays
    });

    reply.send({
      ok: true,
      chatControl
    });
  });

  fastify.post('/admin/ui/user/chat-control', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = setChatControlSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_chat_control_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid chat-control payload.', parsed.error.flatten());
    }

    const chatControl = db.setUserChatControlSettings(principal.userId, {
      archiveCollectionName: parsed.data.archiveCollectionName,
      archiveCollectionParentId: parsed.data.archiveCollectionParentId,
      chatCaptureTagName: parsed.data.chatCaptureTagName,
      chatCaptureTagAiChatEnabled: parsed.data.chatCaptureTagAiChatEnabled,
      chatCaptureTagAiNameEnabled: parsed.data.chatCaptureTagAiNameEnabled,
      aiActivityRetentionDays: parsed.data.aiActivityRetentionDays
    });

    logUiInfo(request, 'ui_user_set_chat_control_success', {
      userId: principal.userId,
      archiveCollectionName: chatControl.archiveCollectionName,
      archiveCollectionParentId: chatControl.archiveCollectionParentId,
      chatCaptureTagName: chatControl.chatCaptureTagName,
      chatCaptureTagAiChatEnabled: chatControl.chatCaptureTagAiChatEnabled,
      chatCaptureTagAiNameEnabled: chatControl.chatCaptureTagAiNameEnabled,
      aiActivityRetentionDays: chatControl.aiActivityRetentionDays
    });

    reply.send({
      ok: true,
      chatControl
    });
  });

  fastify.get('/admin/ui/user/ai-log/settings', async (request, reply) => {
    const principal = requireSession(request, db);
    const chatControl = db.getUserChatControlSettings(principal.userId);

    reply.send({
      ok: true,
      settings: {
        retentionDays: chatControl.aiActivityRetentionDays
      }
    });
  });

  fastify.post('/admin/ui/user/ai-log/settings', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    const parsed = aiLogSettingsSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_ai_log_settings_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid AI log settings payload.', parsed.error.flatten());
    }

    const chatControl = db.setUserChatControlSettings(principal.userId, {
      aiActivityRetentionDays: parsed.data.retentionDays
    });
    db.pruneAiChangeLog(principal.userId, chatControl.aiActivityRetentionDays);

    logUiInfo(request, 'ui_user_set_ai_log_settings_success', {
      userId: principal.userId,
      retentionDays: chatControl.aiActivityRetentionDays
    });

    reply.send({
      ok: true,
      settings: {
        retentionDays: chatControl.aiActivityRetentionDays
      }
    });
  });

  fastify.get('/admin/ui/user/ai-log/facets', async (request, reply) => {
    const principal = requireSession(request, db);
    const parsed = aiLogFacetQuerySchema.safeParse(request.query ?? {});
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_get_ai_log_facets_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid AI log facet query.', parsed.error.flatten());
    }

    const chatControl = db.getUserChatControlSettings(principal.userId);
    const pruned = pruneAiLogIfDue(db, principal.userId, chatControl.aiActivityRetentionDays);
    if (pruned > 0) {
      logUiInfo(request, 'ui_user_ai_log_pruned', {
        userId: principal.userId,
        pruned
      });
    }
    const facets = db.listAiChangeLogFacets(principal.userId, {
      dateFrom: parsed.data.dateFrom,
      dateTo: parsed.data.dateTo
    });

    reply.send({
      ok: true,
      facets
    });
  });

  fastify.get('/admin/ui/user/ai-log', async (request, reply) => {
    const principal = requireSession(request, db);
    const parsed = listAiLogQuerySchema.safeParse(request.query ?? {});
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_get_ai_log_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid AI log query.', parsed.error.flatten());
    }

    const invalidActionTypes = (parsed.data.actionType ?? []).filter(
      (value) => !ALLOWED_AI_CHANGE_ACTION_TYPES.includes(value as AiChangeActionType)
    );
    if (invalidActionTypes.length > 0) {
      throw new AppError(
        400,
        'validation_error',
        `Unknown actionType filter(s): ${invalidActionTypes.join(', ')}.`
      );
    }

    const chatControl = db.getUserChatControlSettings(principal.userId);
    const pruned = pruneAiLogIfDue(db, principal.userId, chatControl.aiActivityRetentionDays);
    if (pruned > 0) {
      logUiInfo(request, 'ui_user_ai_log_pruned', {
        userId: principal.userId,
        pruned
      });
    }

    const page = parsed.data.page;
    const pageSize = parsed.data.pageSize;
    const offset = (page - 1) * pageSize;
    const result = db.listAiChangeLog(
      principal.userId,
      {
        q: parsed.data.q,
        dateFrom: parsed.data.dateFrom,
        dateTo: parsed.data.dateTo,
        actionTypes: (parsed.data.actionType ?? []) as AiChangeActionType[],
        toolNames: parsed.data.toolName ?? [],
        linkId: parsed.data.linkId,
        collectionFromId: parsed.data.collectionFromId,
        collectionToId: parsed.data.collectionToId,
        tagName: parsed.data.tagName,
        trackingTrimmed: parsed.data.trackingTrimmed,
        undoStatus: parsed.data.undoStatus
      },
      {
        limit: pageSize,
        offset
      },
      {
        sortBy: parsed.data.sortBy,
        sortDir: parsed.data.sortDir
      }
    );

    reply.send({
      ok: true,
      items: result.items,
      paging: {
        page,
        pageSize,
        offset,
        returned: result.items.length,
        total: result.total
      }
    });
  });

  fastify.post('/admin/ui/user/ai-log/undo', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    const parsed = aiLogUndoSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_undo_ai_log_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid AI log undo payload.', parsed.error.flatten());
    }

    const runtimeContext = {
      actor: `${principal.username}#${principal.sessionId}`,
      principal: toInternalPrincipal(principal),
      configStore,
      db,
      logger: request.log
    };

    if (parsed.data.mode === 'changes') {
      const result = await undoChangesByIds(runtimeContext, parsed.data.changeIds ?? []);
      reply.send({
        ok: true,
        result
      });
      return;
    }

    const operationIds = [...new Set((parsed.data.operationIds ?? []).map((value) => value.trim()).filter((value) => value.length > 0))];
    const warnings: string[] = [];
    const failures: Array<{ operationId: string; message: string }> = [];
    let undone = 0;
    for (const operationId of operationIds) {
      try {
        const output = await executeTool('linkwarden_undo_operation', { operationId }, runtimeContext);
        const payload = output.structuredContent as Record<string, any>;
        const undoneCount = Number(payload?.summary?.undone ?? 0);
        undone += Number.isFinite(undoneCount) ? undoneCount : 0;
        const toolWarnings = Array.isArray(payload?.warnings) ? payload.warnings : [];
        for (const warning of toolWarnings) {
          warnings.push(String(warning));
        }
      } catch (error) {
        failures.push({
          operationId,
          message: error instanceof Error ? error.message : 'undo operation failed'
        });
      }
    }

    const outcome = failures.length > 0 ? 'failed' : 'success';
    db.insertAudit({
      actor: `${principal.username}#${principal.sessionId}`,
      toolName: 'ui_ai_log_undo_operations',
      targetType: 'operation',
      targetIds: operationIds,
      beforeSummary: 'ui operation undo requested',
      afterSummary: JSON.stringify({
        requested: operationIds.length,
        undone,
        failures: failures.length
      }),
      outcome,
      details: {
        userId: principal.userId,
        warnings
      }
    });

    reply.send({
      ok: true,
      result: {
        requested: operationIds.length,
        undone,
        conflicts: 0,
        failed: failures.length,
        warnings,
        failures,
        operationIdsAffected: operationIds
      }
    });
  });

  fastify.post('/admin/ui/user/linkwarden-token', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = setLinkwardenTokenSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_set_linkwarden_token_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid Linkwarden token payload.', parsed.error.flatten());
    }

    const encryptedToken = configStore.encryptSecret(parsed.data.token);
    db.setUserLinkwardenToken(principal.userId, encryptedToken);

    logUiInfo(request, 'ui_user_set_linkwarden_token_success', {
      userId: principal.userId
    });

    reply.send({
      ok: true,
      userId: principal.userId,
      linkwardenTokenConfigured: true
    });
  });

  fastify.get('/admin/ui/user/api-keys', async (request, reply) => {
    const principal = requireSession(request, db);

    const apiKeys = db.listApiKeys(principal.userId);
    logUiDebug(request, 'ui_user_list_api_keys', {
      userId: principal.userId,
      count: apiKeys.length
    });

    reply.send({
      ok: true,
      apiKeys
    });
  });

  fastify.post('/admin/ui/user/api-keys', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = createOwnApiKeySchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_create_api_key_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid create-api-key payload.', parsed.error.flatten());
    }

    const key = issueApiKey(db, principal.userId, parsed.data.label);

    logUiInfo(request, 'ui_user_create_api_key_success', {
      userId: principal.userId,
      keyId: key.keyId,
      label: parsed.data.label
    });

    reply.code(201).send({
      ok: true,
      userId: principal.userId,
      keyId: key.keyId,
      apiKey: key.token
    });
  });

  fastify.post('/admin/ui/user/api-keys/:keyId/revoke', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);

    const parsed = keyIdParamSchema.safeParse(request.params);
    if (!parsed.success) {
      logUiWarn(request, 'ui_user_revoke_api_key_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid revoke key payload.', parsed.error.flatten());
    }

    db.revokeApiKey(parsed.data.keyId, principal.userId);

    logUiInfo(request, 'ui_user_revoke_api_key_success', {
      userId: principal.userId,
      keyId: parsed.data.keyId
    });

    reply.send({
      ok: true,
      keyId: parsed.data.keyId,
      revoked: true
    });
  });
}
