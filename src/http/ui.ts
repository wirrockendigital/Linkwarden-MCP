// This module provides browser UI routes with session auth for admin and user operations.

import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { getNewLinksRoutineStatus } from '../services/new-links-routine.js';
import type { AuthenticatedPrincipal, SessionPrincipal, UserRole } from '../types/domain.js';
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

// This helper sends the standard login page for initialized systems without session.
function renderLoginPage(csrfToken: string, nextPath: string | null): string {
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp Login</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; max-width: 760px; }
    .card { border: 1px solid #d9d9d9; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    label { display:block; font-weight:600; margin-top:0.8rem; }
    input, select, textarea, button { width:100%; padding:0.6rem; margin-top:0.35rem; border-radius:8px; border:1px solid #b8b8b8; }
    button { cursor:pointer; font-weight:700; }
    pre { background:#f8f8f8; border-radius:10px; padding:0.8rem; overflow:auto; }
  </style>
</head>
<body>
  <h1>linkwarden-mcp</h1>
  <div class="card">
    <h2>Login</h2>
    <label for="username">Benutzername</label>
    <input id="username" autocomplete="username" />
    <label for="password">Passwort</label>
    <input id="password" type="password" autocomplete="current-password" />
    <button onclick="login()">Einloggen</button>
  </div>
  <div class="card">
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
</script>
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
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; max-width: 860px; }
    .card { border: 1px solid #d9d9d9; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    label { display:block; font-weight:600; margin-top:0.8rem; }
    input, textarea, button { width:100%; padding:0.6rem; margin-top:0.35rem; border-radius:8px; border:1px solid #b8b8b8; }
    button { cursor:pointer; font-weight:700; }
    textarea { min-height: 140px; }
    pre { background:#f8f8f8; border-radius:10px; padding:0.8rem; overflow:auto; }
  </style>
</head>
<body>
  <h1>linkwarden-mcp First-Run Setup</h1>
  <div class="card">
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
  <div class="card">
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
</script>
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
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; max-width: 760px; }
    .card { border: 1px solid #d9d9d9; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    label { display:block; font-weight:600; margin-top:0.8rem; }
    input, button { width:100%; padding:0.6rem; margin-top:0.35rem; border-radius:8px; border:1px solid #b8b8b8; }
    button { cursor:pointer; font-weight:700; }
    pre { background:#f8f8f8; border-radius:10px; padding:0.8rem; overflow:auto; }
  </style>
</head>
<body>
  <h1>linkwarden-mcp Unlock</h1>
  <div class="card">
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
</script>
</body>
</html>`;
}

// This helper renders a shared dashboard shell used for admin and standard users.
function renderDashboardPage(principal: SessionPrincipal, csrfToken: string): string {
  const adminSections =
    principal.role === 'admin'
      ? `
  <div class="card">
    <h2>Admin: Benutzer verwalten</h2>
    <button onclick="loadUsers()">Benutzer laden</button>
    <pre id="usersResult">Noch nicht geladen</pre>
    <label for="newUsername">Neuer Benutzername</label>
    <input id="newUsername" />
    <label for="newPassword">Neues Passwort</label>
    <input id="newPassword" type="password" />
    <label for="newRole">Rolle</label>
    <select id="newRole"><option value="user">user</option><option value="admin">admin</option></select>
    <label><input id="newWriteMode" type="checkbox" /> Write-Mode aktiv</label>
    <button onclick="createUser()">Benutzer anlegen</button>
    <label for="toggleUserSelect">Benutzer für Aktiv/Deaktiv</label>
    <select id="toggleUserSelect"></select>
    <label><input id="toggleUserActive" type="checkbox" checked /> Aktiv</label>
    <button onclick="setUserActive()">Aktiv-Status setzen</button>
    <label for="writeModeUserSelect">Benutzer für Write-Mode</label>
    <select id="writeModeUserSelect"></select>
    <label><input id="writeModeForUser" type="checkbox" /> Write-Mode aktiv</label>
    <button onclick="setUserWriteMode()">Write-Mode pro User setzen</button>
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

  <div class="card">
    <h2>Admin: Governed Tagging Policy</h2>
    <button onclick="loadTaggingPolicy()">Tagging-Policy laden</button>
    <pre id="taggingPolicyResult">Noch nicht geladen</pre>
    <label for="policyFetchMode">Globaler Fetch-Mode</label>
    <select id="policyFetchMode">
      <option value="never">never</option>
      <option value="optional">optional</option>
      <option value="always">always</option>
    </select>
    <label><input id="policyAllowUserFetchOverride" type="checkbox" /> User dürfen eigenen Fetch-Mode setzen</label>
    <label for="policyInferenceProvider">AI Provider für Tag-Kontext</label>
    <select id="policyInferenceProvider">
      <option value="builtin">builtin (lokal, ohne externes LLM)</option>
      <option value="perplexity">perplexity</option>
      <option value="mistral">mistral</option>
      <option value="huggingface">huggingface</option>
    </select>
    <label for="policyInferenceModel">AI Modell (optional; bei huggingface empfohlen/üblich erforderlich)</label>
    <input id="policyInferenceModel" placeholder="z. B. sonar, mistral-small-latest, meta-llama/Llama-3.1-8B-Instruct" />
    <label for="policyBlockedTags">Blockierte Tags (Komma-separiert)</label>
    <input id="policyBlockedTags" placeholder="spam, tracking, misc" />
    <label for="policySimilarityThreshold">Similarity Threshold (0-1)</label>
    <input id="policySimilarityThreshold" type="number" min="0" max="1" step="0.01" value="0.88" />
    <label for="policyFetchTimeoutMs">Fetch Timeout (ms)</label>
    <input id="policyFetchTimeoutMs" type="number" min="500" max="20000" value="3000" />
    <label for="policyFetchMaxBytes">Fetch Max Bytes</label>
    <input id="policyFetchMaxBytes" type="number" min="8192" max="1048576" value="131072" />
    <button onclick="setTaggingPolicy()">Tagging-Policy speichern</button>
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

  <div class="card">
    <h2>Admin: MCP API Keys -> AI</h2>
    <button onclick="loadAdminKeys()">Alle MCP API Keys laden</button>
    <pre id="adminKeysResult">Noch nicht geladen</pre>
    <label for="apiKeyUserSelect">Benutzer für neuen MCP API Key</label>
    <select id="apiKeyUserSelect"></select>
    <label for="apiKeyLabel">Key Label</label>
    <input id="apiKeyLabel" value="default" />
    <button onclick="issueAdminKey()">API Key ausstellen</button>
    <label for="revokeKeyId">Key ID zum Revoken</label>
    <input id="revokeKeyId" />
    <button onclick="revokeAdminKey()">API Key revoken</button>
  </div>

  <div class="card">
    <h2>Admin: Linkwarden API Key -> MCP (pro User)</h2>
    <label for="linkwardenTokenUserSelect">Benutzer</label>
    <select id="linkwardenTokenUserSelect"></select>
    <label for="linkwardenTokenValue">Linkwarden API Key</label>
    <input id="linkwardenTokenValue" type="password" />
    <button onclick="setUserLinkwardenToken()">Linkwarden API Key speichern</button>
  </div>

  <div class="card">
    <h2>Admin: Linkwarden Ziel</h2>
    <button onclick="loadLinkwardenConfig()">Aktuelle Konfiguration laden</button>
    <pre id="linkwardenConfigResult">Noch nicht geladen</pre>
    <label for="lwBaseUrl">Neue Base URL</label>
    <input id="lwBaseUrl" placeholder="http://linkwarden:3000" />
    <button onclick="updateLinkwardenConfig()">Linkwarden Konfiguration speichern</button>
  </div>
      `
      : '';

  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>linkwarden-mcp Dashboard</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; max-width: 980px; }
    .card { border: 1px solid #d9d9d9; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    label { display:block; font-weight:600; margin-top:0.8rem; }
    input, select, textarea, button { width:100%; padding:0.6rem; margin-top:0.35rem; border-radius:8px; border:1px solid #b8b8b8; }
    button { cursor:pointer; font-weight:700; }
    textarea { min-height: 120px; }
    pre { background:#f8f8f8; border-radius:10px; padding:0.8rem; overflow:auto; }
  </style>
</head>
<body>
  <h1>linkwarden-mcp Dashboard</h1>
  <div class="card">
    <p>Angemeldet als <strong>${principal.username}</strong> (Rolle: <strong>${principal.role}</strong>)</p>
    <button onclick="logout()">Logout</button>
  </div>

  <div class="card">
    <h2>Mein Profil</h2>
    <button onclick="loadMe()">Profil neu laden</button>
    <pre id="meResult">Noch nicht geladen</pre>
    <label><input id="selfWriteMode" type="checkbox" /> Eigener Write-Mode aktiv</label>
    <button onclick="setOwnWriteMode()">Meinen Write-Mode speichern</button>
  </div>

  <div class="card">
    <h2>Mein Tagging</h2>
    <button onclick="loadOwnTaggingPreferences()">Tagging-Einstellungen laden</button>
    <pre id="ownTaggingPreferencesResult">Noch nicht geladen</pre>
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

  <div class="card">
    <h2>Meine New-Links-Routine</h2>
    <button onclick="loadOwnNewLinksRoutine()">Routine-Status laden</button>
    <pre id="ownNewLinksRoutineResult">Noch nicht geladen</pre>
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

  <div class="card">
    <h2>Mein Linkwarden API Key -> MCP</h2>
    <p id="selfLinkwardenStatus">Status: unbekannt</p>
    <label for="selfLinkwardenToken">Linkwarden API Key</label>
    <input id="selfLinkwardenToken" type="password" />
    <button onclick="setOwnLinkwardenToken()">Linkwarden API Key speichern</button>
  </div>

  <div class="card">
    <h2>Meine MCP API Keys -> AI</h2>
    <button onclick="loadOwnKeys()">Meine MCP API Keys laden</button>
    <pre id="ownKeysResult">Noch nicht geladen</pre>
    <label for="ownKeyLabel">Key Label</label>
    <input id="ownKeyLabel" value="default" />
    <button onclick="issueOwnKey()">Eigenen API Key erzeugen</button>
    <label for="ownRevokeKeyId">Key ID zum Revoken</label>
    <input id="ownRevokeKeyId" />
    <button onclick="revokeOwnKey()">Eigenen API Key revoken</button>
  </div>

  ${adminSections}

  <div class="card">
    <h2>Letzte Aktion</h2>
    <pre id="actionResult">Warte auf Aktion ...</pre>
  </div>

<script>
const csrfToken = ${JSON.stringify(csrfToken)};
const isAdmin = ${JSON.stringify(principal.role === 'admin')};
let usersCache = [];

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

async function api(url, options = {}) {
  const merged = {
    ...options,
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrfToken,
      ...(options.headers || {})
    }
  };

  const res = await fetch(url, merged);
  const json = await res.json();
  document.getElementById('actionResult').textContent = JSON.stringify(json, null, 2);
  if (!res.ok) {
    throw new Error(json?.error?.message || 'API Fehler');
  }
  return json;
}

async function logout() {
  await api('/admin/auth/logout', { method: 'POST', body: '{}' });
  window.location.href = '/admin';
}

async function loadMe() {
  const res = await fetch('/admin/auth/me');
  const json = await res.json();
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
  }
}

async function setOwnWriteMode() {
  await api('/admin/ui/user/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('selfWriteMode').checked })
  });
  await loadMe();
}

async function loadOwnTaggingPreferences() {
  const res = await fetch('/admin/ui/user/tagging-preferences');
  const json = await res.json();
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
    })
  });
  await loadOwnTaggingPreferences();
}

async function loadOwnNewLinksRoutine() {
  const res = await fetch('/admin/ui/user/new-links-routine');
  const json = await res.json();
  document.getElementById('ownNewLinksRoutineResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    applyRoutineSettingsToForm(json?.status?.settings ?? {});
  }
}

async function setOwnNewLinksRoutine() {
  const modules = readRoutineModules();
  if (modules.length === 0) {
    // This guard surfaces validation feedback in the shared action panel without throwing an uncaught browser error.
    document.getElementById('actionResult').textContent = JSON.stringify(
      {
        ok: false,
        error: {
          message: 'Mindestens ein Routine-Modul muss aktiviert sein.'
        }
      },
      null,
      2
    );
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
    })
  });

  document.getElementById('selfRoutineRequestBackfill').checked = false;
  document.getElementById('selfRoutineConfirmBackfill').checked = false;
  await loadOwnNewLinksRoutine();
}

async function setOwnLinkwardenToken() {
  await api('/admin/ui/user/linkwarden-token', {
    method: 'POST',
    body: JSON.stringify({ token: document.getElementById('selfLinkwardenToken').value })
  });
  document.getElementById('selfLinkwardenToken').value = '';
  await loadMe();
}

async function loadOwnKeys() {
  const res = await fetch('/admin/ui/user/api-keys');
  const json = await res.json();
  document.getElementById('ownKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueOwnKey() {
  await api('/admin/ui/user/api-keys', {
    method: 'POST',
    body: JSON.stringify({ label: document.getElementById('ownKeyLabel').value })
  });
  await loadOwnKeys();
}

async function revokeOwnKey() {
  const keyId = document.getElementById('ownRevokeKeyId').value;
  await api('/admin/ui/user/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}'
  });
  await loadOwnKeys();
}

async function loadUsers() {
  const res = await fetch('/admin/ui/admin/users');
  const json = await res.json();
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
    })
  });
  await loadUsers();
}

async function setUserActive() {
  const userId = document.getElementById('toggleUserSelect').value;
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/active', {
    method: 'POST',
    body: JSON.stringify({ active: document.getElementById('toggleUserActive').checked })
  });
  await loadUsers();
}

async function setUserWriteMode() {
  const userId = document.getElementById('writeModeUserSelect').value;
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('writeModeForUser').checked })
  });
  await loadUsers();
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
    })
  });
  await loadUsers();
}

async function loadTaggingPolicy() {
  const res = await fetch('/admin/ui/admin/tagging-policy');
  const json = await res.json();
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
    })
  });
  await loadTaggingPolicy();
  await loadUsers();
}

async function setUserTaggingPreferences() {
  const userId = Number(document.getElementById('taggingPreferenceUserSelect').value);
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/tagging-preferences', {
    method: 'POST',
    body: JSON.stringify({
      taggingStrictness: document.getElementById('taggingStrictnessForUser').value,
      fetchMode: document.getElementById('fetchModeForUser').value,
      queryTimeZone: readOptionalTimeZoneInput('queryTimeZoneForUser')
    })
  });
  await loadUsers();
}

async function loadAdminKeys() {
  const res = await fetch('/admin/ui/admin/api-keys');
  const json = await res.json();
  document.getElementById('adminKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueAdminKey() {
  await api('/admin/ui/admin/api-keys', {
    method: 'POST',
    body: JSON.stringify({
      userId: Number(document.getElementById('apiKeyUserSelect').value),
      label: document.getElementById('apiKeyLabel').value
    })
  });
  await loadAdminKeys();
}

async function revokeAdminKey() {
  const keyId = document.getElementById('revokeKeyId').value;
  await api('/admin/ui/admin/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}'
  });
  await loadAdminKeys();
}

async function loadLinkwardenConfig() {
  const res = await fetch('/admin/ui/admin/linkwarden');
  const json = await res.json();
  document.getElementById('linkwardenConfigResult').textContent = JSON.stringify(json, null, 2);
}

async function updateLinkwardenConfig() {
  const payload = {};
  const baseUrl = document.getElementById('lwBaseUrl').value.trim();

  if (baseUrl) {
    payload.baseUrl = baseUrl;
  }

  await api('/admin/ui/admin/linkwarden', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

  await loadLinkwardenConfig();
}

async function setUserLinkwardenToken() {
  const userId = Number(document.getElementById('linkwardenTokenUserSelect').value);
  await api('/admin/ui/admin/users/' + encodeURIComponent(userId) + '/linkwarden-token', {
    method: 'POST',
    body: JSON.stringify({ token: document.getElementById('linkwardenTokenValue').value })
  });
  document.getElementById('linkwardenTokenValue').value = '';
  await loadUsers();
}

loadMe();
loadOwnTaggingPreferences();
loadOwnNewLinksRoutine();
loadOwnKeys();
if (isAdmin) {
  const offlinePolicySelect = document.getElementById('offlinePolicyUserSelect');
  if (offlinePolicySelect) {
    offlinePolicySelect.addEventListener('change', syncOfflinePolicyFromSelectedUser);
  }
  const taggingPreferenceSelect = document.getElementById('taggingPreferenceUserSelect');
  if (taggingPreferenceSelect) {
    taggingPreferenceSelect.addEventListener('change', syncTaggingPreferencesFromSelectedUser);
  }
  loadTaggingPolicy();
  loadUsers();
}
</script>
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
