// This module provides browser UI routes with session auth for admin and user operations.

import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import type { LinkwardenWhitelistEntry, SessionPrincipal, UserRole } from '../types/domain.js';
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
import { assertBaseUrlWhitelisted, normalizeWhitelistEntry } from '../utils/whitelist.js';
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

const createApiKeySchema = z.object({
  userId: z.number().int().positive(),
  label: z.string().min(2).max(100).default('default')
});

const createOwnApiKeySchema = z.object({
  label: z.string().min(2).max(100).default('default')
});

const whitelistEntrySchema = z.object({
  type: z.enum(['domain', 'ip', 'cidr']),
  value: z.string().min(1).max(255)
});

const updateLinkwardenSchema = z
  .object({
    baseUrl: z.string().url().optional(),
    linkwardenApiToken: z.string().min(20).optional(),
    whitelistEntries: z.array(whitelistEntrySchema).min(1).max(200).optional()
  })
  .refine((payload) => Boolean(payload.baseUrl || payload.linkwardenApiToken || payload.whitelistEntries), {
    message: 'At least one field must be updated.'
  });

const setWhitelistSchema = z.object({
  whitelistEntries: z.array(whitelistEntrySchema).min(1).max(200)
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

// This helper normalizes and validates all whitelist entries before storage.
function normalizeWhitelistEntries(entries: Array<{ type: 'domain' | 'ip' | 'cidr'; value: string }>): Array<{
  type: 'domain' | 'ip' | 'cidr';
  value: string;
}> {
  const normalized = entries.map((entry) => normalizeWhitelistEntry(entry.type, entry.value));
  const deduped = new Map<string, (typeof normalized)[number]>();

  for (const entry of normalized) {
    deduped.set(`${entry.type}:${entry.value}`, entry);
  }

  return [...deduped.values()];
}

// This helper adapts whitelist entries to the validator shape used for base-url checks.
function toWhitelistRecords(entries: Array<{ type: 'domain' | 'ip' | 'cidr'; value: string }>): LinkwardenWhitelistEntry[] {
  const now = new Date().toISOString();

  return entries.map((entry, index) => ({
    id: index + 1,
    type: entry.type,
    value: entry.value,
    createdAt: now
  }));
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

// This helper sends the standard login page for initialized systems without session.
function renderLoginPage(csrfToken: string): string {
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

async function login() {
  const payload = {
    username: document.getElementById('username').value,
    password: document.getElementById('password').value
  };

  const res = await fetch('/auth/login', {
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
    window.location.href = '/';
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
    <p>Richte hier den ersten Admin, Linkwarden-Ziel und die verpflichtende Whitelist ein.</p>
    <label for="masterPassphrase">Master-Passphrase</label>
    <input id="masterPassphrase" type="password" />
    <label for="adminUsername">Admin-Benutzername</label>
    <input id="adminUsername" value="admin" />
    <label for="adminPassword">Admin-Passwort</label>
    <input id="adminPassword" type="password" />
    <label for="baseUrl">Linkwarden Base URL</label>
    <input id="baseUrl" placeholder="http://linkwarden:3000" />
    <label for="apiToken">Linkwarden API Token</label>
    <input id="apiToken" type="password" />
    <label for="whitelist">Whitelist (eine Zeile je Eintrag, Format: domain:host oder ip:1.2.3.4 oder cidr:192.168.0.0/24)</label>
    <textarea id="whitelist" placeholder="domain:linkwarden.internal\nip:192.168.123.10"></textarea>
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

function parseWhitelistInput(value) {
  return value
    .split(/\\r?\\n+/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(':');
      if (idx === -1) {
        throw new Error('Ungültige Whitelist-Zeile: ' + line);
      }
      const type = line.slice(0, idx).trim();
      const entryValue = line.slice(idx + 1).trim();
      return { type, value: entryValue };
    });
}

async function initializeSetup() {
  let whitelistEntries = [];
  try {
    whitelistEntries = parseWhitelistInput(document.getElementById('whitelist').value);
  } catch (error) {
    document.getElementById('result').textContent = String(error);
    return;
  }

  const payload = {
    masterPassphrase: document.getElementById('masterPassphrase').value,
    adminUsername: document.getElementById('adminUsername').value,
    adminPassword: document.getElementById('adminPassword').value,
    linkwardenBaseUrl: document.getElementById('baseUrl').value,
    linkwardenApiToken: document.getElementById('apiToken').value,
    whitelistEntries,
    adminWriteModeDefault: document.getElementById('adminWriteModeDefault').checked,
    issueAdminApiKey: document.getElementById('issueAdminApiKey').checked
  };

  const res = await fetch('/setup/initialize', {
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
    window.location.href = '/';
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
  const res = await fetch('/setup/unlock', {
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
    window.location.href = '/';
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
    <label for="toggleUserId">User ID für Aktiv/Deaktiv</label>
    <input id="toggleUserId" type="number" />
    <label><input id="toggleUserActive" type="checkbox" checked /> Aktiv</label>
    <button onclick="setUserActive()">Aktiv-Status setzen</button>
    <label for="writeModeUserId">User ID für Write-Mode</label>
    <input id="writeModeUserId" type="number" />
    <label><input id="writeModeForUser" type="checkbox" /> Write-Mode aktiv</label>
    <button onclick="setUserWriteMode()">Write-Mode pro User setzen</button>
  </div>

  <div class="card">
    <h2>Admin: API Keys</h2>
    <button onclick="loadAdminKeys()">Alle API Keys laden</button>
    <pre id="adminKeysResult">Noch nicht geladen</pre>
    <label for="apiKeyUserId">User ID</label>
    <input id="apiKeyUserId" type="number" />
    <label for="apiKeyLabel">Key Label</label>
    <input id="apiKeyLabel" value="default" />
    <button onclick="issueAdminKey()">API Key ausstellen</button>
    <label for="revokeKeyId">Key ID zum Revoken</label>
    <input id="revokeKeyId" />
    <button onclick="revokeAdminKey()">API Key revoken</button>
  </div>

  <div class="card">
    <h2>Admin: Linkwarden Ziel + Whitelist</h2>
    <button onclick="loadLinkwardenConfig()">Aktuelle Konfiguration laden</button>
    <pre id="linkwardenConfigResult">Noch nicht geladen</pre>
    <label for="lwBaseUrl">Neue Base URL (optional)</label>
    <input id="lwBaseUrl" placeholder="http://linkwarden:3000" />
    <label for="lwToken">Neuer API Token (optional)</label>
    <input id="lwToken" type="password" />
    <label for="lwWhitelist">Neue Whitelist (optional, Zeilenformat type:value)</label>
    <textarea id="lwWhitelist" placeholder="domain:linkwarden.internal\nip:192.168.123.10"></textarea>
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
    <h2>Meine API Keys</h2>
    <button onclick="loadOwnKeys()">Meine API Keys laden</button>
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

function parseWhitelistInput(value) {
  return value
    .split(/\\r?\\n+/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(':');
      if (idx === -1) {
        throw new Error('Ungültige Whitelist-Zeile: ' + line);
      }
      const type = line.slice(0, idx).trim();
      const entryValue = line.slice(idx + 1).trim();
      return { type, value: entryValue };
    });
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
  await api('/auth/logout', { method: 'POST', body: '{}' });
  window.location.href = '/';
}

async function loadMe() {
  const res = await fetch('/auth/me');
  const json = await res.json();
  document.getElementById('meResult').textContent = JSON.stringify(json, null, 2);
  if (res.ok) {
    document.getElementById('selfWriteMode').checked = Boolean(json?.me?.settings?.writeModeEnabled);
  }
}

async function setOwnWriteMode() {
  await api('/ui/user/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('selfWriteMode').checked })
  });
  await loadMe();
}

async function loadOwnKeys() {
  const res = await fetch('/ui/user/api-keys');
  const json = await res.json();
  document.getElementById('ownKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueOwnKey() {
  await api('/ui/user/api-keys', {
    method: 'POST',
    body: JSON.stringify({ label: document.getElementById('ownKeyLabel').value })
  });
  await loadOwnKeys();
}

async function revokeOwnKey() {
  const keyId = document.getElementById('ownRevokeKeyId').value;
  await api('/ui/user/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}'
  });
  await loadOwnKeys();
}

async function loadUsers() {
  const res = await fetch('/ui/admin/users');
  const json = await res.json();
  document.getElementById('usersResult').textContent = JSON.stringify(json, null, 2);
}

async function createUser() {
  await api('/ui/admin/users', {
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
  const userId = document.getElementById('toggleUserId').value;
  await api('/ui/admin/users/' + encodeURIComponent(userId) + '/active', {
    method: 'POST',
    body: JSON.stringify({ active: document.getElementById('toggleUserActive').checked })
  });
  await loadUsers();
}

async function setUserWriteMode() {
  const userId = document.getElementById('writeModeUserId').value;
  await api('/ui/admin/users/' + encodeURIComponent(userId) + '/write-mode', {
    method: 'POST',
    body: JSON.stringify({ writeModeEnabled: document.getElementById('writeModeForUser').checked })
  });
  await loadUsers();
}

async function loadAdminKeys() {
  const res = await fetch('/ui/admin/api-keys');
  const json = await res.json();
  document.getElementById('adminKeysResult').textContent = JSON.stringify(json, null, 2);
}

async function issueAdminKey() {
  await api('/ui/admin/api-keys', {
    method: 'POST',
    body: JSON.stringify({
      userId: Number(document.getElementById('apiKeyUserId').value),
      label: document.getElementById('apiKeyLabel').value
    })
  });
  await loadAdminKeys();
}

async function revokeAdminKey() {
  const keyId = document.getElementById('revokeKeyId').value;
  await api('/ui/admin/api-keys/' + encodeURIComponent(keyId) + '/revoke', {
    method: 'POST',
    body: '{}'
  });
  await loadAdminKeys();
}

async function loadLinkwardenConfig() {
  const res = await fetch('/ui/admin/linkwarden');
  const json = await res.json();
  document.getElementById('linkwardenConfigResult').textContent = JSON.stringify(json, null, 2);
}

async function updateLinkwardenConfig() {
  const payload = {};
  const baseUrl = document.getElementById('lwBaseUrl').value.trim();
  const token = document.getElementById('lwToken').value.trim();
  const whitelistText = document.getElementById('lwWhitelist').value.trim();

  if (baseUrl) {
    payload.baseUrl = baseUrl;
  }
  if (token) {
    payload.linkwardenApiToken = token;
  }
  if (whitelistText) {
    payload.whitelistEntries = parseWhitelistInput(whitelistText);
  }

  await api('/ui/admin/linkwarden', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

  await loadLinkwardenConfig();
}

loadMe();
loadOwnKeys();
</script>
</body>
</html>`;
}

// This helper returns view data for one authenticated user including per-user settings.
function buildMePayload(db: SqliteStore, principal: SessionPrincipal): Record<string, unknown> {
  const user = db.getUserById(principal.userId);
  const settings = db.getUserSettings(principal.userId);

  return {
    id: user.id,
    username: user.username,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    settings
  };
}

// This function registers root UI, auth/session routes, and admin/user JSON APIs.
export function registerUiRoutes(fastify: FastifyInstance, configStore: ConfigStore, db: SqliteStore): void {
  fastify.get('/', async (request, reply) => {
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
      logUiInfo(request, 'ui_render_login');
      reply.type('text/html').send(renderLoginPage(csrfToken));
      return;
    }

    logUiInfo(request, 'ui_render_dashboard', {
      userId: principal.userId,
      username: principal.username,
      role: principal.role
    });
    reply.type('text/html').send(renderDashboardPage(principal, csrfToken));
  });

  fastify.get('/setup', async (_request, reply) => {
    reply.redirect('/');
  });

  fastify.post('/auth/login', async (request, reply) => {
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

  fastify.post('/auth/logout', async (request, reply) => {
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

  fastify.get('/auth/me', async (request, reply) => {
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

  fastify.get('/ui/admin/users', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const users = db.listUsers();
    const usersWithSettings = users.map((user) => ({
      ...user,
      settings: db.getUserSettings(user.id)
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

  fastify.post('/ui/admin/users', async (request, reply) => {
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

  fastify.post('/ui/admin/users/:userId/active', async (request, reply) => {
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

  fastify.post('/ui/admin/users/:userId/write-mode', async (request, reply) => {
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

  fastify.get('/ui/admin/api-keys', async (request, reply) => {
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

  fastify.post('/ui/admin/api-keys', async (request, reply) => {
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

  fastify.post('/ui/admin/api-keys/:keyId/revoke', async (request, reply) => {
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

  fastify.get('/ui/admin/linkwarden', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const target = db.getLinkwardenTarget();
    const whitelist = db.listWhitelist();

    logUiInfo(request, 'ui_admin_get_linkwarden_config', {
      actorUserId: principal.userId,
      targetConfigured: Boolean(target),
      whitelistCount: whitelist.length
    });

    reply.send({
      ok: true,
      target,
      whitelist
    });
  });

  fastify.post('/ui/admin/linkwarden', async (request, reply) => {
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

    const currentTarget = db.getLinkwardenTarget();
    const currentWhitelist = db.listWhitelist();

    const nextWhitelist = parsed.data.whitelistEntries
      ? normalizeWhitelistEntries(parsed.data.whitelistEntries)
      : currentWhitelist.map((entry) => ({ type: entry.type, value: entry.value }));

    if (nextWhitelist.length === 0) {
      logUiWarn(request, 'ui_admin_update_linkwarden_invalid_whitelist_empty');
      throw new AppError(400, 'invalid_whitelist', 'Whitelist cannot be empty.');
    }

    const nextBaseUrl = parsed.data.baseUrl ?? currentTarget?.baseUrl;
    if (!nextBaseUrl) {
      logUiWarn(request, 'ui_admin_update_linkwarden_missing_target');
      throw new AppError(400, 'linkwarden_target_missing', 'Linkwarden base URL is not configured.');
    }

    assertBaseUrlWhitelisted(nextBaseUrl, toWhitelistRecords(nextWhitelist));

    if (parsed.data.linkwardenApiToken) {
      configStore.updateConfig((current) => ({
        ...current,
        linkwardenApiToken: parsed.data.linkwardenApiToken ?? current.linkwardenApiToken
      }));
    }

    if (parsed.data.baseUrl) {
      db.setLinkwardenTarget(parsed.data.baseUrl);
    }

    if (parsed.data.whitelistEntries) {
      db.replaceWhitelist(nextWhitelist);
    }

    logUiInfo(request, 'ui_admin_update_linkwarden_success', {
      actorUserId: principal.userId,
      baseUrlUpdated: Boolean(parsed.data.baseUrl),
      tokenUpdated: Boolean(parsed.data.linkwardenApiToken),
      whitelistUpdated: Boolean(parsed.data.whitelistEntries),
      whitelistCount: db.listWhitelist().length
    });

    reply.send({
      ok: true,
      target: db.getLinkwardenTarget(),
      whitelist: db.listWhitelist()
    });
  });

  fastify.get('/ui/admin/whitelist', async (request, reply) => {
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const whitelist = db.listWhitelist();
    logUiDebug(request, 'ui_admin_get_whitelist', {
      actorUserId: principal.userId,
      count: whitelist.length
    });

    reply.send({
      ok: true,
      whitelist
    });
  });

  fastify.post('/ui/admin/whitelist', async (request, reply) => {
    requireCsrf(request);
    const principal = requireSession(request, db);
    requireAdminSession(principal);

    const parsed = setWhitelistSchema.safeParse(request.body);
    if (!parsed.success) {
      logUiWarn(request, 'ui_admin_set_whitelist_validation_failed', {
        details: parsed.error.flatten()
      });
      throw new AppError(400, 'validation_error', 'Invalid whitelist payload.', parsed.error.flatten());
    }

    const normalized = normalizeWhitelistEntries(parsed.data.whitelistEntries);
    if (normalized.length === 0) {
      logUiWarn(request, 'ui_admin_set_whitelist_invalid_empty');
      throw new AppError(400, 'invalid_whitelist', 'Whitelist cannot be empty.');
    }

    const target = db.getLinkwardenTarget();
    if (target) {
      assertBaseUrlWhitelisted(target.baseUrl, toWhitelistRecords(normalized));
    }

    db.replaceWhitelist(normalized);

    logUiInfo(request, 'ui_admin_set_whitelist_success', {
      actorUserId: principal.userId,
      whitelistCount: normalized.length
    });

    reply.send({
      ok: true,
      whitelist: db.listWhitelist()
    });
  });

  fastify.get('/ui/user/me', async (request, reply) => {
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

  fastify.post('/ui/user/write-mode', async (request, reply) => {
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

  fastify.get('/ui/user/api-keys', async (request, reply) => {
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

  fastify.post('/ui/user/api-keys', async (request, reply) => {
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

  fastify.post('/ui/user/api-keys/:keyId/revoke', async (request, reply) => {
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
