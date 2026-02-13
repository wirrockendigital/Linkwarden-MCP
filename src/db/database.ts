// This module owns SQLite initialization and persistence operations for state, users, sessions, plans, and audits.

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PassphraseVerifier } from '../config/crypto.js';
import type {
  AuditEntry,
  AuthenticatedPrincipal,
  LinkwardenTarget,
  LinkwardenWhitelistEntry,
  PlanItem,
  PlanScope,
  PlanSummary,
  PlanStrategy,
  SessionPrincipal,
  StoredPlan,
  UserRole,
  UserSettings,
  WhitelistType
} from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { parseJson } from '../utils/json.js';

interface PlanRow {
  plan_id: string;
  strategy: string;
  parameters_json: string;
  scope_json: string | null;
  summary_json: string;
  warnings_json: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  status: string;
  applied_at: string | null;
}

interface PlanItemRow {
  link_id: number;
  action: string;
  before_json: string;
  after_json: string;
  warning: string | null;
}

interface AuthRow {
  user_id: number;
  username: string;
  role: string;
  key_id: string;
}

interface UserAuthRow {
  id: number;
  username: string;
  role: string;
  is_active: number;
  password_salt: string;
  password_hash: string;
  password_kdf: string;
  password_iterations: number;
}

interface SessionRow {
  session_id: string;
  user_id: number;
  username: string;
  role: string;
  expires_at: string;
  invalidated: number;
}

export interface StoredUser {
  id: number;
  username: string;
  role: UserRole;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface StoredApiKey {
  keyId: string;
  userId: number;
  username: string;
  label: string;
  revoked: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

// This store is intentionally synchronous because SQLite calls are local and bounded.
export class SqliteStore {
  private readonly db: Database.Database;

  public constructor(dbPath: string) {
    if (!existsSync(dirname(dbPath))) {
      mkdirSync(dirname(dbPath), { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.initializeSchema();
  }

  // This method creates core tables and applies lightweight migrations in-place.
  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS admin_credentials (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        salt_b64 TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        hash_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
        is_active INTEGER NOT NULL DEFAULT 1,
        password_salt TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL DEFAULT '',
        password_kdf TEXT NOT NULL DEFAULT 'scrypt',
        password_iterations INTEGER NOT NULL DEFAULT 16384,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        write_mode_enabled INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        label TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash ON api_keys(token_hash);

      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        invalidated INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

      CREATE TABLE IF NOT EXISTS linkwarden_target (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        base_url TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS linkwarden_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_type TEXT NOT NULL CHECK (entry_type IN ('domain', 'ip', 'cidr')),
        entry_value TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_linkwarden_whitelist_unique
      ON linkwarden_whitelist(entry_type, entry_value);

      CREATE TABLE IF NOT EXISTS plans (
        plan_id TEXT PRIMARY KEY,
        strategy TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        scope_json TEXT,
        summary_json TEXT NOT NULL,
        warnings_json TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL,
        applied_at TEXT
      );

      CREATE TABLE IF NOT EXISTS plan_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plan_id TEXT NOT NULL,
        link_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        before_json TEXT NOT NULL,
        after_json TEXT NOT NULL,
        warning TEXT,
        FOREIGN KEY(plan_id) REFERENCES plans(plan_id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_plan_items_plan_id ON plan_items(plan_id);

      CREATE TABLE IF NOT EXISTS plan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plan_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL,
        results_json TEXT,
        FOREIGN KEY(plan_id) REFERENCES plans(plan_id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_ids_json TEXT NOT NULL,
        before_summary TEXT NOT NULL,
        after_summary TEXT NOT NULL,
        outcome TEXT NOT NULL,
        details_json TEXT
      );
    `);

    this.migrateUsersTableIfNeeded();
  }

  // This migration upgrades older role/password schemas to the strict admin|user model.
  private migrateUsersTableIfNeeded(): void {
    const columns = this.db
      .prepare('PRAGMA table_info(users)')
      .all() as Array<{ name: string; notnull: number }>;
    const sqlRow = this.db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'")
      .get() as { sql: string } | undefined;

    if (!sqlRow || columns.length === 0) {
      return;
    }

    const hasPasswordColumns = columns.some((column) => column.name === 'password_hash');
    const hasUpdatedAt = columns.some((column) => column.name === 'updated_at');
    const needsRoleMigration = sqlRow.sql.includes("'editor'") || sqlRow.sql.includes("'reader'");

    if (!needsRoleMigration && hasPasswordColumns && hasUpdatedAt) {
      return;
    }

    const hasColumn = (name: string): boolean => columns.some((column) => column.name === name);
    const now = new Date().toISOString();

    const tx = this.db.transaction(() => {
      this.db.pragma('foreign_keys = OFF');

      this.db.exec(`
        CREATE TABLE users_v2 (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
          is_active INTEGER NOT NULL DEFAULT 1,
          password_salt TEXT NOT NULL DEFAULT '',
          password_hash TEXT NOT NULL DEFAULT '',
          password_kdf TEXT NOT NULL DEFAULT 'scrypt',
          password_iterations INTEGER NOT NULL DEFAULT 16384,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);

      const sourceSelect = `
        SELECT
          id,
          username,
          CASE WHEN role = 'admin' THEN 'admin' ELSE 'user' END,
          ${hasColumn('is_active') ? 'is_active' : '1'},
          ${hasColumn('password_salt') ? 'password_salt' : "''"},
          ${hasColumn('password_hash') ? 'password_hash' : "''"},
          ${hasColumn('password_kdf') ? 'password_kdf' : "'scrypt'"},
          ${hasColumn('password_iterations') ? 'password_iterations' : '16384'},
          ${hasColumn('created_at') ? 'created_at' : `'${now}'`},
          ${hasColumn('updated_at') ? 'updated_at' : hasColumn('created_at') ? 'created_at' : `'${now}'`}
        FROM users
      `;

      this.db.exec(`
        INSERT INTO users_v2 (
          id,
          username,
          role,
          is_active,
          password_salt,
          password_hash,
          password_kdf,
          password_iterations,
          created_at,
          updated_at
        )
        ${sourceSelect};
      `);

      this.db.exec('DROP TABLE users;');
      this.db.exec('ALTER TABLE users_v2 RENAME TO users;');

      // This step ensures settings exist for migrated users.
      this.db.exec(`
        INSERT INTO user_settings (user_id, write_mode_enabled, updated_at)
        SELECT id, 0, '${now}' FROM users
        WHERE id NOT IN (SELECT user_id FROM user_settings)
      `);

      this.db.pragma('foreign_keys = ON');
    });

    tx();
  }

  // This method reads a state value from the app_state table.
  public getState(key: string): string | null {
    const row = this.db
      .prepare('SELECT value FROM app_state WHERE key = ?')
      .get(key) as { value: string } | undefined;

    return row?.value ?? null;
  }

  // This method writes a state value atomically.
  public setState(key: string, value: string): void {
    this.db
      .prepare(
        `
        INSERT INTO app_state (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = excluded.updated_at
      `
      )
      .run(key, value, new Date().toISOString());
  }

  // This helper provides a typed boolean for feature and lock flags.
  public getStateBool(key: string, defaultValue: boolean): boolean {
    const raw = this.getState(key);
    if (raw === null) {
      return defaultValue;
    }

    return raw === 'true';
  }

  // This helper stores booleans as string values for compatibility.
  public setStateBool(key: string, value: boolean): void {
    this.setState(key, value ? 'true' : 'false');
  }

  // This method stores the admin passphrase verifier for protected setup access.
  public setAdminVerifier(verifier: PassphraseVerifier): void {
    this.db
      .prepare(
        `
        INSERT INTO admin_credentials (id, salt_b64, iterations, hash_b64, created_at)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          salt_b64 = excluded.salt_b64,
          iterations = excluded.iterations,
          hash_b64 = excluded.hash_b64,
          created_at = excluded.created_at
      `
      )
      .run(verifier.saltB64, verifier.iterations, verifier.hashB64, new Date().toISOString());
  }

  // This method returns the stored passphrase verifier or null when setup has not been completed.
  public getAdminVerifier(): PassphraseVerifier | null {
    const row = this.db
      .prepare('SELECT salt_b64, iterations, hash_b64 FROM admin_credentials WHERE id = 1')
      .get() as { salt_b64: string; iterations: number; hash_b64: string } | undefined;

    if (!row) {
      return null;
    }

    return {
      saltB64: row.salt_b64,
      iterations: row.iterations,
      hashB64: row.hash_b64
    };
  }

  // This method returns true if at least one user already exists.
  public hasAnyUser(): boolean {
    const row = this.db.prepare('SELECT COUNT(1) AS count FROM users').get() as { count: number };
    return row.count > 0;
  }

  // This method creates one user with password credentials and initializes user settings.
  public createUser(input: {
    username: string;
    role: UserRole;
    passwordSalt: string;
    passwordHash: string;
    passwordKdf: string;
    passwordIterations: number;
    writeModeEnabled: boolean;
  }): number {
    const now = new Date().toISOString();

    const tx = this.db.transaction(() => {
      const userInsert = this.db
        .prepare(
          `
          INSERT INTO users (
            username,
            role,
            is_active,
            password_salt,
            password_hash,
            password_kdf,
            password_iterations,
            created_at,
            updated_at
          ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
        `
        )
        .run(
          input.username,
          input.role,
          input.passwordSalt,
          input.passwordHash,
          input.passwordKdf,
          input.passwordIterations,
          now,
          now
        );

      const userId = Number(userInsert.lastInsertRowid);
      this.db
        .prepare('INSERT INTO user_settings (user_id, write_mode_enabled, updated_at) VALUES (?, ?, ?)')
        .run(userId, input.writeModeEnabled ? 1 : 0, now);

      return userId;
    });

    try {
      return tx();
    } catch (error) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        throw new AppError(409, 'user_exists', `User ${input.username} already exists.`);
      }

      throw error;
    }
  }

  // This method toggles active state for one user account.
  public setUserActive(userId: number, active: boolean): void {
    const now = new Date().toISOString();
    const result = this.db
      .prepare('UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?')
      .run(active ? 1 : 0, now, userId);

    if (result.changes === 0) {
      throw new AppError(404, 'user_not_found', `User ${userId} not found.`);
    }
  }

  // This method returns all users with role and activity metadata.
  public listUsers(): StoredUser[] {
    const rows = this.db
      .prepare('SELECT id, username, role, is_active, created_at, updated_at FROM users ORDER BY id ASC')
      .all() as Array<{
      id: number;
      username: string;
      role: string;
      is_active: number;
      created_at: string;
      updated_at: string;
    }>;

    return rows.map((row) => ({
      id: row.id,
      username: row.username,
      role: row.role as UserRole,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  // This method resolves one user id and raises if the user is missing.
  public getUserById(userId: number): StoredUser {
    const row = this.db
      .prepare('SELECT id, username, role, is_active, created_at, updated_at FROM users WHERE id = ?')
      .get(userId) as
      | {
          id: number;
          username: string;
          role: string;
          is_active: number;
          created_at: string;
          updated_at: string;
        }
      | undefined;

    if (!row) {
      throw new AppError(404, 'user_not_found', `User ${userId} not found.`);
    }

    return {
      id: row.id,
      username: row.username,
      role: row.role as UserRole,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // This method loads one user with password auth fields for login verification.
  public getUserForLogin(username: string): UserAuthRow | null {
    const row = this.db
      .prepare(
        `
        SELECT id, username, role, is_active, password_salt, password_hash, password_kdf, password_iterations
        FROM users
        WHERE username = ?
        LIMIT 1
      `
      )
      .get(username) as UserAuthRow | undefined;

    return row ?? null;
  }

  // This method returns per-user write-mode settings.
  public getUserSettings(userId: number): UserSettings {
    const row = this.db
      .prepare('SELECT user_id, write_mode_enabled, updated_at FROM user_settings WHERE user_id = ?')
      .get(userId) as { user_id: number; write_mode_enabled: number; updated_at: string } | undefined;

    if (!row) {
      throw new AppError(404, 'user_settings_not_found', `No settings found for user ${userId}.`);
    }

    return {
      userId: row.user_id,
      writeModeEnabled: row.write_mode_enabled === 1,
      updatedAt: row.updated_at
    };
  }

  // This method toggles per-user write mode independently from other users.
  public setUserWriteMode(userId: number, enabled: boolean): void {
    const now = new Date().toISOString();
    this.getUserById(userId);

    this.db
      .prepare(
        `
        INSERT INTO user_settings (user_id, write_mode_enabled, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          write_mode_enabled = excluded.write_mode_enabled,
          updated_at = excluded.updated_at
      `
      )
      .run(userId, enabled ? 1 : 0, now);
  }

  // This method creates a new API key metadata row using a pre-hashed token.
  public createApiKey(userId: number, label: string, keyId: string, tokenHash: string): void {
    const now = new Date().toISOString();
    this.getUserById(userId);

    this.db
      .prepare(
        'INSERT INTO api_keys (key_id, user_id, label, token_hash, revoked, created_at) VALUES (?, ?, ?, ?, 0, ?)'
      )
      .run(keyId, userId, label, tokenHash, now);
  }

  // This method lists API keys either globally or for one user.
  public listApiKeys(userId?: number): StoredApiKey[] {
    const sql =
      userId === undefined
        ? `
          SELECT k.key_id, k.user_id, u.username, k.label, k.revoked, k.created_at, k.last_used_at
          FROM api_keys k
          JOIN users u ON u.id = k.user_id
          ORDER BY k.id DESC
        `
        : `
          SELECT k.key_id, k.user_id, u.username, k.label, k.revoked, k.created_at, k.last_used_at
          FROM api_keys k
          JOIN users u ON u.id = k.user_id
          WHERE k.user_id = ?
          ORDER BY k.id DESC
        `;

    const rows =
      userId === undefined
        ? (this.db.prepare(sql).all() as Array<{
            key_id: string;
            user_id: number;
            username: string;
            label: string;
            revoked: number;
            created_at: string;
            last_used_at: string | null;
          }>)
        : (this.db.prepare(sql).all(userId) as Array<{
            key_id: string;
            user_id: number;
            username: string;
            label: string;
            revoked: number;
            created_at: string;
            last_used_at: string | null;
          }>);

    return rows.map((row) => ({
      keyId: row.key_id,
      userId: row.user_id,
      username: row.username,
      label: row.label,
      revoked: row.revoked === 1,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at
    }));
  }

  // This method revokes an API key and optionally enforces ownership.
  public revokeApiKey(keyId: string, ownerUserId?: number): void {
    const result =
      ownerUserId === undefined
        ? this.db.prepare('UPDATE api_keys SET revoked = 1 WHERE key_id = ?').run(keyId)
        : this.db.prepare('UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND user_id = ?').run(keyId, ownerUserId);

    if (result.changes === 0) {
      throw new AppError(404, 'api_key_not_found', `API key ${keyId} not found.`);
    }
  }

  // This method verifies a hashed API token and returns the authenticated principal.
  public authenticateByTokenHash(tokenHash: string): AuthenticatedPrincipal | null {
    const row = this.db
      .prepare(
        `
        SELECT u.id AS user_id, u.username, u.role, k.key_id
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        WHERE k.token_hash = ?
          AND k.revoked = 0
          AND u.is_active = 1
        LIMIT 1
      `
      )
      .get(tokenHash) as AuthRow | undefined;

    if (!row) {
      return null;
    }

    this.db
      .prepare('UPDATE api_keys SET last_used_at = ? WHERE key_id = ?')
      .run(new Date().toISOString(), row.key_id);

    return {
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole,
      apiKeyId: row.key_id
    };
  }

  // This method creates one login session for browser-based UI authentication.
  public createSession(input: {
    sessionId: string;
    userId: number;
    tokenHash: string;
    expiresAt: string;
    ip?: string;
    userAgent?: string;
  }): void {
    const now = new Date().toISOString();

    this.db
      .prepare(
        `
        INSERT INTO sessions (session_id, user_id, token_hash, expires_at, created_at, last_seen_at, ip, user_agent, invalidated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
      `
      )
      .run(input.sessionId, input.userId, input.tokenHash, input.expiresAt, now, now, input.ip ?? null, input.userAgent ?? null);
  }

  // This method validates a hashed session token and returns a principal when active.
  public authenticateSessionByTokenHash(tokenHash: string): SessionPrincipal | null {
    const row = this.db
      .prepare(
        `
        SELECT s.session_id, s.user_id, u.username, u.role, s.expires_at, s.invalidated
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND u.is_active = 1
        LIMIT 1
      `
      )
      .get(tokenHash) as SessionRow | undefined;

    if (!row) {
      return null;
    }

    if (row.invalidated === 1) {
      return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return null;
    }

    this.db
      .prepare('UPDATE sessions SET last_seen_at = ? WHERE session_id = ?')
      .run(new Date().toISOString(), row.session_id);

    return {
      sessionId: row.session_id,
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole
    };
  }

  // This method invalidates one browser session by id.
  public invalidateSession(sessionId: string): void {
    this.db.prepare('UPDATE sessions SET invalidated = 1 WHERE session_id = ?').run(sessionId);
  }

  // This method sets the active Linkwarden base URL used by runtime clients.
  public setLinkwardenTarget(baseUrl: string): void {
    const now = new Date().toISOString();

    this.db
      .prepare(
        `
        INSERT INTO linkwarden_target (id, base_url, updated_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          base_url = excluded.base_url,
          updated_at = excluded.updated_at
      `
      )
      .run(baseUrl, now);
  }

  // This method returns the currently active Linkwarden base URL or null when unset.
  public getLinkwardenTarget(): LinkwardenTarget | null {
    const row = this.db
      .prepare('SELECT id, base_url, updated_at FROM linkwarden_target WHERE id = 1')
      .get() as { id: number; base_url: string; updated_at: string } | undefined;

    if (!row) {
      return null;
    }

    return {
      id: 1,
      baseUrl: row.base_url,
      updatedAt: row.updated_at
    };
  }

  // This method replaces whitelist entries atomically to keep allowlist policy coherent.
  public replaceWhitelist(entries: Array<{ type: WhitelistType; value: string }>): void {
    const now = new Date().toISOString();

    const tx = this.db.transaction(() => {
      this.db.prepare('DELETE FROM linkwarden_whitelist').run();
      const insert = this.db.prepare(
        'INSERT INTO linkwarden_whitelist (entry_type, entry_value, created_at) VALUES (?, ?, ?)'
      );

      for (const entry of entries) {
        insert.run(entry.type, entry.value, now);
      }
    });

    tx();
  }

  // This method lists all Linkwarden whitelist entries in deterministic order.
  public listWhitelist(): LinkwardenWhitelistEntry[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, entry_type, entry_value, created_at
        FROM linkwarden_whitelist
        ORDER BY id ASC
      `
      )
      .all() as Array<{ id: number; entry_type: string; entry_value: string; created_at: string }>;

    return rows.map((row) => ({
      id: row.id,
      type: row.entry_type as WhitelistType,
      value: row.entry_value,
      createdAt: row.created_at
    }));
  }

  // This method persists a generated reorganization plan together with all item changes.
  public createPlan(input: {
    planId: string;
    strategy: PlanStrategy;
    parameters: Record<string, unknown>;
    scope?: PlanScope;
    summary: PlanSummary;
    warnings: string[];
    items: PlanItem[];
    createdBy: string;
    expiresAt: string;
  }): void {
    const now = new Date().toISOString();
    const insertPlan = this.db.prepare(
      `
      INSERT INTO plans (
        plan_id,
        strategy,
        parameters_json,
        scope_json,
        summary_json,
        warnings_json,
        created_by,
        created_at,
        expires_at,
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')
    `
    );

    const insertItem = this.db.prepare(
      `
      INSERT INTO plan_items (plan_id, link_id, action, before_json, after_json, warning)
      VALUES (?, ?, ?, ?, ?, ?)
    `
    );

    const tx = this.db.transaction(() => {
      insertPlan.run(
        input.planId,
        input.strategy,
        JSON.stringify(input.parameters),
        input.scope ? JSON.stringify(input.scope) : null,
        JSON.stringify(input.summary),
        JSON.stringify(input.warnings),
        input.createdBy,
        now,
        input.expiresAt
      );

      for (const item of input.items) {
        insertItem.run(
          input.planId,
          item.linkId,
          item.action,
          JSON.stringify(item.before),
          JSON.stringify(item.after),
          item.warning ?? null
        );
      }
    });

    tx();
  }

  // This method fetches a plan and all items so apply can be validated and executed safely.
  public getPlanWithItems(
    planId: string
  ):
    | {
        plan: StoredPlan;
        items: PlanItem[];
      }
    | null {
    const row = this.db.prepare('SELECT * FROM plans WHERE plan_id = ?').get(planId) as PlanRow | undefined;

    if (!row) {
      return null;
    }

    const itemRows = this.db
      .prepare(
        'SELECT link_id, action, before_json, after_json, warning FROM plan_items WHERE plan_id = ? ORDER BY id ASC'
      )
      .all(planId) as PlanItemRow[];

    const plan: StoredPlan = {
      planId: row.plan_id,
      strategy: row.strategy as PlanStrategy,
      parameters: parseJson<Record<string, unknown>>(row.parameters_json, 'plans.parameters_json'),
      scope: row.scope_json ? parseJson<PlanScope>(row.scope_json, 'plans.scope_json') : undefined,
      summary: parseJson<PlanSummary>(row.summary_json, 'plans.summary_json'),
      warnings: parseJson<string[]>(row.warnings_json, 'plans.warnings_json'),
      createdBy: row.created_by,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      status: row.status as StoredPlan['status'],
      appliedAt: row.applied_at
    };

    const items: PlanItem[] = itemRows.map((item) => ({
      linkId: item.link_id,
      action: item.action,
      before: parseJson<Record<string, unknown>>(item.before_json, 'plan_items.before_json'),
      after: parseJson<Record<string, unknown>>(item.after_json, 'plan_items.after_json'),
      warning: item.warning ?? undefined
    }));

    return { plan, items };
  }

  // This method marks a plan status transition and records applied timestamp when relevant.
  public updatePlanStatus(planId: string, status: StoredPlan['status']): void {
    const appliedAt = status === 'applied' ? new Date().toISOString() : null;

    const result = this.db
      .prepare('UPDATE plans SET status = ?, applied_at = COALESCE(?, applied_at) WHERE plan_id = ?')
      .run(status, appliedAt, planId);

    if (result.changes === 0) {
      throw new AppError(404, 'plan_not_found', `Plan ${planId} not found.`);
    }
  }

  // This method records an apply run lifecycle entry for observability and failure analysis.
  public createPlanRun(planId: string): number {
    const result = this.db
      .prepare('INSERT INTO plan_runs (plan_id, started_at, status) VALUES (?, ?, ?)')
      .run(planId, new Date().toISOString(), 'running');

    return Number(result.lastInsertRowid);
  }

  // This method finalizes a plan run with success or failure summary details.
  public finishPlanRun(runId: number, status: 'success' | 'failed', result: Record<string, unknown>): void {
    this.db
      .prepare('UPDATE plan_runs SET ended_at = ?, status = ?, results_json = ? WHERE id = ?')
      .run(new Date().toISOString(), status, JSON.stringify(result), runId);
  }

  // This method persists one audit entry for each write operation.
  public insertAudit(entry: AuditEntry): void {
    this.db
      .prepare(
        `
      INSERT INTO audit_log (
        timestamp,
        actor,
        tool_name,
        target_type,
        target_ids_json,
        before_summary,
        after_summary,
        outcome,
        details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .run(
        new Date().toISOString(),
        entry.actor,
        entry.toolName,
        entry.targetType,
        JSON.stringify(entry.targetIds),
        entry.beforeSummary,
        entry.afterSummary,
        entry.outcome,
        entry.details ? JSON.stringify(entry.details) : null
      );
  }

  // This method allows a clean shutdown of SQLite resources.
  public close(): void {
    this.db.close();
  }
}
