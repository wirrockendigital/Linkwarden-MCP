// This module owns SQLite initialization and persistence operations for state, users, sessions, plans, and audits.

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PassphraseVerifier } from '../config/crypto.js';
import type {
  AuditEntry,
  AuthenticatedPrincipal,
  EncryptedSecret,
  LinkHealthState,
  MaintenanceRunItem,
  LinkwardenTarget,
  OAuthAuthorizationCodeRecord,
  OAuthClientRecord,
  OAuthTokenRecord,
  PlanItem,
  PlanScope,
  PlanSummary,
  PlanStrategy,
  SessionPrincipal,
  StoredPlan,
  UserRole,
  UserSettings
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

interface OAuthClientRow {
  client_id: string;
  client_name: string;
  redirect_uris_json: string;
  token_endpoint_auth_method: string;
  client_secret_hash: string | null;
  created_at: string;
  updated_at: string;
  is_active: number;
}

interface OAuthAuthorizationCodeRow {
  user_id: number;
  username: string;
  role: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  resource: string;
  expires_at: string;
  used_at: string | null;
}

interface OAuthTokenAuthRow {
  token_id: string;
  user_id: number;
  username: string;
  role: string;
  client_id: string;
  scope: string;
  resource: string;
  access_expires_at: string;
  refresh_expires_at: string;
  revoked: number;
}

interface OAuthRefreshRow {
  token_id: string;
  user_id: number;
  username: string;
  role: string;
  client_id: string;
  scope: string;
  resource: string;
  access_expires_at: string;
  refresh_expires_at: string;
  revoked: number;
}

interface LinkHealthStateRow {
  user_id: number;
  link_id: number;
  url: string;
  first_failure_at: string | null;
  last_failure_at: string | null;
  consecutive_failures: number;
  last_status: string;
  last_checked_at: string;
  last_http_status: number | null;
  last_error: string | null;
  archived_at: string | null;
}

interface MaintenanceLockRow {
  user_id: number;
  lock_token: string;
  expires_at: string;
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
        offline_days INTEGER NOT NULL DEFAULT 14,
        offline_min_consecutive_failures INTEGER NOT NULL DEFAULT 3,
        offline_action TEXT NOT NULL DEFAULT 'archive' CHECK (offline_action IN ('archive', 'delete', 'none')),
        offline_archive_collection_id INTEGER,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS user_linkwarden_tokens (
        user_id INTEGER PRIMARY KEY,
        token_enc TEXT NOT NULL,
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

      CREATE INDEX IF NOT EXISTS idx_user_linkwarden_tokens_user_id ON user_linkwarden_tokens(user_id);

      CREATE TABLE IF NOT EXISTS oauth_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL UNIQUE,
        client_name TEXT NOT NULL,
        redirect_uris_json TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none', 'client_secret_post')),
        client_secret_hash TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
        code_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        code_challenge_method TEXT NOT NULL CHECK (code_challenge_method IN ('S256')),
        scope TEXT NOT NULL,
        resource TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_user_id
      ON oauth_authorization_codes(user_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_client_id
      ON oauth_authorization_codes(client_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expires_at
      ON oauth_authorization_codes(expires_at);

      CREATE TABLE IF NOT EXISTS oauth_tokens (
        token_id TEXT NOT NULL UNIQUE,
        access_token_hash TEXT NOT NULL PRIMARY KEY,
        refresh_token_hash TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT NOT NULL,
        access_expires_at TEXT NOT NULL,
        refresh_expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_used_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client_id ON oauth_tokens(client_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh_token_hash ON oauth_tokens(refresh_token_hash);
      CREATE INDEX IF NOT EXISTS idx_oauth_tokens_access_expires_at ON oauth_tokens(access_expires_at);

      CREATE TABLE IF NOT EXISTS linkwarden_target (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        base_url TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

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

      CREATE TABLE IF NOT EXISTS link_health_state (
        user_id INTEGER NOT NULL,
        link_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        first_failure_at TEXT,
        last_failure_at TEXT,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        last_status TEXT NOT NULL CHECK (last_status IN ('up', 'down')),
        last_checked_at TEXT NOT NULL,
        last_http_status INTEGER,
        last_error TEXT,
        archived_at TEXT,
        PRIMARY KEY (user_id, link_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_link_health_state_user_status
      ON link_health_state(user_id, last_status, last_checked_at);

      CREATE TABLE IF NOT EXISTS maintenance_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        mode TEXT NOT NULL CHECK (mode IN ('dry_run', 'apply')),
        reorg_plan_id TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
        summary_json TEXT,
        error_json TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_maintenance_runs_user_started
      ON maintenance_runs(user_id, started_at DESC);

      CREATE TABLE IF NOT EXISTS maintenance_run_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        item_type TEXT NOT NULL CHECK (item_type IN ('reorg', 'offline')),
        link_id INTEGER,
        action TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failed', 'skipped')),
        details_json TEXT,
        FOREIGN KEY(run_id) REFERENCES maintenance_runs(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_maintenance_run_items_run_id
      ON maintenance_run_items(run_id);

      CREATE TABLE IF NOT EXISTS maintenance_locks (
        user_id INTEGER PRIMARY KEY,
        lock_token TEXT NOT NULL,
        acquired_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    this.migrateUsersTableIfNeeded();
    this.migrateUserSettingsTableIfNeeded();
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

  // This migration upgrades older user_settings schemas to include per-user offline maintenance policy fields.
  private migrateUserSettingsTableIfNeeded(): void {
    const columns = this.db
      .prepare('PRAGMA table_info(user_settings)')
      .all() as Array<{ name: string }>;

    if (columns.length === 0) {
      return;
    }

    const hasColumn = (name: string): boolean => columns.some((column) => column.name === name);

    if (!hasColumn('offline_days')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN offline_days INTEGER NOT NULL DEFAULT 14;');
    }

    if (!hasColumn('offline_min_consecutive_failures')) {
      this.db.exec(
        'ALTER TABLE user_settings ADD COLUMN offline_min_consecutive_failures INTEGER NOT NULL DEFAULT 3;'
      );
    }

    if (!hasColumn('offline_action')) {
      this.db.exec(
        "ALTER TABLE user_settings ADD COLUMN offline_action TEXT NOT NULL DEFAULT 'archive' CHECK (offline_action IN ('archive', 'delete', 'none'));"
      );
    }

    if (!hasColumn('offline_archive_collection_id')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN offline_archive_collection_id INTEGER;');
    }
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
      .prepare(
        `
        SELECT
          user_id,
          write_mode_enabled,
          offline_days,
          offline_min_consecutive_failures,
          offline_action,
          offline_archive_collection_id,
          updated_at
        FROM user_settings
        WHERE user_id = ?
      `
      )
      .get(userId) as
      | {
          user_id: number;
          write_mode_enabled: number;
          offline_days: number;
          offline_min_consecutive_failures: number;
          offline_action: 'archive' | 'delete' | 'none';
          offline_archive_collection_id: number | null;
          updated_at: string;
        }
      | undefined;

    if (!row) {
      throw new AppError(404, 'user_settings_not_found', `No settings found for user ${userId}.`);
    }

    return {
      userId: row.user_id,
      writeModeEnabled: row.write_mode_enabled === 1,
      offlineDays: row.offline_days,
      offlineMinConsecutiveFailures: row.offline_min_consecutive_failures,
      offlineAction: row.offline_action,
      offlineArchiveCollectionId: row.offline_archive_collection_id,
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

  // This method updates per-user offline maintenance policy settings used by monitor and maintenance tools.
  public setUserOfflinePolicy(
    userId: number,
    policy: {
      offlineDays: number;
      offlineMinConsecutiveFailures: number;
      offlineAction: 'archive' | 'delete' | 'none';
      offlineArchiveCollectionId: number | null;
    }
  ): void {
    const now = new Date().toISOString();
    this.getUserById(userId);
    const existing = this.db
      .prepare('SELECT write_mode_enabled FROM user_settings WHERE user_id = ?')
      .get(userId) as { write_mode_enabled: number } | undefined;
    const writeModeEnabled = existing?.write_mode_enabled === 1 ? 1 : 0;

    this.db
      .prepare(
        `
        INSERT INTO user_settings (
          user_id,
          write_mode_enabled,
          offline_days,
          offline_min_consecutive_failures,
          offline_action,
          offline_archive_collection_id,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          offline_days = excluded.offline_days,
          offline_min_consecutive_failures = excluded.offline_min_consecutive_failures,
          offline_action = excluded.offline_action,
          offline_archive_collection_id = excluded.offline_archive_collection_id,
          updated_at = excluded.updated_at
      `
      )
      .run(
        userId,
        writeModeEnabled,
        policy.offlineDays,
        policy.offlineMinConsecutiveFailures,
        policy.offlineAction,
        policy.offlineArchiveCollectionId,
        now
      );
  }

  // This method stores the encrypted Linkwarden API token for a specific user.
  public setUserLinkwardenToken(userId: number, token: EncryptedSecret): void {
    const now = new Date().toISOString();
    this.getUserById(userId);

    this.db
      .prepare(
        `
        INSERT INTO user_linkwarden_tokens (user_id, token_enc, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          token_enc = excluded.token_enc,
          updated_at = excluded.updated_at
      `
      )
      .run(userId, JSON.stringify(token), now);
  }

  // This method returns the encrypted Linkwarden API token for a user, if configured.
  public getUserLinkwardenToken(userId: number): EncryptedSecret | null {
    const row = this.db
      .prepare('SELECT token_enc FROM user_linkwarden_tokens WHERE user_id = ?')
      .get(userId) as { token_enc: string } | undefined;

    if (!row) {
      return null;
    }

    return parseJson<EncryptedSecret>(row.token_enc, 'user_linkwarden_tokens.token_enc');
  }

  // This method checks whether a user has configured a Linkwarden API token.
  public hasUserLinkwardenToken(userId: number): boolean {
    const row = this.db
      .prepare('SELECT 1 AS present FROM user_linkwarden_tokens WHERE user_id = ? LIMIT 1')
      .get(userId) as { present: number } | undefined;

    return Boolean(row?.present);
  }

  // This method returns one active user with a configured Linkwarden token, preferring admins.
  public getAnyUserWithLinkwardenToken(): { userId: number; role: UserRole } | null {
    const row = this.db
      .prepare(
        `
        SELECT u.id AS user_id, u.role
        FROM users u
        JOIN user_linkwarden_tokens t ON t.user_id = u.id
        WHERE u.is_active = 1
        ORDER BY CASE WHEN u.role = 'admin' THEN 0 ELSE 1 END, u.id ASC
        LIMIT 1
      `
      )
      .get() as { user_id: number; role: string } | undefined;

    if (!row) {
      return null;
    }

    return {
      userId: row.user_id,
      role: row.role as UserRole
    };
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

  // This method creates or updates one OAuth client registration record.
  public upsertOAuthClient(input: {
    clientId: string;
    clientName: string;
    redirectUris: string[];
    tokenEndpointAuthMethod: 'none' | 'client_secret_post';
    clientSecretHash?: string;
  }): OAuthClientRecord {
    const now = new Date().toISOString();

    this.db
      .prepare(
        `
        INSERT INTO oauth_clients (
          client_id,
          client_name,
          redirect_uris_json,
          token_endpoint_auth_method,
          client_secret_hash,
          is_active,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET
          client_name = excluded.client_name,
          redirect_uris_json = excluded.redirect_uris_json,
          token_endpoint_auth_method = excluded.token_endpoint_auth_method,
          client_secret_hash = excluded.client_secret_hash,
          is_active = 1,
          updated_at = excluded.updated_at
      `
      )
      .run(
        input.clientId,
        input.clientName,
        JSON.stringify(input.redirectUris),
        input.tokenEndpointAuthMethod,
        input.clientSecretHash ?? null,
        now,
        now
      );

    const client = this.getOAuthClient(input.clientId);
    if (!client) {
      throw new AppError(500, 'oauth_client_store_failed', 'Failed to persist OAuth client.');
    }

    return client;
  }

  // This method returns one OAuth client by client-id when active.
  public getOAuthClient(clientId: string): OAuthClientRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT
          client_id,
          client_name,
          redirect_uris_json,
          token_endpoint_auth_method,
          client_secret_hash,
          created_at,
          updated_at,
          is_active
        FROM oauth_clients
        WHERE client_id = ?
        LIMIT 1
      `
      )
      .get(clientId) as OAuthClientRow | undefined;

    if (!row || row.is_active !== 1) {
      return null;
    }

    return {
      clientId: row.client_id,
      clientName: row.client_name,
      redirectUris: parseJson<string[]>(row.redirect_uris_json, 'oauth_clients.redirect_uris_json'),
      tokenEndpointAuthMethod: row.token_endpoint_auth_method as OAuthClientRecord['tokenEndpointAuthMethod'],
      clientSecretHash: row.client_secret_hash ?? undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // This method stores one short-lived OAuth authorization code for later token exchange.
  public createOAuthAuthorizationCode(input: {
    codeHash: string;
    userId: number;
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    codeChallengeMethod: 'S256';
    scope: string;
    resource: string;
    expiresAt: string;
  }): void {
    const now = new Date().toISOString();
    this.getUserById(input.userId);

    this.db
      .prepare(
        `
        INSERT INTO oauth_authorization_codes (
          code_hash,
          user_id,
          client_id,
          redirect_uri,
          code_challenge,
          code_challenge_method,
          scope,
          resource,
          expires_at,
          used_at,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
      `
      )
      .run(
        input.codeHash,
        input.userId,
        input.clientId,
        input.redirectUri,
        input.codeChallenge,
        input.codeChallengeMethod,
        input.scope,
        input.resource,
        input.expiresAt,
        now
      );
  }

  // This method atomically consumes one OAuth authorization code and rejects replay attempts.
  public consumeOAuthAuthorizationCode(
    codeHash: string,
    clientId: string,
    redirectUri: string
  ): OAuthAuthorizationCodeRecord | null {
    const nowIso = new Date().toISOString();

    const tx = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `
          SELECT
            c.user_id,
            u.username,
            u.role,
            c.client_id,
            c.redirect_uri,
            c.code_challenge,
            c.code_challenge_method,
            c.scope,
            c.resource,
            c.expires_at,
            c.used_at
          FROM oauth_authorization_codes c
          JOIN users u ON u.id = c.user_id
          WHERE c.code_hash = ?
            AND c.client_id = ?
            AND c.redirect_uri = ?
            AND u.is_active = 1
          LIMIT 1
        `
        )
        .get(codeHash, clientId, redirectUri) as OAuthAuthorizationCodeRow | undefined;

      if (!row) {
        return null;
      }

      if (row.used_at !== null) {
        return null;
      }

      if (new Date(row.expires_at).getTime() <= Date.now()) {
        return null;
      }

      const result = this.db
        .prepare('UPDATE oauth_authorization_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL')
        .run(nowIso, codeHash);
      if (result.changes !== 1) {
        return null;
      }

      return {
        userId: row.user_id,
        username: row.username,
        role: row.role as UserRole,
        clientId: row.client_id,
        redirectUri: row.redirect_uri,
        codeChallenge: row.code_challenge,
        codeChallengeMethod: row.code_challenge_method as OAuthAuthorizationCodeRecord['codeChallengeMethod'],
        scope: row.scope,
        resource: row.resource,
        expiresAt: row.expires_at
      } satisfies OAuthAuthorizationCodeRecord;
    });

    return tx();
  }

  // This method stores one OAuth access+refresh token pair.
  public createOAuthToken(input: {
    tokenId: string;
    accessTokenHash: string;
    refreshTokenHash: string;
    userId: number;
    clientId: string;
    scope: string;
    resource: string;
    accessExpiresAt: string;
    refreshExpiresAt: string;
  }): void {
    const now = new Date().toISOString();
    this.getUserById(input.userId);

    this.db
      .prepare(
        `
        INSERT INTO oauth_tokens (
          token_id,
          access_token_hash,
          refresh_token_hash,
          user_id,
          client_id,
          scope,
          resource,
          access_expires_at,
          refresh_expires_at,
          revoked,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      `
      )
      .run(
        input.tokenId,
        input.accessTokenHash,
        input.refreshTokenHash,
        input.userId,
        input.clientId,
        input.scope,
        input.resource,
        input.accessExpiresAt,
        input.refreshExpiresAt,
        now,
        now
      );
  }

  // This method validates OAuth bearer tokens for MCP access and updates last-used metadata.
  public authenticateOAuthAccessToken(tokenHash: string, acceptedResources: string[]): AuthenticatedPrincipal | null {
    const row = this.db
      .prepare(
        `
        SELECT
          t.token_id,
          t.user_id,
          u.username,
          u.role,
          t.client_id,
          t.scope,
          t.resource,
          t.access_expires_at,
          t.refresh_expires_at,
          t.revoked
        FROM oauth_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.access_token_hash = ?
          AND u.is_active = 1
        LIMIT 1
      `
      )
      .get(tokenHash) as OAuthTokenAuthRow | undefined;

    if (!row || row.revoked === 1) {
      return null;
    }

    if (new Date(row.access_expires_at).getTime() <= Date.now()) {
      return null;
    }

    if (!acceptedResources.includes(row.resource)) {
      return null;
    }

    this.db
      .prepare('UPDATE oauth_tokens SET last_used_at = ?, updated_at = ? WHERE token_id = ?')
      .run(new Date().toISOString(), new Date().toISOString(), row.token_id);

    return {
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole,
      apiKeyId: `oauth:${row.token_id}`
    };
  }

  // This helper maps one OAuth refresh-token row into the shared token record domain shape.
  private mapOAuthRefreshRowToTokenRecord(row: OAuthRefreshRow): OAuthTokenRecord {
    return {
      tokenId: row.token_id,
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole,
      clientId: row.client_id,
      scope: row.scope,
      resource: row.resource,
      accessExpiresAt: row.access_expires_at,
      refreshExpiresAt: row.refresh_expires_at
    } satisfies OAuthTokenRecord;
  }

  // This method reads one refresh token without revoking it so callers can validate client/resource first.
  public getOAuthRefreshToken(refreshTokenHash: string): OAuthTokenRecord | null {
    const row = this.db
      .prepare(
        `
          SELECT
            t.token_id,
            t.user_id,
            u.username,
            u.role,
            t.client_id,
            t.scope,
            t.resource,
            t.access_expires_at,
            t.refresh_expires_at,
            t.revoked
          FROM oauth_tokens t
          JOIN users u ON u.id = t.user_id
          WHERE t.refresh_token_hash = ?
            AND u.is_active = 1
          LIMIT 1
        `
      )
      .get(refreshTokenHash) as OAuthRefreshRow | undefined;

    if (!row || row.revoked === 1) {
      return null;
    }

    if (new Date(row.refresh_expires_at).getTime() <= Date.now()) {
      return null;
    }

    return this.mapOAuthRefreshRowToTokenRecord(row);
  }

  // This method consumes a refresh token and revokes it to enforce refresh rotation.
  public consumeOAuthRefreshToken(refreshTokenHash: string, expectedClientId?: string): OAuthTokenRecord | null {
    const nowIso = new Date().toISOString();

    const tx = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `
          SELECT
            t.token_id,
            t.user_id,
            u.username,
            u.role,
            t.client_id,
            t.scope,
            t.resource,
            t.access_expires_at,
            t.refresh_expires_at,
            t.revoked
          FROM oauth_tokens t
          JOIN users u ON u.id = t.user_id
          WHERE t.refresh_token_hash = ?
            AND u.is_active = 1
          LIMIT 1
        `
        )
        .get(refreshTokenHash) as OAuthRefreshRow | undefined;

      if (!row || row.revoked === 1) {
        return null;
      }

      if (new Date(row.refresh_expires_at).getTime() <= Date.now()) {
        return null;
      }

      // This client binding guard prevents revocation when the caller presents a mismatched client id.
      if (expectedClientId && row.client_id !== expectedClientId) {
        return null;
      }

      const result = this.db
        .prepare('UPDATE oauth_tokens SET revoked = 1, updated_at = ? WHERE token_id = ? AND revoked = 0')
        .run(nowIso, row.token_id);
      if (result.changes !== 1) {
        return null;
      }

      return this.mapOAuthRefreshRowToTokenRecord(row);
    });

    return tx();
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

  // This method creates one daily-maintenance run entry before workflow execution starts.
  public createMaintenanceRun(input: { userId: number; mode: 'dry_run' | 'apply' }): number {
    this.getUserById(input.userId);
    const now = new Date().toISOString();
    const result = this.db
      .prepare(
        `
        INSERT INTO maintenance_runs (user_id, started_at, mode, status)
        VALUES (?, ?, ?, 'running')
      `
      )
      .run(input.userId, now, input.mode);

    return Number(result.lastInsertRowid);
  }

  // This method attaches a generated reorg plan id to one maintenance run.
  public setMaintenanceRunReorgPlanId(runId: number, planId: string): void {
    this.db.prepare('UPDATE maintenance_runs SET reorg_plan_id = ? WHERE id = ?').run(planId, runId);
  }

  // This method stores step-level or link-level maintenance run item records.
  public insertMaintenanceRunItems(
    runId: number,
    items: Array<{
      itemType: MaintenanceRunItem['itemType'];
      linkId?: number | null;
      action: string;
      outcome: MaintenanceRunItem['outcome'];
      details?: Record<string, unknown>;
    }>
  ): void {
    if (items.length === 0) {
      return;
    }

    const insert = this.db.prepare(
      `
      INSERT INTO maintenance_run_items (run_id, item_type, link_id, action, outcome, details_json)
      VALUES (?, ?, ?, ?, ?, ?)
    `
    );

    const tx = this.db.transaction(() => {
      for (const item of items) {
        insert.run(runId, item.itemType, item.linkId ?? null, item.action, item.outcome, JSON.stringify(item.details ?? {}));
      }
    });

    tx();
  }

  // This method finalizes a maintenance run with summary payload and optional error details.
  public finishMaintenanceRun(input: {
    runId: number;
    status: 'success' | 'failed';
    summary: Record<string, unknown>;
    error?: Record<string, unknown>;
  }): void {
    this.db
      .prepare(
        `
        UPDATE maintenance_runs
        SET ended_at = ?, status = ?, summary_json = ?, error_json = ?
        WHERE id = ?
      `
      )
      .run(
        new Date().toISOString(),
        input.status,
        JSON.stringify(input.summary),
        input.error ? JSON.stringify(input.error) : null,
        input.runId
      );
  }

  // This method acquires a per-user maintenance lock and returns false when another active lock exists.
  public acquireMaintenanceLock(userId: number, lockToken: string, ttlSeconds = 1800): boolean {
    this.getUserById(userId);
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const result = this.db
      .prepare(
        `
        INSERT INTO maintenance_locks (user_id, lock_token, acquired_at, expires_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          lock_token = excluded.lock_token,
          acquired_at = excluded.acquired_at,
          expires_at = excluded.expires_at,
          updated_at = excluded.updated_at
        WHERE maintenance_locks.expires_at <= excluded.acquired_at
      `
      )
      .run(userId, lockToken, now, expiresAt, now);

    return result.changes > 0;
  }

  // This method releases a per-user maintenance lock only when the lock token matches.
  public releaseMaintenanceLock(userId: number, lockToken: string): void {
    this.db.prepare('DELETE FROM maintenance_locks WHERE user_id = ? AND lock_token = ?').run(userId, lockToken);
  }

  // This method returns active lock metadata for diagnostics or conflict messages.
  public getActiveMaintenanceLock(userId: number): { lockToken: string; expiresAt: string } | null {
    const row = this.db
      .prepare(
        `
        SELECT user_id, lock_token, expires_at
        FROM maintenance_locks
        WHERE user_id = ?
        LIMIT 1
      `
      )
      .get(userId) as MaintenanceLockRow | undefined;

    if (!row) {
      return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      this.db.prepare('DELETE FROM maintenance_locks WHERE user_id = ?').run(userId);
      return null;
    }

    return {
      lockToken: row.lock_token,
      expiresAt: row.expires_at
    };
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

  // This method returns stored health-state snapshots for selected links of one user.
  public listLinkHealthStates(userId: number, linkIds: number[]): LinkHealthState[] {
    if (linkIds.length === 0) {
      return [];
    }

    const placeholders = linkIds.map(() => '?').join(', ');
    const rows = this.db
      .prepare(
        `
        SELECT
          user_id,
          link_id,
          url,
          first_failure_at,
          last_failure_at,
          consecutive_failures,
          last_status,
          last_checked_at,
          last_http_status,
          last_error,
          archived_at
        FROM link_health_state
        WHERE user_id = ?
          AND link_id IN (${placeholders})
      `
      )
      .all(userId, ...linkIds) as LinkHealthStateRow[];

    return rows.map((row) => ({
      userId: row.user_id,
      linkId: row.link_id,
      url: row.url,
      firstFailureAt: row.first_failure_at,
      lastFailureAt: row.last_failure_at,
      consecutiveFailures: row.consecutive_failures,
      lastStatus: row.last_status as LinkHealthState['lastStatus'],
      lastCheckedAt: row.last_checked_at,
      lastHttpStatus: row.last_http_status,
      lastError: row.last_error,
      archivedAt: row.archived_at
    }));
  }

  // This method upserts one link health-state snapshot after each monitor run.
  public upsertLinkHealthState(state: LinkHealthState): void {
    this.db
      .prepare(
        `
        INSERT INTO link_health_state (
          user_id,
          link_id,
          url,
          first_failure_at,
          last_failure_at,
          consecutive_failures,
          last_status,
          last_checked_at,
          last_http_status,
          last_error,
          archived_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, link_id) DO UPDATE SET
          url = excluded.url,
          first_failure_at = excluded.first_failure_at,
          last_failure_at = excluded.last_failure_at,
          consecutive_failures = excluded.consecutive_failures,
          last_status = excluded.last_status,
          last_checked_at = excluded.last_checked_at,
          last_http_status = excluded.last_http_status,
          last_error = excluded.last_error,
          archived_at = excluded.archived_at
      `
      )
      .run(
        state.userId,
        state.linkId,
        state.url,
        state.firstFailureAt,
        state.lastFailureAt,
        state.consecutiveFailures,
        state.lastStatus,
        state.lastCheckedAt,
        state.lastHttpStatus,
        state.lastError,
        state.archivedAt
      );
  }

  // This method marks a link as archived in health-state tracking after successful archival move.
  public markLinkHealthArchived(userId: number, linkId: number): void {
    this.db
      .prepare('UPDATE link_health_state SET archived_at = ? WHERE user_id = ? AND link_id = ?')
      .run(new Date().toISOString(), userId, linkId);
  }

  // This method allows a clean shutdown of SQLite resources.
  public close(): void {
    this.db.close();
  }
}
