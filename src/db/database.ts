// This module owns SQLite initialization and persistence operations for state, users, sessions, plans, and audits.

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PassphraseVerifier } from '../config/crypto.js';
import type {
  AiChangeActionType,
  AiChangeLogFacets,
  AiChangeLogFilters,
  AiChangeLogRecord,
  AiChangeUndoStatus,
  AuditEntry,
  AuthenticatedPrincipal,
  EncryptedSecret,
  FetchMode,
  GlobalTaggingPolicy,
  NewLinksCursor,
  NewLinksRoutineModule,
  NewLinksRoutineSettings,
  LinkHealthState,
  LinkContextCacheRecord,
  LinkSelector,
  TagAliasRecord,
  TagCandidateRecord,
  TaggingInferenceProvider,
  TaggingStrictness,
  MaintenanceRunItem,
  LinkwardenTarget,
  OperationItemRecord,
  OperationRecord,
  OAuthAuthorizationCodeRecord,
  OAuthClientRecord,
  OAuthTokenRecord,
  PlanItem,
  PlanScope,
  PlanSummary,
  PlanStrategy,
  RuleRecord,
  SavedQueryRecord,
  SessionPrincipal,
  StoredPlan,
  UserRole,
  UserChatControlSettings,
  UserSettings
} from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { parseJson } from '../utils/json.js';
import { normalizeResourceValue } from '../utils/oauth.js';

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

// This helper normalizes resource strings and checks whether one OAuth token resource is accepted for this request.
function isAcceptedOAuthResource(resource: string, acceptedResources: string[]): boolean {
  const normalizedResource = normalizeResourceValue(resource);
  if (normalizedResource.length === 0) {
    return false;
  }

  for (const accepted of acceptedResources) {
    if (normalizeResourceValue(accepted) === normalizedResource) {
      return true;
    }
  }

  return false;
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
  tool_scopes_json: string;
  collection_scopes_json: string;
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

interface SavedQueryRow {
  id: string;
  user_id: number;
  name: string;
  selector_json: string;
  fields_json: string;
  verbosity: 'minimal' | 'normal' | 'debug';
  created_at: string;
  updated_at: string;
}

interface RuleRow {
  id: string;
  user_id: number;
  name: string;
  selector_json: string;
  action_json: string;
  schedule_json: string;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface OperationRow {
  id: string;
  user_id: number;
  tool_name: string;
  summary_json: string;
  undo_until: string | null;
  created_at: string;
}

interface OperationItemRow {
  operation_id: string;
  item_type: string;
  item_id: number;
  before_json: string;
  after_json: string;
  undo_status: 'pending' | 'applied' | 'failed';
}

interface TagAliasRow {
  user_id: number;
  canonical_tag_id: number;
  alias_normalized: string;
  confidence: number;
  created_at: string;
  updated_at: string;
}

interface TagCandidateRow {
  user_id: number;
  candidate_normalized: string;
  support_count: number;
  first_seen_at: string;
  last_seen_at: string;
  blocked_reason: string | null;
}

interface LinkContextCacheRow {
  user_id: number;
  link_id: number;
  context_hash: string;
  extracted_tokens_json: string;
  expires_at: string;
  updated_at: string;
}

interface NewLinksRoutineUserRow {
  id: number;
  username: string;
  role: string;
}

interface UserChatControlRow {
  user_id: number;
  archive_collection_name: string;
  archive_collection_parent_id: number | null;
  chat_capture_tag_name: string;
  chat_capture_tag_ai_chat_enabled: number;
  chat_capture_tag_ai_name_enabled: number;
  ai_activity_retention_days: number;
  updated_at: string;
}

interface AiChangeLogRow {
  id: number;
  user_id: number;
  operation_id: string;
  operation_item_id: number;
  tool_name: string;
  action_type: string;
  link_id: number | null;
  link_title: string | null;
  url_before: string | null;
  url_after: string | null;
  tracking_trimmed: number;
  collection_from_id: number | null;
  collection_from_name: string | null;
  collection_to_id: number | null;
  collection_to_name: string | null;
  tags_added_json: string;
  tags_removed_json: string;
  changed_at: string;
  undo_status: 'pending' | 'applied' | 'conflict' | 'failed';
  undone_at: string | null;
  undo_operation_id: string | null;
  meta_json: string | null;
}

interface AiChangeUndoCandidateRow extends AiChangeLogRow {
  before_json: string;
  after_json: string;
  undo_until: string | null;
  has_newer_open_change: number;
}

// This constant defines the allowed strictness presets for deterministic DB validation and API parsing.
const ALLOWED_TAGGING_STRICTNESS: TaggingStrictness[] = ['very_strict', 'medium', 'relaxed'];

// This constant defines the allowed fetch modes for governed tagging context enrichment.
const ALLOWED_FETCH_MODES: FetchMode[] = ['never', 'optional', 'always'];

// This constant defines supported AI provider backends for optional governed-tagging inference.
const ALLOWED_TAGGING_INFERENCE_PROVIDERS: TaggingInferenceProvider[] = [
  'builtin',
  'perplexity',
  'mistral',
  'huggingface'
];

// This constant defines allowed per-user AI activity retention windows in days.
const ALLOWED_AI_ACTIVITY_RETENTION_DAYS: Array<30 | 90 | 180 | 365> = [30, 90, 180, 365];

// This constant defines one deterministic global policy baseline when no policy row exists yet.
const DEFAULT_GLOBAL_TAGGING_POLICY: GlobalTaggingPolicy = {
  fetchMode: 'optional',
  allowUserFetchModeOverride: false,
  inferenceProvider: 'builtin',
  inferenceModel: null,
  blockedTagNames: [],
  similarityThreshold: 0.88,
  fetchTimeoutMs: 3000,
  fetchMaxBytes: 131072
};

// This constant stores default module order for new-link routine execution and deterministic persistence.
const DEFAULT_NEW_LINKS_ROUTINE_MODULES: NewLinksRoutineModule[] = ['governed_tagging', 'normalize_urls', 'dedupe'];

// This helper validates allowed new-link routine module names.
function isAllowedNewLinksRoutineModule(value: unknown): value is NewLinksRoutineModule {
  return (
    value === 'governed_tagging' ||
    value === 'normalize_urls' ||
    value === 'dedupe'
  );
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
        tagging_strictness TEXT NOT NULL DEFAULT 'very_strict' CHECK (tagging_strictness IN ('very_strict', 'medium', 'relaxed')),
        fetch_mode TEXT NOT NULL DEFAULT 'optional' CHECK (fetch_mode IN ('never', 'optional', 'always')),
        query_timezone TEXT,
        new_links_routine_enabled INTEGER NOT NULL DEFAULT 0,
        new_links_routine_interval_minutes INTEGER NOT NULL DEFAULT 15,
        new_links_routine_modules_json TEXT NOT NULL DEFAULT '["governed_tagging","normalize_urls","dedupe"]',
        new_links_routine_batch_size INTEGER NOT NULL DEFAULT 200,
        new_links_cursor_created_at TEXT,
        new_links_cursor_link_id INTEGER,
        new_links_last_run_at TEXT,
        new_links_last_status TEXT,
        new_links_last_error TEXT,
        new_links_backfill_requested INTEGER NOT NULL DEFAULT 0,
        new_links_backfill_confirmed INTEGER NOT NULL DEFAULT 0,
        offline_days INTEGER NOT NULL DEFAULT 14,
        offline_min_consecutive_failures INTEGER NOT NULL DEFAULT 3,
        offline_action TEXT NOT NULL DEFAULT 'archive' CHECK (offline_action IN ('archive', 'delete', 'none')),
        offline_archive_collection_id INTEGER,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS user_chat_control (
        user_id INTEGER PRIMARY KEY,
        archive_collection_name TEXT NOT NULL DEFAULT 'Archive',
        archive_collection_parent_id INTEGER,
        chat_capture_tag_name TEXT NOT NULL DEFAULT 'AI Chat',
        chat_capture_tag_ai_chat_enabled INTEGER NOT NULL DEFAULT 1,
        chat_capture_tag_ai_name_enabled INTEGER NOT NULL DEFAULT 1,
        ai_activity_retention_days INTEGER NOT NULL DEFAULT 180 CHECK (ai_activity_retention_days IN (30, 90, 180, 365)),
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
        tool_scopes_json TEXT NOT NULL DEFAULT '["*"]',
        collection_scopes_json TEXT NOT NULL DEFAULT '[]',
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

      CREATE TABLE IF NOT EXISTS query_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        selector_json TEXT NOT NULL,
        fields_json TEXT NOT NULL,
        items_json TEXT NOT NULL,
        total INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_query_snapshots_user_expires
      ON query_snapshots(user_id, expires_at);

      CREATE TABLE IF NOT EXISTS idempotency_keys (
        user_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        key TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        PRIMARY KEY (user_id, tool_name, key),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_idempotency_keys_user_expires
      ON idempotency_keys(user_id, expires_at);

      CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        selector_json TEXT NOT NULL,
        action_json TEXT NOT NULL,
        schedule_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_rules_user_enabled
      ON rules(user_id, enabled, updated_at DESC);

      CREATE TABLE IF NOT EXISTS rule_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
        summary_json TEXT,
        error_json TEXT,
        FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_rule_runs_user_started
      ON rule_runs(user_id, started_at DESC);

      CREATE TABLE IF NOT EXISTS saved_queries (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        selector_json TEXT NOT NULL,
        fields_json TEXT NOT NULL,
        verbosity TEXT NOT NULL CHECK (verbosity IN ('minimal', 'normal', 'debug')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_saved_queries_user_name
      ON saved_queries(user_id, name);

      CREATE TABLE IF NOT EXISTS operation_log (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        undo_until TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_operation_log_user_created
      ON operation_log(user_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS operation_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        operation_id TEXT NOT NULL,
        item_type TEXT NOT NULL,
        item_id INTEGER NOT NULL,
        before_json TEXT NOT NULL,
        after_json TEXT NOT NULL,
        undo_status TEXT NOT NULL DEFAULT 'pending' CHECK (undo_status IN ('pending', 'applied', 'failed')),
        FOREIGN KEY(operation_id) REFERENCES operation_log(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_operation_items_operation
      ON operation_items(operation_id);

      CREATE TABLE IF NOT EXISTS ai_change_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        operation_id TEXT NOT NULL,
        operation_item_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        link_id INTEGER,
        link_title TEXT,
        url_before TEXT,
        url_after TEXT,
        tracking_trimmed INTEGER NOT NULL DEFAULT 0,
        collection_from_id INTEGER,
        collection_from_name TEXT,
        collection_to_id INTEGER,
        collection_to_name TEXT,
        tags_added_json TEXT NOT NULL DEFAULT '[]',
        tags_removed_json TEXT NOT NULL DEFAULT '[]',
        changed_at TEXT NOT NULL,
        undo_status TEXT NOT NULL DEFAULT 'pending' CHECK (undo_status IN ('pending', 'applied', 'conflict', 'failed')),
        undone_at TEXT,
        undo_operation_id TEXT,
        meta_json TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(operation_id) REFERENCES operation_log(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_changed
      ON ai_change_log(user_id, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_link_changed
      ON ai_change_log(user_id, link_id, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_action_changed
      ON ai_change_log(user_id, action_type, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_operation
      ON ai_change_log(user_id, operation_id);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_undo_changed
      ON ai_change_log(user_id, undo_status, changed_at DESC);

      CREATE TABLE IF NOT EXISTS tag_aliases (
        user_id INTEGER NOT NULL,
        canonical_tag_id INTEGER NOT NULL,
        alias_normalized TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (user_id, alias_normalized),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_tag_aliases_user_tag
      ON tag_aliases(user_id, canonical_tag_id);

      CREATE TABLE IF NOT EXISTS tag_candidates (
        user_id INTEGER NOT NULL,
        candidate_normalized TEXT NOT NULL,
        support_count INTEGER NOT NULL DEFAULT 0,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        blocked_reason TEXT,
        PRIMARY KEY (user_id, candidate_normalized),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_tag_candidates_user_support
      ON tag_candidates(user_id, support_count DESC, last_seen_at DESC);

      CREATE TABLE IF NOT EXISTS link_context_cache (
        user_id INTEGER NOT NULL,
        link_id INTEGER NOT NULL,
        context_hash TEXT NOT NULL,
        extracted_tokens_json TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (user_id, link_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_link_context_cache_expires
      ON link_context_cache(user_id, expires_at);
    `);

    this.migrateUsersTableIfNeeded();
    this.migrateUserSettingsTableIfNeeded();
    this.migrateUserChatControlTableIfNeeded();
    this.migrateAiChangeLogTableIfNeeded();
    this.migrateApiKeyScopesIfNeeded();
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
        CREATE TABLE users_tmp (
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
        INSERT INTO users_tmp (
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
      this.db.exec('ALTER TABLE users_tmp RENAME TO users;');

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

    if (!hasColumn('tagging_strictness')) {
      this.db.exec(
        "ALTER TABLE user_settings ADD COLUMN tagging_strictness TEXT NOT NULL DEFAULT 'very_strict' CHECK (tagging_strictness IN ('very_strict', 'medium', 'relaxed'));"
      );
    }

    if (!hasColumn('fetch_mode')) {
      this.db.exec(
        "ALTER TABLE user_settings ADD COLUMN fetch_mode TEXT NOT NULL DEFAULT 'optional' CHECK (fetch_mode IN ('never', 'optional', 'always'));"
      );
    }

    if (!hasColumn('query_timezone')) {
      // This migration adds per-user query timezone persistence for natural date filtering in MCP selectors.
      this.db.exec('ALTER TABLE user_settings ADD COLUMN query_timezone TEXT;');
    }

    if (!hasColumn('new_links_routine_enabled')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_routine_enabled INTEGER NOT NULL DEFAULT 0;');
    }

    if (!hasColumn('new_links_routine_interval_minutes')) {
      this.db.exec(
        'ALTER TABLE user_settings ADD COLUMN new_links_routine_interval_minutes INTEGER NOT NULL DEFAULT 15;'
      );
    }

    if (!hasColumn('new_links_routine_modules_json')) {
      this.db.exec(
        'ALTER TABLE user_settings ADD COLUMN new_links_routine_modules_json TEXT NOT NULL DEFAULT \'["governed_tagging","normalize_urls","dedupe"]\';'
      );
    }

    if (!hasColumn('new_links_routine_batch_size')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_routine_batch_size INTEGER NOT NULL DEFAULT 200;');
    }

    if (!hasColumn('new_links_cursor_created_at')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_cursor_created_at TEXT;');
    }

    if (!hasColumn('new_links_cursor_link_id')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_cursor_link_id INTEGER;');
    }

    if (!hasColumn('new_links_last_run_at')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_last_run_at TEXT;');
    }

    if (!hasColumn('new_links_last_status')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_last_status TEXT;');
    }

    if (!hasColumn('new_links_last_error')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_last_error TEXT;');
    }

    if (!hasColumn('new_links_backfill_requested')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_backfill_requested INTEGER NOT NULL DEFAULT 0;');
    }

    if (!hasColumn('new_links_backfill_confirmed')) {
      this.db.exec('ALTER TABLE user_settings ADD COLUMN new_links_backfill_confirmed INTEGER NOT NULL DEFAULT 0;');
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

  // This migration upgrades user_chat_control to include archive defaults for backend-driven delete alternatives.
  private migrateUserChatControlTableIfNeeded(): void {
    const columns = this.db
      .prepare('PRAGMA table_info(user_chat_control)')
      .all() as Array<{ name: string }>;

    // This branch exits when the table is unavailable in very old schemas and is created by initializeSchema.
    if (columns.length === 0) {
      return;
    }

    const hasColumn = (name: string): boolean => columns.some((column) => column.name === name);

    if (!hasColumn('archive_collection_name')) {
      this.db.exec("ALTER TABLE user_chat_control ADD COLUMN archive_collection_name TEXT NOT NULL DEFAULT 'Archive';");
    }

    if (!hasColumn('archive_collection_parent_id')) {
      this.db.exec('ALTER TABLE user_chat_control ADD COLUMN archive_collection_parent_id INTEGER;');
    }

    // This migration adds the configurable static chat-capture tag default used by link capture workflows.
    if (!hasColumn('chat_capture_tag_name')) {
      this.db.exec("ALTER TABLE user_chat_control ADD COLUMN chat_capture_tag_name TEXT NOT NULL DEFAULT 'AI Chat';");
    }

    // This migration adds the toggle for applying the static AI Chat tag during chat-link capture.
    if (!hasColumn('chat_capture_tag_ai_chat_enabled')) {
      this.db.exec('ALTER TABLE user_chat_control ADD COLUMN chat_capture_tag_ai_chat_enabled INTEGER NOT NULL DEFAULT 1;');
    }

    // This migration adds the toggle for applying the dynamic AI Name tag during chat-link capture.
    if (!hasColumn('chat_capture_tag_ai_name_enabled')) {
      this.db.exec('ALTER TABLE user_chat_control ADD COLUMN chat_capture_tag_ai_name_enabled INTEGER NOT NULL DEFAULT 1;');
    }

    // This migration adds per-user AI activity log retention control for /admin log pruning.
    if (!hasColumn('ai_activity_retention_days')) {
      this.db.exec(
        'ALTER TABLE user_chat_control ADD COLUMN ai_activity_retention_days INTEGER NOT NULL DEFAULT 180;'
      );
    }

    if (!hasColumn('updated_at')) {
      this.db.exec("ALTER TABLE user_chat_control ADD COLUMN updated_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z';");
    }

    // This migration normalizes retention values to supported presets after schema upgrades.
    this.db.exec(`
      UPDATE user_chat_control
      SET ai_activity_retention_days = 180
      WHERE ai_activity_retention_days NOT IN (30, 90, 180, 365)
    `);
  }

  // This migration ensures AI change-log schema and indexes exist for user-facing undo history.
  private migrateAiChangeLogTableIfNeeded(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ai_change_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        operation_id TEXT NOT NULL,
        operation_item_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        link_id INTEGER,
        link_title TEXT,
        url_before TEXT,
        url_after TEXT,
        tracking_trimmed INTEGER NOT NULL DEFAULT 0,
        collection_from_id INTEGER,
        collection_from_name TEXT,
        collection_to_id INTEGER,
        collection_to_name TEXT,
        tags_added_json TEXT NOT NULL DEFAULT '[]',
        tags_removed_json TEXT NOT NULL DEFAULT '[]',
        changed_at TEXT NOT NULL,
        undo_status TEXT NOT NULL DEFAULT 'pending' CHECK (undo_status IN ('pending', 'applied', 'conflict', 'failed')),
        undone_at TEXT,
        undo_operation_id TEXT,
        meta_json TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(operation_id) REFERENCES operation_log(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_changed
      ON ai_change_log(user_id, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_link_changed
      ON ai_change_log(user_id, link_id, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_action_changed
      ON ai_change_log(user_id, action_type, changed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_operation
      ON ai_change_log(user_id, operation_id);
      CREATE INDEX IF NOT EXISTS idx_ai_change_log_user_undo_changed
      ON ai_change_log(user_id, undo_status, changed_at DESC);
    `);
  }

  // This migration upgrades api_keys with optional tool and collection scope columns for fine-grained MCP authorization.
  private migrateApiKeyScopesIfNeeded(): void {
    const columns = this.db
      .prepare('PRAGMA table_info(api_keys)')
      .all() as Array<{ name: string }>;

    if (columns.length === 0) {
      return;
    }

    const hasColumn = (name: string): boolean => columns.some((column) => column.name === name);

    if (!hasColumn('tool_scopes_json')) {
      this.db.exec('ALTER TABLE api_keys ADD COLUMN tool_scopes_json TEXT NOT NULL DEFAULT \'["*"]\';');
    }

    if (!hasColumn('collection_scopes_json')) {
      this.db.exec('ALTER TABLE api_keys ADD COLUMN collection_scopes_json TEXT NOT NULL DEFAULT \'[]\';');
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
      this.db
        .prepare(
          `
          INSERT INTO user_chat_control (
            user_id,
            archive_collection_name,
            archive_collection_parent_id,
            chat_capture_tag_name,
            chat_capture_tag_ai_chat_enabled,
            chat_capture_tag_ai_name_enabled,
            ai_activity_retention_days,
            updated_at
          )
          VALUES (?, 'Archive', NULL, 'AI Chat', 1, 1, 180, ?)
          ON CONFLICT(user_id) DO NOTHING
        `
        )
        .run(userId, now);

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

  // This helper normalizes persisted module JSON and keeps one deterministic fallback order when parsing fails.
  private parseNewLinksRoutineModules(raw: string): NewLinksRoutineModule[] {
    try {
      const parsed = parseJson<unknown[]>(raw, 'user_settings.new_links_routine_modules_json');
      const modules = parsed.filter((value): value is NewLinksRoutineModule => isAllowedNewLinksRoutineModule(value));
      if (modules.length === 0) {
        return [...DEFAULT_NEW_LINKS_ROUTINE_MODULES];
      }

      return [...new Set(modules)];
    } catch {
      return [...DEFAULT_NEW_LINKS_ROUTINE_MODULES];
    }
  }

  // This helper returns one normalized createdAt/linkId cursor only when both persisted columns are valid.
  private parseNewLinksCursor(createdAt: string | null, linkId: number | null): NewLinksCursor | null {
    if (!createdAt || typeof linkId !== 'number' || !Number.isInteger(linkId) || linkId < 0) {
      return null;
    }

    return {
      createdAt,
      linkId
    };
  }

  // This method returns per-user write-mode settings.
  public getUserSettings(userId: number): UserSettings {
    const row = this.db
      .prepare(
        `
        SELECT
          user_id,
          write_mode_enabled,
          tagging_strictness,
          fetch_mode,
          query_timezone,
          new_links_routine_enabled,
          new_links_routine_interval_minutes,
          new_links_routine_modules_json,
          new_links_routine_batch_size,
          new_links_cursor_created_at,
          new_links_cursor_link_id,
          new_links_last_run_at,
          new_links_last_status,
          new_links_last_error,
          new_links_backfill_requested,
          new_links_backfill_confirmed,
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
          tagging_strictness: string;
          fetch_mode: string;
          query_timezone: string | null;
          new_links_routine_enabled: number;
          new_links_routine_interval_minutes: number;
          new_links_routine_modules_json: string;
          new_links_routine_batch_size: number;
          new_links_cursor_created_at: string | null;
          new_links_cursor_link_id: number | null;
          new_links_last_run_at: string | null;
          new_links_last_status: string | null;
          new_links_last_error: string | null;
          new_links_backfill_requested: number;
          new_links_backfill_confirmed: number;
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
      taggingStrictness: ALLOWED_TAGGING_STRICTNESS.includes(row.tagging_strictness as TaggingStrictness)
        ? (row.tagging_strictness as TaggingStrictness)
        : 'very_strict',
      fetchMode: ALLOWED_FETCH_MODES.includes(row.fetch_mode as FetchMode) ? (row.fetch_mode as FetchMode) : 'optional',
      queryTimeZone: row.query_timezone ?? null,
      newLinksRoutineEnabled: row.new_links_routine_enabled === 1,
      newLinksRoutineIntervalMinutes: Math.min(1440, Math.max(1, row.new_links_routine_interval_minutes)),
      newLinksRoutineModules: this.parseNewLinksRoutineModules(row.new_links_routine_modules_json),
      newLinksRoutineBatchSize: Math.min(1000, Math.max(1, row.new_links_routine_batch_size)),
      newLinksCursor: this.parseNewLinksCursor(row.new_links_cursor_created_at, row.new_links_cursor_link_id),
      newLinksLastRunAt: row.new_links_last_run_at,
      newLinksLastStatus: row.new_links_last_status,
      newLinksLastError: row.new_links_last_error,
      newLinksBackfillRequested: row.new_links_backfill_requested === 1,
      newLinksBackfillConfirmed: row.new_links_backfill_confirmed === 1,
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

  // This helper ensures one default chat-control row exists for every user.
  private ensureUserChatControlSettingsRow(userId: number): void {
    this.db
      .prepare(
        `
        INSERT INTO user_chat_control (
          user_id,
          archive_collection_name,
          archive_collection_parent_id,
          chat_capture_tag_name,
          chat_capture_tag_ai_chat_enabled,
          chat_capture_tag_ai_name_enabled,
          ai_activity_retention_days,
          updated_at
        )
        VALUES (?, 'Archive', NULL, 'AI Chat', 1, 1, 180, ?)
        ON CONFLICT(user_id) DO NOTHING
      `
      )
      .run(userId, new Date().toISOString());
  }

  // This helper enforces supported AI activity retention presets for deterministic pruning behavior.
  private normalizeAiActivityRetentionDays(value: number | null | undefined): 30 | 90 | 180 | 365 {
    const normalized = Number(value);
    if (ALLOWED_AI_ACTIVITY_RETENTION_DAYS.includes(normalized as 30 | 90 | 180 | 365)) {
      return normalized as 30 | 90 | 180 | 365;
    }
    return 180;
  }

  // This method returns one normalized user chat-control document including archive routing defaults.
  public getUserChatControlSettings(userId: number): UserChatControlSettings {
    this.getUserById(userId);
    this.ensureUserChatControlSettingsRow(userId);

    const row = this.db
      .prepare(
        `
        SELECT
          user_id,
          archive_collection_name,
          archive_collection_parent_id,
          chat_capture_tag_name,
          chat_capture_tag_ai_chat_enabled,
          chat_capture_tag_ai_name_enabled,
          ai_activity_retention_days,
          updated_at
        FROM user_chat_control
        WHERE user_id = ?
      `
      )
      .get(userId) as UserChatControlRow | undefined;

    if (!row) {
      throw new AppError(404, 'user_chat_control_not_found', `No chat-control settings found for user ${userId}.`);
    }

    const normalizedName = row.archive_collection_name.trim().slice(0, 120) || 'Archive';
    const normalizedChatCaptureTagName = row.chat_capture_tag_name.trim().slice(0, 80) || 'AI Chat';
    const normalizedRetentionDays = this.normalizeAiActivityRetentionDays(row.ai_activity_retention_days);
    return {
      userId: row.user_id,
      archiveCollectionName: normalizedName,
      archiveCollectionParentId: row.archive_collection_parent_id,
      chatCaptureTagName: normalizedChatCaptureTagName,
      chatCaptureTagAiChatEnabled: row.chat_capture_tag_ai_chat_enabled === 1,
      chatCaptureTagAiNameEnabled: row.chat_capture_tag_ai_name_enabled === 1,
      aiActivityRetentionDays: normalizedRetentionDays,
      updatedAt: row.updated_at
    };
  }

  // This method updates one user's archive-routing defaults used by backend delete alternatives.
  public setUserChatControlSettings(
    userId: number,
    payload: {
      archiveCollectionName?: string;
      archiveCollectionParentId?: number | null;
      chatCaptureTagName?: string;
      chatCaptureTagAiChatEnabled?: boolean;
      chatCaptureTagAiNameEnabled?: boolean;
      aiActivityRetentionDays?: 30 | 90 | 180 | 365;
    }
  ): UserChatControlSettings {
    const now = new Date().toISOString();
    this.getUserById(userId);
    const existing = this.getUserChatControlSettings(userId);

    const nextArchiveCollectionName =
      typeof payload.archiveCollectionName === 'string'
        ? payload.archiveCollectionName.trim().slice(0, 120) || 'Archive'
        : existing.archiveCollectionName;
    const nextArchiveCollectionParentId =
      payload.archiveCollectionParentId === undefined
        ? existing.archiveCollectionParentId
        : payload.archiveCollectionParentId;
    const nextChatCaptureTagName =
      typeof payload.chatCaptureTagName === 'string'
        ? payload.chatCaptureTagName.trim().slice(0, 80) || 'AI Chat'
        : existing.chatCaptureTagName;
    const nextChatCaptureTagAiChatEnabled =
      payload.chatCaptureTagAiChatEnabled === undefined
        ? existing.chatCaptureTagAiChatEnabled
        : payload.chatCaptureTagAiChatEnabled;
    const nextChatCaptureTagAiNameEnabled =
      payload.chatCaptureTagAiNameEnabled === undefined
        ? existing.chatCaptureTagAiNameEnabled
        : payload.chatCaptureTagAiNameEnabled;
    const nextAiActivityRetentionDays =
      payload.aiActivityRetentionDays === undefined
        ? existing.aiActivityRetentionDays
        : this.normalizeAiActivityRetentionDays(payload.aiActivityRetentionDays);

    this.db
      .prepare(
        `
        UPDATE user_chat_control
        SET
          archive_collection_name = ?,
          archive_collection_parent_id = ?,
          chat_capture_tag_name = ?,
          chat_capture_tag_ai_chat_enabled = ?,
          chat_capture_tag_ai_name_enabled = ?,
          ai_activity_retention_days = ?,
          updated_at = ?
        WHERE user_id = ?
      `
      )
      .run(
        nextArchiveCollectionName,
        nextArchiveCollectionParentId,
        nextChatCaptureTagName,
        nextChatCaptureTagAiChatEnabled ? 1 : 0,
        nextChatCaptureTagAiNameEnabled ? 1 : 0,
        nextAiActivityRetentionDays,
        now,
        userId
      );

    return this.getUserChatControlSettings(userId);
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

  // This method returns one normalized global governed-tagging policy with safe defaults.
  public getGlobalTaggingPolicy(): GlobalTaggingPolicy {
    const raw = this.getState('global_tagging_policy');
    if (!raw) {
      return {
        ...DEFAULT_GLOBAL_TAGGING_POLICY
      };
    }

    const parsed = parseJson<Partial<GlobalTaggingPolicy>>(raw, 'app_state.global_tagging_policy');
    const fetchMode = ALLOWED_FETCH_MODES.includes(parsed.fetchMode as FetchMode)
      ? (parsed.fetchMode as FetchMode)
      : DEFAULT_GLOBAL_TAGGING_POLICY.fetchMode;
    const allowUserFetchModeOverride =
      typeof parsed.allowUserFetchModeOverride === 'boolean'
        ? parsed.allowUserFetchModeOverride
        : DEFAULT_GLOBAL_TAGGING_POLICY.allowUserFetchModeOverride;
    const inferenceProvider = ALLOWED_TAGGING_INFERENCE_PROVIDERS.includes(
      parsed.inferenceProvider as TaggingInferenceProvider
    )
      ? (parsed.inferenceProvider as TaggingInferenceProvider)
      : DEFAULT_GLOBAL_TAGGING_POLICY.inferenceProvider;
    const inferenceModel =
      typeof parsed.inferenceModel === 'string'
        ? parsed.inferenceModel.trim().slice(0, 200) || null
        : parsed.inferenceModel === null
          ? null
          : DEFAULT_GLOBAL_TAGGING_POLICY.inferenceModel;
    const blockedTagNames = Array.isArray(parsed.blockedTagNames)
      ? parsed.blockedTagNames
          .map((item) => String(item).trim().toLocaleLowerCase())
          .filter((item) => item.length > 0)
      : DEFAULT_GLOBAL_TAGGING_POLICY.blockedTagNames;
    const similarityThreshold =
      typeof parsed.similarityThreshold === 'number' && Number.isFinite(parsed.similarityThreshold)
        ? Math.min(1, Math.max(0, parsed.similarityThreshold))
        : DEFAULT_GLOBAL_TAGGING_POLICY.similarityThreshold;
    const fetchTimeoutMs =
      typeof parsed.fetchTimeoutMs === 'number' && Number.isInteger(parsed.fetchTimeoutMs)
        ? Math.min(20000, Math.max(500, parsed.fetchTimeoutMs))
        : DEFAULT_GLOBAL_TAGGING_POLICY.fetchTimeoutMs;
    const fetchMaxBytes =
      typeof parsed.fetchMaxBytes === 'number' && Number.isInteger(parsed.fetchMaxBytes)
        ? Math.min(1_048_576, Math.max(8192, parsed.fetchMaxBytes))
        : DEFAULT_GLOBAL_TAGGING_POLICY.fetchMaxBytes;

    return {
      fetchMode,
      allowUserFetchModeOverride,
      inferenceProvider,
      inferenceModel,
      blockedTagNames: [...new Set(blockedTagNames)].sort(),
      similarityThreshold,
      fetchTimeoutMs,
      fetchMaxBytes
    };
  }

  // This method persists one global governed-tagging policy document atomically in app_state.
  public setGlobalTaggingPolicy(policy: GlobalTaggingPolicy): void {
    this.setState('global_tagging_policy', JSON.stringify(policy));
  }

  // This method updates one user's tagging strictness and optional fetch mode preferences.
  public setUserTaggingPreferences(
    userId: number,
    preferences: {
      taggingStrictness?: TaggingStrictness;
      fetchMode?: FetchMode;
      queryTimeZone?: string | null;
    }
  ): void {
    const now = new Date().toISOString();
    this.getUserById(userId);
    const existing = this.getUserSettings(userId);
    const nextStrictness =
      preferences.taggingStrictness && ALLOWED_TAGGING_STRICTNESS.includes(preferences.taggingStrictness)
        ? preferences.taggingStrictness
        : existing.taggingStrictness;
    const nextFetchMode =
      preferences.fetchMode && ALLOWED_FETCH_MODES.includes(preferences.fetchMode)
        ? preferences.fetchMode
        : existing.fetchMode;
    // This branch keeps timezone updates explicit while allowing null to clear a user override.
    const nextQueryTimeZone =
      preferences.queryTimeZone === undefined
        ? existing.queryTimeZone
        : preferences.queryTimeZone === null
          ? null
          : preferences.queryTimeZone.trim();

    this.db
      .prepare(
        `
        UPDATE user_settings
        SET tagging_strictness = ?, fetch_mode = ?, query_timezone = ?, updated_at = ?
        WHERE user_id = ?
      `
      )
      .run(nextStrictness, nextFetchMode, nextQueryTimeZone, now, userId);
  }

  // This method sets all users' fetch mode to one value and returns the affected row count.
  public resetAllUserFetchModes(fetchMode: FetchMode): number {
    const result = this.db
      .prepare(
        `
        UPDATE user_settings
        SET fetch_mode = ?, updated_at = ?
      `
      )
      .run(fetchMode, new Date().toISOString());

    return result.changes;
  }

  // This method returns one normalized new-link routine settings object derived from user_settings columns.
  public getUserNewLinksRoutineSettings(userId: number): NewLinksRoutineSettings {
    const settings = this.getUserSettings(userId);
    return {
      userId: settings.userId,
      enabled: settings.newLinksRoutineEnabled,
      intervalMinutes: settings.newLinksRoutineIntervalMinutes,
      modules: settings.newLinksRoutineModules,
      batchSize: settings.newLinksRoutineBatchSize,
      cursor: settings.newLinksCursor,
      lastRunAt: settings.newLinksLastRunAt,
      lastStatus: settings.newLinksLastStatus,
      lastError: settings.newLinksLastError,
      backfillRequested: settings.newLinksBackfillRequested,
      backfillConfirmed: settings.newLinksBackfillConfirmed,
      updatedAt: settings.updatedAt
    };
  }

  // This method updates one user's new-link routine preferences and applies first-run/backfill cursor rules.
  public setUserNewLinksRoutineSettings(
    userId: number,
    payload: {
      enabled?: boolean;
      intervalMinutes?: number;
      modules?: NewLinksRoutineModule[];
      batchSize?: number;
      requestBackfill?: boolean;
      confirmBackfill?: boolean;
    }
  ): NewLinksRoutineSettings {
    const now = new Date().toISOString();
    this.getUserById(userId);
    const existing = this.getUserNewLinksRoutineSettings(userId);

    const nextEnabled = payload.enabled ?? existing.enabled;
    const nextIntervalMinutes =
      typeof payload.intervalMinutes === 'number'
        ? Math.min(1440, Math.max(1, Math.floor(payload.intervalMinutes)))
        : existing.intervalMinutes;
    const nextModules =
      Array.isArray(payload.modules) && payload.modules.length > 0
        ? [...new Set(payload.modules.filter((module) => isAllowedNewLinksRoutineModule(module)))]
        : existing.modules;
    const normalizedModules = nextModules.length > 0 ? nextModules : [...DEFAULT_NEW_LINKS_ROUTINE_MODULES];
    const nextBatchSize =
      typeof payload.batchSize === 'number'
        ? Math.min(1000, Math.max(1, Math.floor(payload.batchSize)))
        : existing.batchSize;
    let nextCursor: NewLinksCursor | null = existing.cursor;
    let nextBackfillRequested = existing.backfillRequested;
    let nextBackfillConfirmed = existing.backfillConfirmed;

    // This branch allows users to cancel pending backfill requests explicitly.
    if (payload.requestBackfill === false) {
      nextBackfillRequested = false;
      nextBackfillConfirmed = false;
    }

    // This branch records that a user requested history processing but has not confirmed destructive scope yet.
    if (payload.requestBackfill === true) {
      nextBackfillRequested = true;
      nextBackfillConfirmed = false;
    }

    // This branch enforces explicit confirmation before resetting the cursor for full-history processing.
    if (payload.confirmBackfill === true) {
      nextBackfillRequested = true;
      nextBackfillConfirmed = true;
      nextCursor = null;
    }

    // This branch sets the first enabled cursor to now so default behavior starts after activation without backfill.
    if (nextEnabled && !existing.enabled && existing.cursor === null && !nextBackfillConfirmed) {
      nextCursor = {
        createdAt: now,
        linkId: 0
      };
    }

    this.db
      .prepare(
        `
        UPDATE user_settings
        SET
          new_links_routine_enabled = ?,
          new_links_routine_interval_minutes = ?,
          new_links_routine_modules_json = ?,
          new_links_routine_batch_size = ?,
          new_links_cursor_created_at = ?,
          new_links_cursor_link_id = ?,
          new_links_backfill_requested = ?,
          new_links_backfill_confirmed = ?,
          updated_at = ?
        WHERE user_id = ?
      `
      )
      .run(
        nextEnabled ? 1 : 0,
        nextIntervalMinutes,
        JSON.stringify(normalizedModules),
        nextBatchSize,
        nextCursor?.createdAt ?? null,
        nextCursor?.linkId ?? null,
        nextBackfillRequested ? 1 : 0,
        nextBackfillConfirmed ? 1 : 0,
        now,
        userId
      );

    return this.getUserNewLinksRoutineSettings(userId);
  }

  // This method updates one user's new-link cursor after successful routine progression.
  public updateUserNewLinksRoutineCursor(userId: number, cursor: NewLinksCursor | null): void {
    this.getUserById(userId);
    this.db
      .prepare(
        `
        UPDATE user_settings
        SET new_links_cursor_created_at = ?, new_links_cursor_link_id = ?, updated_at = ?
        WHERE user_id = ?
      `
      )
      .run(cursor?.createdAt ?? null, cursor?.linkId ?? null, new Date().toISOString(), userId);
  }

  // This method stores one routine run-state snapshot including last-run timestamp and optional error message.
  public setUserNewLinksRoutineRunState(userId: number, status: string, error?: string | null): void {
    this.getUserById(userId);
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        UPDATE user_settings
        SET
          new_links_last_run_at = ?,
          new_links_last_status = ?,
          new_links_last_error = ?,
          updated_at = ?
        WHERE user_id = ?
      `
      )
      .run(now, status, error ?? null, now, userId);
  }

  // This method returns active users with configured token and enabled routine for scheduler iteration.
  public listUsersWithEnabledNewLinksRoutine(): Array<{ userId: number; username: string; role: UserRole }> {
    const rows = this.db
      .prepare(
        `
        SELECT u.id, u.username, u.role
        FROM users u
        JOIN user_settings s ON s.user_id = u.id
        JOIN user_linkwarden_tokens t ON t.user_id = u.id
        WHERE u.is_active = 1 AND s.new_links_routine_enabled = 1
        ORDER BY u.id ASC
      `
      )
      .all() as NewLinksRoutineUserRow[];

    return rows.map((row) => ({
      userId: row.id,
      username: row.username,
      role: row.role as UserRole
    }));
  }

  // This method estimates backlog size for a cursor using caller-provided createdAt/id entries.
  public estimateUserNewLinksBacklog(
    userId: number,
    cursor: NewLinksCursor | null,
    entries: Array<{ createdAt: string; linkId: number }>
  ): number {
    this.getUserById(userId);
    if (!cursor) {
      return entries.length;
    }

    const cursorCreatedAtMs = new Date(cursor.createdAt).getTime();
    if (!Number.isFinite(cursorCreatedAtMs)) {
      return entries.length;
    }

    let count = 0;
    for (const entry of entries) {
      const createdAtMs = new Date(entry.createdAt).getTime();
      if (!Number.isFinite(createdAtMs)) {
        continue;
      }

      if (createdAtMs < cursorCreatedAtMs || (createdAtMs === cursorCreatedAtMs && entry.linkId <= cursor.linkId)) {
        count += 1;
      }
    }

    return count;
  }

  // This method returns all alias mappings for one user ordered by confidence and recency.
  public listTagAliases(userId: number): TagAliasRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT user_id, canonical_tag_id, alias_normalized, confidence, created_at, updated_at
        FROM tag_aliases
        WHERE user_id = ?
        ORDER BY confidence DESC, updated_at DESC
      `
      )
      .all(userId) as TagAliasRow[];

    return rows.map((row) => ({
      userId: row.user_id,
      canonicalTagId: row.canonical_tag_id,
      aliasNormalized: row.alias_normalized,
      confidence: row.confidence,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  // This method returns one alias mapping for one normalized candidate or null when absent.
  public getTagAlias(userId: number, aliasNormalized: string): TagAliasRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT user_id, canonical_tag_id, alias_normalized, confidence, created_at, updated_at
        FROM tag_aliases
        WHERE user_id = ? AND alias_normalized = ?
        LIMIT 1
      `
      )
      .get(userId, aliasNormalized) as TagAliasRow | undefined;

    if (!row) {
      return null;
    }

    return {
      userId: row.user_id,
      canonicalTagId: row.canonical_tag_id,
      aliasNormalized: row.alias_normalized,
      confidence: row.confidence,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // This method upserts one alias mapping for a user and canonical tag pair.
  public upsertTagAlias(input: {
    userId: number;
    canonicalTagId: number;
    aliasNormalized: string;
    confidence: number;
  }): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        INSERT INTO tag_aliases (user_id, canonical_tag_id, alias_normalized, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, alias_normalized) DO UPDATE SET
          canonical_tag_id = excluded.canonical_tag_id,
          confidence = excluded.confidence,
          updated_at = excluded.updated_at
      `
      )
      .run(input.userId, input.canonicalTagId, input.aliasNormalized, input.confidence, now, now);
  }

  // This method returns one persisted candidate support record or null if it does not exist yet.
  public getTagCandidate(userId: number, candidateNormalized: string): TagCandidateRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT user_id, candidate_normalized, support_count, first_seen_at, last_seen_at, blocked_reason
        FROM tag_candidates
        WHERE user_id = ? AND candidate_normalized = ?
        LIMIT 1
      `
      )
      .get(userId, candidateNormalized) as TagCandidateRow | undefined;

    if (!row) {
      return null;
    }

    return {
      userId: row.user_id,
      candidateNormalized: row.candidate_normalized,
      supportCount: row.support_count,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      blockedReason: row.blocked_reason
    };
  }

  // This method increments support for one candidate and optionally stores a blocked reason.
  public bumpTagCandidateSupport(input: {
    userId: number;
    candidateNormalized: string;
    delta: number;
    blockedReason?: string | null;
  }): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        INSERT INTO tag_candidates (
          user_id,
          candidate_normalized,
          support_count,
          first_seen_at,
          last_seen_at,
          blocked_reason
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, candidate_normalized) DO UPDATE SET
          support_count = tag_candidates.support_count + excluded.support_count,
          last_seen_at = excluded.last_seen_at,
          blocked_reason = excluded.blocked_reason
      `
      )
      .run(
        input.userId,
        input.candidateNormalized,
        Math.max(1, input.delta),
        now,
        now,
        input.blockedReason ?? null
      );
  }

  // This method reads one cached token set for a link when the hash matches and cache entry is still valid.
  public getLinkContextCache(userId: number, linkId: number, contextHash: string): LinkContextCacheRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT user_id, link_id, context_hash, extracted_tokens_json, expires_at, updated_at
        FROM link_context_cache
        WHERE user_id = ? AND link_id = ? AND context_hash = ?
        LIMIT 1
      `
      )
      .get(userId, linkId, contextHash) as LinkContextCacheRow | undefined;

    if (!row) {
      return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      this.db.prepare('DELETE FROM link_context_cache WHERE user_id = ? AND link_id = ?').run(userId, linkId);
      return null;
    }

    return {
      userId: row.user_id,
      linkId: row.link_id,
      contextHash: row.context_hash,
      extractedTokens: parseJson<string[]>(row.extracted_tokens_json, 'link_context_cache.extracted_tokens_json'),
      expiresAt: row.expires_at,
      updatedAt: row.updated_at
    };
  }

  // This method upserts one link context token cache entry with an absolute expiration timestamp.
  public upsertLinkContextCache(input: {
    userId: number;
    linkId: number;
    contextHash: string;
    extractedTokens: string[];
    expiresAt: string;
  }): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        INSERT INTO link_context_cache (
          user_id,
          link_id,
          context_hash,
          extracted_tokens_json,
          expires_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, link_id) DO UPDATE SET
          context_hash = excluded.context_hash,
          extracted_tokens_json = excluded.extracted_tokens_json,
          expires_at = excluded.expires_at,
          updated_at = excluded.updated_at
      `
      )
      .run(input.userId, input.linkId, input.contextHash, JSON.stringify(input.extractedTokens), input.expiresAt, now);
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
  public createApiKey(
    userId: number,
    label: string,
    keyId: string,
    tokenHash: string,
    options?: { toolScopes?: string[]; collectionScopes?: number[] }
  ): void {
    const now = new Date().toISOString();
    this.getUserById(userId);
    const toolScopes = options?.toolScopes && options.toolScopes.length > 0 ? options.toolScopes : ['*'];
    const collectionScopes = options?.collectionScopes ?? [];

    this.db
      .prepare(
        `
        INSERT INTO api_keys (
          key_id,
          user_id,
          label,
          token_hash,
          tool_scopes_json,
          collection_scopes_json,
          revoked,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
      `
      )
      .run(keyId, userId, label, tokenHash, JSON.stringify(toolScopes), JSON.stringify(collectionScopes), now);
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

    if (!isAcceptedOAuthResource(row.resource, acceptedResources)) {
      return null;
    }

    this.db
      .prepare('UPDATE oauth_tokens SET last_used_at = ?, updated_at = ? WHERE token_id = ?')
      .run(new Date().toISOString(), new Date().toISOString(), row.token_id);

    // This parser maps OAuth scope tokens into MCP tool and collection scope constraints.
    const rawScopes = row.scope
      .split(/\s+/)
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    const toolScopes = rawScopes
      .filter((value) => value.startsWith('tool:'))
      .map((value) => value.slice('tool:'.length));
    const collectionScopes = rawScopes
      .filter((value) => value.startsWith('collection:'))
      .map((value) => Number(value.slice('collection:'.length)))
      .filter((value) => Number.isInteger(value) && value > 0);
    const resolvedToolScopes =
      rawScopes.includes('*') || rawScopes.includes('tool:*') || toolScopes.length === 0 ? ['*'] : toolScopes;

    return {
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole,
      apiKeyId: `oauth:${row.token_id}`,
      toolScopes: resolvedToolScopes,
      collectionScopes
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
        SELECT u.id AS user_id, u.username, u.role, k.key_id, k.tool_scopes_json, k.collection_scopes_json
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

    const toolScopes = parseJson<string[]>(row.tool_scopes_json ?? '["*"]', 'api_keys.tool_scopes_json');
    const collectionScopes = parseJson<number[]>(
      row.collection_scopes_json ?? '[]',
      'api_keys.collection_scopes_json'
    ).filter((value) => Number.isInteger(value) && value > 0);
    const resolvedToolScopes = toolScopes.length > 0 ? toolScopes : ['*'];

    return {
      userId: row.user_id,
      username: row.username,
      role: row.role as UserRole,
      apiKeyId: row.key_id,
      toolScopes: resolvedToolScopes,
      collectionScopes
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

  // This method stores one cursor snapshot so query_links can resume deterministically with a stable data slice.
  public createQuerySnapshot(input: {
    snapshotId: string;
    userId: number;
    selector: LinkSelector;
    fields: string[];
    items: Array<Record<string, unknown>>;
    total: number;
    ttlSeconds: number;
  }): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000).toISOString();
    this.db
      .prepare(
        `
        INSERT INTO query_snapshots (
          snapshot_id,
          user_id,
          selector_json,
          fields_json,
          items_json,
          total,
          created_at,
          expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `
      )
      .run(
        input.snapshotId,
        input.userId,
        JSON.stringify(input.selector),
        JSON.stringify(input.fields),
        JSON.stringify(input.items),
        input.total,
        now.toISOString(),
        expiresAt
      );
  }

  // This method reads one active query snapshot and returns null when the snapshot is missing or expired.
  public getQuerySnapshot(snapshotId: string, userId: number): {
    selector: LinkSelector;
    fields: string[];
    items: Array<Record<string, unknown>>;
    total: number;
    expiresAt: string;
  } | null {
    const row = this.db
      .prepare(
        `
        SELECT selector_json, fields_json, items_json, total, expires_at
        FROM query_snapshots
        WHERE snapshot_id = ? AND user_id = ?
        LIMIT 1
      `
      )
      .get(snapshotId, userId) as
      | {
          selector_json: string;
          fields_json: string;
          items_json: string;
          total: number;
          expires_at: string;
        }
      | undefined;

    if (!row) {
      return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      this.db.prepare('DELETE FROM query_snapshots WHERE snapshot_id = ? AND user_id = ?').run(snapshotId, userId);
      return null;
    }

    return {
      selector: parseJson<LinkSelector>(row.selector_json, 'query_snapshots.selector_json'),
      fields: parseJson<string[]>(row.fields_json, 'query_snapshots.fields_json'),
      items: parseJson<Array<Record<string, unknown>>>(row.items_json, 'query_snapshots.items_json'),
      total: row.total,
      expiresAt: row.expires_at
    };
  }

  // This method stores one idempotent response payload for deterministic write retries.
  public upsertIdempotencyRecord(input: {
    userId: number;
    toolName: string;
    key: string;
    requestHash: string;
    response: Record<string, unknown>;
    ttlSeconds: number;
  }): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000).toISOString();
    this.db
      .prepare(
        `
        INSERT INTO idempotency_keys (
          user_id,
          tool_name,
          key,
          request_hash,
          response_json,
          created_at,
          expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, tool_name, key) DO UPDATE SET
          request_hash = excluded.request_hash,
          response_json = excluded.response_json,
          created_at = excluded.created_at,
          expires_at = excluded.expires_at
      `
      )
      .run(
        input.userId,
        input.toolName,
        input.key,
        input.requestHash,
        JSON.stringify(input.response),
        now.toISOString(),
        expiresAt
      );
  }

  // This method returns one idempotent response when the key exists, matches request hash, and has not expired.
  public getIdempotencyRecord(
    userId: number,
    toolName: string,
    key: string,
    requestHash: string
  ): Record<string, unknown> | null {
    const row = this.db
      .prepare(
        `
        SELECT request_hash, response_json, expires_at
        FROM idempotency_keys
        WHERE user_id = ? AND tool_name = ? AND key = ?
        LIMIT 1
      `
      )
      .get(userId, toolName, key) as { request_hash: string; response_json: string; expires_at: string } | undefined;

    if (!row) {
      return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      this.db.prepare('DELETE FROM idempotency_keys WHERE user_id = ? AND tool_name = ? AND key = ?').run(
        userId,
        toolName,
        key
      );
      return null;
    }

    if (row.request_hash !== requestHash) {
      return null;
    }

    return parseJson<Record<string, unknown>>(row.response_json, 'idempotency_keys.response_json');
  }

  // This method creates one saved query definition for lightweight query-id execution.
  public createSavedQuery(input: {
    id: string;
    userId: number;
    name: string;
    selector: LinkSelector;
    fields: string[];
    verbosity: 'minimal' | 'normal' | 'debug';
  }): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        INSERT INTO saved_queries (
          id,
          user_id,
          name,
          selector_json,
          fields_json,
          verbosity,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `
      )
      .run(
        input.id,
        input.userId,
        input.name,
        JSON.stringify(input.selector),
        JSON.stringify(input.fields),
        input.verbosity,
        now,
        now
      );
  }

  // This method lists saved queries for one user sorted by most recently updated definition.
  public listSavedQueries(userId: number): SavedQueryRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, user_id, name, selector_json, fields_json, verbosity, created_at, updated_at
        FROM saved_queries
        WHERE user_id = ?
        ORDER BY updated_at DESC
      `
      )
      .all(userId) as SavedQueryRow[];

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      name: row.name,
      selector: parseJson<LinkSelector>(row.selector_json, 'saved_queries.selector_json'),
      fields: parseJson<string[]>(row.fields_json, 'saved_queries.fields_json'),
      verbosity: row.verbosity,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  // This method fetches one saved query by id and user ownership.
  public getSavedQuery(id: string, userId: number): SavedQueryRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT id, user_id, name, selector_json, fields_json, verbosity, created_at, updated_at
        FROM saved_queries
        WHERE id = ? AND user_id = ?
        LIMIT 1
      `
      )
      .get(id, userId) as SavedQueryRow | undefined;

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      selector: parseJson<LinkSelector>(row.selector_json, 'saved_queries.selector_json'),
      fields: parseJson<string[]>(row.fields_json, 'saved_queries.fields_json'),
      verbosity: row.verbosity,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // This method deletes one saved query owned by one user.
  public deleteSavedQuery(id: string, userId: number): void {
    const result = this.db.prepare('DELETE FROM saved_queries WHERE id = ? AND user_id = ?').run(id, userId);
    if (result.changes === 0) {
      throw new AppError(404, 'saved_query_not_found', `Saved query ${id} not found.`);
    }
  }

  // This method creates one rule definition for scheduled or ad-hoc maintenance execution.
  public createRule(input: {
    id: string;
    userId: number;
    name: string;
    selector: LinkSelector;
    action: Record<string, unknown>;
    schedule: Record<string, unknown>;
    enabled: boolean;
  }): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `
        INSERT INTO rules (
          id,
          user_id,
          name,
          selector_json,
          action_json,
          schedule_json,
          enabled,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `
      )
      .run(
        input.id,
        input.userId,
        input.name,
        JSON.stringify(input.selector),
        JSON.stringify(input.action),
        JSON.stringify(input.schedule),
        input.enabled ? 1 : 0,
        now,
        now
      );
  }

  // This method lists all rules for one user ordered by update time descending.
  public listRules(userId: number): RuleRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, user_id, name, selector_json, action_json, schedule_json, enabled, created_at, updated_at
        FROM rules
        WHERE user_id = ?
        ORDER BY updated_at DESC
      `
      )
      .all(userId) as RuleRow[];

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      name: row.name,
      selector: parseJson<LinkSelector>(row.selector_json, 'rules.selector_json'),
      action: parseJson<Record<string, unknown>>(row.action_json, 'rules.action_json'),
      schedule: parseJson<Record<string, unknown>>(row.schedule_json, 'rules.schedule_json'),
      enabled: row.enabled === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  // This method fetches one rule by id and user ownership.
  public getRule(id: string, userId: number): RuleRecord | null {
    const row = this.db
      .prepare(
        `
        SELECT id, user_id, name, selector_json, action_json, schedule_json, enabled, created_at, updated_at
        FROM rules
        WHERE id = ? AND user_id = ?
        LIMIT 1
      `
      )
      .get(id, userId) as RuleRow | undefined;

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      selector: parseJson<LinkSelector>(row.selector_json, 'rules.selector_json'),
      action: parseJson<Record<string, unknown>>(row.action_json, 'rules.action_json'),
      schedule: parseJson<Record<string, unknown>>(row.schedule_json, 'rules.schedule_json'),
      enabled: row.enabled === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // This method updates enabled state for one rule and fails when the rule is missing.
  public setRuleEnabled(id: string, userId: number, enabled: boolean): void {
    const result = this.db
      .prepare('UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ? AND user_id = ?')
      .run(enabled ? 1 : 0, new Date().toISOString(), id, userId);
    if (result.changes === 0) {
      throw new AppError(404, 'rule_not_found', `Rule ${id} not found.`);
    }
  }

  // This method deletes one rule owned by one user.
  public deleteRule(id: string, userId: number): void {
    const result = this.db.prepare('DELETE FROM rules WHERE id = ? AND user_id = ?').run(id, userId);
    if (result.changes === 0) {
      throw new AppError(404, 'rule_not_found', `Rule ${id} not found.`);
    }
  }

  // This method creates one rule-run row before execution starts.
  public createRuleRun(ruleId: string, userId: number): number {
    const result = this.db
      .prepare(
        `
        INSERT INTO rule_runs (rule_id, user_id, started_at, status)
        VALUES (?, ?, ?, 'running')
      `
      )
      .run(ruleId, userId, new Date().toISOString());
    return Number(result.lastInsertRowid);
  }

  // This method finalizes one rule run with summary and optional error payload.
  public finishRuleRun(input: {
    runId: number;
    status: 'success' | 'failed';
    summary: Record<string, unknown>;
    error?: Record<string, unknown>;
  }): void {
    this.db
      .prepare(
        `
        UPDATE rule_runs
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

  // This method creates one operation header used by audit and undo workflows.
  public createOperation(input: {
    id: string;
    userId: number;
    toolName: string;
    summary: Record<string, unknown>;
    undoUntil: string | null;
  }): void {
    this.db
      .prepare(
        `
        INSERT INTO operation_log (id, user_id, tool_name, summary_json, undo_until, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `
      )
      .run(input.id, input.userId, input.toolName, JSON.stringify(input.summary), input.undoUntil, new Date().toISOString());
  }

  // This method stores operation items with before/after snapshots for deterministic undo execution.
  public insertOperationItems(
    operationId: string,
    items: Array<{
      itemType: string;
      itemId: number;
      before: Record<string, unknown>;
      after: Record<string, unknown>;
    }>
  ): void {
    if (items.length === 0) {
      return;
    }
    const insert = this.db.prepare(
      `
      INSERT INTO operation_items (operation_id, item_type, item_id, before_json, after_json, undo_status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `
    );
    const tx = this.db.transaction(() => {
      for (const item of items) {
        insert.run(operationId, item.itemType, item.itemId, JSON.stringify(item.before), JSON.stringify(item.after));
      }
    });
    tx();
  }

  // This method returns operation headers for one user ordered by creation time descending.
  public listOperations(userId: number, limit = 50, offset = 0): OperationRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, user_id, tool_name, summary_json, undo_until, created_at
        FROM operation_log
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `
      )
      .all(userId, limit, offset) as OperationRow[];

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      toolName: row.tool_name,
      summary: parseJson<Record<string, unknown>>(row.summary_json, 'operation_log.summary_json'),
      undoUntil: row.undo_until,
      createdAt: row.created_at
    }));
  }

  // This method returns one operation and all item snapshots or null when no owned operation exists.
  public getOperationWithItems(
    operationId: string,
    userId: number
  ): { operation: OperationRecord; items: OperationItemRecord[] } | null {
    const opRow = this.db
      .prepare(
        `
        SELECT id, user_id, tool_name, summary_json, undo_until, created_at
        FROM operation_log
        WHERE id = ? AND user_id = ?
        LIMIT 1
      `
      )
      .get(operationId, userId) as OperationRow | undefined;

    if (!opRow) {
      return null;
    }

    const itemRows = this.db
      .prepare(
        `
        SELECT operation_id, item_type, item_id, before_json, after_json, undo_status
        FROM operation_items
        WHERE operation_id = ?
        ORDER BY id DESC
      `
      )
      .all(operationId) as OperationItemRow[];

    return {
      operation: {
        id: opRow.id,
        userId: opRow.user_id,
        toolName: opRow.tool_name,
        summary: parseJson<Record<string, unknown>>(opRow.summary_json, 'operation_log.summary_json'),
        undoUntil: opRow.undo_until,
        createdAt: opRow.created_at
      },
      items: itemRows.map((row) => ({
        operationId: row.operation_id,
        itemType: row.item_type,
        itemId: row.item_id,
        before: parseJson<Record<string, unknown>>(row.before_json, 'operation_items.before_json'),
        after: parseJson<Record<string, unknown>>(row.after_json, 'operation_items.after_json'),
        undoStatus: row.undo_status
      }))
    };
  }

  // This method updates one operation item undo status after each undo attempt.
  public setOperationItemUndoStatus(operationId: string, itemId: number, status: 'pending' | 'applied' | 'failed'): void {
    this.db
      .prepare('UPDATE operation_items SET undo_status = ? WHERE operation_id = ? AND item_id = ?')
      .run(status, operationId, itemId);
  }

  // This helper maps raw AI change-log rows to strongly typed domain records.
  private mapAiChangeLogRow(row: AiChangeLogRow): AiChangeLogRecord {
    return {
      id: row.id,
      userId: row.user_id,
      operationId: row.operation_id,
      operationItemId: row.operation_item_id,
      toolName: row.tool_name,
      actionType: row.action_type as AiChangeActionType,
      linkId: row.link_id,
      linkTitle: row.link_title,
      urlBefore: row.url_before,
      urlAfter: row.url_after,
      trackingTrimmed: row.tracking_trimmed === 1,
      collectionFromId: row.collection_from_id,
      collectionFromName: row.collection_from_name,
      collectionToId: row.collection_to_id,
      collectionToName: row.collection_to_name,
      tagsAdded: parseJson<string[]>(row.tags_added_json, 'ai_change_log.tags_added_json'),
      tagsRemoved: parseJson<string[]>(row.tags_removed_json, 'ai_change_log.tags_removed_json'),
      changedAt: row.changed_at,
      undoStatus: row.undo_status as AiChangeUndoStatus,
      undoneAt: row.undone_at,
      undoOperationId: row.undo_operation_id,
      meta: row.meta_json ? parseJson<Record<string, unknown>>(row.meta_json, 'ai_change_log.meta_json') : null
    };
  }

  // This method appends one or more normalized AI change-log records derived from MCP write operations.
  public appendAiChangeLogEntries(input: {
    userId: number;
    operationId: string;
    toolName: string;
    changedAt?: string;
    entries: Array<{
      operationItemId: number;
      actionType: AiChangeActionType;
      linkId: number | null;
      linkTitle?: string | null;
      urlBefore?: string | null;
      urlAfter?: string | null;
      trackingTrimmed?: boolean;
      collectionFromId?: number | null;
      collectionFromName?: string | null;
      collectionToId?: number | null;
      collectionToName?: string | null;
      tagsAdded?: string[];
      tagsRemoved?: string[];
      undoStatus?: AiChangeUndoStatus;
      meta?: Record<string, unknown> | null;
    }>;
  }): void {
    if (input.entries.length === 0) {
      return;
    }

    const changedAt = input.changedAt ?? new Date().toISOString();
    const insert = this.db.prepare(
      `
      INSERT INTO ai_change_log (
        user_id,
        operation_id,
        operation_item_id,
        tool_name,
        action_type,
        link_id,
        link_title,
        url_before,
        url_after,
        tracking_trimmed,
        collection_from_id,
        collection_from_name,
        collection_to_id,
        collection_to_name,
        tags_added_json,
        tags_removed_json,
        changed_at,
        undo_status,
        undone_at,
        undo_operation_id,
        meta_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
    `
    );

    const tx = this.db.transaction(() => {
      for (const entry of input.entries) {
        insert.run(
          input.userId,
          input.operationId,
          entry.operationItemId,
          input.toolName,
          entry.actionType,
          entry.linkId,
          entry.linkTitle ?? null,
          entry.urlBefore ?? null,
          entry.urlAfter ?? null,
          entry.trackingTrimmed ? 1 : 0,
          entry.collectionFromId ?? null,
          entry.collectionFromName ?? null,
          entry.collectionToId ?? null,
          entry.collectionToName ?? null,
          JSON.stringify(entry.tagsAdded ?? []),
          JSON.stringify(entry.tagsRemoved ?? []),
          changedAt,
          entry.undoStatus ?? 'pending',
          entry.meta ? JSON.stringify(entry.meta) : null
        );
      }
    });
    tx();
  }

  // This method returns paged AI change-log rows with deterministic filtering and sorting for /admin UI.
  public listAiChangeLog(
    userId: number,
    filters: AiChangeLogFilters,
    paging: { limit: number; offset: number },
    sorting: { sortBy: 'changedAt' | 'linkId' | 'actionType' | 'toolName'; sortDir: 'asc' | 'desc' }
  ): { items: AiChangeLogRecord[]; total: number } {
    const conditions: string[] = ['user_id = ?'];
    const params: Array<string | number> = [userId];

    if (filters.q) {
      const query = `%${filters.q.trim().toLocaleLowerCase()}%`;
      conditions.push(
        `(LOWER(COALESCE(link_title, '')) LIKE ? OR LOWER(COALESCE(url_before, '')) LIKE ? OR LOWER(COALESCE(url_after, '')) LIKE ? OR LOWER(COALESCE(collection_from_name, '')) LIKE ? OR LOWER(COALESCE(collection_to_name, '')) LIKE ? OR LOWER(COALESCE(tags_added_json, '')) LIKE ? OR LOWER(COALESCE(tags_removed_json, '')) LIKE ?)`
      );
      params.push(query, query, query, query, query, query, query);
    }

    if (filters.dateFrom) {
      conditions.push('changed_at >= ?');
      params.push(filters.dateFrom);
    }
    if (filters.dateTo) {
      conditions.push('changed_at <= ?');
      params.push(filters.dateTo);
    }

    if (filters.actionTypes && filters.actionTypes.length > 0) {
      const placeholders = filters.actionTypes.map(() => '?').join(', ');
      conditions.push(`action_type IN (${placeholders})`);
      params.push(...filters.actionTypes);
    }

    if (filters.toolNames && filters.toolNames.length > 0) {
      const placeholders = filters.toolNames.map(() => '?').join(', ');
      conditions.push(`tool_name IN (${placeholders})`);
      params.push(...filters.toolNames);
    }

    if (typeof filters.linkId === 'number') {
      conditions.push('link_id = ?');
      params.push(filters.linkId);
    }
    if (typeof filters.collectionFromId === 'number') {
      conditions.push('collection_from_id = ?');
      params.push(filters.collectionFromId);
    }
    if (typeof filters.collectionToId === 'number') {
      conditions.push('collection_to_id = ?');
      params.push(filters.collectionToId);
    }

    if (filters.tagName) {
      const normalizedTagName = `%${filters.tagName.trim().toLocaleLowerCase()}%`;
      conditions.push('(LOWER(tags_added_json) LIKE ? OR LOWER(tags_removed_json) LIKE ?)');
      params.push(normalizedTagName, normalizedTagName);
    }

    if (typeof filters.trackingTrimmed === 'boolean') {
      conditions.push('tracking_trimmed = ?');
      params.push(filters.trackingTrimmed ? 1 : 0);
    }

    if (filters.undoStatus) {
      conditions.push('undo_status = ?');
      params.push(filters.undoStatus);
    }

    const whereSql = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sortBySql =
      sorting.sortBy === 'linkId'
        ? 'link_id'
        : sorting.sortBy === 'actionType'
          ? 'action_type'
          : sorting.sortBy === 'toolName'
            ? 'tool_name'
            : 'changed_at';
    const sortDirSql = sorting.sortDir === 'asc' ? 'ASC' : 'DESC';

    const rows = this.db
      .prepare(
        `
        SELECT
          id,
          user_id,
          operation_id,
          operation_item_id,
          tool_name,
          action_type,
          link_id,
          link_title,
          url_before,
          url_after,
          tracking_trimmed,
          collection_from_id,
          collection_from_name,
          collection_to_id,
          collection_to_name,
          tags_added_json,
          tags_removed_json,
          changed_at,
          undo_status,
          undone_at,
          undo_operation_id,
          meta_json
        FROM ai_change_log
        ${whereSql}
        ORDER BY ${sortBySql} ${sortDirSql}, id ${sortDirSql}
        LIMIT ? OFFSET ?
      `
      )
      .all(...params, paging.limit, paging.offset) as AiChangeLogRow[];

    const totalRow = this.db
      .prepare(
        `
        SELECT COUNT(1) AS count
        FROM ai_change_log
        ${whereSql}
      `
      )
      .get(...params) as { count: number };

    return {
      items: rows.map((row) => this.mapAiChangeLogRow(row)),
      total: totalRow.count
    };
  }

  // This method returns dynamic AI log facets so the UI can populate deterministic filter options.
  public listAiChangeLogFacets(userId: number, baseFilters: Pick<AiChangeLogFilters, 'dateFrom' | 'dateTo'>): AiChangeLogFacets {
    const conditions: string[] = ['user_id = ?'];
    const params: Array<string | number> = [userId];

    if (baseFilters.dateFrom) {
      conditions.push('changed_at >= ?');
      params.push(baseFilters.dateFrom);
    }
    if (baseFilters.dateTo) {
      conditions.push('changed_at <= ?');
      params.push(baseFilters.dateTo);
    }

    const whereSql = `WHERE ${conditions.join(' AND ')}`;

    const actionRows = this.db
      .prepare(
        `
        SELECT DISTINCT action_type
        FROM ai_change_log
        ${whereSql}
        ORDER BY action_type ASC
      `
      )
      .all(...params) as Array<{ action_type: string }>;

    const toolRows = this.db
      .prepare(
        `
        SELECT DISTINCT tool_name
        FROM ai_change_log
        ${whereSql}
        ORDER BY tool_name ASC
      `
      )
      .all(...params) as Array<{ tool_name: string }>;

    const collectionFromRows = this.db
      .prepare(
        `
        SELECT collection_from_id, collection_from_name
        FROM ai_change_log
        ${whereSql}
          AND collection_from_id IS NOT NULL
        GROUP BY collection_from_id, collection_from_name
        ORDER BY LOWER(COALESCE(collection_from_name, '')), collection_from_id
      `
      )
      .all(...params) as Array<{ collection_from_id: number; collection_from_name: string | null }>;

    const collectionToRows = this.db
      .prepare(
        `
        SELECT collection_to_id, collection_to_name
        FROM ai_change_log
        ${whereSql}
          AND collection_to_id IS NOT NULL
        GROUP BY collection_to_id, collection_to_name
        ORDER BY LOWER(COALESCE(collection_to_name, '')), collection_to_id
      `
      )
      .all(...params) as Array<{ collection_to_id: number; collection_to_name: string | null }>;

    const tagRows = this.db
      .prepare(
        `
        SELECT tags_added_json, tags_removed_json
        FROM ai_change_log
        ${whereSql}
      `
      )
      .all(...params) as Array<{ tags_added_json: string; tags_removed_json: string }>;

    const bounds = this.db
      .prepare(
        `
        SELECT MIN(changed_at) AS min_changed_at, MAX(changed_at) AS max_changed_at
        FROM ai_change_log
        ${whereSql}
      `
      )
      .get(...params) as { min_changed_at: string | null; max_changed_at: string | null };

    const tagSet = new Set<string>();
    for (const row of tagRows) {
      const added = parseJson<string[]>(row.tags_added_json, 'ai_change_log.tags_added_json');
      const removed = parseJson<string[]>(row.tags_removed_json, 'ai_change_log.tags_removed_json');
      for (const tagName of [...added, ...removed]) {
        const normalized = String(tagName || '').trim();
        if (normalized.length > 0) {
          tagSet.add(normalized);
        }
      }
    }

    return {
      actionTypes: actionRows.map((row) => row.action_type as AiChangeActionType),
      toolNames: toolRows.map((row) => row.tool_name),
      collectionFrom: collectionFromRows.map((row) => ({
        id: row.collection_from_id,
        name: row.collection_from_name ?? `Collection ${row.collection_from_id}`
      })),
      collectionTo: collectionToRows.map((row) => ({
        id: row.collection_to_id,
        name: row.collection_to_name ?? `Collection ${row.collection_to_id}`
      })),
      tags: [...tagSet].sort((left, right) => left.localeCompare(right, 'de')),
      minChangedAt: bounds.min_changed_at,
      maxChangedAt: bounds.max_changed_at
    };
  }

  // This method returns selected AI change rows together with operation snapshots and conflict indicators.
  public getAiChangeUndoCandidates(
    userId: number,
    changeIds: number[]
  ): Array<{
    change: AiChangeLogRecord;
    before: Record<string, unknown>;
    after: Record<string, unknown>;
    undoUntil: string | null;
    hasNewerOpenChange: boolean;
  }> {
    if (changeIds.length === 0) {
      return [];
    }

    const placeholders = changeIds.map(() => '?').join(', ');
    const rows = this.db
      .prepare(
        `
        SELECT
          l.id,
          l.user_id,
          l.operation_id,
          l.operation_item_id,
          l.tool_name,
          l.action_type,
          l.link_id,
          l.link_title,
          l.url_before,
          l.url_after,
          l.tracking_trimmed,
          l.collection_from_id,
          l.collection_from_name,
          l.collection_to_id,
          l.collection_to_name,
          l.tags_added_json,
          l.tags_removed_json,
          l.changed_at,
          l.undo_status,
          l.undone_at,
          l.undo_operation_id,
          l.meta_json,
          oi.before_json,
          oi.after_json,
          o.undo_until,
          CASE
            WHEN l.link_id IS NULL THEN 0
            WHEN EXISTS (
              SELECT 1
              FROM ai_change_log newer
              WHERE newer.user_id = l.user_id
                AND newer.link_id = l.link_id
                AND newer.id NOT IN (${placeholders})
                AND newer.undo_status <> 'applied'
                AND (
                  newer.changed_at > l.changed_at
                  OR (newer.changed_at = l.changed_at AND newer.id > l.id)
                )
            ) THEN 1
            ELSE 0
          END AS has_newer_open_change
        FROM ai_change_log l
        JOIN operation_items oi
          ON oi.operation_id = l.operation_id
         AND oi.item_id = l.operation_item_id
        JOIN operation_log o
          ON o.id = l.operation_id
         AND o.user_id = l.user_id
        WHERE l.user_id = ?
          AND l.id IN (${placeholders})
        ORDER BY l.changed_at DESC, l.id DESC
      `
      )
      .all(...changeIds, userId, ...changeIds) as AiChangeUndoCandidateRow[];

    return rows.map((row) => ({
      change: this.mapAiChangeLogRow(row),
      before: parseJson<Record<string, unknown>>(row.before_json, 'operation_items.before_json'),
      after: parseJson<Record<string, unknown>>(row.after_json, 'operation_items.after_json'),
      undoUntil: row.undo_until,
      hasNewerOpenChange: row.has_newer_open_change === 1
    }));
  }

  // This method marks selected AI change rows as successfully undone with one undo operation reference.
  public markAiChangesUndone(userId: number, changeIds: number[], undoOperationId: string, atIso: string): void {
    if (changeIds.length === 0) {
      return;
    }
    const placeholders = changeIds.map(() => '?').join(', ');
    this.db
      .prepare(
        `
        UPDATE ai_change_log
        SET
          undo_status = 'applied',
          undone_at = ?,
          undo_operation_id = ?
        WHERE user_id = ?
          AND id IN (${placeholders})
      `
      )
      .run(atIso, undoOperationId, userId, ...changeIds);
  }

  // This method updates selected AI change rows with one explicit undo status for conflict/failed tracking.
  public setAiChangeUndoStatus(
    userId: number,
    changeIds: number[],
    status: AiChangeUndoStatus,
    options?: {
      atIso?: string;
      undoOperationId?: string | null;
    }
  ): void {
    if (changeIds.length === 0) {
      return;
    }
    const placeholders = changeIds.map(() => '?').join(', ');
    this.db
      .prepare(
        `
        UPDATE ai_change_log
        SET
          undo_status = ?,
          undone_at = ?,
          undo_operation_id = ?
        WHERE user_id = ?
          AND id IN (${placeholders})
      `
      )
      .run(status, options?.atIso ?? null, options?.undoOperationId ?? null, userId, ...changeIds);
  }

  // This method updates undo status for AI change rows scoped to one operation and selected operation-item ids.
  public setAiChangeUndoStatusByOperationItems(
    userId: number,
    operationId: string,
    operationItemIds: number[],
    status: AiChangeUndoStatus,
    options?: {
      atIso?: string;
      undoOperationId?: string | null;
    }
  ): void {
    if (operationItemIds.length === 0) {
      return;
    }
    const placeholders = operationItemIds.map(() => '?').join(', ');
    this.db
      .prepare(
        `
        UPDATE ai_change_log
        SET
          undo_status = ?,
          undone_at = ?,
          undo_operation_id = ?
        WHERE user_id = ?
          AND operation_id = ?
          AND operation_item_id IN (${placeholders})
      `
      )
      .run(status, options?.atIso ?? null, options?.undoOperationId ?? null, userId, operationId, ...operationItemIds);
  }

  // This method removes expired AI change-log rows for one user according to selected retention days.
  public pruneAiChangeLog(userId: number, retentionDays: 30 | 90 | 180 | 365): number {
    const safeRetentionDays = this.normalizeAiActivityRetentionDays(retentionDays);
    const cutoffIso = new Date(Date.now() - safeRetentionDays * 24 * 60 * 60 * 1000).toISOString();
    const result = this.db
      .prepare(
        `
        DELETE FROM ai_change_log
        WHERE user_id = ?
          AND changed_at < ?
      `
      )
      .run(userId, cutoffIso);
    return result.changes;
  }

  // This method returns audit log rows with deterministic paging for MCP audit tools.
  public listAuditEntries(userId: number, limit = 100, offset = 0): Array<Record<string, unknown>> {
    const rows = this.db
      .prepare(
        `
        SELECT id, timestamp, actor, tool_name, target_type, target_ids_json, before_summary, after_summary, outcome, details_json
        FROM audit_log
        WHERE json_extract(details_json, '$.userId') = ?
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `
      )
      .all(userId, limit, offset) as Array<{
      id: number;
      timestamp: string;
      actor: string;
      tool_name: string;
      target_type: string;
      target_ids_json: string;
      before_summary: string;
      after_summary: string;
      outcome: string;
      details_json: string | null;
    }>;

    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      actor: row.actor,
      toolName: row.tool_name,
      targetType: row.target_type,
      targetIds: parseJson<Array<string | number>>(row.target_ids_json, 'audit_log.target_ids_json'),
      beforeSummary: row.before_summary,
      afterSummary: row.after_summary,
      outcome: row.outcome,
      details: row.details_json ? parseJson<Record<string, unknown>>(row.details_json, 'audit_log.details_json') : null
    }));
  }

  // This method allows a clean shutdown of SQLite resources.
  public close(): void {
    this.db.close();
  }
}
