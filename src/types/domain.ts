// This file centralizes domain models used across API, planning, storage, and MCP responses.

export interface LinkTag {
  id: number;
  name: string;
}

export interface LinkCollection {
  id: number;
  name: string;
  parentId?: number | null;
  ownerId?: number;
}

export interface LinkItem {
  id: number;
  title: string;
  url: string;
  description?: string | null;
  tags: LinkTag[];
  collection?: LinkCollection | null;
  archived?: boolean;
  pinned?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface PagingInput {
  limit: number;
  offset: number;
}

export interface PagingOutput {
  limit: number;
  offset: number;
  returned: number;
  total?: number;
}

// This selector captures deterministic scope filters shared by query, mutate, delete, and rule tools.
export interface LinkSelector {
  query?: string;
  ids?: number[];
  collectionId?: number;
  collectionNamesAny?: string[];
  includeDescendants?: boolean;
  tagIdsAny?: number[];
  tagIdsAll?: number[];
  tagNamesAny?: string[];
  tagNamesAll?: string[];
  archived?: boolean;
  pinned?: boolean;
  changedSince?: string;
  createdAtFrom?: string;
  createdAtTo?: string;
  createdAtRelative?: CreatedAtRelativeWindow;
  timeZone?: string;
}

// This model captures relative created-at windows for natural date filters in query selectors.
export interface CreatedAtRelativeWindow {
  amount: number;
  unit: 'day' | 'week' | 'month' | 'year';
  mode: 'rolling' | 'previous_calendar';
}

export type PlanStrategy =
  | 'tag-by-keywords'
  | 'move-to-collection'
  | 'rename-tags'
  | 'dedupe-tags';

export interface PlanScope {
  query?: string;
  collectionId?: number;
  tagIds?: number[];
  archived?: boolean;
  pinned?: boolean;
}

export interface PlanItem {
  linkId: number;
  action: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  warning?: string;
}

export interface PlanSummary {
  scanned: number;
  changes: number;
  unchanged: number;
}

export interface StoredPlan {
  planId: string;
  strategy: PlanStrategy;
  parameters: Record<string, unknown>;
  scope?: PlanScope;
  summary: PlanSummary;
  warnings: string[];
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  status: 'draft' | 'applied' | 'expired' | 'failed';
  appliedAt?: string | null;
}

export interface EncryptedConfig {
  version: 1;
  cipher: 'aes-256-gcm';
  kdf: 'pbkdf2-sha512';
  iterations: number;
  saltB64: string;
  ivB64: string;
  ciphertextB64: string;
  authTagB64: string;
}

export type EncryptedSecret = EncryptedConfig;

export interface RuntimeConfig {
  requestTimeoutMs: number;
  maxRetries: number;
  retryBaseDelayMs: number;
  planTtlHours: number;
  oauthClientId?: string;
  oauthClientSecret?: string;
}

export interface SetupPayload {
  masterPassphrase: string;
  adminUsername: string;
  adminPassword: string;
  linkwardenBaseUrl: string;
  linkwardenApiToken: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  adminWriteModeDefault: boolean;
  requestTimeoutMs?: number;
  maxRetries?: number;
  retryBaseDelayMs?: number;
  planTtlHours?: number;
}

export type UserRole = 'admin' | 'user';

export interface AuthenticatedPrincipal {
  userId: number;
  username: string;
  role: UserRole;
  apiKeyId: string;
  toolScopes?: string[];
  collectionScopes?: number[];
}

export type AuthMethod = 'api_key' | 'oauth';

export interface OAuthClientRecord {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  tokenEndpointAuthMethod: 'none' | 'client_secret_post';
  clientSecretHash?: string;
  createdAt: string;
  updatedAt: string;
}

export interface OAuthAuthorizationCodeRecord {
  userId: number;
  username: string;
  role: UserRole;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  scope: string;
  resource: string;
  expiresAt: string;
}

export interface OAuthTokenRecord {
  tokenId: string;
  userId: number;
  username: string;
  role: UserRole;
  clientId: string;
  scope: string;
  resource: string;
  accessExpiresAt: string;
  refreshExpiresAt: string;
}

export interface SessionPrincipal {
  userId: number;
  username: string;
  role: UserRole;
  sessionId: string;
}

export interface UserSettings {
  userId: number;
  writeModeEnabled: boolean;
  taggingStrictness: TaggingStrictness;
  fetchMode: FetchMode;
  queryTimeZone: string | null;
  newLinksRoutineEnabled: boolean;
  newLinksRoutineIntervalMinutes: number;
  newLinksRoutineModules: NewLinksRoutineModule[];
  newLinksRoutineBatchSize: number;
  newLinksCursor: NewLinksCursor | null;
  newLinksLastRunAt: string | null;
  newLinksLastStatus: string | null;
  newLinksLastError: string | null;
  newLinksBackfillRequested: boolean;
  newLinksBackfillConfirmed: boolean;
  offlineDays: number;
  offlineMinConsecutiveFailures: number;
  offlineAction: 'archive' | 'delete' | 'none';
  offlineArchiveCollectionId: number | null;
  updatedAt: string;
}

// This model stores per-user chat control settings used by backend-managed archive routing defaults.
export interface UserChatControlSettings {
  userId: number;
  archiveCollectionName: string;
  archiveCollectionParentId: number | null;
  chatCaptureTagName: string;
  chatCaptureTagAiChatEnabled: boolean;
  chatCaptureTagAiNameEnabled: boolean;
  updatedAt: string;
}

// This union keeps per-user tagging strictness presets explicit and validation-friendly.
export type TaggingStrictness = 'very_strict' | 'medium' | 'relaxed';

// This union captures the allowed context-fetch behavior for governed tagging.
export type FetchMode = 'never' | 'optional' | 'always';

// This union captures the supported provider backends for optional AI-assisted tag extraction.
export type TaggingInferenceProvider = 'builtin' | 'perplexity' | 'mistral' | 'huggingface';

// This union keeps new-link auto-routine modules explicit and validation-friendly.
export type NewLinksRoutineModule = 'governed_tagging' | 'normalize_urls' | 'dedupe';

// This model stores one deterministic createdAt/id cursor for new-link delta processing.
export interface NewLinksCursor {
  createdAt: string;
  linkId: number;
}

// This model stores one user's configurable new-link routine preferences and state.
export interface NewLinksRoutineSettings {
  userId: number;
  enabled: boolean;
  intervalMinutes: number;
  modules: NewLinksRoutineModule[];
  batchSize: number;
  cursor: NewLinksCursor | null;
  lastRunAt: string | null;
  lastStatus: string | null;
  lastError: string | null;
  backfillRequested: boolean;
  backfillConfirmed: boolean;
  updatedAt: string;
}

// This model stores one computed runtime status payload for the new-link auto-routine.
export interface NewLinksRoutineStatus {
  userId: number;
  settings: NewLinksRoutineSettings;
  due: boolean;
  nextDueAt: string | null;
  backlogCount: number | null;
  warnings: string[];
}

// This model stores global governed-tagging policy values controlled by admins.
export interface GlobalTaggingPolicy {
  fetchMode: FetchMode;
  allowUserFetchModeOverride: boolean;
  inferenceProvider: TaggingInferenceProvider;
  inferenceModel: string | null;
  blockedTagNames: string[];
  similarityThreshold: number;
  fetchTimeoutMs: number;
  fetchMaxBytes: number;
}

// This model stores one user's governed-tagging preferences consumed at tool runtime.
export interface UserTaggingPreferences {
  userId: number;
  taggingStrictness: TaggingStrictness;
  fetchMode: FetchMode;
  queryTimeZone: string | null;
  updatedAt: string;
}

// This model stores deterministic alias mappings from normalized tokens to canonical tags.
export interface TagAliasRecord {
  userId: number;
  canonicalTagId: number;
  aliasNormalized: string;
  confidence: number;
  createdAt: string;
  updatedAt: string;
}

// This model stores candidate support counters used to gate new-tag creation.
export interface TagCandidateRecord {
  userId: number;
  candidateNormalized: string;
  supportCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  blockedReason: string | null;
}

// This model stores cached extracted context tokens per link to reduce repeated fetch/token usage.
export interface LinkContextCacheRecord {
  userId: number;
  linkId: number;
  contextHash: string;
  extractedTokens: string[];
  expiresAt: string;
  updatedAt: string;
}

export interface LinkwardenTarget {
  id: 1;
  baseUrl: string;
  updatedAt: string;
}

export interface LinkHealthState {
  userId: number;
  linkId: number;
  url: string;
  firstFailureAt: string | null;
  lastFailureAt: string | null;
  consecutiveFailures: number;
  lastStatus: 'up' | 'down';
  lastCheckedAt: string;
  lastHttpStatus: number | null;
  lastError: string | null;
  archivedAt: string | null;
}

export interface MaintenanceRun {
  id: number;
  userId: number;
  startedAt: string;
  endedAt: string | null;
  mode: 'dry_run' | 'apply';
  reorgPlanId: string | null;
  status: 'running' | 'success' | 'failed';
  summary?: Record<string, unknown> | null;
  error?: Record<string, unknown> | null;
}

export interface MaintenanceRunItem {
  runId: number;
  itemType: 'reorg' | 'offline';
  linkId?: number | null;
  action: string;
  outcome: 'success' | 'failed' | 'skipped';
  details?: Record<string, unknown>;
}

export interface AuditEntry {
  actor: string;
  toolName: string;
  targetType: string;
  targetIds: Array<number | string>;
  beforeSummary: string;
  afterSummary: string;
  outcome: 'success' | 'failed';
  details?: Record<string, unknown>;
}

export interface BulkUpdateRequest {
  linkIds: number[];
  updates: {
    collectionId?: number | null;
    tagIds?: number[];
  };
  mode: 'replace' | 'add' | 'remove';
  dryRun?: boolean;
}

// This model stores one persisted saved-query definition for deterministic short-id execution.
export interface SavedQueryRecord {
  id: string;
  userId: number;
  name: string;
  selector: LinkSelector;
  fields: string[];
  verbosity: 'minimal' | 'normal' | 'debug';
  createdAt: string;
  updatedAt: string;
}

// This model stores one persisted rule definition used by the maintenance rule runner.
export interface RuleRecord {
  id: string;
  userId: number;
  name: string;
  selector: LinkSelector;
  action: Record<string, unknown>;
  schedule: Record<string, unknown>;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// This model stores one operation header used for audit views and undo eligibility checks.
export interface OperationRecord {
  id: string;
  userId: number;
  toolName: string;
  summary: Record<string, unknown>;
  undoUntil: string | null;
  createdAt: string;
}

// This model stores one operation item with before/after snapshots for deterministic undo.
export interface OperationItemRecord {
  operationId: string;
  itemType: string;
  itemId: number;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  undoStatus: 'pending' | 'applied' | 'failed';
}
