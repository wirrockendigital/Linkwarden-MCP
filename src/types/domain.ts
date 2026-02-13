// This file centralizes domain models used across API, planning, storage, and MCP responses.

export interface LinkTag {
  id: number;
  name: string;
}

export interface LinkCollection {
  id: number;
  name: string;
  parentId?: number | null;
}

export interface LinkItem {
  id: number;
  title: string;
  url: string;
  description?: string | null;
  tags: LinkTag[];
  collection?: LinkCollection | null;
  archived?: boolean;
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
  whitelistEntries: Array<{
    type: WhitelistType;
    value: string;
  }>;
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
  updatedAt: string;
}

export type WhitelistType = 'domain' | 'ip' | 'cidr';

export interface LinkwardenWhitelistEntry {
  id: number;
  type: WhitelistType;
  value: string;
  createdAt: string;
}

export interface LinkwardenTarget {
  id: 1;
  baseUrl: string;
  updatedAt: string;
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
    collectionId?: number;
    tagIds?: number[];
  };
  mode: 'replace' | 'add' | 'remove';
  dryRun?: boolean;
}
