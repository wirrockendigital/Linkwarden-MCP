// This module implements the alpha MCP tool surface with deterministic selectors, compact envelopes, and native-only behavior.

import { createHash, randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { LinkwardenClient } from '../linkwarden/client.js';
import { createUserLinkwardenClient } from '../linkwarden/runtime.js';
import {
  getLink404MonitorStatus,
  runLink404MonitorNow
} from '../services/link-404-routine.js';
import {
  getNewLinksRoutineStatus,
  runNewLinksRoutineNow
} from '../services/new-links-routine.js';
import type {
  AiChangeActionType,
  AuthenticatedPrincipal,
  FetchMode,
  GlobalTaggingPolicy,
  LinkCollection,
  LinkItem,
  LinkSelector,
  LinkTag,
  TagAliasRecord,
  TaggingStrictness,
  OperationItemRecord,
  RuleRecord
} from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { cleanTrackedUrl } from '../utils/url-cleaner.js';
import { fetchLinkContext } from '../utils/link-context-fetch.js';
import { inferTagTokensViaProvider } from '../utils/tag-inference-provider.js';
import { compileCreatedWindow } from '../utils/created-window.js';
import { errorForLog, sanitizeForLog } from '../utils/logger.js';
import {
  aggregateLinksSchema,
  applyRuleSchema,
  assignTagsSchema,
  captureChatLinksSchema,
  createCollectionSchema,
  createRuleSchema,
  createSavedQuerySchema,
  createTagSchema,
  deleteCollectionSchema,
  deleteLinksSchema,
  deleteRuleSchema,
  deleteTagSchema,
  findDuplicatesSchema,
  getAuditSchema,
  getLink404MonitorStatusSchema,
  getLinkSchema,
  getNewLinksRoutineStatusSchema,
  getStatsSchema,
  governedTagLinksSchema,
  listCollectionsSchema,
  listRulesSchema,
  listSavedQueriesSchema,
  listTagsSchema,
  mergeDuplicatesSchema,
  mutateLinksSchema,
  normalizeUrlsSchema,
  queryLinksSchema,
  runRulesNowSchema,
  runLink404MonitorNowSchema,
  runNewLinksRoutineNowSchema,
  runSavedQuerySchema,
  serverInfoSchema,
  testRuleSchema,
  undoOperationSchema,
  updateCollectionSchema
} from './tool-schemas.js';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, formatProtocolVersionWithTimestamp } from '../version.js';

export interface ToolRuntimeContext {
  actor: string;
  principal: AuthenticatedPrincipal;
  configStore: ConfigStore;
  db: SqliteStore;
  logger: FastifyBaseLogger;
}

// This type captures the normalized MCP tool output format returned to connectors.
export interface ToolCallResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: Record<string, unknown>;
}

interface ResolvedScope {
  links: LinkItem[];
  selectedCollectionIds: number[];
  warnings: string[];
}

interface QuerySlice {
  items: Array<Record<string, unknown>>;
  paging: {
    limit: number;
    returned: number;
    total: number;
    hasMore: boolean;
    nextCursor: string | null;
  };
}

interface CanonicalDuplicateGroup {
  canonicalUrl: string;
  links: LinkItem[];
}

interface ResolvedHierarchicalCollection {
  rootCollection: LinkCollection | null;
  aiCollection: LinkCollection | null;
  chatCollection: LinkCollection | null;
  createdCollections: LinkCollection[];
  wouldCreate: Array<{ level: 'root' | 'ai' | 'chat'; name: string; parentId: number | null }>;
}

// This type carries resolved ids and user-facing warnings for name-based selector filters.
interface ResolvedNameFilters {
  ids: number[];
  warnings: string[];
}

// This type captures resolved selector state so local filtering can run deterministically.
interface SelectorFilterRuntime {
  collectionScopeSet: Set<number> | null;
  tagIdsAny: number[] | null;
  tagIdsAll: number[] | null;
  createdWindow: {
    fromMs?: number;
    toMs?: number;
  } | null;
}

// This type captures fuzzy matching outcomes including explicit ambiguity handling.
type FuzzyNameMatchResult =
  | { kind: 'matched'; candidate: { id: number; name: string }; score: number }
  | { kind: 'ambiguous'; bestScore: number; secondScore: number }
  | { kind: 'none' };

// These constants bound fuzzy selector name resolution to high-confidence, low-ambiguity matches.
const FUZZY_NAME_MATCH_THRESHOLD = 0.88;
const FUZZY_NAME_MIN_GAP = 0.05;

// This helper wraps structured payloads in text plus structured fields for MCP connector compatibility.
function mcpResult(payload: Record<string, unknown>): ToolCallResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

// This helper wraps successful payloads with the standardized alpha result envelope.
function ok(
  data: Record<string, unknown>,
  extras?: {
    summary?: Record<string, unknown>;
    paging?: Record<string, unknown>;
    warnings?: string[];
    failures?: Array<Record<string, unknown>>;
  }
): ToolCallResult {
  return mcpResult(normalizeEnvelope({
    ok: true,
    data,
    summary: extras?.summary ?? {},
    paging: extras?.paging ?? null,
    warnings: extras?.warnings ?? [],
    failures: extras?.failures ?? [],
    error: null
  }));
}

// This helper guarantees one complete response envelope shape for all tools and cached idempotent payloads.
function normalizeEnvelope(payload: Record<string, unknown>): Record<string, unknown> {
  const safeData =
    payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)
      ? (payload.data as Record<string, unknown>)
      : {};
  const safeSummary =
    payload.summary && typeof payload.summary === 'object' && !Array.isArray(payload.summary)
      ? (payload.summary as Record<string, unknown>)
      : {};
  const safeFailures = Array.isArray(payload.failures)
    ? (payload.failures as Array<Record<string, unknown>>)
    : [];
  const safeWarnings = Array.isArray(payload.warnings) ? (payload.warnings as string[]) : [];
  const safePaging =
    payload.paging && typeof payload.paging === 'object' && !Array.isArray(payload.paging)
      ? (payload.paging as Record<string, unknown>)
      : null;

  return {
    ok: typeof payload.ok === 'boolean' ? payload.ok : true,
    data: safeData,
    summary: safeSummary,
    paging: safePaging,
    warnings: safeWarnings,
    error: (payload.error as Record<string, unknown> | null | undefined) ?? null,
    failures: safeFailures
  };
}

// This helper normalizes tag names for deterministic matching across case and spacing variants.
function normalizeTagName(value: string): string {
  return value.trim().toLocaleLowerCase();
}

// This helper keeps tag id lists deterministic and duplicate-free for stable write payloads.
function normalizeTagIds(ids: number[]): number[] {
  return [...new Set(ids.filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
}

// This helper computes one deterministic hash for idempotency request matching.
function stableHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// This helper creates one cursor token for deterministic query pagination resume.
function encodeCursor(snapshotId: string, offset: number): string {
  return Buffer.from(JSON.stringify({ snapshotId, offset }), 'utf8').toString('base64url');
}

// This helper decodes one cursor token and validates its structural integrity.
function decodeCursor(cursor: string): { snapshotId: string; offset: number } {
  try {
    const raw = Buffer.from(cursor, 'base64url').toString('utf8');
    const parsed = JSON.parse(raw) as { snapshotId?: string; offset?: number };
    const offset = parsed.offset;
    if (!parsed.snapshotId || typeof offset !== 'number' || !Number.isInteger(offset) || offset < 0) {
      throw new Error('invalid cursor shape');
    }
    return {
      snapshotId: parsed.snapshotId,
      offset
    };
  } catch {
    throw new AppError(400, 'validation_error', 'Invalid cursor format.');
  }
}

// This helper converts one arbitrary string into an URL-normalized canonical form for duplicate detection.
function canonicalizeUrl(url: string): string {
  try {
    const cleaned = cleanTrackedUrl(url, {
      removeUtm: true,
      removeKnownTracking: true,
      keepParams: [],
      extraTrackingParams: []
    });
    const parsed = new URL(cleaned.cleanedUrl);
    if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) {
      parsed.port = '';
    }
    parsed.hash = '';
    if (parsed.pathname !== '/' && parsed.pathname.endsWith('/')) {
      parsed.pathname = parsed.pathname.slice(0, -1);
    }
    return parsed.toString();
  } catch {
    return url.trim();
  }
}

// This helper extracts one lowercase domain candidate from a link URL for classification and aggregation.
function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.toLocaleLowerCase();
  } catch {
    return 'invalid-url';
  }
}

// This helper normalizes one collection segment string with deterministic length and fallback handling.
function normalizeCollectionSegment(raw: string | undefined, fallback: string, maxLength: number): string {
  const compact = (raw ?? '')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, maxLength);
  return compact.length > 0 ? compact : fallback;
}

// This helper normalizes one AI name into a deterministic tag label.
function normalizeAiNameTag(raw: string | undefined): string {
  return normalizeCollectionSegment(raw, 'ChatGPT', 80);
}

// This helper normalizes collection names for deterministic case-insensitive hierarchy matching.
function normalizeCollectionMatchName(value: string): string {
  return value
    .trim()
    .replace(/\s+/g, ' ')
    .toLocaleLowerCase();
}

// This helper resolves chat-name input priority across explicit field and known alias metadata keys.
function resolveChatNamePreference(input: {
  chatName?: string;
  chatTitle?: string;
  conversationTitle?: string;
  threadTitle?: string;
}): { rawName: string | undefined; source: 'chatName' | 'chatTitle' | 'conversationTitle' | 'threadTitle' | 'fallback' } {
  const candidates: Array<{ source: 'chatName' | 'chatTitle' | 'conversationTitle' | 'threadTitle'; value: string | undefined }> = [
    { source: 'chatName', value: input.chatName },
    { source: 'chatTitle', value: input.chatTitle },
    { source: 'conversationTitle', value: input.conversationTitle },
    { source: 'threadTitle', value: input.threadTitle }
  ];

  for (const candidate of candidates) {
    if (typeof candidate.value === 'string' && candidate.value.trim().length > 0) {
      return {
        rawName: candidate.value,
        source: candidate.source
      };
    }
  }

  return {
    rawName: undefined,
    source: 'fallback'
  };
}

// This helper normalizes one create-link error into a stable readable message.
function formatCreateLinkError(error: unknown): string {
  if (error instanceof Error) {
    const rawMessage = error.message.trim();
    if (!rawMessage) {
      return 'create link failed';
    }

    // This parsing extracts nested API response strings that may be wrapped as serialized JSON.
    try {
      const parsed = JSON.parse(rawMessage) as { response?: unknown; message?: unknown };
      if (typeof parsed.response === 'string' && parsed.response.trim().length > 0) {
        return parsed.response.trim();
      }
      if (typeof parsed.message === 'string' && parsed.message.trim().length > 0) {
        return parsed.message.trim();
      }
    } catch {
      // This branch intentionally falls back to the raw error message when JSON parsing is not applicable.
    }

    return rawMessage;
  }

  return 'create link failed';
}

// This helper classifies link-create validation failures that are specifically tied to the tags field.
function isTagRelatedCreateError(error: unknown): boolean {
  const normalizedMessage = formatCreateLinkError(error).toLocaleLowerCase();
  return (
    /\[tags(?:,\s*\d+)?\]/i.test(normalizedMessage) ||
    /expected object,\s*received number.*tags/i.test(normalizedMessage) ||
    /invalid input.*tags/i.test(normalizedMessage) ||
    /validation.*tags/i.test(normalizedMessage)
  );
}

// This helper trims wrapper and trailing punctuation artifacts from extracted URL candidates.
function cleanExtractedUrlCandidate(raw: string): string {
  let value = raw.trim();
  value = value.replace(/^[<("'[{]+/, '');
  value = value.replace(/[>"'\]}]+$/, '');
  value = value.replace(/[.,;!?]+$/, '');
  return value.trim();
}

// This helper extracts URL candidates from plain chat text including markdown links and raw URLs.
function extractUrlsFromChatText(chatText: string): string[] {
  const values: string[] = [];
  const markdownLinkPattern = /\[[^\]]+]\((https?:\/\/[^)\s]+)\)/gi;
  for (const match of chatText.matchAll(markdownLinkPattern)) {
    if (match[1]) {
      values.push(match[1]);
    }
  }

  const rawUrlPattern = /\bhttps?:\/\/[^\s<>"']+/gi;
  for (const match of chatText.matchAll(rawUrlPattern)) {
    if (match[0]) {
      values.push(match[0]);
    }
  }

  return values;
}

// This helper validates and canonicalizes chat URL candidates while collecting deterministic warnings.
function normalizeChatUrlCandidates(urls: string[]): {
  normalized: Array<{ originalUrl: string; canonicalUrl: string }>;
  warnings: string[];
  invalidCount: number;
  duplicatesWithinInput: number;
} {
  const warnings: string[] = [];
  const canonicalMap = new Map<string, { originalUrl: string; canonicalUrl: string }>();
  let invalidCount = 0;
  let duplicatesWithinInput = 0;

  for (const raw of urls) {
    const cleaned = cleanExtractedUrlCandidate(raw);
    if (!cleaned) {
      continue;
    }

    let parsed: URL;
    try {
      parsed = new URL(cleaned);
    } catch {
      invalidCount += 1;
      warnings.push(`capture_chat_links: invalid URL skipped "${cleaned}".`);
      continue;
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      invalidCount += 1;
      warnings.push(`capture_chat_links: unsupported URL protocol skipped "${cleaned}".`);
      continue;
    }

    const canonicalUrl = canonicalizeUrl(parsed.toString());
    if (canonicalMap.has(canonicalUrl)) {
      duplicatesWithinInput += 1;
      continue;
    }

    canonicalMap.set(canonicalUrl, {
      originalUrl: parsed.toString(),
      canonicalUrl
    });
  }

  return {
    normalized: [...canonicalMap.values()],
    warnings,
    invalidCount,
    duplicatesWithinInput
  };
}

// This helper chooses one deterministic exact collection match by smallest id.
function pickExactCollectionMatchByParent(
  collections: LinkCollection[],
  name: string,
  parentId: number | null
): LinkCollection | null {
  const normalizedTargetName = normalizeCollectionMatchName(name);
  const matches = collections
    .filter(
      (collection) =>
        normalizeCollectionMatchName(collection.name) === normalizedTargetName && collection.parentId === parentId
    )
    .sort((left, right) => left.id - right.id);
  return matches[0] ?? null;
}

// This helper resolves (and optionally creates) one deterministic AI chat collection hierarchy.
async function resolveChatCollectionHierarchy(
  client: LinkwardenClient,
  aiName: string,
  chatName: string,
  allowCreate: boolean
): Promise<ResolvedHierarchicalCollection> {
  const allCollections = await client.listAllCollections();
  const createdCollections: LinkCollection[] = [];
  const wouldCreate: Array<{ level: 'root' | 'ai' | 'chat'; name: string; parentId: number | null }> = [];

  const ensureCollection = async (
    level: 'root' | 'ai' | 'chat',
    name: string,
    parentId: number | null
  ): Promise<LinkCollection | null> => {
    const existing = pickExactCollectionMatchByParent(allCollections, name, parentId);
    if (existing) {
      return existing;
    }

    if (!allowCreate) {
      wouldCreate.push({ level, name, parentId });
      return null;
    }

    const created = await client.createCollection({
      name,
      parentId
    });
    allCollections.push(created);
    createdCollections.push(created);
    return created;
  };

  const rootCollection = await ensureCollection('root', 'AI Chats', null);
  const aiCollection = rootCollection ? await ensureCollection('ai', aiName, rootCollection.id) : null;
  const chatCollection = aiCollection ? await ensureCollection('chat', chatName, aiCollection.id) : null;

  return {
    rootCollection,
    aiCollection,
    chatCollection,
    createdCollections,
    wouldCreate
  };
}

// This helper checks whether the principal can execute one specific tool based on configured tool scopes.
function assertToolScopeAccess(context: ToolRuntimeContext, toolName: string): void {
  const toolScopes = context.principal.toolScopes ?? ['*'];
  if (toolScopes.includes('*')) {
    return;
  }
  if (!toolScopes.includes(toolName)) {
    throw new AppError(403, 'forbidden', `Tool ${toolName} is not allowed by token scope.`);
  }
}

// This helper checks write-mode state and role before mutating Linkwarden data.
function assertWriteAccess(context: ToolRuntimeContext): void {
  if (context.principal.role !== 'admin' && context.principal.role !== 'user') {
    throw new AppError(403, 'forbidden', 'Role is not allowed to execute write operations.');
  }
  const settings = context.db.getUserSettings(context.principal.userId);
  if (!settings.writeModeEnabled) {
    throw new AppError(403, 'write_mode_disabled', 'Write mode is disabled for this user.');
  }
}

// This helper enforces optional collection scope restrictions on explicit collection targets.
function assertCollectionScopeAccess(context: ToolRuntimeContext, collectionId: number | null | undefined): void {
  if (collectionId === null || collectionId === undefined) {
    return;
  }
  const scoped = context.principal.collectionScopes ?? [];
  if (scoped.length === 0) {
    return;
  }
  if (!scoped.includes(collectionId)) {
    throw new AppError(403, 'forbidden', `Collection ${collectionId} is outside token scope.`);
  }
}

// This helper returns one user-bound Linkwarden API client instance from runtime secrets.
function getClient(context: ToolRuntimeContext): LinkwardenClient {
  return createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
}

// This helper keeps link projection deterministic and token-efficient based on requested fields and verbosity mode.
function projectLink(
  link: LinkItem,
  requestedFields: string[],
  verbosity: 'minimal' | 'normal' | 'debug'
): Record<string, unknown> {
  const minimalProjection: Record<string, unknown> = {
    id: link.id,
    title: link.title,
    url: link.url,
    collectionId: link.collection?.id ?? null,
    tagIds: link.tags.map((tag) => tag.id),
    pinned: Boolean(link.pinned),
    archived: Boolean(link.archived),
    updatedAt: link.updatedAt ?? null
  };

  const normalProjection: Record<string, unknown> = {
    ...minimalProjection,
    description: link.description ?? null,
    tags: link.tags,
    collection: link.collection ?? null,
    createdAt: link.createdAt ?? null
  };

  const debugProjection: Record<string, unknown> = {
    ...normalProjection,
    domain: extractDomain(link.url)
  };

  const base = verbosity === 'minimal' ? minimalProjection : verbosity === 'normal' ? normalProjection : debugProjection;
  if (requestedFields.length === 0) {
    return base;
  }

  const projected: Record<string, unknown> = {};
  for (const field of requestedFields) {
    if (Object.prototype.hasOwnProperty.call(base, field)) {
      projected[field] = base[field];
    }
  }

  if (!Object.prototype.hasOwnProperty.call(projected, 'id')) {
    projected.id = link.id;
  }
  return projected;
}

// This helper resolves selector collections with optional descendant expansion for deterministic subtree targeting.
function resolveCollectionScope(collections: LinkCollection[], collectionId: number, includeDescendants: boolean): Set<number> {
  const selected = new Set<number>([collectionId]);
  if (!includeDescendants) {
    return selected;
  }

  const byParent = new Map<number, number[]>();
  for (const collection of collections) {
    if (typeof collection.parentId !== 'number') {
      continue;
    }
    const children = byParent.get(collection.parentId) ?? [];
    children.push(collection.id);
    byParent.set(collection.parentId, children);
  }

  const queue = [collectionId];
  while (queue.length > 0) {
    const current = queue.shift() as number;
    const children = byParent.get(current) ?? [];
    for (const childId of children) {
      if (selected.has(childId)) {
        continue;
      }
      selected.add(childId);
      queue.push(childId);
    }
  }
  return selected;
}

// This helper computes one deterministic fuzzy match candidate and rejects ambiguous score ties.
function pickFuzzyMatch(
  requestedName: string,
  candidates: Array<{ id: number; name: string }>
): FuzzyNameMatchResult {
  const scored = candidates
    .map((candidate) => ({
      candidate,
      score: diceSimilarity(requestedName, candidate.name)
    }))
    .sort((left, right) => right.score - left.score || left.candidate.id - right.candidate.id);

  const best = scored[0];
  if (!best || best.score < FUZZY_NAME_MATCH_THRESHOLD) {
    return { kind: 'none' };
  }

  const second = scored[1];
  if (second && best.score - second.score < FUZZY_NAME_MIN_GAP) {
    return {
      kind: 'ambiguous',
      bestScore: best.score,
      secondScore: second.score
    };
  }

  return {
    kind: 'matched',
    candidate: best.candidate,
    score: best.score
  };
}

// This helper resolves tag names to ids with exact, alias, and deterministic fuzzy matching.
function resolveTagNameFilters(
  names: string[] | undefined,
  allTags: LinkTag[],
  aliases: TagAliasRecord[] | undefined,
  selectorField: 'tagNamesAny' | 'tagNamesAll'
): ResolvedNameFilters {
  const warnings: string[] = [];
  const resolvedIds = new Set<number>();
  const uniqueNames = [...new Set((names ?? []).map((name) => name.trim()).filter((name) => name.length > 0))];
  const tagsById = new Map<number, LinkTag>(allTags.map((tag) => [tag.id, tag]));
  const tagsByNormalized = new Map<string, LinkTag[]>();
  const aliasByNormalized = new Map<string, TagAliasRecord>();

  for (const tag of allTags) {
    const normalized = normalizeTagName(tag.name);
    const existing = tagsByNormalized.get(normalized) ?? [];
    existing.push(tag);
    tagsByNormalized.set(normalized, existing);
  }

  for (const alias of aliases ?? []) {
    if (!aliasByNormalized.has(alias.aliasNormalized)) {
      aliasByNormalized.set(alias.aliasNormalized, alias);
    }
  }

  for (const rawName of uniqueNames) {
    const normalized = normalizeTagName(rawName);
    const exactMatches = (tagsByNormalized.get(normalized) ?? []).sort((left, right) => left.id - right.id);
    if (exactMatches.length > 0) {
      resolvedIds.add(exactMatches[0].id);
      if (exactMatches.length > 1) {
        warnings.push(
          `${selectorField}: multiple exact tag matches for "${rawName}", selected id ${exactMatches[0].id}.`
        );
      }
      continue;
    }

    const alias = aliasByNormalized.get(normalized);
    if (alias) {
      const aliasedTag = tagsById.get(alias.canonicalTagId);
      if (aliasedTag) {
        resolvedIds.add(aliasedTag.id);
        continue;
      }
    }

    const fuzzyMatch = pickFuzzyMatch(normalized, allTags.map((tag) => ({ id: tag.id, name: tag.name })));
    if (fuzzyMatch.kind === 'none') {
      warnings.push(`${selectorField}: unresolved tag name "${rawName}".`);
      continue;
    }
    if (fuzzyMatch.kind === 'ambiguous') {
      warnings.push(
        `${selectorField}: ambiguous fuzzy candidates for "${rawName}" (best ${fuzzyMatch.bestScore.toFixed(2)}, second ${fuzzyMatch.secondScore.toFixed(2)}), skipped.`
      );
      continue;
    }

    const matchedTag = tagsById.get(fuzzyMatch.candidate.id);
    if (!matchedTag) {
      warnings.push(`${selectorField}: unresolved tag name "${rawName}".`);
      continue;
    }

    resolvedIds.add(matchedTag.id);
    warnings.push(
      `${selectorField}: fuzzy matched "${rawName}" to tag "${matchedTag.name}" (id ${matchedTag.id}, score ${fuzzyMatch.score.toFixed(2)}).`
    );
  }

  return {
    ids: [...resolvedIds].sort((left, right) => left - right),
    warnings
  };
}

// This helper resolves collection names to ids with exact and deterministic fuzzy matching.
function resolveCollectionNameFilters(
  names: string[] | undefined,
  collections: LinkCollection[],
  includeDescendants: boolean
): ResolvedNameFilters {
  const warnings: string[] = [];
  const resolvedBaseIds = new Set<number>();
  const uniqueNames = [...new Set((names ?? []).map((name) => name.trim()).filter((name) => name.length > 0))];
  const collectionsByNormalized = new Map<string, LinkCollection[]>();

  for (const collection of collections) {
    const normalized = normalizeTagName(collection.name);
    const existing = collectionsByNormalized.get(normalized) ?? [];
    existing.push(collection);
    collectionsByNormalized.set(normalized, existing);
  }

  for (const rawName of uniqueNames) {
    const normalized = normalizeTagName(rawName);
    const exactMatches = (collectionsByNormalized.get(normalized) ?? []).sort((left, right) => left.id - right.id);
    if (exactMatches.length > 0) {
      resolvedBaseIds.add(exactMatches[0].id);
      if (exactMatches.length > 1) {
        warnings.push(
          `collectionNamesAny: multiple exact collection matches for "${rawName}", selected id ${exactMatches[0].id}.`
        );
      }
      continue;
    }

    const fuzzyMatch = pickFuzzyMatch(
      normalized,
      collections.map((collection) => ({ id: collection.id, name: collection.name }))
    );
    if (fuzzyMatch.kind === 'none') {
      warnings.push(`collectionNamesAny: unresolved collection name "${rawName}".`);
      continue;
    }
    if (fuzzyMatch.kind === 'ambiguous') {
      warnings.push(
        `collectionNamesAny: ambiguous fuzzy candidates for "${rawName}" (best ${fuzzyMatch.bestScore.toFixed(2)}, second ${fuzzyMatch.secondScore.toFixed(2)}), skipped.`
      );
      continue;
    }

    resolvedBaseIds.add(fuzzyMatch.candidate.id);
    warnings.push(
      `collectionNamesAny: fuzzy matched "${rawName}" to collection "${fuzzyMatch.candidate.name}" (id ${fuzzyMatch.candidate.id}, score ${fuzzyMatch.score.toFixed(2)}).`
    );
  }

  const resolvedIds = new Set<number>();
  for (const id of resolvedBaseIds) {
    if (includeDescendants) {
      const scoped = resolveCollectionScope(collections, id, true);
      for (const scopedId of scoped) {
        resolvedIds.add(scopedId);
      }
      continue;
    }
    resolvedIds.add(id);
  }

  return {
    ids: [...resolvedIds].sort((left, right) => left - right),
    warnings
  };
}

// This helper filters one link list with selector constraints that are not guaranteed by upstream query semantics.
function applyLocalSelectorFilters(
  links: LinkItem[],
  selector: LinkSelector | undefined,
  runtime: SelectorFilterRuntime
): LinkItem[] {
  const idsSet = selector?.ids ? new Set(selector.ids) : null;
  const tagAnySet = runtime.tagIdsAny ? new Set(runtime.tagIdsAny) : null;
  const tagAllSet = runtime.tagIdsAll ? new Set(runtime.tagIdsAll) : null;
  const changedSinceMs = selector?.changedSince ? new Date(selector.changedSince).getTime() : null;

  return links.filter((link) => {
    if (idsSet && !idsSet.has(link.id)) {
      return false;
    }

    if (runtime.collectionScopeSet) {
      const collectionId = link.collection?.id;
      if (typeof collectionId !== 'number' || !runtime.collectionScopeSet.has(collectionId)) {
        return false;
      }
    }

    if (typeof selector?.archived === 'boolean' && Boolean(link.archived) !== selector.archived) {
      return false;
    }

    if (typeof selector?.pinned === 'boolean' && Boolean(link.pinned) !== selector.pinned) {
      return false;
    }

    if (tagAnySet) {
      const hasAny = link.tags.some((tag) => tagAnySet.has(tag.id));
      if (!hasAny) {
        return false;
      }
    }

    if (tagAllSet) {
      if (tagAllSet.size === 0) {
        return false;
      }
      const linkTagIds = new Set(link.tags.map((tag) => tag.id));
      for (const requiredTagId of tagAllSet) {
        if (!linkTagIds.has(requiredTagId)) {
          return false;
        }
      }
    }

    if (typeof changedSinceMs === 'number' && Number.isFinite(changedSinceMs)) {
      const sourceDate = link.updatedAt ?? link.createdAt;
      if (!sourceDate) {
        return false;
      }
      if (new Date(sourceDate).getTime() < changedSinceMs) {
        return false;
      }
    }

    if (runtime.createdWindow) {
      const createdAt = link.createdAt;
      if (!createdAt) {
        return false;
      }
      const createdAtMs = new Date(createdAt).getTime();
      if (!Number.isFinite(createdAtMs)) {
        return false;
      }
      if (typeof runtime.createdWindow.fromMs === 'number' && createdAtMs < runtime.createdWindow.fromMs) {
        return false;
      }
      if (typeof runtime.createdWindow.toMs === 'number' && createdAtMs > runtime.createdWindow.toMs) {
        return false;
      }
    }

    return true;
  });
}

// This helper applies principal collection scope restrictions to one candidate link set.
function applyPrincipalCollectionScope(links: LinkItem[], principal: AuthenticatedPrincipal): LinkItem[] {
  const scopedCollections = principal.collectionScopes ?? [];
  if (scopedCollections.length === 0) {
    return links;
  }
  const allowed = new Set(scopedCollections);
  return links.filter((link) => typeof link.collection?.id === 'number' && allowed.has(link.collection.id));
}

// This helper resolves links for selector/ids requests while keeping result order deterministic.
async function resolveLinks(
  context: ToolRuntimeContext,
  selector: LinkSelector | undefined,
  ids: number[] | undefined
): Promise<ResolvedScope> {
  const client = getClient(context);
  let links: LinkItem[] = [];
  let selectedCollectionIds: number[] = [];
  const warnings: string[] = [];

  if (Array.isArray(ids) && ids.length > 0) {
    const loaded = await Promise.all(ids.map(async (id) => client.getLink(id)));
    links = loaded;
    selectedCollectionIds = loaded
      .map((link) => link.collection?.id)
      .filter((value): value is number => typeof value === 'number');
  } else {
    const userSettings = context.db.getUserSettings(context.principal.userId);
    const compiledWindow = compileCreatedWindow({
      selector,
      userTimeZone: userSettings.queryTimeZone,
      serverDefaultTimeZone: process.env.MCP_DEFAULT_QUERY_TIMEZONE ?? null
    });
    warnings.push(...compiledWindow.warnings);

    let allCollections: LinkCollection[] = [];
    let scopeSet: Set<number> | null = null;
    const selectorCollectionId = selector?.collectionId;
    const hasCollectionNameFilter = Array.isArray(selector?.collectionNamesAny) && selector.collectionNamesAny.length > 0;
    const shouldLoadCollections = typeof selectorCollectionId === 'number' || hasCollectionNameFilter;

    if (shouldLoadCollections) {
      allCollections = await client.listAllCollections();
    }

    if (typeof selectorCollectionId === 'number') {
      scopeSet = resolveCollectionScope(allCollections, selectorCollectionId, Boolean(selector?.includeDescendants));
      selectedCollectionIds = [...scopeSet].sort((left, right) => left - right);
    } else if (hasCollectionNameFilter) {
      const collectionResolution = resolveCollectionNameFilters(
        selector?.collectionNamesAny,
        allCollections,
        Boolean(selector?.includeDescendants)
      );
      warnings.push(...collectionResolution.warnings);
      scopeSet = new Set(collectionResolution.ids);
      selectedCollectionIds = collectionResolution.ids;
    }

    for (const selectedCollectionId of selectedCollectionIds) {
      assertCollectionScopeAccess(context, selectedCollectionId);
    }

    // This short-circuit avoids full scans when collection names resolve to zero accessible scopes.
    if (scopeSet && scopeSet.size === 0) {
      return {
        links: [],
        selectedCollectionIds,
        warnings
      };
    }

    let resolvedTagIdsAny: number[] | null = selector?.tagIdsAny ? [...selector.tagIdsAny] : null;
    let resolvedTagIdsAll: number[] | null = selector?.tagIdsAll ? [...selector.tagIdsAll] : null;
    const hasTagNameFilter =
      (Array.isArray(selector?.tagNamesAny) && selector.tagNamesAny.length > 0) ||
      (Array.isArray(selector?.tagNamesAll) && selector.tagNamesAll.length > 0);

    if (hasTagNameFilter) {
      const allTags = await client.listAllTags();
      const aliases = context.db.listTagAliases(context.principal.userId);
      if (Array.isArray(selector?.tagNamesAny) && selector.tagNamesAny.length > 0) {
        const anyResolution = resolveTagNameFilters(selector.tagNamesAny, allTags, aliases, 'tagNamesAny');
        resolvedTagIdsAny = anyResolution.ids;
        warnings.push(...anyResolution.warnings);
      }
      if (Array.isArray(selector?.tagNamesAll) && selector.tagNamesAll.length > 0) {
        const allResolution = resolveTagNameFilters(selector.tagNamesAll, allTags, aliases, 'tagNamesAll');
        resolvedTagIdsAll = allResolution.ids;
        warnings.push(...allResolution.warnings);
      }
    }

    // This branch keeps upstream filtering broad enough for descendant/name scopes while still reducing obvious payload size.
    const upstreamCollectionId =
      typeof selectorCollectionId === 'number' && !Boolean(selector?.includeDescendants) ? selectorCollectionId : undefined;
    const upstreamTagIds = resolvedTagIdsAny ?? resolvedTagIdsAll ?? undefined;
    const loaded = await client.loadLinksForScope({
      query: selector?.query,
      collectionId: upstreamCollectionId,
      tagIds: upstreamTagIds ?? undefined,
      archived: selector?.archived,
      pinned: selector?.pinned
    });
    links = applyLocalSelectorFilters(loaded, selector, {
      collectionScopeSet: scopeSet,
      tagIdsAny: resolvedTagIdsAny,
      tagIdsAll: resolvedTagIdsAll,
      createdWindow:
        typeof compiledWindow.fromMs === 'number' || typeof compiledWindow.toMs === 'number'
          ? {
              fromMs: compiledWindow.fromMs,
              toMs: compiledWindow.toMs
            }
          : null
    });
  }

  const scoped = applyPrincipalCollectionScope(links, context.principal);
  const deduped = new Map<number, LinkItem>();
  for (const link of scoped) {
    deduped.set(link.id, link);
  }
  const sorted = [...deduped.values()].sort((left, right) => left.id - right.id);
  return {
    links: sorted,
    selectedCollectionIds,
    warnings
  };
}

// This helper creates or resolves tag ids by name with deterministic normalized matching rules.
async function resolveTagIdsByName(
  client: LinkwardenClient,
  names: string[],
  createMissing: boolean,
  dryRun: boolean
): Promise<{ tagIds: number[]; created: LinkTag[]; missing: string[] }> {
  const normalizedNames = [...new Set(names.map((name) => name.trim()).filter((name) => name.length > 0))];
  const allTags = await client.listAllTags();
  const byNormalized = new Map<string, LinkTag>(allTags.map((tag) => [normalizeTagName(tag.name), tag]));
  const created: LinkTag[] = [];
  const missing: string[] = [];

  for (const name of normalizedNames) {
    const normalized = normalizeTagName(name);
    if (byNormalized.has(normalized)) {
      continue;
    }
    if (!createMissing || dryRun) {
      missing.push(name);
      continue;
    }
    const createdTag = await client.createTag(name);
    byNormalized.set(normalizeTagName(createdTag.name), createdTag);
    created.push(createdTag);
  }

  const tagIds = normalizedNames
    .map((name) => byNormalized.get(normalizeTagName(name)))
    .filter((tag): tag is LinkTag => Boolean(tag))
    .map((tag) => tag.id);

  return {
    tagIds: normalizeTagIds(tagIds),
    created,
    missing
  };
}

// This helper computes one next tag state based on replace/add/remove semantics.
function computeNextTagIds(currentTagIds: number[], nextTagIds: number[], mode: 'replace' | 'add' | 'remove'): number[] {
  const current = new Set(currentTagIds);

  if (mode === 'replace') {
    return normalizeTagIds(nextTagIds);
  }
  if (mode === 'add') {
    for (const tagId of nextTagIds) {
      current.add(tagId);
    }
    return normalizeTagIds([...current]);
  }
  for (const tagId of nextTagIds) {
    current.delete(tagId);
  }
  return normalizeTagIds([...current]);
}

// This helper executes one mutation callback with optional idempotency replay support.
async function withIdempotency(
  context: ToolRuntimeContext,
  toolName: string,
  idempotencyKey: string | undefined,
  requestPayload: Record<string, unknown>,
  work: () => Promise<Record<string, unknown>>
): Promise<ToolCallResult> {
  if (!idempotencyKey) {
    return mcpResult(normalizeEnvelope(await work()));
  }

  const hash = stableHash(requestPayload);
  const cached = context.db.getIdempotencyRecord(context.principal.userId, toolName, idempotencyKey, hash);
  if (cached) {
    return mcpResult(normalizeEnvelope(cached));
  }

  const payload = normalizeEnvelope(await work());
  context.db.upsertIdempotencyRecord({
    userId: context.principal.userId,
    toolName,
    key: idempotencyKey,
    requestHash: hash,
    response: payload,
    ttlSeconds: 24 * 60 * 60
  });
  return mcpResult(payload);
}

// This helper creates one operation record and returns its identifier for undo/audit tracking.
function beginOperation(
  context: ToolRuntimeContext,
  toolName: string,
  summary: Record<string, unknown>,
  undoDays = 7
): string {
  const operationId = randomUUID();
  const undoUntil = new Date(Date.now() + undoDays * 24 * 60 * 60 * 1000).toISOString();
  context.db.createOperation({
    id: operationId,
    userId: context.principal.userId,
    toolName,
    summary,
    undoUntil
  });
  return operationId;
}

// This helper creates one compact model for operation item snapshots used by undo flows.
function snapshotForUndo(link: LinkItem): Record<string, unknown> {
  return {
    title: link.title,
    url: link.url,
    description: link.description ?? null,
    collectionId: link.collection?.id ?? null,
    tagIds: link.tags.map((tag) => tag.id),
    pinned: Boolean(link.pinned),
    archived: Boolean(link.archived)
  };
}

// This helper reads optional snapshot string values and normalizes empty values to null.
function readSnapshotString(snapshot: Record<string, unknown>, key: string): string | null {
  const raw = snapshot[key];
  if (typeof raw !== 'string') {
    return null;
  }
  const normalized = raw.trim();
  return normalized.length > 0 ? normalized : null;
}

// This helper reads optional snapshot numeric identifiers as nullable positive integers.
function readSnapshotId(snapshot: Record<string, unknown>, key: string): number | null {
  const raw = snapshot[key];
  const numeric = Number(raw);
  if (!Number.isInteger(numeric) || numeric <= 0) {
    return null;
  }
  return numeric;
}

// This helper reads one deterministic snapshot tag-id array while discarding invalid values.
function readSnapshotTagIds(snapshot: Record<string, unknown>): number[] {
  const raw = snapshot.tagIds;
  if (!Array.isArray(raw)) {
    return [];
  }
  return normalizeTagIds(raw.map((value) => Number(value)));
}

// This helper resolves one human-readable tag name from cache and falls back to an id marker.
function resolveTagNameById(tagId: number, byTagId: Map<number, string>): string {
  const resolved = byTagId.get(tagId);
  if (typeof resolved === 'string' && resolved.trim().length > 0) {
    return resolved.trim();
  }
  return `tag:${tagId}`;
}

// This helper classifies one operation-item delta into a stable AI change action type.
function inferAiChangeActionType(input: {
  toolName: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  tagsAddedCount: number;
  tagsRemovedCount: number;
  collectionChanged: boolean;
  urlChanged: boolean;
}): AiChangeActionType {
  const beforeDeleted = input.before.deleted === true;
  const afterDeleted = input.after.deleted === true;
  if (beforeDeleted && !afterDeleted) {
    return 'create_link';
  }
  if (!beforeDeleted && afterDeleted) {
    return 'delete_link';
  }

  if (input.toolName === 'linkwarden_normalize_urls' && input.urlChanged) {
    return 'normalize_url';
  }
  if (input.toolName === 'linkwarden_merge_duplicates') {
    return 'merge';
  }
  if (input.collectionChanged) {
    return 'move_collection';
  }
  if (input.tagsAddedCount > 0 && input.tagsRemovedCount === 0) {
    return 'tag_add';
  }
  if (input.tagsRemovedCount > 0 && input.tagsAddedCount === 0) {
    return 'tag_remove';
  }

  const beforeArchived = input.before.archived === true;
  const afterArchived = input.after.archived === true;
  if (!beforeArchived && afterArchived) {
    return 'archive';
  }
  if (beforeArchived && !afterArchived) {
    return 'unarchive';
  }
  return 'update_link';
}

// This helper records normalized AI change-log entries derived from operation-item before/after snapshots.
async function appendAiChangeLogForOperation(
  context: ToolRuntimeContext,
  client: LinkwardenClient,
  toolName: string,
  operationId: string,
  operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }>
): Promise<void> {
  if (operationItems.length === 0) {
    return;
  }

  const [collections, tags] = await Promise.all([client.listAllCollections(), client.listAllTags()]);
  const collectionNameById = new Map<number, string>();
  const tagNameById = new Map<number, string>();
  for (const collection of collections) {
    collectionNameById.set(collection.id, collection.name);
  }
  for (const tag of tags) {
    tagNameById.set(tag.id, tag.name);
  }

  const entries = operationItems.map((item) => {
    const before = item.before;
    const after = item.after;
    const beforeUrl = readSnapshotString(before, 'url');
    const afterUrl = readSnapshotString(after, 'url');
    const beforeCollectionId = readSnapshotId(before, 'collectionId');
    const afterCollectionId = readSnapshotId(after, 'collectionId');
    const beforeTagIds = readSnapshotTagIds(before);
    const afterTagIds = readSnapshotTagIds(after);
    const beforeTagSet = new Set(beforeTagIds);
    const afterTagSet = new Set(afterTagIds);
    const tagsAddedIds = afterTagIds.filter((tagId) => !beforeTagSet.has(tagId));
    const tagsRemovedIds = beforeTagIds.filter((tagId) => !afterTagSet.has(tagId));
    const tagsAdded = tagsAddedIds.map((tagId) => resolveTagNameById(tagId, tagNameById));
    const tagsRemoved = tagsRemovedIds.map((tagId) => resolveTagNameById(tagId, tagNameById));
    const collectionChanged = beforeCollectionId !== afterCollectionId;
    const urlChanged = beforeUrl !== afterUrl;
    const actionType = inferAiChangeActionType({
      toolName,
      before,
      after,
      tagsAddedCount: tagsAdded.length,
      tagsRemovedCount: tagsRemoved.length,
      collectionChanged,
      urlChanged
    });

    return {
      operationItemId: item.itemId,
      actionType,
      linkId: Number.isInteger(item.itemId) && item.itemId > 0 ? item.itemId : null,
      linkTitle: readSnapshotString(after, 'title') ?? readSnapshotString(before, 'title'),
      urlBefore: beforeUrl,
      urlAfter: afterUrl,
      trackingTrimmed: actionType === 'normalize_url' && urlChanged,
      collectionFromId: beforeCollectionId,
      collectionFromName: beforeCollectionId ? (collectionNameById.get(beforeCollectionId) ?? null) : null,
      collectionToId: afterCollectionId,
      collectionToName: afterCollectionId ? (collectionNameById.get(afterCollectionId) ?? null) : null,
      tagsAdded,
      tagsRemoved,
      undoStatus: 'pending' as const,
      meta: {
        itemType: item.itemType,
        deleteMode: typeof after.deleteMode === 'string' ? after.deleteMode : null
      }
    };
  });

  context.db.appendAiChangeLogEntries({
    userId: context.principal.userId,
    operationId,
    toolName,
    entries
  });
}

// This helper generates one deterministic query page response from a persisted query snapshot.
function readQuerySlice(
  snapshotId: string,
  items: Array<Record<string, unknown>>,
  limit: number,
  offset: number
): QuerySlice {
  const pageItems = items.slice(offset, offset + limit);
  const nextOffset = offset + pageItems.length;
  const hasMore = nextOffset < items.length;
  return {
    items: pageItems,
    paging: {
      limit,
      returned: pageItems.length,
      total: items.length,
      hasMore,
      nextCursor: hasMore ? encodeCursor(snapshotId, nextOffset) : null
    }
  };
}

// This helper collects duplicate groups by canonical URL with deterministic output ordering.
function groupDuplicates(links: LinkItem[]): CanonicalDuplicateGroup[] {
  const grouped = new Map<string, LinkItem[]>();
  for (const link of links) {
    const canonicalUrl = canonicalizeUrl(link.url);
    const existing = grouped.get(canonicalUrl) ?? [];
    existing.push(link);
    grouped.set(canonicalUrl, existing);
  }
  return [...grouped.entries()]
    .map(([canonicalUrl, groupLinks]) => ({
      canonicalUrl,
      links: groupLinks.sort((left, right) => left.id - right.id)
    }))
    .filter((group) => group.links.length > 1)
    .sort((left, right) => right.links.length - left.links.length || left.canonicalUrl.localeCompare(right.canonicalUrl));
}

// This helper formats one compact tool result summary for structured completion logs.
function summarizeToolOutput(output: ToolCallResult): Record<string, unknown> {
  const payload = output.structuredContent;
  return sanitizeForLog({
    ok: payload.ok,
    keys: Object.keys(payload),
    summary: payload.summary,
    paging: payload.paging
  }) as Record<string, unknown>;
}

// This function handles linkwarden_get_server_info and returns alpha protocol metadata.
async function handleGetServerInfo(args: unknown): Promise<ToolCallResult> {
  serverInfoSchema.parse(args);
  return ok({
    name: MCP_SERVER_NAME,
    version: MCP_SERVER_VERSION,
    protocolVersion: formatProtocolVersionWithTimestamp(),
    supportedTagInferenceProviders: ['builtin', 'perplexity', 'mistral', 'huggingface']
  });
}

// This function handles linkwarden_get_stats with hard counters for links, collections, tags, pinned, and archived.
async function handleGetStats(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = getStatsSchema.parse(args);
  const client = getClient(context);
  const resolved = await resolveLinks(context, input.selector, undefined);
  const collections = await client.listAllCollections();
  const tags = await client.listAllTags();
  const pinnedCount = resolved.links.filter((link) => Boolean(link.pinned)).length;
  const archivedCount = resolved.links.filter((link) => Boolean(link.archived)).length;

  return ok(
    {
      linksTotal: resolved.links.length,
      collectionsTotal: collections.length,
      tagsTotal: tags.length,
      pinnedTotal: pinnedCount,
      archivedTotal: archivedCount
    },
    {
      summary: {
        selectorApplied: Boolean(input.selector)
      },
      warnings: resolved.warnings
    }
  );
}

// This function handles linkwarden_query_links using persisted snapshots and deterministic cursor paging.
async function handleQueryLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = queryLinksSchema.parse(args);

  if (input.cursor) {
    const decoded = decodeCursor(input.cursor);
    const snapshot = context.db.getQuerySnapshot(decoded.snapshotId, context.principal.userId);
    if (!snapshot) {
      throw new AppError(404, 'cursor_not_found', 'Cursor snapshot missing or expired.');
    }
    const slice = readQuerySlice(decoded.snapshotId, snapshot.items, input.limit, decoded.offset);
    return ok(
      {
        links: slice.items
      },
      {
        paging: slice.paging,
        warnings: []
      }
    );
  }

  const resolved = await resolveLinks(context, input.selector, undefined);
  const projected = resolved.links.map((link) => projectLink(link, input.fields, input.verbosity));
  const snapshotId = randomUUID();
  context.db.createQuerySnapshot({
    snapshotId,
    userId: context.principal.userId,
    selector: input.selector ?? {},
    fields: input.fields,
    items: projected,
    total: projected.length,
    ttlSeconds: 30 * 60
  });
  const slice = readQuerySlice(snapshotId, projected, input.limit, 0);
  return ok(
    {
      links: slice.items
    },
    {
      paging: slice.paging,
      warnings: resolved.warnings
    }
  );
}

// This function handles linkwarden_aggregate_links with grouped counters over one selector-scoped link set.
async function handleAggregateLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = aggregateLinksSchema.parse(args);
  const resolved = await resolveLinks(context, input.selector, undefined);
  const buckets = new Map<string, number>();

  for (const link of resolved.links) {
    if (input.groupBy === 'collection') {
      const key = link.collection ? `${link.collection.id}:${link.collection.name}` : 'null:Unassigned';
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
      continue;
    }
    if (input.groupBy === 'tag') {
      if (link.tags.length === 0) {
        buckets.set('0:untagged', (buckets.get('0:untagged') ?? 0) + 1);
      } else {
        for (const tag of link.tags) {
          const key = `${tag.id}:${tag.name}`;
          buckets.set(key, (buckets.get(key) ?? 0) + 1);
        }
      }
      continue;
    }
    if (input.groupBy === 'domain') {
      const key = extractDomain(link.url);
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
      continue;
    }
    if (input.groupBy === 'pinned') {
      const key = Boolean(link.pinned) ? 'pinned:true' : 'pinned:false';
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
      continue;
    }
    const key = Boolean(link.archived) ? 'archived:true' : 'archived:false';
    buckets.set(key, (buckets.get(key) ?? 0) + 1);
  }

  const aggregates = [...buckets.entries()]
    .map(([bucket, count]) => ({ bucket, count }))
    .sort((left, right) => right.count - left.count || left.bucket.localeCompare(right.bucket))
    .slice(0, input.topN);

  return ok(
    {
      aggregates
    },
    {
      summary: {
        groupBy: input.groupBy,
        scanned: resolved.links.length
      },
      warnings: resolved.warnings
    }
  );
}

// This function handles linkwarden_get_link and applies projection + verbosity for token-efficient responses.
async function handleGetLink(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = getLinkSchema.parse(args);
  const client = getClient(context);
  const link = await client.getLink(input.id);
  const projected = projectLink(link, input.fields, input.verbosity);
  return ok({
    link: projected
  });
}

// This helper computes one mutation preview entry with deterministic before/after snapshots.
function buildMutationPreview(
  link: LinkItem,
  updates: {
    title?: string;
    url?: string;
    description?: string;
    collectionId?: number | null;
    pinned?: boolean;
    archived?: boolean;
    tagMode: 'replace' | 'add' | 'remove';
    tagIds: number[];
  }
): { before: Record<string, unknown>; after: Record<string, unknown> } {
  const before = snapshotForUndo(link);
  const currentTagIds = link.tags.map((tag) => tag.id);
  const afterTagIds = computeNextTagIds(currentTagIds, updates.tagIds, updates.tagMode);
  const after: Record<string, unknown> = {
    title: updates.title ?? link.title,
    url: updates.url ?? link.url,
    description: updates.description ?? (link.description ?? null),
    collectionId: updates.collectionId === undefined ? (link.collection?.id ?? null) : updates.collectionId,
    tagIds: afterTagIds,
    pinned: updates.pinned === undefined ? Boolean(link.pinned) : updates.pinned,
    archived: updates.archived === undefined ? Boolean(link.archived) : updates.archived
  };
  return { before, after };
}

// This helper applies one mutation snapshot to one link via native update calls and returns the refreshed entity.
async function applyMutationSnapshot(
  client: LinkwardenClient,
  linkId: number,
  snapshot: Record<string, unknown>
): Promise<LinkItem> {
  return client.updateLink(linkId, {
    title: snapshot.title,
    url: snapshot.url,
    description: snapshot.description,
    collectionId: snapshot.collectionId,
    tagIds: snapshot.tagIds,
    pinned: snapshot.pinned,
    archived: snapshot.archived
  });
}

// This function handles linkwarden_mutate_links with selector-based targeting, dry-run previews, and idempotency.
async function handleMutateLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = mutateLinksSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }
  const client = getClient(context);
  const resolved = await resolveLinks(context, input.selector, input.ids);

  if (resolved.links.length === 0) {
    return ok(
      {
        operationId: null,
        preview: []
      },
      {
        summary: {
          total: 0,
          changes: 0,
          applied: 0
        }
      }
    );
  }

  if (input.updates.collectionId !== undefined) {
    assertCollectionScopeAccess(context, input.updates.collectionId);
  }

  const tagResolution = await resolveTagIdsByName(
    client,
    input.updates.tagNames ?? [],
    input.updates.createMissingTags,
    input.dryRun
  );

  const previews = resolved.links.map((link) => {
    const snapshot = buildMutationPreview(link, {
      title: input.updates.title,
      url: input.updates.url,
      description: input.updates.description,
      collectionId: input.updates.collectionId,
      pinned: input.updates.pinned,
      archived: input.updates.archived,
      tagMode: input.updates.tagMode,
      tagIds: tagResolution.tagIds
    });
    return {
      linkId: link.id,
      before: snapshot.before,
      after: snapshot.after
    };
  });

  const changed = previews.filter((item) => JSON.stringify(item.before) !== JSON.stringify(item.after));
  if (input.dryRun) {
    return ok(
      {
        operationId: null,
        createdTags: tagResolution.created,
        missingTags: tagResolution.missing,
        preview: changed.slice(0, input.previewLimit)
      },
      {
        summary: {
          total: previews.length,
          changes: changed.length,
          applied: 0
        }
      }
    );
  }

  return withIdempotency(
    context,
    'linkwarden_mutate_links',
    input.idempotencyKey,
    {
      selector: input.selector,
      ids: input.ids,
      updates: input.updates
    },
    async () => {
      const operationId = beginOperation(context, 'linkwarden_mutate_links', {
        requested: previews.length,
        changed: changed.length
      });
      const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
      const operationItems: Array<{
        itemType: string;
        itemId: number;
        before: Record<string, unknown>;
        after: Record<string, unknown>;
      }> = [];
      let applied = 0;

      for (const item of changed) {
        try {
          await applyMutationSnapshot(client, item.linkId, item.after);
          operationItems.push({
            itemType: 'link',
            itemId: item.linkId,
            before: item.before,
            after: item.after
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: item.linkId,
            code: 'update_failed',
            message: error instanceof Error ? error.message : 'update failed',
            retryable: true
          });
        }
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for selective undo and dashboard filtering.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_mutate_links', operationId, operationItems);
      } catch (error) {
        // This warning keeps successful mutations non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_mutate_links',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_mutate_links',
        targetType: 'link',
        targetIds: changed.map((item) => item.linkId),
        beforeSummary: 'mutation preview',
        afterSummary: JSON.stringify(input.updates),
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          createdTags: tagResolution.created,
          missingTags: tagResolution.missing,
          preview: changed.slice(0, input.previewLimit)
        },
        summary: {
          total: previews.length,
          changes: changed.length,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

interface ArchiveCollectionResolution {
  collection: LinkCollection | null;
  created: boolean;
  wouldCreate: boolean;
  strategy: 'explicit_id' | 'existing_name_match' | 'created_new';
  archiveCollectionName: string;
}

// This helper selects one deterministic archive collection when multiple exact-name matches exist.
function pickArchiveCollectionByPriority(collections: LinkCollection[]): LinkCollection {
  const roots = collections.filter((collection) => collection.parentId === null);
  const sortedRoots = [...roots].sort((left, right) => left.id - right.id);
  if (sortedRoots.length > 0) {
    return sortedRoots[0];
  }

  const sortedAll = [...collections].sort((left, right) => left.id - right.id);
  return sortedAll[0];
}

// This helper resolves archive preferences from persisted per-user chat-control settings.
function resolveArchivePreferences(context: ToolRuntimeContext): { archiveCollectionName: string; archiveCollectionParentId: number | null } {
  const chatControl = context.db.getUserChatControlSettings(context.principal.userId);
  return {
    archiveCollectionName: chatControl.archiveCollectionName.trim() || 'Archive',
    archiveCollectionParentId: chatControl.archiveCollectionParentId
  };
}

// This helper resolves or creates the archive collection used by soft-delete workflows.
async function resolveArchiveCollection(
  client: LinkwardenClient,
  context: ToolRuntimeContext,
  input: {
    explicitCollectionId?: number;
    allowCreate: boolean;
  }
): Promise<ArchiveCollectionResolution> {
  if (typeof input.explicitCollectionId === 'number') {
    const explicitCollection = await client.getCollection(input.explicitCollectionId);
    return {
      collection: explicitCollection,
      created: false,
      wouldCreate: false,
      strategy: 'explicit_id',
      archiveCollectionName: explicitCollection.name
    };
  }

  const preferences = resolveArchivePreferences(context);
  // This match remains exact (trimmed) so per-user archive names stay deterministic and explicit.
  const archiveCollectionNameExact = preferences.archiveCollectionName;
  const collections = await client.listAllCollections();
  const exactMatches = collections.filter(
    (collection) => collection.name.trim() === archiveCollectionNameExact
  );
  if (exactMatches.length > 0) {
    return {
      collection: pickArchiveCollectionByPriority(exactMatches),
      created: false,
      wouldCreate: false,
      strategy: 'existing_name_match',
      archiveCollectionName: preferences.archiveCollectionName
    };
  }

  if (!input.allowCreate) {
    return {
      collection: null,
      created: false,
      wouldCreate: true,
      strategy: 'created_new',
      archiveCollectionName: preferences.archiveCollectionName
    };
  }

  return {
    collection: await client.createCollection({
      name: preferences.archiveCollectionName,
      parentId: preferences.archiveCollectionParentId ?? null
    }),
    created: true,
    wouldCreate: false,
    strategy: 'created_new',
    archiveCollectionName: preferences.archiveCollectionName
  };
}

// This function handles linkwarden_delete_links with soft/hard mode semantics and deterministic previews.
async function handleDeleteLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteLinksSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }
  const client = getClient(context);
  const resolved = await resolveLinks(context, input.selector, input.ids);

  const archiveResolution =
    input.mode === 'soft'
      ? await resolveArchiveCollection(client, context, {
          explicitCollectionId: input.archiveCollectionId,
          allowCreate: !input.dryRun
        })
      : null;
  const archiveCollection = archiveResolution?.collection ?? null;
  if (archiveCollection) {
    assertCollectionScopeAccess(context, archiveCollection.id);
  }

  const tagResolution =
    input.mode === 'soft'
      ? await resolveTagIdsByName(client, [input.markTagName], true, input.dryRun)
      : { tagIds: [], created: [], missing: [] };
  const softDeleteTagId = input.mode === 'soft' ? tagResolution.tagIds[0] : undefined;

  const preview = resolved.links.map((link) => {
    const before = snapshotForUndo(link);
    if (input.mode === 'hard') {
      return {
        linkId: link.id,
        before,
        after: {
          deleted: true,
          mode: 'hard'
        }
      };
    }
    const currentTagIds = link.tags.map((tag) => tag.id);
    const nextTagIds =
      typeof softDeleteTagId === 'number' ? computeNextTagIds(currentTagIds, [softDeleteTagId], 'add') : currentTagIds;
    return {
      linkId: link.id,
      before,
      after: {
        ...before,
        collectionId: archiveCollection?.id ?? before.collectionId,
        tagIds: nextTagIds,
        archived: true,
        deleteMode: 'soft'
      }
    };
  });

  if (input.dryRun) {
    const warnings =
      input.mode === 'soft' && archiveResolution?.wouldCreate
        ? [`archive_collection_missing: "${archiveResolution.archiveCollectionName}" would be created on apply.`]
        : [];
    return ok(
      {
        operationId: null,
        archiveCollection,
        archiveCollectionResolution: archiveResolution
          ? {
              created: archiveResolution.created,
              wouldCreate: archiveResolution.wouldCreate,
              strategy: archiveResolution.strategy,
              archiveCollectionName: archiveResolution.archiveCollectionName
            }
          : null,
        preview: preview.slice(0, input.previewLimit)
      },
      {
        summary: {
          total: preview.length,
          mode: input.mode,
          applied: 0
        },
        warnings
      }
    );
  }

  return withIdempotency(
    context,
    'linkwarden_delete_links',
    input.idempotencyKey,
    {
      selector: input.selector,
      ids: input.ids,
      mode: input.mode,
      archiveCollectionId: archiveCollection?.id ?? null
    },
    async () => {
      const operationId = beginOperation(context, 'linkwarden_delete_links', {
        total: preview.length,
        mode: input.mode,
        archiveCollectionCreated: Boolean(archiveResolution?.created),
        archiveCollectionId: archiveCollection?.id ?? null,
        archiveCollectionResolutionStrategy: archiveResolution?.strategy ?? null
      });
      const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
        [];
      const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
      let applied = 0;

      for (const item of preview) {
        try {
          if (input.mode === 'hard') {
            await client.deleteLink(item.linkId);
          } else {
            const afterTagIds = Array.isArray((item.after as { tagIds?: unknown }).tagIds)
              ? ((item.after as { tagIds: number[] }).tagIds)
              : [];
            await client.updateLink(item.linkId, {
              collectionId: archiveCollection?.id,
              tagIds: afterTagIds,
              archived: true
            });
          }
          operationItems.push({
            itemType: 'link',
            itemId: item.linkId,
            before: item.before,
            after: item.after
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: item.linkId,
            code: 'delete_failed',
            message: error instanceof Error ? error.message : 'delete failed',
            retryable: true
          });
        }
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for delete workflows and undo tracing.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_delete_links', operationId, operationItems);
      } catch (error) {
        // This warning keeps delete apply behavior non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_delete_links',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_delete_links',
        targetType: 'link',
        targetIds: preview.map((item) => item.linkId),
        beforeSummary: 'delete preview',
        afterSummary: JSON.stringify({
          mode: input.mode,
          archiveCollectionId: archiveCollection?.id ?? null
        }),
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length,
          archiveCollectionId: archiveCollection?.id ?? null,
          archiveCollectionCreated: Boolean(archiveResolution?.created),
          archiveCollectionResolutionStrategy: archiveResolution?.strategy ?? null
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          archiveCollection,
          archiveCollectionResolution: archiveResolution
            ? {
                created: archiveResolution.created,
                wouldCreate: archiveResolution.wouldCreate,
                strategy: archiveResolution.strategy,
                archiveCollectionName: archiveResolution.archiveCollectionName
              }
            : null,
          preview: preview.slice(0, input.previewLimit)
        },
        summary: {
          total: preview.length,
          mode: input.mode,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

// This function handles linkwarden_list_collections with deterministic paging over fully loaded collection data.
async function handleListCollections(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listCollectionsSchema.parse(args);
  const client = getClient(context);
  const all = await client.listAllCollections();
  const scoped = context.principal.collectionScopes && context.principal.collectionScopes.length > 0
    ? all.filter((collection) => context.principal.collectionScopes?.includes(collection.id))
    : all;
  const page = scoped.slice(input.offset, input.offset + input.limit);
  return ok(
    {
      collections: page
    },
    {
      paging: {
        limit: input.limit,
        offset: input.offset,
        returned: page.length,
        total: scoped.length
      }
    }
  );
}

// This function handles linkwarden_create_collection with write-mode and scope enforcement.
async function handleCreateCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createCollectionSchema.parse(args);
  assertWriteAccess(context);
  if (typeof input.parentId === 'number') {
    assertCollectionScopeAccess(context, input.parentId);
  }
  const client = getClient(context);
  const created = await client.createCollection({
    name: input.name,
    parentId: input.parentId
  });
  assertCollectionScopeAccess(context, created.id);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_create_collection',
    targetType: 'collection',
    targetIds: [created.id],
    beforeSummary: 'collection missing',
    afterSummary: JSON.stringify(created),
    outcome: 'success',
    details: {
      userId: context.principal.userId
    }
  });
  return ok({
    collection: created
  });
}

// This function handles linkwarden_update_collection with deterministic validation and audit logging.
async function handleUpdateCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = updateCollectionSchema.parse(args);
  assertWriteAccess(context);
  assertCollectionScopeAccess(context, input.id);
  if (typeof input.updates.parentId === 'number') {
    assertCollectionScopeAccess(context, input.updates.parentId);
  }
  const client = getClient(context);
  const updated = await client.updateCollection(input.id, input.updates);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_update_collection',
    targetType: 'collection',
    targetIds: [input.id],
    beforeSummary: 'collection update requested',
    afterSummary: JSON.stringify(updated),
    outcome: 'success',
    details: {
      userId: context.principal.userId
    }
  });
  return ok({
    collection: updated
  });
}

// This function handles linkwarden_delete_collection and records one audit trail entry.
async function handleDeleteCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteCollectionSchema.parse(args);
  assertWriteAccess(context);
  assertCollectionScopeAccess(context, input.id);
  const client = getClient(context);
  await client.deleteCollection(input.id);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_delete_collection',
    targetType: 'collection',
    targetIds: [input.id],
    beforeSummary: 'collection delete requested',
    afterSummary: 'collection deleted',
    outcome: 'success',
    details: {
      userId: context.principal.userId
    }
  });
  return ok({
    deleted: true,
    id: input.id
  });
}

// This function handles linkwarden_list_tags with deterministic offset paging.
async function handleListTags(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listTagsSchema.parse(args);
  const client = getClient(context);
  const all = await client.listAllTags();
  const page = all.slice(input.offset, input.offset + input.limit);
  return ok(
    {
      tags: page
    },
    {
      paging: {
        limit: input.limit,
        offset: input.offset,
        returned: page.length,
        total: all.length
      }
    }
  );
}

// This function handles linkwarden_create_tag with idempotent normalized-name behavior.
async function handleCreateTag(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createTagSchema.parse(args);
  assertWriteAccess(context);
  const client = getClient(context);
  const tags = await client.listAllTags();
  const existing = tags.find((tag) => normalizeTagName(tag.name) === normalizeTagName(input.name));
  if (existing) {
    return ok({
      tag: existing,
      created: false
    });
  }
  const created = await client.createTag(input.name);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_create_tag',
    targetType: 'tag',
    targetIds: [created.id],
    beforeSummary: 'tag missing',
    afterSummary: JSON.stringify(created),
    outcome: 'success',
    details: {
      userId: context.principal.userId
    }
  });
  return ok({
    tag: created,
    created: true
  });
}

// This function handles linkwarden_delete_tag by id with deterministic error and audit behavior.
async function handleDeleteTag(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteTagSchema.parse(args);
  assertWriteAccess(context);
  const client = getClient(context);
  await client.deleteTag(input.id);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_delete_tag',
    targetType: 'tag',
    targetIds: [input.id],
    beforeSummary: 'delete tag requested',
    afterSummary: 'tag deleted',
    outcome: 'success',
    details: {
      userId: context.principal.userId
    }
  });
  return ok({
    deleted: true,
    id: input.id
  });
}

// This function handles linkwarden_assign_tags with selector or explicit link id targeting.
async function handleAssignTags(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = assignTagsSchema.parse(args);
  const resolved = await resolveLinks(context, input.selector, input.linkIds);
  const client = getClient(context);
  const tagResolution = await resolveTagIdsByName(client, input.tagNames, input.createMissingTags, input.dryRun);
  const preview = resolved.links.map((link) => {
    const beforeTagIds = link.tags.map((tag) => tag.id);
    const afterTagIds = computeNextTagIds(beforeTagIds, tagResolution.tagIds, input.mode);
    return {
      linkId: link.id,
      beforeTagIds,
      afterTagIds
    };
  });

  if (input.dryRun) {
    return ok(
      {
        createdTags: tagResolution.created,
        missingTags: tagResolution.missing,
        preview: preview.slice(0, input.previewLimit)
      },
      {
        summary: {
          total: preview.length,
          changes: preview.filter((item) => JSON.stringify(item.beforeTagIds) !== JSON.stringify(item.afterTagIds)).length,
          applied: 0
        }
      }
    );
  }

  assertWriteAccess(context);
  return withIdempotency(
    context,
    'linkwarden_assign_tags',
    input.idempotencyKey,
    {
      selector: input.selector,
      linkIds: input.linkIds,
      tagNames: input.tagNames,
      mode: input.mode
    },
    async () => {
      const operationId = beginOperation(context, 'linkwarden_assign_tags', {
        total: preview.length,
        mode: input.mode
      });
      const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
      const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
        [];
      let applied = 0;
      const byLink = new Map<number, LinkItem>(resolved.links.map((link) => [link.id, link]));

      for (const item of preview) {
        const link = byLink.get(item.linkId);
        if (!link) {
          continue;
        }
        const before = snapshotForUndo(link);
        const after = {
          ...before,
          tagIds: item.afterTagIds
        };
        try {
          await client.updateLink(item.linkId, { tagIds: item.afterTagIds });
          operationItems.push({
            itemType: 'link',
            itemId: item.linkId,
            before,
            after
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: item.linkId,
            code: 'assign_tags_failed',
            message: error instanceof Error ? error.message : 'assign tags failed',
            retryable: true
          });
        }
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for explicit tag assignment workflows.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_assign_tags', operationId, operationItems);
      } catch (error) {
        // This warning keeps tag assignment behavior non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_assign_tags',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_assign_tags',
        targetType: 'link',
        targetIds: preview.map((item) => item.linkId),
        beforeSummary: 'assign tags preview',
        afterSummary: JSON.stringify({
          mode: input.mode,
          tagIds: tagResolution.tagIds
        }),
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          createdTags: tagResolution.created,
          missingTags: tagResolution.missing,
          preview: preview.slice(0, input.previewLimit)
        },
        summary: {
          total: preview.length,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

// This constant stores deterministic stopwords used by governed tagging token extraction.
const TAG_STOPWORDS = new Set([
  'http',
  'https',
  'www',
  'com',
  'net',
  'org',
  'und',
  'der',
  'die',
  'das',
  'the',
  'and',
  'for',
  'with',
  'from',
  'this',
  'that',
  'your',
  'you'
]);

interface StrictnessPreset {
  minConfidence: number;
  minSupport: number;
  maxNewTagsPerRun: number;
  maxTagsPerLink: number;
}

interface RankedTagCandidate {
  token: string;
  confidence: number;
}

interface CandidateDecision {
  candidate: string;
  confidence: number;
  action: 'reuse_exact' | 'reuse_alias' | 'reuse_similar' | 'create' | 'skip_policy' | 'skip_budget' | 'skip_limit';
  reason: string;
  tagId: number | null;
}

// This constant maps per-user strictness presets to deterministic gating thresholds.
const STRICTNESS_PRESETS: Record<TaggingStrictness, StrictnessPreset> = {
  very_strict: {
    minConfidence: 0.82,
    minSupport: 5,
    maxNewTagsPerRun: 3,
    maxTagsPerLink: 6
  },
  medium: {
    minConfidence: 0.68,
    minSupport: 3,
    maxNewTagsPerRun: 10,
    maxTagsPerLink: 10
  },
  relaxed: {
    minConfidence: 0.52,
    minSupport: 2,
    maxNewTagsPerRun: 24,
    maxTagsPerLink: 16
  }
};

// This helper normalizes candidate tokens into one deterministic lowercase slug.
function normalizeCandidateToken(value: string): string {
  return value
    .trim()
    .toLocaleLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// This helper tokenizes free text and removes stopwords/noise for taxonomy candidate generation.
function tokenizeForTags(text: string): string[] {
  return text
    .toLocaleLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .map((token) => normalizeCandidateToken(token))
    .filter((token) => token.length >= 3 && token.length <= 40)
    .filter((token) => !TAG_STOPWORDS.has(token))
    .filter((token) => !/^\d+$/.test(token));
}

// This helper adds weighted token scores into one candidate map while preserving deterministic accumulation.
function addWeightedTokens(
  target: Map<string, number>,
  tokens: string[],
  weight: number
): void {
  for (const token of tokens) {
    target.set(token, (target.get(token) ?? 0) + weight);
  }
}

// This helper builds one deterministic candidate ranking from weighted metadata and optional fetched tokens.
function rankTagCandidates(
  link: LinkItem,
  fetchedTokens: string[]
): RankedTagCandidate[] {
  const scores = new Map<string, number>();
  addWeightedTokens(scores, tokenizeForTags(link.title), 1.0);
  addWeightedTokens(scores, tokenizeForTags(link.description ?? ''), 0.55);
  addWeightedTokens(scores, tokenizeForTags(extractDomain(link.url).replace(/\./g, ' ')), 0.75);
  addWeightedTokens(scores, tokenizeForTags(link.collection?.name ?? ''), 0.35);
  addWeightedTokens(scores, fetchedTokens, 0.2);

  const ranked = [...scores.entries()]
    .map(([token, score]) => ({
      token,
      confidence: Math.min(1, score / 2.4)
    }))
    .sort((left, right) => right.confidence - left.confidence || left.token.localeCompare(right.token));

  return ranked.slice(0, 8);
}

// This helper builds one deterministic bigram set for string similarity checks.
function buildBigrams(value: string): Set<string> {
  const normalized = normalizeCandidateToken(value);
  if (normalized.length < 2) {
    return new Set([normalized]);
  }
  const bigrams = new Set<string>();
  for (let index = 0; index < normalized.length - 1; index += 1) {
    bigrams.add(normalized.slice(index, index + 2));
  }
  return bigrams;
}

// This helper computes a Dice coefficient for fuzzy tag-to-candidate matching.
function diceSimilarity(left: string, right: string): number {
  const leftSet = buildBigrams(left);
  const rightSet = buildBigrams(right);
  if (leftSet.size === 0 || rightSet.size === 0) {
    return 0;
  }
  let overlap = 0;
  for (const value of leftSet) {
    if (rightSet.has(value)) {
      overlap += 1;
    }
  }
  return (2 * overlap) / (leftSet.size + rightSet.size);
}

// This helper resolves one optional similarity match against existing tags under one threshold.
function findSimilarTagMatch(
  candidate: string,
  tags: LinkTag[],
  threshold: number
): { tag: LinkTag; score: number } | null {
  let best: { tag: LinkTag; score: number } | null = null;
  for (const tag of tags) {
    const score = diceSimilarity(candidate, tag.name);
    if (score < threshold) {
      continue;
    }
    if (!best || score > best.score || (score === best.score && tag.id < best.tag.id)) {
      best = { tag, score };
    }
  }
  return best;
}

// This helper resolves one effective fetch mode from global policy and per-user override preferences.
function resolveEffectiveFetchMode(policy: GlobalTaggingPolicy, userFetchMode: FetchMode): FetchMode {
  return policy.allowUserFetchModeOverride ? userFetchMode : policy.fetchMode;
}

// This helper deterministically appends tag ids without exceeding one per-link tag limit.
function appendTagIdsWithLimit(current: number[], additions: number[], maxTags: number): { after: number[]; skipped: number } {
  const seen = new Set(current);
  const merged = [...current];
  let skipped = 0;

  for (const tagId of additions) {
    if (seen.has(tagId)) {
      continue;
    }
    if (merged.length >= maxTags) {
      skipped += 1;
      continue;
    }
    seen.add(tagId);
    merged.push(tagId);
  }

  return {
    after: normalizeTagIds(merged),
    skipped
  };
}

// This helper fetches optional page context with deterministic cache keys and expiration behavior.
async function loadOptionalContextTokens(
  context: ToolRuntimeContext,
  link: LinkItem,
  fetchMode: FetchMode,
  threshold: number,
  topConfidence: number,
  policy: GlobalTaggingPolicy
): Promise<{ tokens: string[]; fetched: boolean }> {
  if (fetchMode === 'never') {
    return { tokens: [], fetched: false };
  }
  if (fetchMode === 'optional' && topConfidence >= threshold) {
    return { tokens: [], fetched: false };
  }

  const contextHash = stableHash({
    url: link.url,
    updatedAt: link.updatedAt ?? link.createdAt ?? null,
    fetchMode,
    fetchMaxBytes: policy.fetchMaxBytes,
    inferenceProvider: policy.inferenceProvider,
    inferenceModel: policy.inferenceModel
  });
  const cached = context.db.getLinkContextCache(context.principal.userId, link.id, contextHash);
  if (cached) {
    return {
      tokens: cached.extractedTokens,
      fetched: true
    };
  }

  const fetchResult = await fetchLinkContext(link.url, {
    timeoutMs: policy.fetchTimeoutMs,
    maxBytes: policy.fetchMaxBytes,
    logger: context.logger
  });
  const fetchedTokens = fetchResult.text.length > 0 ? tokenizeForTags(fetchResult.text).slice(0, 240) : [];
  const providerTokens =
    policy.inferenceProvider === 'builtin' || fetchResult.text.length === 0
      ? []
      : await inferTagTokensViaProvider({
          provider: policy.inferenceProvider,
          model: policy.inferenceModel,
          link,
          contextText: fetchResult.text,
          timeoutMs: policy.fetchTimeoutMs,
          logger: context.logger
        });
  const tokens =
    policy.inferenceProvider === 'builtin'
      ? fetchedTokens
      : [...new Set([...providerTokens, ...fetchedTokens])].slice(0, 240);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  context.db.upsertLinkContextCache({
    userId: context.principal.userId,
    linkId: link.id,
    contextHash,
    extractedTokens: tokens,
    expiresAt
  });
  return {
    tokens,
    fetched: fetchResult.fetched
  };
}

// This function handles linkwarden_governed_tag_links as one native end-to-end taxonomy-first tagging flow.
async function handleGovernedTagLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = governedTagLinksSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }

  const client = getClient(context);
  const resolved = await resolveLinks(context, input.selector, input.linkIds);
  const userSettings = context.db.getUserSettings(context.principal.userId);
  const globalPolicy = context.db.getGlobalTaggingPolicy();
  const strictnessPreset = STRICTNESS_PRESETS[userSettings.taggingStrictness];
  const effectiveFetchMode = resolveEffectiveFetchMode(globalPolicy, userSettings.fetchMode);

  if (resolved.links.length === 0) {
    return ok(
      {
        operationId: null,
        policy: {
          strictness: userSettings.taggingStrictness,
          fetchMode: effectiveFetchMode,
          allowUserFetchModeOverride: globalPolicy.allowUserFetchModeOverride,
          inferenceProvider: globalPolicy.inferenceProvider,
          inferenceModel: globalPolicy.inferenceModel
        },
        preview: [],
        createdTags: [],
        reusedTags: []
      },
      {
        summary: {
          scanned: 0,
          suggested: 0,
          assigned: 0,
          created: 0,
          skippedByPolicy: 0,
          skippedByBudget: 0
        }
      }
    );
  }

  const allTags = await client.listAllTags();
  const tagsByNormalized = new Map<string, LinkTag>(allTags.map((tag) => [normalizeCandidateToken(tag.name), tag]));
  const tagsById = new Map<number, LinkTag>(allTags.map((tag) => [tag.id, tag]));
  const aliases = context.db.listTagAliases(context.principal.userId);
  const aliasesByNormalized = new Map<string, TagAliasRecord>(aliases.map((alias) => [alias.aliasNormalized, alias]));
  const blockedSet = new Set(globalPolicy.blockedTagNames.map((name) => normalizeCandidateToken(name)));

  const perLinkRanked = new Map<number, RankedTagCandidate[]>();
  const perLinkFetched = new Map<number, boolean>();
  const supportInRun = new Map<string, number>();

  for (const link of resolved.links) {
    const baseRanking = rankTagCandidates(link, []);
    const topConfidence = baseRanking[0]?.confidence ?? 0;
    const optionalContext = await loadOptionalContextTokens(
      context,
      link,
      effectiveFetchMode,
      strictnessPreset.minConfidence,
      topConfidence,
      globalPolicy
    );
    const ranking = rankTagCandidates(link, optionalContext.tokens);
    perLinkRanked.set(link.id, ranking);
    perLinkFetched.set(link.id, optionalContext.fetched);
    for (const candidate of ranking) {
      supportInRun.set(candidate.token, (supportInRun.get(candidate.token) ?? 0) + 1);
    }
  }

  const supportPersisted = new Map<string, number>();
  for (const token of supportInRun.keys()) {
    const record = context.db.getTagCandidate(context.principal.userId, token);
    supportPersisted.set(token, record?.supportCount ?? 0);
  }

  const preview: Array<{
    linkId: number;
    fetchedContext: boolean;
    beforeTagIds: number[];
    afterTagIds: number[];
    decisions: CandidateDecision[];
  }> = [];
  const createdTags: LinkTag[] = [];
  const reusedTagIds = new Set<number>();
  const aliasUpdates = new Map<string, { canonicalTagId: number; confidence: number }>();
  const candidateSupportBumps = new Map<string, number>();
  const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];

  let skippedByPolicy = 0;
  let skippedByBudget = 0;
  let skippedByLimit = 0;
  let totalSuggested = 0;
  let createdThisRun = 0;
  const createdByNormalized = new Map<string, LinkTag>();

  for (const link of resolved.links) {
    const ranked = perLinkRanked.get(link.id) ?? [];
    const decisions: CandidateDecision[] = [];
    const proposedTagIds: number[] = [];

    for (const candidate of ranked) {
      totalSuggested += 1;
      const token = candidate.token;
      if (blockedSet.has(token)) {
        skippedByPolicy += 1;
        decisions.push({
          candidate: token,
          confidence: candidate.confidence,
          action: 'skip_policy',
          reason: 'blocked_by_policy',
          tagId: null
        });
        candidateSupportBumps.set(token, (candidateSupportBumps.get(token) ?? 0) + 1);
        continue;
      }

      const exactTag = tagsByNormalized.get(token);
      if (exactTag) {
        reusedTagIds.add(exactTag.id);
        proposedTagIds.push(exactTag.id);
        decisions.push({
          candidate: token,
          confidence: candidate.confidence,
          action: 'reuse_exact',
          reason: 'matched_existing_tag',
          tagId: exactTag.id
        });
        continue;
      }

      const aliasMatch = aliasesByNormalized.get(token);
      if (aliasMatch) {
        const canonical = tagsById.get(aliasMatch.canonicalTagId);
        if (canonical) {
          reusedTagIds.add(canonical.id);
          proposedTagIds.push(canonical.id);
          decisions.push({
            candidate: token,
            confidence: candidate.confidence,
            action: 'reuse_alias',
            reason: 'matched_alias',
            tagId: canonical.id
          });
          continue;
        }
      }

      const similar = findSimilarTagMatch(token, allTags, globalPolicy.similarityThreshold);
      if (similar) {
        reusedTagIds.add(similar.tag.id);
        proposedTagIds.push(similar.tag.id);
        decisions.push({
          candidate: token,
          confidence: candidate.confidence,
          action: 'reuse_similar',
          reason: `similarity_${similar.score.toFixed(2)}`,
          tagId: similar.tag.id
        });
        aliasUpdates.set(token, {
          canonicalTagId: similar.tag.id,
          confidence: similar.score
        });
        continue;
      }

      const persistedSupport = supportPersisted.get(token) ?? 0;
      const runSupport = supportInRun.get(token) ?? 0;
      const totalSupport = persistedSupport + runSupport;
      if (candidate.confidence < strictnessPreset.minConfidence || totalSupport < strictnessPreset.minSupport) {
        skippedByPolicy += 1;
        decisions.push({
          candidate: token,
          confidence: candidate.confidence,
          action: 'skip_policy',
          reason:
            candidate.confidence < strictnessPreset.minConfidence
              ? 'below_confidence_threshold'
              : `support_${totalSupport}_below_${strictnessPreset.minSupport}`,
          tagId: null
        });
        candidateSupportBumps.set(token, (candidateSupportBumps.get(token) ?? 0) + 1);
        continue;
      }

      if (!createdByNormalized.has(token) && !tagsByNormalized.has(token)) {
        if (createdThisRun >= strictnessPreset.maxNewTagsPerRun) {
          skippedByBudget += 1;
          decisions.push({
            candidate: token,
            confidence: candidate.confidence,
            action: 'skip_budget',
            reason: 'max_new_tags_per_run_reached',
            tagId: null
          });
          candidateSupportBumps.set(token, (candidateSupportBumps.get(token) ?? 0) + 1);
          continue;
        }

        if (!input.dryRun) {
          try {
            const created = await client.createTag(token);
            createdThisRun += 1;
            createdByNormalized.set(token, created);
            tagsByNormalized.set(token, created);
            tagsById.set(created.id, created);
            allTags.push(created);
            createdTags.push(created);
          } catch (error) {
            failures.push({
              itemId: link.id,
              code: 'governed_create_tag_failed',
              message: error instanceof Error ? error.message : 'governed create tag failed',
              retryable: true
            });
            decisions.push({
              candidate: token,
              confidence: candidate.confidence,
              action: 'skip_policy',
              reason: 'create_tag_failed',
              tagId: null
            });
            continue;
          }
        } else {
          createdThisRun += 1;
          const simulatedId = -createdThisRun;
          const simulatedTag: LinkTag = { id: simulatedId, name: token };
          createdByNormalized.set(token, simulatedTag);
          createdTags.push(simulatedTag);
        }
      }

      const createdTag = createdByNormalized.get(token) ?? tagsByNormalized.get(token) ?? null;
      if (!createdTag) {
        skippedByPolicy += 1;
        decisions.push({
          candidate: token,
          confidence: candidate.confidence,
          action: 'skip_policy',
          reason: 'created_tag_missing_after_create',
          tagId: null
        });
        continue;
      }

      proposedTagIds.push(createdTag.id);
      decisions.push({
        candidate: token,
        confidence: candidate.confidence,
        action: 'create',
        reason: 'created_under_policy',
        tagId: createdTag.id
      });
      candidateSupportBumps.set(token, (candidateSupportBumps.get(token) ?? 0) + 1);
    }

    const beforeTagIds = normalizeTagIds(link.tags.map((tag) => tag.id));
    const merged = appendTagIdsWithLimit(beforeTagIds, normalizeTagIds(proposedTagIds), strictnessPreset.maxTagsPerLink);
    skippedByLimit += merged.skipped;

    if (merged.skipped > 0) {
      decisions.push({
        candidate: '__limit__',
        confidence: 1,
        action: 'skip_limit',
        reason: 'max_tags_per_link_reached',
        tagId: null
      });
    }

    preview.push({
      linkId: link.id,
      fetchedContext: Boolean(perLinkFetched.get(link.id)),
      beforeTagIds,
      afterTagIds: merged.after,
      decisions
    });
  }

  const changedItems = preview.filter(
    (item) => JSON.stringify(item.beforeTagIds) !== JSON.stringify(item.afterTagIds)
  );

  if (input.dryRun) {
    return ok(
      {
        operationId: null,
        policy: {
          strictness: userSettings.taggingStrictness,
          fetchMode: effectiveFetchMode,
          allowUserFetchModeOverride: globalPolicy.allowUserFetchModeOverride,
          inferenceProvider: globalPolicy.inferenceProvider,
          inferenceModel: globalPolicy.inferenceModel
        },
        preview: preview.slice(0, input.previewLimit),
        createdTags: createdTags.map((tag) => ({
          name: tag.name
        })),
        reusedTags: [...reusedTagIds].sort((left, right) => left - right)
      },
      {
        summary: {
          scanned: resolved.links.length,
          suggested: totalSuggested,
          assigned: changedItems.length,
          created: createdTags.length,
          skippedByPolicy,
          skippedByBudget,
          skippedByLimit,
          applied: 0
        },
        failures
      }
    );
  }

  return withIdempotency(
    context,
    'linkwarden_governed_tag_links',
    input.idempotencyKey,
    {
      selector: input.selector,
      linkIds: input.linkIds,
      dryRun: false
    },
    async () => {
      const operationId = beginOperation(context, 'linkwarden_governed_tag_links', {
        scanned: resolved.links.length,
        changed: changedItems.length,
        strictness: userSettings.taggingStrictness,
        fetchMode: effectiveFetchMode,
        inferenceProvider: globalPolicy.inferenceProvider,
        inferenceModel: globalPolicy.inferenceModel
      });
      const byLink = new Map<number, LinkItem>(resolved.links.map((link) => [link.id, link]));
      const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
        [];
      let applied = 0;

      for (const item of changedItems) {
        const link = byLink.get(item.linkId);
        if (!link) {
          continue;
        }
        const before = snapshotForUndo(link);
        const after = {
          ...before,
          tagIds: item.afterTagIds
        };
        try {
          await client.updateLink(item.linkId, { tagIds: item.afterTagIds });
          operationItems.push({
            itemType: 'link',
            itemId: item.linkId,
            before,
            after
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: item.linkId,
            code: 'governed_assign_failed',
            message: error instanceof Error ? error.message : 'governed assign failed',
            retryable: true
          });
        }
      }

      for (const [candidate, alias] of aliasUpdates.entries()) {
        context.db.upsertTagAlias({
          userId: context.principal.userId,
          canonicalTagId: alias.canonicalTagId,
          aliasNormalized: candidate,
          confidence: alias.confidence
        });
      }

      for (const [candidate, delta] of candidateSupportBumps.entries()) {
        context.db.bumpTagCandidateSupport({
          userId: context.principal.userId,
          candidateNormalized: candidate,
          delta
        });
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for governed tagging mutations.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_governed_tag_links', operationId, operationItems);
      } catch (error) {
        // This warning keeps governed tagging behavior non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_governed_tag_links',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_governed_tag_links',
        targetType: 'link',
        targetIds: changedItems.map((item) => item.linkId),
        beforeSummary: 'governed tagging preview',
        afterSummary: JSON.stringify({
          strictness: userSettings.taggingStrictness,
          fetchMode: effectiveFetchMode,
          inferenceProvider: globalPolicy.inferenceProvider,
          inferenceModel: globalPolicy.inferenceModel
        }),
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          policy: {
            strictness: userSettings.taggingStrictness,
            fetchMode: effectiveFetchMode,
            allowUserFetchModeOverride: globalPolicy.allowUserFetchModeOverride,
            inferenceProvider: globalPolicy.inferenceProvider,
            inferenceModel: globalPolicy.inferenceModel
          },
          preview: preview.slice(0, input.previewLimit),
          createdTags,
          reusedTags: [...reusedTagIds].sort((left, right) => left - right)
        },
        summary: {
          scanned: resolved.links.length,
          suggested: totalSuggested,
          assigned: changedItems.length,
          created: createdTags.length,
          skippedByPolicy,
          skippedByBudget,
          skippedByLimit,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

// This function handles linkwarden_normalize_urls with dry-run and apply paths.
async function handleNormalizeUrls(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = normalizeUrlsSchema.parse(args);
  const resolved = await resolveLinks(context, input.selector, input.linkIds);
  const preview = resolved.links.map((link) => {
    const cleaned = cleanTrackedUrl(link.url, {
      removeUtm: input.removeUtm,
      removeKnownTracking: input.removeKnownTracking,
      keepParams: input.keepParams,
      extraTrackingParams: input.extraTrackingParams
    });
    return {
      linkId: link.id,
      beforeUrl: link.url,
      afterUrl: cleaned.cleanedUrl,
      changed: cleaned.changed,
      removedParams: cleaned.removedParams
    };
  });

  if (input.dryRun) {
    return ok(
      {
        preview: preview.slice(0, input.previewLimit)
      },
      {
        summary: {
          total: preview.length,
          changed: preview.filter((item) => item.changed).length,
          applied: 0
        }
      }
    );
  }

  assertWriteAccess(context);
  const client = getClient(context);
  return withIdempotency(
    context,
    'linkwarden_normalize_urls',
    input.idempotencyKey,
    {
      selector: input.selector,
      linkIds: input.linkIds,
      removeUtm: input.removeUtm,
      removeKnownTracking: input.removeKnownTracking,
      keepParams: input.keepParams,
      extraTrackingParams: input.extraTrackingParams
    },
    async () => {
      const changed = preview.filter((item) => item.changed);
      const operationId = beginOperation(context, 'linkwarden_normalize_urls', {
        total: preview.length,
        changed: changed.length
      });
      const byLink = new Map<number, LinkItem>(resolved.links.map((link) => [link.id, link]));
      const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
      const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
        [];
      let applied = 0;

      for (const item of changed) {
        const link = byLink.get(item.linkId);
        if (!link) {
          continue;
        }
        const before = snapshotForUndo(link);
        const after = {
          ...before,
          url: item.afterUrl
        };
        try {
          await client.updateLink(item.linkId, { url: item.afterUrl });
          operationItems.push({
            itemType: 'link',
            itemId: item.linkId,
            before,
            after
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: item.linkId,
            code: 'normalize_url_failed',
            message: error instanceof Error ? error.message : 'normalize url failed',
            retryable: true
          });
        }
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for URL normalization workflows.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_normalize_urls', operationId, operationItems);
      } catch (error) {
        // This warning keeps URL normalization behavior non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_normalize_urls',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_normalize_urls',
        targetType: 'link',
        targetIds: changed.map((item) => item.linkId),
        beforeSummary: 'normalize urls preview',
        afterSummary: 'normalize urls apply',
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          preview: preview.slice(0, input.previewLimit)
        },
        summary: {
          total: preview.length,
          changed: changed.length,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

// This function handles linkwarden_find_duplicates with canonical URL grouping.
async function handleFindDuplicates(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = findDuplicatesSchema.parse(args);
  const resolved = await resolveLinks(context, input.selector, undefined);
  const scoped = input.includeArchived ? resolved.links : resolved.links.filter((link) => !Boolean(link.archived));
  const groups = groupDuplicates(scoped).slice(0, input.topN);
  return ok(
    {
      groups: groups.map((group) => ({
        canonicalUrl: group.canonicalUrl,
        linkIds: group.links.map((link) => link.id),
        size: group.links.length
      }))
    },
    {
      summary: {
        scanned: scoped.length,
        duplicateGroups: groups.length
      }
    }
  );
}

// This helper resolves one duplicate-group keep id with deterministic fallback strategy.
function resolveKeepId(group: { linkIds: number[]; keepId?: number }, strategy: 'lowestId' | 'highestId'): number {
  if (typeof group.keepId === 'number' && group.linkIds.includes(group.keepId)) {
    return group.keepId;
  }
  const sorted = [...group.linkIds].sort((left, right) => left - right);
  return strategy === 'lowestId' ? sorted[0] : sorted[sorted.length - 1];
}

// This function handles linkwarden_merge_duplicates and supports dry-run plus soft/hard delete cleanup.
async function handleMergeDuplicates(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = mergeDuplicatesSchema.parse(args);
  const client = getClient(context);
  const archiveResolution =
    input.deleteMode === 'soft'
      ? await resolveArchiveCollection(client, context, {
          explicitCollectionId: input.archiveCollectionId,
          allowCreate: !input.dryRun
        })
      : null;
  const archiveCollection = archiveResolution?.collection ?? null;
  if (archiveCollection) {
    assertCollectionScopeAccess(context, archiveCollection.id);
  }
  const markTag =
    input.deleteMode === 'soft' ? await resolveTagIdsByName(client, [input.markTagName], true, input.dryRun) : null;
  const markTagId = markTag?.tagIds[0];

  const groupPreview: Array<{
    canonicalUrl: string;
    keepId: number;
    mergeIds: number[];
    resultingTagIds: number[];
  }> = [];

  for (const group of input.groups) {
    const keepId = resolveKeepId(group, input.keepStrategy);
    const mergeIds = group.linkIds.filter((id) => id !== keepId);
    const links = await Promise.all(group.linkIds.map((id) => client.getLink(id)));
    const keepLink = links.find((link) => link.id === keepId);
    if (!keepLink) {
      throw new AppError(404, 'link_not_found', `Keep link ${keepId} was not found.`);
    }
    const mergedTagIds = normalizeTagIds(links.flatMap((link) => link.tags.map((tag) => tag.id)));
    groupPreview.push({
      canonicalUrl: group.canonicalUrl,
      keepId,
      mergeIds,
      resultingTagIds: mergedTagIds
    });
  }

  if (input.dryRun) {
    const warnings =
      input.deleteMode === 'soft' && archiveResolution?.wouldCreate
        ? [`archive_collection_missing: "${archiveResolution.archiveCollectionName}" would be created on apply.`]
        : [];
    return ok(
      {
        preview: groupPreview,
        archiveCollectionResolution: archiveResolution
          ? {
              created: archiveResolution.created,
              wouldCreate: archiveResolution.wouldCreate,
              strategy: archiveResolution.strategy,
              archiveCollectionName: archiveResolution.archiveCollectionName
            }
          : null
      },
      {
        summary: {
          groups: groupPreview.length,
          deleteMode: input.deleteMode
        },
        warnings
      }
    );
  }

  assertWriteAccess(context);
  return withIdempotency(
    context,
    'linkwarden_merge_duplicates',
    input.idempotencyKey,
    {
      groups: input.groups,
      keepStrategy: input.keepStrategy,
      deleteMode: input.deleteMode
    },
    async () => {
      const operationId = beginOperation(context, 'linkwarden_merge_duplicates', {
        groups: groupPreview.length,
        deleteMode: input.deleteMode,
        archiveCollectionCreated: Boolean(archiveResolution?.created),
        archiveCollectionId: archiveCollection?.id ?? null,
        archiveCollectionResolutionStrategy: archiveResolution?.strategy ?? null
      });
      const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
      const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
        [];
      let applied = 0;

      for (const group of groupPreview) {
        const keepLink = await client.getLink(group.keepId);
        const beforeKeep = snapshotForUndo(keepLink);
        const afterKeep = {
          ...beforeKeep,
          tagIds: group.resultingTagIds
        };
        try {
          await client.updateLink(group.keepId, { tagIds: group.resultingTagIds });
          operationItems.push({
            itemType: 'link',
            itemId: group.keepId,
            before: beforeKeep,
            after: afterKeep
          });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: group.keepId,
            code: 'merge_keep_update_failed',
            message: error instanceof Error ? error.message : 'merge keep update failed',
            retryable: true
          });
          continue;
        }

        for (const mergeId of group.mergeIds) {
          try {
            const mergeLink = await client.getLink(mergeId);
            const beforeMerge = snapshotForUndo(mergeLink);
            if (input.deleteMode === 'hard') {
              await client.deleteLink(mergeId);
              operationItems.push({
                itemType: 'link',
                itemId: mergeId,
                before: beforeMerge,
                after: { deleted: true, mode: 'hard' }
              });
            } else {
              const mergedTags =
                typeof markTagId === 'number'
                  ? computeNextTagIds(mergeLink.tags.map((tag) => tag.id), [markTagId], 'add')
                  : mergeLink.tags.map((tag) => tag.id);
              await client.updateLink(mergeId, {
                collectionId: archiveCollection?.id,
                tagIds: mergedTags,
                archived: true
              });
              operationItems.push({
                itemType: 'link',
                itemId: mergeId,
                before: beforeMerge,
                after: {
                  ...beforeMerge,
                  collectionId: archiveCollection?.id ?? beforeMerge.collectionId,
                  tagIds: mergedTags,
                  archived: true
                }
              });
            }
            applied += 1;
          } catch (error) {
            failures.push({
              itemId: mergeId,
              code: 'merge_delete_failed',
              message: error instanceof Error ? error.message : 'merge delete failed',
              retryable: true
            });
          }
        }
      }

      context.db.insertOperationItems(operationId, operationItems);
      try {
        // This call persists user-facing AI change-log rows for duplicate merge workflows.
        await appendAiChangeLogForOperation(context, client, 'linkwarden_merge_duplicates', operationId, operationItems);
      } catch (error) {
        // This warning keeps duplicate merge behavior non-blocking when auxiliary log persistence fails unexpectedly.
        context.logger.warn(
          {
            event: 'ai_change_log_append_failed',
            toolName: 'linkwarden_merge_duplicates',
            operationId,
            error: errorForLog(error)
          },
          'ai_change_log_append_failed'
        );
      }
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_merge_duplicates',
        targetType: 'link',
        targetIds: groupPreview.flatMap((group) => [group.keepId, ...group.mergeIds]),
        beforeSummary: 'merge duplicates preview',
        afterSummary: JSON.stringify({
          groups: groupPreview.length,
          deleteMode: input.deleteMode
        }),
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          operationId,
          applied,
          failures: failures.length,
          archiveCollectionId: archiveCollection?.id ?? null,
          archiveCollectionCreated: Boolean(archiveResolution?.created),
          archiveCollectionResolutionStrategy: archiveResolution?.strategy ?? null
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          archiveCollectionResolution: archiveResolution
            ? {
                created: archiveResolution.created,
                wouldCreate: archiveResolution.wouldCreate,
                strategy: archiveResolution.strategy,
                archiveCollectionName: archiveResolution.archiveCollectionName
              }
            : null,
          preview: groupPreview
        },
        summary: {
          groups: groupPreview.length,
          applied
        },
        paging: null,
        warnings: [],
        failures
      };
    }
  );
}

// This helper executes one rule action in dry-run or apply mode and returns deterministic result details.
async function executeRuleAction(
  context: ToolRuntimeContext,
  rule: RuleRecord,
  links: LinkItem[],
  dryRun: boolean
): Promise<{
  applied: number;
  failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }>;
  preview: Array<Record<string, unknown>>;
}> {
  const client = getClient(context);
  const actionType = String(rule.action.type ?? 'none');
  const preview: Array<Record<string, unknown>> = [];
  const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
  let applied = 0;

  for (const link of links) {
    if (actionType === 'add-tags') {
      const tagNames = Array.isArray(rule.action.tagNames) ? (rule.action.tagNames as string[]) : [];
      const tags = await resolveTagIdsByName(client, tagNames, true, dryRun);
      const nextTagIds = computeNextTagIds(link.tags.map((tag) => tag.id), tags.tagIds, 'add');
      preview.push({
        linkId: link.id,
        action: actionType,
        beforeTagIds: link.tags.map((tag) => tag.id),
        afterTagIds: nextTagIds
      });
      if (!dryRun) {
        try {
          await client.updateLink(link.id, { tagIds: nextTagIds });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: link.id,
            code: 'rule_add_tags_failed',
            message: error instanceof Error ? error.message : 'rule add tags failed',
            retryable: true
          });
        }
      }
      continue;
    }

    if (actionType === 'move-to-collection') {
      const collectionId = Number(rule.action.collectionId);
      preview.push({
        linkId: link.id,
        action: actionType,
        beforeCollectionId: link.collection?.id ?? null,
        afterCollectionId: collectionId
      });
      if (!dryRun) {
        try {
          await client.updateLink(link.id, { collectionId });
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: link.id,
            code: 'rule_move_failed',
            message: error instanceof Error ? error.message : 'rule move failed',
            retryable: true
          });
        }
      }
      continue;
    }

    if (actionType === 'pin') {
      const pinned = Boolean(rule.action.pinned);
      preview.push({
        linkId: link.id,
        action: actionType,
        beforePinned: Boolean(link.pinned),
        afterPinned: pinned
      });
      if (!dryRun) {
        try {
          await client.setLinkPinned(link.id, pinned);
          applied += 1;
        } catch (error) {
          failures.push({
            itemId: link.id,
            code: 'rule_pin_failed',
            message: error instanceof Error ? error.message : 'rule pin failed',
            retryable: true
          });
        }
      }
      continue;
    }

    preview.push({
      linkId: link.id,
      action: 'none'
    });
  }

  return {
    applied,
    failures,
    preview
  };
}

// This function handles linkwarden_create_rule by persisting one deterministic selector/action schedule record.
async function handleCreateRule(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createRuleSchema.parse(args);
  assertWriteAccess(context);
  const ruleId = randomUUID();
  context.db.createRule({
    id: ruleId,
    userId: context.principal.userId,
    name: input.name,
    selector: input.selector,
    action: input.action,
    schedule: input.schedule,
    enabled: input.enabled
  });
  return ok({
    ruleId
  });
}

// This function handles linkwarden_test_rule with read-only selector resolution and action preview.
async function handleTestRule(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = testRuleSchema.parse(args);
  const rule = context.db.getRule(input.id, context.principal.userId);
  if (!rule) {
    throw new AppError(404, 'rule_not_found', `Rule ${input.id} not found.`);
  }
  const resolved = await resolveLinks(context, rule.selector, undefined);
  const sampledLinks = resolved.links.slice(0, input.limit);
  const result = await executeRuleAction(context, rule, sampledLinks, true);
  return ok(
    {
      ruleId: rule.id,
      preview: result.preview
    },
    {
      summary: {
        scanned: sampledLinks.length,
        failures: result.failures.length
      },
      failures: result.failures
    }
  );
}

// This function handles linkwarden_apply_rule by executing one persisted rule now in dry-run or apply mode.
async function handleApplyRule(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = applyRuleSchema.parse(args);
  const rule = context.db.getRule(input.id, context.principal.userId);
  if (!rule) {
    throw new AppError(404, 'rule_not_found', `Rule ${input.id} not found.`);
  }
  if (!input.dryRun) {
    assertWriteAccess(context);
  }

  return withIdempotency(
    context,
    'linkwarden_apply_rule',
    input.idempotencyKey,
    {
      id: input.id,
      dryRun: input.dryRun
    },
    async () => {
      const runId = context.db.createRuleRun(rule.id, context.principal.userId);
      try {
        const resolved = await resolveLinks(context, rule.selector, undefined);
        const actionResult = await executeRuleAction(context, rule, resolved.links, input.dryRun);
        const status = actionResult.failures.length === 0 ? 'success' : 'failed';
        context.db.finishRuleRun({
          runId,
          status,
          summary: {
            dryRun: input.dryRun,
            scanned: resolved.links.length,
            applied: actionResult.applied,
            failures: actionResult.failures.length
          }
        });

        return {
          ok: true,
          data: {
            ruleId: rule.id,
            runId,
            preview: actionResult.preview
          },
          summary: {
            dryRun: input.dryRun,
            scanned: resolved.links.length,
            applied: actionResult.applied
          },
          paging: null,
          warnings: [],
          failures: actionResult.failures
        };
      } catch (error) {
        context.db.finishRuleRun({
          runId,
          status: 'failed',
          summary: {
            dryRun: input.dryRun
          },
          error: {
            message: error instanceof Error ? error.message : 'rule apply failed'
          }
        });
        throw error;
      }
    }
  );
}

// This function handles linkwarden_run_rules_now by executing all enabled or selected rules under one maintenance lock.
async function handleRunRulesNow(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = runRulesNowSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }
  const lockToken = randomUUID();
  const acquired = context.db.acquireMaintenanceLock(context.principal.userId, lockToken, 1800);
  if (!acquired) {
    throw new AppError(409, 'rules_locked', 'A rules run is already active for this user.');
  }

  try {
    const allRules = context.db.listRules(context.principal.userId);
    const selected = input.ids && input.ids.length > 0 ? allRules.filter((rule) => input.ids?.includes(rule.id)) : allRules.filter((rule) => rule.enabled);
    const results: Array<Record<string, unknown>> = [];
    const failures: Array<{ itemId: string; code: string; message: string; retryable: boolean }> = [];
    let applied = 0;

    for (const rule of selected) {
      const runId = context.db.createRuleRun(rule.id, context.principal.userId);
      try {
        const resolved = await resolveLinks(context, rule.selector, undefined);
        const actionResult = await executeRuleAction(context, rule, resolved.links, input.dryRun);
        applied += actionResult.applied;
        const status = actionResult.failures.length === 0 ? 'success' : 'failed';
        context.db.finishRuleRun({
          runId,
          status,
          summary: {
            dryRun: input.dryRun,
            scanned: resolved.links.length,
            applied: actionResult.applied,
            failures: actionResult.failures.length
          }
        });
        results.push({
          ruleId: rule.id,
          runId,
          scanned: resolved.links.length,
          applied: actionResult.applied,
          failures: actionResult.failures
        });
      } catch (error) {
        context.db.finishRuleRun({
          runId,
          status: 'failed',
          summary: {
            dryRun: input.dryRun
          },
          error: {
            message: error instanceof Error ? error.message : 'rule run failed'
          }
        });
        failures.push({
          itemId: rule.id,
          code: 'rule_run_failed',
          message: error instanceof Error ? error.message : 'rule run failed',
          retryable: true
        });
      }
    }

    return ok(
      {
        runs: results
      },
      {
        summary: {
          selectedRules: selected.length,
          applied
        },
        failures
      }
    );
  } finally {
    context.db.releaseMaintenanceLock(context.principal.userId, lockToken);
  }
}

// This function handles link capture from AI chats into deterministic AI Chats > <AI Name> > <Chat Name> collections.
async function handleCaptureChatLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const rawArgs = typeof args === 'object' && args !== null ? (args as Record<string, unknown>) : {};
  const input = captureChatLinksSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }

  // This helper preserves only explicit non-empty string inputs from raw tool arguments.
  const rawString = (value: unknown): string | undefined =>
    typeof value === 'string' && value.trim().length > 0 ? value : undefined;

  const chatNamePreference = resolveChatNamePreference({
    chatName: rawString(rawArgs.chatName),
    chatTitle: rawString(rawArgs.chatTitle),
    conversationTitle: rawString(rawArgs.conversationTitle),
    threadTitle: rawString(rawArgs.threadTitle)
  });
  const client = getClient(context);
  const aiCollectionName = normalizeCollectionSegment(input.aiName, 'ChatGPT', 120);
  const chatCollectionName = normalizeCollectionSegment(chatNamePreference.rawName, 'Current Chat', 160);
  const aiNameTag = normalizeAiNameTag(input.aiName);

  return withIdempotency(
    context,
    'linkwarden_capture_chat_links',
    input.idempotencyKey,
    {
      urls: input.urls ?? [],
      chatText: input.chatText ?? '',
      aiName: aiCollectionName,
      chatName: chatCollectionName,
      dryRun: input.dryRun
    },
    async () => {
      const extractedUrls = input.chatText ? extractUrlsFromChatText(input.chatText) : [];
      const allInputUrls = [...(input.urls ?? []), ...extractedUrls];
      const normalizedCandidates = normalizeChatUrlCandidates(allInputUrls);
      const hierarchy = await resolveChatCollectionHierarchy(client, aiCollectionName, chatCollectionName, !input.dryRun);
      const warnings = [...normalizedCandidates.warnings];

      if (chatNamePreference.source === 'fallback') {
        warnings.push(
          `capture_chat_links: chatName not provided, fallback "${chatCollectionName}" was used.`
        );
      } else if (chatNamePreference.source !== 'chatName') {
        warnings.push(
          `capture_chat_links: chatName resolved from alias "${chatNamePreference.source}" as "${chatCollectionName}".`
        );
      }

      for (const pending of hierarchy.wouldCreate) {
        warnings.push(
          `capture_chat_links: missing ${pending.level} collection "${pending.name}" would be created on apply.`
        );
      }

      if (hierarchy.chatCollection) {
        assertCollectionScopeAccess(context, hierarchy.chatCollection.id);
      }

      const chatControl = context.db.getUserChatControlSettings(context.principal.userId);
      const configuredStaticTagName = normalizeCollectionSegment(chatControl.chatCaptureTagName, 'AI Chat', 80);
      const desiredTagNames: string[] = [];
      if (chatControl.chatCaptureTagAiChatEnabled) {
        desiredTagNames.push(configuredStaticTagName);
      }
      if (chatControl.chatCaptureTagAiNameEnabled) {
        desiredTagNames.push(aiNameTag);
      }

      // This deduplication guarantees deterministic tag payloads even when names overlap case-insensitively.
      const appliedTagNames: string[] = [];
      const seenTagNames = new Set<string>();
      for (const tagName of desiredTagNames) {
        const normalized = normalizeTagName(tagName);
        if (normalized.length === 0 || seenTagNames.has(normalized)) {
          continue;
        }
        seenTagNames.add(normalized);
        appliedTagNames.push(tagName);
      }

      const tagResolution =
        appliedTagNames.length > 0
          ? await resolveTagIdsByName(client, appliedTagNames, true, input.dryRun)
          : { tagIds: [], created: [], missing: [] };

      if (tagResolution.missing.length > 0) {
        warnings.push(`capture_chat_links: missing tags in dry-run: ${tagResolution.missing.join(', ')}.`);
      }

      let existingCanonicalUrls = new Set<string>();
      if (hierarchy.chatCollection) {
        const existingLinks = await client.listLinksByCollection(hierarchy.chatCollection.id);
        existingCanonicalUrls = new Set(existingLinks.map((link) => canonicalizeUrl(link.url)));
      }

      const toCreateCandidates: Array<{ originalUrl: string; canonicalUrl: string }> = [];
      let skippedExisting = 0;
      for (const candidate of normalizedCandidates.normalized) {
        if (existingCanonicalUrls.has(candidate.canonicalUrl)) {
          skippedExisting += 1;
          continue;
        }
        toCreateCandidates.push(candidate);
      }

      if (input.dryRun) {
        return {
          ok: true,
          data: {
            aiName: aiCollectionName,
            chatName: chatCollectionName,
            hierarchy,
            tagConfig: {
              chatCaptureTagName: configuredStaticTagName,
              chatCaptureTagAiChatEnabled: chatControl.chatCaptureTagAiChatEnabled,
              chatCaptureTagAiNameEnabled: chatControl.chatCaptureTagAiNameEnabled,
              aiNameTag
            },
            appliedTagNames,
            appliedTagIds: tagResolution.tagIds,
            createdTags: tagResolution.created,
            missingTags: tagResolution.missing,
            preview: toCreateCandidates.slice(0, input.previewLimit).map((item) => item.originalUrl)
          },
          summary: {
            dryRun: true,
            detected: normalizedCandidates.normalized.length,
            duplicatesWithinInput: normalizedCandidates.duplicatesWithinInput,
            duplicatesInTargetCollection: skippedExisting,
            toCreate: toCreateCandidates.length,
            createdWithoutTags: 0,
            invalid: normalizedCandidates.invalidCount
          },
          paging: null,
          warnings,
          failures: []
        };
      }

      if (!hierarchy.chatCollection) {
        throw new AppError(409, 'chat_collection_missing', 'Chat collection could not be resolved during apply.');
      }

      const failures: Array<{ itemId: string; code: string; message: string; retryable: boolean }> = [];
      const createdLinks: Array<{
        id: number;
        title: string;
        url: string;
        description: string | null;
        collectionId: number;
        tagIds: number[];
        pinned: boolean;
        archived: boolean;
      }> = [];
      const createdWithoutTagsLinks: Array<{ id: number; url: string; collectionId: number }> = [];

      for (const candidate of toCreateCandidates) {
        // This payload keeps one shared base for first create attempt and optional fallback retry.
        const createInputBase = {
          url: candidate.originalUrl,
          title: candidate.originalUrl,
          collectionId: hierarchy.chatCollection.id
        };
        const requestedTagIds = tagResolution.tagIds.length > 0 ? tagResolution.tagIds : undefined;

        try {
          const created = await client.createLink({
            ...createInputBase,
            tagIds: requestedTagIds
          });
          createdLinks.push({
            id: created.id,
            title: created.title,
            url: created.url,
            description: created.description ?? null,
            collectionId: hierarchy.chatCollection.id,
            tagIds: requestedTagIds ?? [],
            pinned: Boolean(created.pinned),
            archived: Boolean(created.archived)
          });
        } catch (error) {
          const firstErrorMessage = formatCreateLinkError(error);

          // This retry keeps link ingestion available even when Linkwarden rejects tag shape or tag validation on create.
          if (requestedTagIds && isTagRelatedCreateError(error)) {
            try {
              const retryCreated = await client.createLink(createInputBase);
              createdLinks.push({
                id: retryCreated.id,
                title: retryCreated.title,
                url: retryCreated.url,
                description: retryCreated.description ?? null,
                collectionId: hierarchy.chatCollection.id,
                tagIds: [],
                pinned: Boolean(retryCreated.pinned),
                archived: Boolean(retryCreated.archived)
              });
              createdWithoutTagsLinks.push({
                id: retryCreated.id,
                url: retryCreated.url,
                collectionId: hierarchy.chatCollection.id
              });
              warnings.push(
                `capture_chat_links: tag application failed for "${candidate.originalUrl}", link was created without tags.`
              );
              continue;
            } catch (retryError) {
              const retryErrorMessage = formatCreateLinkError(retryError);
              failures.push({
                itemId: candidate.originalUrl,
                code: 'create_link_failed',
                message: `${firstErrorMessage} | retry_without_tags_failed: ${retryErrorMessage}`,
                retryable: true
              });
              continue;
            }
          }

          failures.push({
            itemId: candidate.originalUrl,
            code: 'create_link_failed',
            message: firstErrorMessage,
            retryable: true
          });
        }
      }

      let operationId: string | null = null;
      if (createdLinks.length > 0) {
        operationId = beginOperation(context, 'linkwarden_capture_chat_links', {
          detected: normalizedCandidates.normalized.length,
          created: createdLinks.length,
          failed: failures.length
        });
        const operationItems = createdLinks.map((link) => ({
          itemType: 'link',
          itemId: link.id,
          before: {
            deleted: true
          },
          after: {
            title: link.title,
            url: link.url,
            description: link.description,
            collectionId: link.collectionId,
            tagIds: link.tagIds,
            pinned: link.pinned,
            archived: link.archived
          }
        }));
        context.db.insertOperationItems(operationId, operationItems);
        try {
          // This call persists user-facing AI change-log rows for capture-created links.
          await appendAiChangeLogForOperation(context, client, 'linkwarden_capture_chat_links', operationId, operationItems);
        } catch (error) {
          // This warning keeps capture apply behavior non-blocking when auxiliary log persistence fails unexpectedly.
          context.logger.warn(
            {
              event: 'ai_change_log_append_failed',
              toolName: 'linkwarden_capture_chat_links',
              operationId,
              error: errorForLog(error)
            },
            'ai_change_log_append_failed'
          );
        }
      }

      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_capture_chat_links',
        targetType: 'link',
        targetIds: createdLinks.map((link) => link.id),
        beforeSummary: 'chat link capture apply requested',
        afterSummary: 'chat link capture apply finished',
        outcome: failures.length === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          aiName: aiCollectionName,
          chatName: chatCollectionName,
          rootCollectionId: hierarchy.rootCollection?.id ?? null,
          aiCollectionId: hierarchy.aiCollection?.id ?? null,
          chatCollectionId: hierarchy.chatCollection?.id ?? null,
          createdCollectionIds: hierarchy.createdCollections.map((collection) => collection.id),
          tagNames: appliedTagNames,
          tagIds: tagResolution.tagIds,
          operationId,
          detected: normalizedCandidates.normalized.length,
          created: createdLinks.length,
          createdWithoutTags: createdWithoutTagsLinks.length,
          failed: failures.length
        }
      });

      return {
        ok: true,
        data: {
          operationId,
          aiName: aiCollectionName,
          chatName: chatCollectionName,
          hierarchy,
          tagConfig: {
            chatCaptureTagName: configuredStaticTagName,
            chatCaptureTagAiChatEnabled: chatControl.chatCaptureTagAiChatEnabled,
            chatCaptureTagAiNameEnabled: chatControl.chatCaptureTagAiNameEnabled,
            aiNameTag
          },
          appliedTagNames,
          appliedTagIds: tagResolution.tagIds,
          createdTags: tagResolution.created,
          missingTags: tagResolution.missing,
          createdLinks: createdLinks.slice(0, input.previewLimit),
          createdWithoutTagsLinks: createdWithoutTagsLinks.slice(0, input.previewLimit)
        },
        summary: {
          dryRun: false,
          detected: normalizedCandidates.normalized.length,
          duplicatesWithinInput: normalizedCandidates.duplicatesWithinInput,
          duplicatesInTargetCollection: skippedExisting,
          toCreate: toCreateCandidates.length,
          created: createdLinks.length,
          createdWithoutTags: createdWithoutTagsLinks.length,
          failed: failures.length,
          invalid: normalizedCandidates.invalidCount
        },
        paging: null,
        warnings,
        failures
      };
    }
  );
}

// This function handles linkwarden_get_new_links_routine_status and returns schedule, settings, and backlog warnings.
async function handleGetNewLinksRoutineStatus(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  getNewLinksRoutineStatusSchema.parse(args);
  const status = await getNewLinksRoutineStatus(context, {
    includeBacklogEstimate: true
  });

  return ok(
    {
      routine: status
    },
    {
      summary: {
        enabled: status.settings.enabled,
        due: status.due
      },
      warnings: status.warnings
    }
  );
}

// This function handles linkwarden_run_new_links_routine_now and delegates to the shared routine service path.
async function handleRunNewLinksRoutineNow(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  runNewLinksRoutineNowSchema.parse(args);
  const routineResult = await runNewLinksRoutineNow(
    context,
    async (toolName, payload, nestedContext) => {
      const handler = toolHandlers[toolName];
      if (!handler) {
        throw new AppError(404, 'tool_not_found', `Unknown tool: ${toolName}`);
      }
      return handler(payload, nestedContext);
    },
    {
      ignoreSchedule: true
    }
  );

  return ok(
    {
      routine: routineResult
    },
    {
      summary: routineResult.summary,
      warnings: routineResult.warnings,
      failures: routineResult.failures.map((failure) => ({ ...failure }))
    }
  );
}

// This function handles linkwarden_get_link_404_monitor_status and returns schedule/status warnings for 404 monitoring.
async function handleGetLink404MonitorStatus(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  getLink404MonitorStatusSchema.parse(args);
  const status = await getLink404MonitorStatus(context, {});

  return ok(
    {
      routine: status
    },
    {
      summary: {
        enabled: status.settings.enabled,
        due: status.due,
        interval: status.settings.interval,
        toDeleteAfter: status.settings.toDeleteAfter
      },
      warnings: status.warnings
    }
  );
}

// This function handles linkwarden_run_link_404_monitor_now and delegates to the shared 404-monitor service path.
async function handleRunLink404MonitorNow(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  runLink404MonitorNowSchema.parse(args);
  const routineResult = await runLink404MonitorNow(context, {
    ignoreSchedule: true
  });

  return ok(
    {
      routine: routineResult
    },
    {
      summary: routineResult.summary,
      warnings: routineResult.warnings,
      failures: routineResult.failures.map((failure) => ({ ...failure }))
    }
  );
}

// This function handles linkwarden_list_rules and supports optional enabled-only filtering.
async function handleListRules(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listRulesSchema.parse(args);
  const all = context.db.listRules(context.principal.userId);
  const rules = input.enabledOnly ? all.filter((rule) => rule.enabled) : all;
  return ok({
    rules
  });
}

// This function handles linkwarden_delete_rule for one user-owned rule identifier.
async function handleDeleteRule(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteRuleSchema.parse(args);
  assertWriteAccess(context);
  context.db.deleteRule(input.id, context.principal.userId);
  return ok({
    deleted: true,
    ruleId: input.id
  });
}

// This function handles linkwarden_create_saved_query for compact query-id based retrieval.
async function handleCreateSavedQuery(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createSavedQuerySchema.parse(args);
  assertWriteAccess(context);
  const id = randomUUID();
  context.db.createSavedQuery({
    id,
    userId: context.principal.userId,
    name: input.name,
    selector: input.selector,
    fields: input.fields,
    verbosity: input.verbosity
  });
  return ok({
    savedQueryId: id
  });
}

// This function handles linkwarden_list_saved_queries for one user.
async function handleListSavedQueries(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  listSavedQueriesSchema.parse(args);
  return ok({
    savedQueries: context.db.listSavedQueries(context.principal.userId)
  });
}

// This function handles linkwarden_run_saved_query by delegating to deterministic query snapshot paging.
async function handleRunSavedQuery(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = runSavedQuerySchema.parse(args);
  const saved = context.db.getSavedQuery(input.id, context.principal.userId);
  if (!saved) {
    throw new AppError(404, 'saved_query_not_found', `Saved query ${input.id} not found.`);
  }
  return handleQueryLinks(
    {
      selector: saved.selector,
      fields: saved.fields,
      verbosity: saved.verbosity,
      limit: input.limit,
      cursor: input.cursor
    },
    context
  );
}

// This function handles linkwarden_get_audit by returning both operation history and write audit records.
async function handleGetAudit(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = getAuditSchema.parse(args);
  const operations = context.db.listOperations(context.principal.userId, input.limit, input.offset);
  const audit = context.db.listAuditEntries(context.principal.userId, input.limit, input.offset);
  return ok(
    {
      operations,
      audit
    },
    {
      paging: {
        limit: input.limit,
        offset: input.offset,
        returned: Math.max(operations.length, audit.length)
      }
    }
  );
}

// This helper undoes selected AI change-log rows with conflict checks and deterministic status updates.
export async function undoChangesByIds(
  context: ToolRuntimeContext,
  changeIds: number[]
): Promise<{
  requested: number;
  undone: number;
  conflicts: Array<{ changeId: number; linkId: number | null; reason: string }>;
  failed: Array<{ changeId: number; linkId: number | null; reason: string }>;
  warnings: string[];
  operationIdsAffected: string[];
  undoOperationId: string;
}> {
  assertWriteAccess(context);
  const requestedIds = [...new Set(changeIds.filter((value) => Number.isInteger(value) && value > 0))];
  if (requestedIds.length === 0) {
    throw new AppError(400, 'validation_error', 'At least one valid change id is required.');
  }

  const client = getClient(context);
  const candidates = context.db.getAiChangeUndoCandidates(context.principal.userId, requestedIds);
  const candidateById = new Map(candidates.map((candidate) => [candidate.change.id, candidate]));
  const warnings: string[] = [];
  const conflicts: Array<{ changeId: number; linkId: number | null; reason: string }> = [];
  const failed: Array<{ changeId: number; linkId: number | null; reason: string }> = [];
  const appliedChangeIds: number[] = [];
  const conflictChangeIds: number[] = [];
  const failedChangeIds: number[] = [];
  const operationIdsAffected = new Set<string>();
  let undone = 0;

  const nowIso = new Date().toISOString();
  const undoOperationId = randomUUID();
  context.db.createOperation({
    id: undoOperationId,
    userId: context.principal.userId,
    toolName: 'linkwarden_undo_changes',
    summary: {
      requested: requestedIds.length
    },
    undoUntil: null
  });

  for (const changeId of requestedIds) {
    const candidate = candidateById.get(changeId);
    if (!candidate) {
      const reason = 'Change id was not found for this user.';
      failed.push({ changeId, linkId: null, reason });
      failedChangeIds.push(changeId);
      continue;
    }

    const change = candidate.change;
    operationIdsAffected.add(change.operationId);

    if (change.undoStatus === 'applied') {
      warnings.push(`Change ${change.id} was already undone and was skipped.`);
      continue;
    }

    if (!candidate.undoUntil || new Date(candidate.undoUntil).getTime() <= Date.now()) {
      const reason = `Undo window expired for change ${change.id}.`;
      failed.push({ changeId: change.id, linkId: change.linkId, reason });
      failedChangeIds.push(change.id);
      continue;
    }

    if (candidate.hasNewerOpenChange) {
      const reason = `A newer non-undone change exists for link ${change.linkId ?? 'unknown'}.`;
      conflicts.push({ changeId: change.id, linkId: change.linkId, reason });
      conflictChangeIds.push(change.id);
      continue;
    }

    const undoItem: OperationItemRecord = {
      operationId: change.operationId,
      itemType: 'link',
      itemId: change.operationItemId,
      before: candidate.before,
      after: candidate.after,
      undoStatus: 'pending'
    };
    const undoResult = await undoOperationItem(context, client, change.operationId, undoItem);
    if (undoResult.ok) {
      undone += 1;
      appliedChangeIds.push(change.id);
    } else {
      const reason = undoResult.message ?? 'undo failed';
      failed.push({ changeId: change.id, linkId: change.linkId, reason });
      failedChangeIds.push(change.id);
    }
  }

  if (appliedChangeIds.length > 0) {
    context.db.markAiChangesUndone(context.principal.userId, appliedChangeIds, undoOperationId, nowIso);
  }
  if (conflictChangeIds.length > 0) {
    context.db.setAiChangeUndoStatus(context.principal.userId, conflictChangeIds, 'conflict', {
      atIso: nowIso,
      undoOperationId
    });
  }
  if (failedChangeIds.length > 0) {
    context.db.setAiChangeUndoStatus(context.principal.userId, failedChangeIds, 'failed', {
      atIso: nowIso,
      undoOperationId
    });
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_undo_changes',
    targetType: 'ai_change',
    targetIds: requestedIds,
    beforeSummary: 'undo selected changes requested',
    afterSummary: JSON.stringify({
      undone,
      conflicts: conflicts.length,
      failed: failed.length
    }),
    outcome: failed.length === 0 ? 'success' : 'failed',
    details: {
      userId: context.principal.userId,
      undoOperationId
    }
  });

  return {
    requested: requestedIds.length,
    undone,
    conflicts,
    failed,
    warnings,
    operationIdsAffected: [...operationIdsAffected].sort((left, right) => left.localeCompare(right)),
    undoOperationId
  };
}

// This helper applies one before-snapshot to a link and updates operation item state based on outcome.
async function undoOperationItem(
  context: ToolRuntimeContext,
  client: LinkwardenClient,
  operationId: string,
  item: OperationItemRecord
): Promise<{ ok: boolean; message?: string }> {
  if (item.before.deleted === true) {
    try {
      // This branch undoes create-link operations by deleting the newly created link entity.
      await client.deleteLink(item.itemId);
      context.db.setOperationItemUndoStatus(operationId, item.itemId, 'applied');
      return { ok: true };
    } catch (error) {
      context.db.setOperationItemUndoStatus(operationId, item.itemId, 'failed');
      return {
        ok: false,
        message: error instanceof Error ? error.message : 'undo delete failed'
      };
    }
  }

  try {
    await client.updateLink(item.itemId, {
      title: item.before.title,
      url: item.before.url,
      description: item.before.description,
      collectionId: item.before.collectionId,
      tagIds: item.before.tagIds,
      pinned: item.before.pinned,
      archived: item.before.archived
    });
    context.db.setOperationItemUndoStatus(operationId, item.itemId, 'applied');
    return { ok: true };
  } catch (error) {
    context.db.setOperationItemUndoStatus(operationId, item.itemId, 'failed');
    return {
      ok: false,
      message: error instanceof Error ? error.message : 'undo failed'
    };
  }
}

// This function handles linkwarden_undo_operation by replaying before-snapshots in reverse item order.
async function handleUndoOperation(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = undoOperationSchema.parse(args);
  assertWriteAccess(context);
  const operation = context.db.getOperationWithItems(input.operationId, context.principal.userId);
  if (!operation) {
    throw new AppError(404, 'operation_not_found', `Operation ${input.operationId} not found.`);
  }
  if (!operation.operation.undoUntil || new Date(operation.operation.undoUntil).getTime() <= Date.now()) {
    throw new AppError(409, 'undo_expired', `Operation ${input.operationId} is no longer undoable.`);
  }

  const client = getClient(context);
  const failures: Array<{ itemId: number; code: string; message: string; retryable: boolean }> = [];
  const appliedItemIds: number[] = [];
  const failedItemIds: number[] = [];
  let undone = 0;

  for (const item of operation.items) {
    const result = await undoOperationItem(context, client, input.operationId, item);
    if (result.ok) {
      undone += 1;
      appliedItemIds.push(item.itemId);
    } else {
      failedItemIds.push(item.itemId);
      failures.push({
        itemId: item.itemId,
        code: 'undo_failed',
        message: result.message ?? 'undo failed',
        retryable: false
      });
    }
  }

  const undoAppliedAt = new Date().toISOString();
  if (appliedItemIds.length > 0) {
    context.db.setAiChangeUndoStatusByOperationItems(
      context.principal.userId,
      input.operationId,
      appliedItemIds,
      'applied',
      {
        atIso: undoAppliedAt,
        undoOperationId: input.operationId
      }
    );
  }
  if (failedItemIds.length > 0) {
    context.db.setAiChangeUndoStatusByOperationItems(
      context.principal.userId,
      input.operationId,
      failedItemIds,
      'failed',
      {
        atIso: undoAppliedAt,
        undoOperationId: input.operationId
      }
    );
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_undo_operation',
    targetType: 'operation',
    targetIds: [input.operationId],
    beforeSummary: 'undo operation requested',
    afterSummary: JSON.stringify({
      undone,
      failures: failures.length
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: {
      userId: context.principal.userId
    }
  });

  return ok(
    {
      operationId: input.operationId
    },
    {
      summary: {
        items: operation.items.length,
        undone
      },
      failures
    }
  );
}

const toolHandlers: Record<string, (args: unknown, context: ToolRuntimeContext) => Promise<ToolCallResult>> = {
  linkwarden_get_server_info: handleGetServerInfo,
  linkwarden_get_stats: handleGetStats,
  linkwarden_query_links: handleQueryLinks,
  linkwarden_aggregate_links: handleAggregateLinks,
  linkwarden_get_link: handleGetLink,
  linkwarden_mutate_links: handleMutateLinks,
  linkwarden_delete_links: handleDeleteLinks,
  linkwarden_list_collections: handleListCollections,
  linkwarden_create_collection: handleCreateCollection,
  linkwarden_update_collection: handleUpdateCollection,
  linkwarden_delete_collection: handleDeleteCollection,
  linkwarden_list_tags: handleListTags,
  linkwarden_create_tag: handleCreateTag,
  linkwarden_delete_tag: handleDeleteTag,
  linkwarden_assign_tags: handleAssignTags,
  linkwarden_governed_tag_links: handleGovernedTagLinks,
  linkwarden_normalize_urls: handleNormalizeUrls,
  linkwarden_find_duplicates: handleFindDuplicates,
  linkwarden_merge_duplicates: handleMergeDuplicates,
  linkwarden_create_rule: handleCreateRule,
  linkwarden_test_rule: handleTestRule,
  linkwarden_apply_rule: handleApplyRule,
  linkwarden_run_rules_now: handleRunRulesNow,
  linkwarden_capture_chat_links: handleCaptureChatLinks,
  linkwarden_get_new_links_routine_status: handleGetNewLinksRoutineStatus,
  linkwarden_run_new_links_routine_now: handleRunNewLinksRoutineNow,
  linkwarden_get_link_404_monitor_status: handleGetLink404MonitorStatus,
  linkwarden_run_link_404_monitor_now: handleRunLink404MonitorNow,
  linkwarden_list_rules: handleListRules,
  linkwarden_delete_rule: handleDeleteRule,
  linkwarden_create_saved_query: handleCreateSavedQuery,
  linkwarden_list_saved_queries: handleListSavedQueries,
  linkwarden_run_saved_query: handleRunSavedQuery,
  linkwarden_get_audit: handleGetAudit,
  linkwarden_undo_operation: handleUndoOperation
};

// This function dispatches validated tool calls and normalizes validation errors for JSON-RPC transport.
export async function executeTool(
  toolName: string,
  args: unknown,
  context: ToolRuntimeContext
): Promise<ToolCallResult> {
  const startedAt = Date.now();
  context.logger.info(
    {
      event: 'mcp_tool_execution_started',
      toolName,
      actor: context.actor,
      userId: context.principal.userId,
      username: context.principal.username,
      role: context.principal.role,
      apiKeyId: context.principal.apiKeyId,
      args: sanitizeForLog(args)
    },
    'mcp_tool_execution_started'
  );

  const handler = toolHandlers[toolName];
  if (!handler) {
    throw new AppError(404, 'tool_not_found', `Unknown tool: ${toolName}`);
  }

  assertToolScopeAccess(context, toolName);

  try {
    const result = await handler(args, context);
    context.logger.info(
      {
        event: 'mcp_tool_execution_completed',
        toolName,
        actor: context.actor,
        userId: context.principal.userId,
        durationMs: Date.now() - startedAt,
        result: summarizeToolOutput(result)
      },
      'mcp_tool_execution_completed'
    );
    return result;
  } catch (error) {
    context.logger.error(
      {
        event: 'mcp_tool_execution_failed',
        toolName,
        actor: context.actor,
        userId: context.principal.userId,
        durationMs: Date.now() - startedAt,
        error: errorForLog(error)
      },
      'mcp_tool_execution_failed'
    );

    if (error instanceof z.ZodError) {
      throw new AppError(400, 'validation_error', 'Tool input validation failed.', error.flatten());
    }
    throw error;
  }
}
