// This module implements all MCP tool handlers with validation, safety guards, and audit logging.

import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { LinkwardenClient } from '../linkwarden/client.js';
import { createUserLinkwardenClient } from '../linkwarden/runtime.js';
import { computeReorgPlan } from '../planning/reorg.js';
import type {
  AuthenticatedPrincipal,
  BulkUpdateRequest,
  LinkCollection,
  LinkHealthState,
  LinkItem,
  LinkTag,
  MaintenanceRunItem,
  PlanItem,
  PlanScope
} from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { errorForLog, sanitizeForLog } from '../utils/logger.js';
import { cleanTrackedUrl } from '../utils/url-cleaner.js';
import {
  assignTagsSchema,
  bulkUpdateSchema,
  captureChatLinksSchema,
  cleanLinkUrlsSchema,
  createCollectionSchema,
  createTagSchema,
  deleteCollectionSchema,
  deleteTagSchema,
  applyPlanSchema,
  connectorFetchSchema,
  connectorSearchSchema,
  getLinkSchema,
  listCollectionsSchema,
  listTagsSchema,
  monitorOfflineLinksSchema,
  planReorgSchema,
  runDailyMaintenanceSchema,
  serverInfoSchema,
  setLinksCollectionSchema,
  setLinksPinnedSchema,
  searchLinksSchema,
  suggestTaxonomySchema,
  updateCollectionSchema,
  updateLinkSchema
} from './tool-schemas.js';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, formatProtocolVersionWithTimestamp } from '../version.js';

export interface ToolRuntimeContext {
  actor: string;
  principal: AuthenticatedPrincipal;
  configStore: ConfigStore;
  db: SqliteStore;
  logger: FastifyBaseLogger;
}

// This type captures the normalized MCP tool output format returned to the connector.
export interface ToolCallResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: Record<string, unknown>;
}

// This helper wraps structured objects in both text and structured fields for connector compatibility.
function mcpResult(payload: Record<string, unknown>): ToolCallResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

// This helper removes duplicate tag ids and keeps deterministic order.
function normalizeTagIds(tagIds: number[]): number[] {
  return [...new Set(tagIds)].sort((a, b) => a - b);
}

// This helper normalizes tag names for deterministic comparisons across case and whitespace variations.
function normalizeTagName(name: string): string {
  return name.trim().toLocaleLowerCase();
}

// This helper de-duplicates tag names by normalized representation while preserving first-seen order.
function dedupeTagNames(tagNames: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const rawName of tagNames) {
    const trimmed = rawName.trim();
    const normalized = normalizeTagName(trimmed);
    if (trimmed.length === 0 || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    result.push(trimmed);
  }

  return result;
}

// This helper resolves tag ids back to human-readable names for deterministic dry-run previews.
function mapTagIdsToNames(tagIds: number[], tagById: Map<number, string>): string[] {
  return tagIds.map((tagId) => tagById.get(tagId) ?? `tag:${tagId}`);
}

// This helper enforces role and write-mode policy before mutating operations.
function assertWriteAccess(context: ToolRuntimeContext): void {
  if (context.principal.role !== 'admin' && context.principal.role !== 'user') {
    context.logger.warn(
      {
        event: 'tool_write_access_denied_role',
        userId: context.principal.userId,
        username: context.principal.username,
        role: context.principal.role
      },
      'tool_write_access_denied_role'
    );
    throw new AppError(403, 'forbidden', 'Role is not allowed to execute write operations.');
  }

  const settings = context.db.getUserSettings(context.principal.userId);
  if (!settings.writeModeEnabled) {
    context.logger.warn(
      {
        event: 'tool_write_access_denied_write_mode_disabled',
        userId: context.principal.userId,
        username: context.principal.username
      },
      'tool_write_access_denied_write_mode_disabled'
    );
    throw new AppError(
      403,
      'write_mode_disabled',
      'Write mode is disabled for this user. Enable it in the web UI first.'
    );
  }
}

// This helper adds actor metadata that must always be present in write audit records.
function withActorDetails(
  context: ToolRuntimeContext,
  details?: Record<string, unknown>
): Record<string, unknown> {
  return {
    userId: context.principal.userId,
    username: context.principal.username,
    role: context.principal.role,
    apiKeyId: context.principal.apiKeyId,
    ...(details ?? {})
  };
}

// This helper extracts integer arrays from plan item snapshots used during apply.
function readAfterState(item: PlanItem): { tagIds?: number[]; collectionId?: number | null } {
  const after = item.after as { tagIds?: unknown; collectionId?: unknown };
  const tagIds = Array.isArray(after.tagIds)
    ? normalizeTagIds(after.tagIds.filter((id): id is number => Number.isFinite(id as number)))
    : undefined;

  const collectionId =
    after.collectionId === null || Number.isFinite(after.collectionId as number)
      ? (after.collectionId as number | null)
      : undefined;

  return { tagIds, collectionId };
}

// This helper computes next tag ids for add/remove/replace bulk modes.
function computeBulkTagResult(current: number[], updates: number[] | undefined, mode: BulkUpdateRequest['mode']): number[] {
  if (!updates || updates.length === 0) {
    return normalizeTagIds(current);
  }

  if (mode === 'replace') {
    return normalizeTagIds(updates);
  }

  const currentSet = new Set(current);
  if (mode === 'add') {
    for (const tagId of updates) {
      currentSet.add(tagId);
    }
    return normalizeTagIds([...currentSet]);
  }

  for (const tagId of updates) {
    currentSet.delete(tagId);
  }

  return normalizeTagIds([...currentSet]);
}

// This helper creates a Linkwarden client from currently unlocked runtime secrets.
function getClient(context: ToolRuntimeContext): LinkwardenClient {
  return createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
}

// This helper returns compact result metadata to keep tool completion logs concise.
function summarizeToolOutput(output: ToolCallResult): Record<string, unknown> {
  const payload = output.structuredContent;

  if ('paging' in payload) {
    return sanitizeForLog({
      paging: payload.paging
    }) as Record<string, unknown>;
  }

  if ('plan_id' in payload || 'applied' in payload) {
    return sanitizeForLog({
      plan_id: payload.plan_id,
      applied: payload.applied,
      failures: Array.isArray(payload.failures) ? payload.failures.length : undefined,
      warnings: Array.isArray(payload.warnings) ? payload.warnings.length : undefined
    }) as Record<string, unknown>;
  }

  return sanitizeForLog({
    keys: Object.keys(payload)
  }) as Record<string, unknown>;
}

// This helper normalizes URLs for stable deduping independent of trailing slashes.
function normalizeUrl(input: string): string {
  try {
    const url = new URL(input.trim());
    if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) {
      url.port = '';
    }
    if (url.pathname !== '/' && url.pathname.endsWith('/')) {
      url.pathname = url.pathname.slice(0, -1);
    }
    url.hash = '';
    return url.toString();
  } catch {
    return input.trim();
  }
}

// This helper extracts unique HTTP(S) URLs from free-form chat text while preserving input order.
function extractUrlsFromText(text: string, maxLinks: number): string[] {
  const matches = text.match(/https?:\/\/[^\s<>"'`]+/gi) ?? [];
  const cleaned = matches
    .map((raw) => raw.replace(/[),.;!?]+$/g, ''))
    .filter((value) => value.length > 0);
  const seen = new Set<string>();
  const result: string[] = [];

  for (const url of cleaned) {
    const key = normalizeUrl(url);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(url);
    if (result.length >= maxLinks) {
      break;
    }
  }

  return result;
}

// This helper resolves one direct child collection by name and parent relation.
function findCollectionByNameAndParent(
  collections: LinkCollection[],
  name: string,
  parentId: number | null
): LinkCollection | undefined {
  return collections.find((collection) => collection.name === name && (collection.parentId ?? null) === parentId);
}

// This helper ensures one parent->child collection path exists and creates missing segments on demand.
async function ensureCollectionPath(
  client: LinkwardenClient,
  parentName: string,
  childName: string
): Promise<{ parent: LinkCollection; child: LinkCollection; created: LinkCollection[] }> {
  const created: LinkCollection[] = [];
  const collections = await client.listAllCollections();

  let parent = findCollectionByNameAndParent(collections, parentName, null);
  if (!parent) {
    parent = await client.createCollection({ name: parentName, parentId: null });
    created.push(parent);
    collections.push(parent);
  }

  let child = findCollectionByNameAndParent(collections, childName, parent.id);
  if (!child) {
    child = await client.createCollection({ name: childName, parentId: parent.id });
    created.push(child);
  }

  return { parent, child, created };
}

interface LinkAvailabilityResult {
  ok: boolean;
  httpStatus: number | null;
  error: string | null;
}

// This helper classifies statuses that still indicate a reachable destination for link-health monitoring.
function isHealthyAvailabilityStatus(status: number): boolean {
  if (status === 404 || status === 410) {
    return false;
  }

  // This keeps protected URLs (for example login-protected pages) from being treated as offline.
  if (status === 401 || status === 403) {
    return true;
  }

  return status >= 200 && status < 400;
}

// This helper checks whether one URL is reachable enough for archival decisions.
async function checkLinkAvailability(url: string, timeoutMs: number): Promise<LinkAvailabilityResult> {
  const probe = async (method: 'HEAD' | 'GET'): Promise<Response> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, {
        method,
        redirect: 'follow',
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    const headResponse = await probe('HEAD');
    if (isHealthyAvailabilityStatus(headResponse.status)) {
      return { ok: true, httpStatus: headResponse.status, error: null };
    }
    return { ok: false, httpStatus: headResponse.status, error: `http_${headResponse.status}` };
  } catch (headError) {
    try {
      const getResponse = await probe('GET');
      if (isHealthyAvailabilityStatus(getResponse.status)) {
        return { ok: true, httpStatus: getResponse.status, error: null };
      }
      return { ok: false, httpStatus: getResponse.status, error: `http_${getResponse.status}` };
    } catch (getError) {
      const reason = getError instanceof Error ? getError.message : String(getError);
      const fallback = headError instanceof Error ? headError.message : reason;
      return { ok: false, httpStatus: null, error: reason || fallback || 'unreachable' };
    }
  }
}

// This helper computes the next persisted health-state snapshot from the latest probe result.
function computeNextHealthState(
  userId: number,
  link: LinkItem,
  previous: LinkHealthState | undefined,
  probe: LinkAvailabilityResult,
  checkedAtIso: string
): LinkHealthState {
  if (probe.ok) {
    return {
      userId,
      linkId: link.id,
      url: link.url,
      firstFailureAt: null,
      lastFailureAt: null,
      consecutiveFailures: 0,
      lastStatus: 'up',
      lastCheckedAt: checkedAtIso,
      lastHttpStatus: probe.httpStatus,
      lastError: null,
      archivedAt: previous?.archivedAt ?? null
    };
  }

  const baseFirstFailure =
    previous?.lastStatus === 'down' && previous.firstFailureAt ? previous.firstFailureAt : checkedAtIso;
  const consecutiveFailures =
    previous?.lastStatus === 'down' ? Math.max(1, previous.consecutiveFailures + 1) : 1;

  return {
    userId,
    linkId: link.id,
    url: link.url,
    firstFailureAt: baseFirstFailure,
    lastFailureAt: checkedAtIso,
    consecutiveFailures,
    lastStatus: 'down',
    lastCheckedAt: checkedAtIso,
    lastHttpStatus: probe.httpStatus,
    lastError: probe.error,
    archivedAt: previous?.archivedAt ?? null
  };
}

// This helper counts standard failure arrays in tool payloads for maintenance status decisions.
function readFailureCount(payload: Record<string, unknown>): number {
  const failures = payload.failures;
  if (!Array.isArray(failures)) {
    return 0;
  }
  return failures.length;
}

// This function handles linkwarden_search_links and supports unbounded mode when limit is omitted.
async function handleSearchLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = searchLinksSchema.parse(args);
  const client = getClient(context);
  const collectionId = input.collectionId ?? input.collection_id;
  const tagIds = input.tagIds ?? input.tag_ids;
  // This call intentionally performs one deterministic full scope load so totals remain stable on broken upstream offset paging.
  const loaded = await client.loadLinksForScopeDetailed(
    {
      query: input.query,
      collectionId,
      tagIds,
      archived: input.archived,
      pinned: input.pinned
    },
    100
  );
  const all = loaded.items;
  const items =
    input.limit === undefined ? all.slice(input.offset) : all.slice(input.offset, input.offset + input.limit);

  const payload: Record<string, unknown> = {
    links: items.map((item) => ({
      id: item.id,
      title: item.title,
      url: item.url,
      description: item.description,
      tags: item.tags,
      collection: item.collection,
      pinned: item.pinned,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    })),
    paging: {
      limit: input.limit ?? null,
      offset: input.offset,
      returned: items.length,
      total: all.length
    }
  };

  // This optional debug branch exposes scope loading diagnostics for paging investigations.
  if (input.debug) {
    payload.debug = {
      scopeLoad: loaded.diagnostics,
      scopeWarning: loaded.warning ?? null
    };
  }

  return mcpResult(payload);
}

// This function returns MCP server metadata so clients can query the running server version.
async function handleGetServerInfo(args: unknown): Promise<ToolCallResult> {
  serverInfoSchema.parse(args);
  return mcpResult({
    name: MCP_SERVER_NAME,
    version: MCP_SERVER_VERSION,
    protocolVersion: formatProtocolVersionWithTimestamp()
  });
}

// This function provides the generic `search` tool contract expected by OpenAI connector examples.
async function handleConnectorSearch(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = connectorSearchSchema.parse(args);
  const client = getClient(context);
  // This connector path intentionally loads all matching links so ChatGPT is not artificially limited.
  const result = await client.loadLinksForScope({
    query: input.query
  });

  return mcpResult({
    results: result.map((item) => ({
      id: String(item.id),
      title: item.title,
      url: item.url
    }))
  });
}

// This function provides the generic `fetch` tool contract expected by OpenAI connector examples.
async function handleConnectorFetch(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = connectorFetchSchema.parse(args);

  // This guard keeps the wrapper deterministic by accepting only positive numeric Linkwarden ids.
  const linkId = Number(input.id);
  if (!Number.isInteger(linkId) || linkId <= 0) {
    throw new AppError(400, 'validation_error', 'fetch id must be a positive numeric link id.');
  }

  const client = getClient(context);
  const link = await client.getLink(linkId);

  // This fallback text keeps the response useful even when the Linkwarden description is empty.
  const textLines = [`URL: ${link.url}`];
  if (link.description) {
    textLines.push('', link.description);
  }

  return mcpResult({
    id: String(link.id),
    title: link.title,
    text: textLines.join('\n'),
    url: link.url,
    metadata: {
      source: 'linkwarden',
      linkId: link.id,
      archived: link.archived ?? null,
      collection: link.collection?.name ?? null,
      tags: link.tags.map((tag) => tag.name),
      createdAt: link.createdAt ?? null,
      updatedAt: link.updatedAt ?? null
    }
  });
}

// This function handles linkwarden_list_collections with paging controls.
async function handleListCollections(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listCollectionsSchema.parse(args);
  const client = getClient(context);

  if (input.limit === undefined) {
    // This branch returns every collection when no explicit limit is provided.
    const items = await client.listAllCollections();
    const offsetItems = items.slice(input.offset);
    return mcpResult({
      collections: offsetItems,
      paging: {
        limit: null,
        offset: input.offset,
        returned: offsetItems.length,
        total: items.length
      }
    });
  }

  // This branch keeps explicit paging behavior when the caller provides a concrete limit.
  const result = await client.listCollections({
    limit: input.limit,
    offset: input.offset
  });

  return mcpResult({
    collections: result.items,
    paging: {
      limit: input.limit,
      offset: input.offset,
      returned: result.items.length,
      total: result.total
    }
  });
}

// This function creates one collection and optionally nests it under a parent collection.
async function handleCreateCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createCollectionSchema.parse(args);
  assertWriteAccess(context);

  const client = getClient(context);
  if (typeof input.parentId === 'number') {
    const collections = await client.listAllCollections();
    const parentExists = collections.some((collection) => collection.id === input.parentId);
    if (!parentExists) {
      throw new AppError(404, 'collection_not_found', `Parent collection ${input.parentId} was not found.`);
    }
  }

  const created = await client.createCollection({
    name: input.name,
    parentId: input.parentId
  });

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_create_collection',
    targetType: 'collection',
    targetIds: [created.id],
    beforeSummary: 'collection missing',
    afterSummary: JSON.stringify({
      id: created.id,
      name: created.name,
      parentId: created.parentId ?? null
    }),
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    created: true,
    collection: created
  });
}

// This function renames or moves one collection by id.
async function handleUpdateCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = updateCollectionSchema.parse(args);
  assertWriteAccess(context);

  if (input.updates.parentId === input.id) {
    throw new AppError(400, 'validation_error', 'A collection cannot be moved under itself.');
  }

  const client = getClient(context);
  const allCollections = await client.listAllCollections();
  const existing = allCollections.find((collection) => collection.id === input.id);
  if (!existing) {
    throw new AppError(404, 'collection_not_found', `Collection ${input.id} was not found.`);
  }

  if (typeof input.updates.parentId === 'number') {
    const parentExists = allCollections.some((collection) => collection.id === input.updates.parentId);
    if (!parentExists) {
      throw new AppError(404, 'collection_not_found', `Parent collection ${input.updates.parentId} was not found.`);
    }
  }

  const updated = await client.updateCollection(input.id, {
    name: input.updates.name,
    parentId: input.updates.parentId
  });

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_update_collection',
    targetType: 'collection',
    targetIds: [input.id],
    beforeSummary: JSON.stringify({
      name: existing.name,
      parentId: existing.parentId ?? null
    }),
    afterSummary: JSON.stringify({
      name: updated.name,
      parentId: updated.parentId ?? null
    }),
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    updated: true,
    collection: updated
  });
}

// This function deletes one collection by id.
async function handleDeleteCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteCollectionSchema.parse(args);
  assertWriteAccess(context);

  const client = getClient(context);
  const allCollections = await client.listAllCollections();
  const existing = allCollections.find((collection) => collection.id === input.id);
  if (!existing) {
    throw new AppError(404, 'collection_not_found', `Collection ${input.id} was not found.`);
  }

  await client.deleteCollection(input.id);

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_delete_collection',
    targetType: 'collection',
    targetIds: [input.id],
    beforeSummary: JSON.stringify({
      id: existing.id,
      name: existing.name,
      parentId: existing.parentId ?? null
    }),
    afterSummary: 'collection deleted',
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    deleted: true,
    collection: existing
  });
}

// This function handles linkwarden_list_tags with paging controls.
async function handleListTags(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listTagsSchema.parse(args);
  const client = getClient(context);

  if (input.limit === undefined) {
    // This branch returns every tag when no explicit limit is provided.
    const items = await client.listAllTags();
    const offsetItems = items.slice(input.offset);
    return mcpResult({
      tags: offsetItems,
      paging: {
        limit: null,
        offset: input.offset,
        returned: offsetItems.length,
        total: items.length
      }
    });
  }

  // This branch keeps explicit paging behavior when the caller provides a concrete limit.
  const result = await client.listTags({
    limit: input.limit,
    offset: input.offset
  });

  return mcpResult({
    tags: result.items,
    paging: {
      limit: input.limit,
      offset: input.offset,
      returned: result.items.length,
      total: result.total
    }
  });
}

// This function handles linkwarden_create_tag with idempotent normalized-name behavior.
async function handleCreateTag(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = createTagSchema.parse(args);
  assertWriteAccess(context);

  const client = getClient(context);
  const allTags = await client.listAllTags();
  const normalizedInput = normalizeTagName(input.name);
  const existing = allTags.find((tag) => normalizeTagName(tag.name) === normalizedInput);

  if (existing) {
    return mcpResult({
      created: false,
      tag: existing
    });
  }

  const created = await client.createTag(input.name.trim());
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_create_tag',
    targetType: 'tag',
    targetIds: [created.id],
    beforeSummary: 'tag missing',
    afterSummary: JSON.stringify({
      id: created.id,
      name: created.name
    }),
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    created: true,
    tag: created
  });
}

// This function handles linkwarden_delete_tag by id with strict existence checks.
async function handleDeleteTag(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = deleteTagSchema.parse(args);
  assertWriteAccess(context);

  const client = getClient(context);
  const allTags = await client.listAllTags();
  const existing = allTags.find((tag) => tag.id === input.id);
  if (!existing) {
    throw new AppError(404, 'tag_not_found', `Tag ${input.id} was not found.`);
  }

  await client.deleteTag(input.id);
  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_delete_tag',
    targetType: 'tag',
    targetIds: [input.id],
    beforeSummary: JSON.stringify({
      id: existing.id,
      name: existing.name
    }),
    afterSummary: 'tag deleted',
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    deleted: true,
    tag: existing
  });
}

// This function handles name-based tag assignment with optional auto-creation for missing tags.
async function handleAssignTags(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = assignTagsSchema.parse(args);
  if (!input.dryRun) {
    assertWriteAccess(context);
  }

  const client = getClient(context);
  const requestedTagNames = dedupeTagNames(input.tagNames);
  const tagsBefore = await client.listAllTags();
  const tagsByNormalizedName = new Map<string, LinkTag>(
    tagsBefore.map((tag) => [normalizeTagName(tag.name), tag])
  );

  const existingResolvedTags: LinkTag[] = [];
  const missingTagNames: string[] = [];
  for (const name of requestedTagNames) {
    const existing = tagsByNormalizedName.get(normalizeTagName(name));
    if (existing) {
      existingResolvedTags.push(existing);
    } else {
      missingTagNames.push(name);
    }
  }

  // This branch avoids unnecessary tag creation for remove mode because unknown tags cannot be removed.
  const missingRelevantForWrite = input.mode === 'remove' ? [] : missingTagNames;
  if (!input.dryRun && missingRelevantForWrite.length > 0 && !input.createMissingTags) {
    throw new AppError(
      400,
      'validation_error',
      `Missing tags cannot be assigned without createMissingTags=true: ${missingRelevantForWrite.join(', ')}`
    );
  }

  const createdTags: LinkTag[] = [];
  if (!input.dryRun && input.createMissingTags) {
    for (const missingName of missingRelevantForWrite) {
      const created = await client.createTag(missingName);
      createdTags.push(created);
      tagsByNormalizedName.set(normalizeTagName(created.name), created);
    }
  }

  const selectedTags = [...existingResolvedTags, ...createdTags];
  const selectedTagIds = normalizeTagIds(selectedTags.map((tag) => tag.id));
  const knownTagNamesById = new Map<number, string>();
  for (const tag of tagsBefore) {
    knownTagNamesById.set(tag.id, tag.name);
  }
  for (const tag of createdTags) {
    knownTagNamesById.set(tag.id, tag.name);
  }

  const links = await Promise.all(input.linkIds.map((linkId) => client.getLink(linkId)));
  const preview = links.map((link) => {
    const currentTagIds = normalizeTagIds(link.tags.map((tag) => tag.id));
    const nextTagIds = computeBulkTagResult(currentTagIds, selectedTagIds, input.mode);

    return {
      linkId: link.id,
      before: {
        tagIds: currentTagIds,
        tagNames: mapTagIdsToNames(currentTagIds, knownTagNamesById)
      },
      after: {
        tagIds: nextTagIds,
        tagNames: mapTagIdsToNames(nextTagIds, knownTagNamesById)
      }
    };
  });

  if (input.dryRun) {
    return mcpResult({
      dryRun: true,
      mode: input.mode,
      summary: {
        total: input.linkIds.length,
        changes: preview.filter((item) => JSON.stringify(item.before.tagIds) !== JSON.stringify(item.after.tagIds)).length,
        existingResolvedTags: existingResolvedTags.length,
        missingTags: missingRelevantForWrite.length,
        wouldCreateTags: input.createMissingTags ? missingRelevantForWrite.length : 0
      },
      requestedTagNames,
      existingTags: existingResolvedTags,
      missingTags: missingRelevantForWrite,
      preview: preview.slice(0, input.previewLimit)
    });
  }

  const failures: Array<{ linkId: number; message: string }> = [];
  let applied = 0;

  for (const item of preview) {
    try {
      await client.updateLink(item.linkId, { tagIds: item.after.tagIds });
      applied += 1;
    } catch (error) {
      failures.push({
        linkId: item.linkId,
        message: error instanceof Error ? error.message : 'tag assignment failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_assign_tags',
    targetType: 'link',
    targetIds: input.linkIds,
    beforeSummary: 'tag assignment preview snapshot',
    afterSummary: JSON.stringify({
      mode: input.mode,
      requestedTagNames,
      selectedTagIds,
      createdTagIds: createdTags.map((tag) => tag.id)
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      applied,
      failures: failures.length
    })
  });

  return mcpResult({
    dryRun: false,
    mode: input.mode,
    requestedTagNames,
    createdTags,
    applied,
    failures,
    preview: preview.slice(0, input.previewLimit)
  });
}

// This function handles linkwarden_get_link and returns bounded details for one link id.
async function handleGetLink(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = getLinkSchema.parse(args);
  const client = getClient(context);
  const link = await client.getLink(input.id);

  return mcpResult({
    link
  });
}

// This helper creates scope-limited link sets for planning operations.
async function loadScopeLinks(context: ToolRuntimeContext, scope: PlanScope | undefined): Promise<LinkItem[]> {
  const client = getClient(context);
  return client.loadLinksForScope(scope);
}

// This function handles linkwarden_plan_reorg by persisting a dry-run plan with preview and warnings.
async function handlePlanReorg(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = planReorgSchema.parse(args);
  context.logger.info(
    {
      event: 'tool_plan_reorg_started',
      strategy: input.strategy,
      previewLimit: input.previewLimit,
      scope: sanitizeForLog(input.scope)
    },
    'tool_plan_reorg_started'
  );

  const links = await loadScopeLinks(context, input.scope);
  const computation = computeReorgPlan(input.strategy, input.parameters, links);
  const ttlHours = context.configStore.getRuntimeConfig().planTtlHours;
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
  const planId = randomUUID();

  context.db.createPlan({
    planId,
    strategy: input.strategy,
    parameters: input.parameters,
    scope: input.scope,
    summary: computation.summary,
    warnings: computation.warnings,
    items: computation.items,
    createdBy: context.actor,
    expiresAt
  });

  context.logger.info(
    {
      event: 'tool_plan_reorg_created',
      planId,
      expiresAt,
      scanned: computation.summary.scanned,
      changes: computation.summary.changes,
      warnings: computation.warnings.length
    },
    'tool_plan_reorg_created'
  );

  return mcpResult({
    plan_id: planId,
    expires_at: expiresAt,
    summary: computation.summary,
    warnings: computation.warnings,
    preview: computation.items.slice(0, input.previewLimit)
  });
}

// This function handles linkwarden_apply_plan with confirm gate, expiry checks, and write auditing.
async function handleApplyPlan(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = applyPlanSchema.parse(args);
  assertWriteAccess(context);
  context.logger.info(
    {
      event: 'tool_apply_plan_started',
      planId: input.plan_id,
      actor: context.actor
    },
    'tool_apply_plan_started'
  );

  const planData = context.db.getPlanWithItems(input.plan_id);
  if (!planData) {
    context.logger.warn(
      {
        event: 'tool_apply_plan_not_found',
        planId: input.plan_id
      },
      'tool_apply_plan_not_found'
    );
    throw new AppError(404, 'plan_not_found', `Plan ${input.plan_id} not found.`);
  }

  if (planData.plan.status !== 'draft') {
    context.logger.warn(
      {
        event: 'tool_apply_plan_invalid_status',
        planId: input.plan_id,
        status: planData.plan.status
      },
      'tool_apply_plan_invalid_status'
    );
    throw new AppError(409, 'plan_not_applicable', `Plan status is ${planData.plan.status}, expected draft.`);
  }

  if (new Date(planData.plan.expiresAt).getTime() < Date.now()) {
    context.db.updatePlanStatus(input.plan_id, 'expired');
    context.logger.warn(
      {
        event: 'tool_apply_plan_expired',
        planId: input.plan_id,
        expiresAt: planData.plan.expiresAt
      },
      'tool_apply_plan_expired'
    );
    throw new AppError(409, 'plan_expired', 'Plan is expired and can no longer be applied.');
  }

  const client = getClient(context);
  const runId = context.db.createPlanRun(input.plan_id);
  const failures: Array<{ linkId: number; message: string }> = [];
  let applied = 0;

  try {
    const grouped = new Map<string, { linkIds: number[]; tagIds?: number[]; collectionId?: number | null }>();

    for (const item of planData.items) {
      const after = readAfterState(item);
      const key = JSON.stringify(after);
      const group = grouped.get(key) ?? {
        linkIds: [],
        tagIds: after.tagIds,
        collectionId: after.collectionId
      };
      group.linkIds.push(item.linkId);
      grouped.set(key, group);
    }

    for (const [, group] of grouped) {
      const updates: Record<string, unknown> = {};
      if (group.tagIds) {
        updates.tagIds = group.tagIds;
      }
      if (group.collectionId !== undefined) {
        updates.collectionId = group.collectionId;
      }

      // This guard ensures native update calls are only sent for groups with real write fields.
      if (Object.keys(updates).length === 0) {
        continue;
      }

      for (const linkId of group.linkIds) {
        try {
          await client.updateLink(linkId, updates);
          applied += 1;

          context.db.insertAudit({
            actor: context.actor,
            toolName: 'linkwarden_apply_plan',
            targetType: 'link',
            targetIds: [linkId],
            beforeSummary: 'plan-item-snapshot',
            afterSummary: JSON.stringify(updates),
            outcome: 'success',
            details: withActorDetails(context, {
              planId: input.plan_id,
              mode: 'native-single-update'
            })
          });
        } catch (error) {
          failures.push({
            linkId,
            message: error instanceof Error ? error.message : 'link update failed'
          });

          context.db.insertAudit({
            actor: context.actor,
            toolName: 'linkwarden_apply_plan',
            targetType: 'link',
            targetIds: [linkId],
            beforeSummary: 'plan-item-snapshot',
            afterSummary: 'single patch failed',
            outcome: 'failed',
            details: withActorDetails(context, {
              planId: input.plan_id,
              mode: 'native-single-update',
              error: error instanceof Error ? error.message : 'unknown'
            })
          });
        }
      }
    }

    if (failures.length === 0) {
      context.db.updatePlanStatus(input.plan_id, 'applied');
      context.db.finishPlanRun(runId, 'success', { applied, failures: [] });
    } else {
      context.db.updatePlanStatus(input.plan_id, 'failed');
      context.db.finishPlanRun(runId, 'failed', { applied, failures });
    }

    context.logger.info(
      {
        event: 'tool_apply_plan_completed',
        planId: input.plan_id,
        applied,
        failures: failures.length
      },
      'tool_apply_plan_completed'
    );

    return mcpResult({
      plan_id: input.plan_id,
      applied,
      failures
    });
  } catch (error) {
    context.db.finishPlanRun(runId, 'failed', {
      applied,
      failures,
      fatalError: error instanceof Error ? error.message : 'unknown'
    });

    context.logger.error(
      {
        event: 'tool_apply_plan_failed',
        planId: input.plan_id,
        applied,
        failures: failures.length,
        error: errorForLog(error)
      },
      'tool_apply_plan_failed'
    );

    throw error;
  }
}

// This function handles linkwarden_update_link with write mode guard and audit logging.
async function handleUpdateLink(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = updateLinkSchema.parse(args);
  assertWriteAccess(context);

  const client = getClient(context);
  const before = await client.getLink(input.id);
  const updates = {
    ...input.updates,
    tagIds: input.updates.tagIds ? normalizeTagIds(input.updates.tagIds) : input.updates.tagIds
  };

  const updated = await client.updateLink(input.id, updates);

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_update_link',
    targetType: 'link',
    targetIds: [input.id],
    beforeSummary: JSON.stringify({
      title: before.title,
      collectionId: before.collection?.id ?? null,
      tagIds: before.tags.map((tag) => tag.id)
    }),
    afterSummary: JSON.stringify({
      title: updated.title,
      collectionId: updated.collection?.id ?? null,
      tagIds: updated.tags.map((tag) => tag.id)
    }),
    outcome: 'success',
    details: withActorDetails(context)
  });

  return mcpResult({
    updated: {
      id: updated.id,
      title: updated.title,
      url: updated.url,
      collection: updated.collection,
      tags: updated.tags,
      archived: updated.archived,
      pinned: updated.pinned,
      updatedAt: updated.updatedAt
    }
  });
}

// This function assigns or clears one collection for multiple links with deterministic preview support.
async function handleSetLinksCollection(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = setLinksCollectionSchema.parse(args);
  const client = getClient(context);
  if (typeof input.collectionId === 'number') {
    const collections = await client.listAllCollections();
    const targetExists = collections.some((collection) => collection.id === input.collectionId);
    if (!targetExists) {
      throw new AppError(404, 'collection_not_found', `Collection ${input.collectionId} was not found.`);
    }
  }
  const links = await Promise.all(input.linkIds.map((linkId) => client.getLink(linkId)));
  const preview = links.map((link) => ({
    linkId: link.id,
    before: {
      collectionId: link.collection?.id ?? null
    },
    after: {
      collectionId: input.collectionId
    }
  }));
  const changes = preview.filter((item) => item.before.collectionId !== item.after.collectionId);

  if (input.dryRun) {
    return mcpResult({
      dryRun: true,
      summary: {
        total: input.linkIds.length,
        changes: changes.length
      },
      preview: preview.slice(0, input.previewLimit)
    });
  }

  assertWriteAccess(context);

  let applied = 0;
  const failures: Array<{ linkId: number; message: string }> = [];
  for (const change of changes) {
    try {
      await client.updateLink(change.linkId, {
        collectionId: input.collectionId
      });
      applied += 1;
    } catch (error) {
      failures.push({
        linkId: change.linkId,
        message: error instanceof Error ? error.message : 'collection update failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_set_links_collection',
    targetType: 'link',
    targetIds: input.linkIds,
    beforeSummary: 'collection assignment preview snapshot',
    afterSummary: JSON.stringify({
      collectionId: input.collectionId,
      requested: input.linkIds.length,
      changed: changes.length
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      applied,
      failures: failures.length
    })
  });

  return mcpResult({
    dryRun: false,
    summary: {
      total: input.linkIds.length,
      changes: changes.length,
      applied,
      failures: failures.length
    },
    failures
  });
}

// This function pins or unpins multiple links using Linkwarden's native pinnedBy relation semantics.
async function handleSetLinksPinned(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = setLinksPinnedSchema.parse(args);
  const client = getClient(context);
  const links = await Promise.all(input.linkIds.map((linkId) => client.getLink(linkId)));
  const preview = links.map((link) => ({
    linkId: link.id,
    before: {
      pinned: Boolean(link.pinned)
    },
    after: {
      pinned: input.pinned
    }
  }));
  const changes = preview.filter((item) => item.before.pinned !== item.after.pinned);

  if (input.dryRun) {
    return mcpResult({
      dryRun: true,
      summary: {
        total: input.linkIds.length,
        changes: changes.length,
        pinned: input.pinned
      },
      preview: preview.slice(0, input.previewLimit)
    });
  }

  assertWriteAccess(context);

  let applied = 0;
  const failures: Array<{ linkId: number; message: string }> = [];
  for (const change of changes) {
    try {
      await client.setLinkPinned(change.linkId, input.pinned);
      applied += 1;
    } catch (error) {
      failures.push({
        linkId: change.linkId,
        message: error instanceof Error ? error.message : 'pin update failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_set_links_pinned',
    targetType: 'link',
    targetIds: input.linkIds,
    beforeSummary: 'pin assignment preview snapshot',
    afterSummary: JSON.stringify({
      pinned: input.pinned,
      requested: input.linkIds.length,
      changed: changes.length
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      applied,
      failures: failures.length
    })
  });

  return mcpResult({
    dryRun: false,
    summary: {
      total: input.linkIds.length,
      changes: changes.length,
      applied,
      failures: failures.length,
      pinned: input.pinned
    },
    failures
  });
}

// This function handles linkwarden_bulk_update_links with dry-run preview and optional apply.
async function handleBulkUpdate(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = bulkUpdateSchema.parse(args);
  context.logger.info(
    {
      event: 'tool_bulk_update_started',
      dryRun: input.dryRun,
      mode: input.mode,
      linkCount: input.linkIds.length
    },
    'tool_bulk_update_started'
  );
  const client = getClient(context);

  const sampledLinks = await Promise.all(input.linkIds.map((linkId) => client.getLink(linkId)));

  const preview = sampledLinks.map((link) => {
    const currentTags = link.tags.map((tag) => tag.id);
    const nextTags = computeBulkTagResult(currentTags, input.updates.tagIds, input.mode);
    const hasCollectionUpdate = Object.prototype.hasOwnProperty.call(input.updates, 'collectionId');

    return {
      linkId: link.id,
      before: {
        collectionId: link.collection?.id ?? null,
        tagIds: currentTags
      },
      after: {
        collectionId: hasCollectionUpdate ? input.updates.collectionId ?? null : link.collection?.id ?? null,
        tagIds: nextTags
      }
    };
  });

  if (input.dryRun) {
    context.logger.info(
      {
        event: 'tool_bulk_update_dry_run_completed',
        linkCount: input.linkIds.length,
        previewCount: preview.length
      },
      'tool_bulk_update_dry_run_completed'
    );
    return mcpResult({
      dryRun: true,
      summary: {
        total: input.linkIds.length,
        changes: preview.length
      },
      preview: preview.slice(0, input.previewLimit)
    });
  }

  assertWriteAccess(context);

  const failures: Array<{ linkId: number; message: string }> = [];
  let applied = 0;

  for (const link of sampledLinks) {
    const currentTags = link.tags.map((tag) => tag.id);
    const nextTags = computeBulkTagResult(currentTags, input.updates.tagIds, input.mode);
    const updates: Record<string, unknown> = {};
    const hasCollectionUpdate = Object.prototype.hasOwnProperty.call(input.updates, 'collectionId');

    // This condition keeps native writes collection-neutral when callers do not request collection changes.
    if (hasCollectionUpdate) {
      updates.collectionId = input.updates.collectionId ?? null;
    }

    // This condition keeps native writes tag-neutral when callers only change collections.
    if (input.updates.tagIds) {
      updates.tagIds = nextTags;
    }

    try {
      await client.updateLink(link.id, updates);
      applied += 1;
    } catch (error) {
      failures.push({
        linkId: link.id,
        message: error instanceof Error ? error.message : 'update failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_bulk_update_links',
    targetType: 'link',
    targetIds: input.linkIds,
    beforeSummary: 'bulk preview snapshot',
    afterSummary: JSON.stringify({
      mode: input.mode,
      updates: input.updates
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      applied,
      failuresCount: failures.length
    })
  });

  return mcpResult({
    dryRun: false,
    applied,
    failures
  });
}

// This function removes tracking parameters from URLs and can apply cleaned URLs back to Linkwarden.
async function handleCleanLinkUrls(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = cleanLinkUrlsSchema.parse(args);
  const client = getClient(context);
  const resolvedLinks = await Promise.all(
    input.linkIds.map(async (linkId) => {
      try {
        const link = await client.getLink(linkId);
        return {
          linkId,
          link,
          error: null as string | null
        };
      } catch (error) {
        return {
          linkId,
          link: null as LinkItem | null,
          error: error instanceof Error ? error.message : 'link lookup failed'
        };
      }
    })
  );

  const accessibleLinks = resolvedLinks
    .filter((item): item is { linkId: number; link: LinkItem; error: null } => item.link !== null)
    .map((item) => item.link);
  const skipped = resolvedLinks
    .filter((item) => item.link === null)
    .map((item) => ({
      linkId: item.linkId,
      message: item.error ?? 'link lookup failed'
    }));

  const preview = accessibleLinks.map((link) => {
    try {
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
        removedParams: cleaned.removedParams,
        error: null as string | null
      };
    } catch (error) {
      return {
        linkId: link.id,
        beforeUrl: link.url,
        afterUrl: link.url,
        changed: false,
        removedParams: [] as string[],
        error: error instanceof Error ? error.message : 'invalid url'
      };
    }
  });

  const changed = preview.filter((item) => item.changed && item.error === null);
  const invalid = preview.filter((item) => item.error !== null);

  if (input.dryRun) {
    return mcpResult({
      dryRun: true,
      summary: {
        total: input.linkIds.length,
        accessible: accessibleLinks.length,
        changed: changed.length,
        invalid: invalid.length,
        skipped: skipped.length
      },
      preview: preview.slice(0, input.previewLimit),
      skipped
    });
  }

  assertWriteAccess(context);

  let applied = 0;
  const failures: Array<{ linkId: number; message: string }> = [];
  for (const item of changed) {
    try {
      await client.updateLink(item.linkId, {
        url: item.afterUrl
      });
      applied += 1;
    } catch (error) {
      failures.push({
        linkId: item.linkId,
        message: error instanceof Error ? error.message : 'url update failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_clean_link_urls',
    targetType: 'link',
    targetIds: input.linkIds,
    beforeSummary: 'url cleanup preview snapshot',
    afterSummary: JSON.stringify({
      removeUtm: input.removeUtm,
      removeKnownTracking: input.removeKnownTracking,
      keepParams: input.keepParams,
      extraTrackingParams: input.extraTrackingParams
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      accessible: accessibleLinks.length,
      changed: changed.length,
      applied,
      invalid: invalid.length,
      failures: failures.length,
      skipped: skipped.length
    })
  });

  return mcpResult({
    dryRun: false,
    summary: {
      total: input.linkIds.length,
      accessible: accessibleLinks.length,
      changed: changed.length,
      applied,
      invalid: invalid.length,
      failures: failures.length,
      skipped: skipped.length
    },
    failures,
    skipped,
    preview: preview.slice(0, input.previewLimit)
  });
}

// This function handles linkwarden_suggest_taxonomy as a pure analysis feature without writes.
async function handleSuggestTaxonomy(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = suggestTaxonomySchema.parse(args);
  const client = getClient(context);
  const links = await client.loadLinksForScope({ query: input.query }, 100);
  // This optional limit allows either full-corpus analysis or bounded sampling.
  const subset = typeof input.limit === 'number' ? links.slice(0, input.limit) : links;
  const stopwords = new Set(['https', 'http', 'www', 'com', 'net', 'org', 'und', 'der', 'die', 'das']);
  const counts = new Map<string, number>();

  for (const link of subset) {
    const text = `${link.title} ${link.description ?? ''}`.toLowerCase();
    const words = text
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .map((word) => word.trim())
      .filter((word) => word.length >= 4 && !stopwords.has(word));

    for (const word of words) {
      counts.set(word, (counts.get(word) ?? 0) + 1);
    }
  }

  const suggestedTags = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 15)
    .map(([keyword, frequency]) => ({ keyword, frequency }));

  return mcpResult({
    analyzedLinks: subset.length,
    suggestedTags,
    note: 'This analysis is read-only and does not modify Linkwarden data.'
  });
}

// This function extracts URLs from chat text and stores them under ChatGPT Chats > Chat Name.
async function handleCaptureChatLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = captureChatLinksSchema.parse(args);
  // This fallback keeps extraction unlimited when maxLinks is not provided by the caller.
  const urls = extractUrlsFromText(input.text, input.maxLinks ?? Number.POSITIVE_INFINITY);
  const client = getClient(context);
  const collections = await client.listAllCollections();
  const parent = findCollectionByNameAndParent(collections, input.parentCollectionName, null);
  const child = parent ? findCollectionByNameAndParent(collections, input.chatName, parent.id) : undefined;

  if (urls.length === 0) {
    return mcpResult({
      dryRun: input.dryRun,
      summary: {
        extracted: 0,
        created: 0,
        skippedDuplicate: 0,
        failed: 0
      },
      target: {
        parentCollectionName: input.parentCollectionName,
        chatName: input.chatName,
        parentCollectionId: parent?.id ?? null,
        collectionId: child?.id ?? null
      }
    });
  }

  if (input.dryRun) {
    return mcpResult({
      dryRun: true,
      summary: {
        extracted: urls.length,
        created: 0,
        skippedDuplicate: 0,
        failed: 0
      },
      target: {
        parentCollectionName: input.parentCollectionName,
        chatName: input.chatName,
        parentCollectionId: parent?.id ?? null,
        collectionId: child?.id ?? null,
        willCreateParent: !parent,
        willCreateChild: !child
      },
      previewUrls: urls
    });
  }

  assertWriteAccess(context);

  const path = await ensureCollectionPath(client, input.parentCollectionName, input.chatName);
  const targetCollectionId = path.child.id;
  const existingInCollection = input.dedupeByUrl ? await client.listLinksByCollection(targetCollectionId) : [];
  const existingUrlSet = new Set(existingInCollection.map((link) => normalizeUrl(link.url)));
  const created: Array<{ id: number; url: string; title: string }> = [];
  const skipped: string[] = [];
  const failed: Array<{ url: string; message: string }> = [];

  for (const url of urls) {
    const normalized = normalizeUrl(url);
    if (input.dedupeByUrl && existingUrlSet.has(normalized)) {
      skipped.push(url);
      continue;
    }

    try {
      const createdLink = await client.createLink({
        url,
        title: url,
        collectionId: targetCollectionId
      });

      created.push({
        id: createdLink.id,
        url: createdLink.url,
        title: createdLink.title
      });
      existingUrlSet.add(normalized);
    } catch (error) {
      failed.push({
        url,
        message: error instanceof Error ? error.message : 'create failed'
      });
    }
  }

  if (created.length > 0) {
    context.db.insertAudit({
      actor: context.actor,
      toolName: 'linkwarden_capture_chat_links',
      targetType: 'link',
      targetIds: created.map((item) => item.id),
      beforeSummary: 'chat link extraction',
      afterSummary: JSON.stringify({
        collectionId: targetCollectionId,
        created: created.length,
        skipped: skipped.length
      }),
      outcome: failed.length === 0 ? 'success' : 'failed',
      details: withActorDetails(context, {
        parentCollectionId: path.parent.id,
        collectionId: targetCollectionId,
        createdCollections: path.created.map((collection) => collection.id),
        failed
      })
    });
  }

  return mcpResult({
    dryRun: false,
    target: {
      parentCollectionId: path.parent.id,
      collectionId: targetCollectionId,
      parentCollectionName: path.parent.name,
      chatName: path.child.name,
      createdCollections: path.created
    },
    summary: {
      extracted: urls.length,
      created: created.length,
      skippedDuplicate: skipped.length,
      failed: failed.length
    },
    created,
    failed
  });
}

// This function monitors link availability and applies per-user archive/delete policy when links stay offline.
async function handleMonitorOfflineLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = monitorOfflineLinksSchema.parse(args);
  const client = getClient(context);
  const settings = context.db.getUserSettings(context.principal.userId);
  const resolvedOfflineDays = input.offlineDays ?? settings.offlineDays;
  const resolvedMinConsecutiveFailures = input.minConsecutiveFailures ?? settings.offlineMinConsecutiveFailures;
  const resolvedAction = input.action ?? settings.offlineAction;
  const resolvedArchiveCollectionId = input.archiveCollectionId ?? settings.offlineArchiveCollectionId ?? undefined;
  const loaded = await client.loadLinksForScopeDetailed(input.scope, 100);
  const links = loaded.items;
  // This paging window applies offset first so callers can scan the full corpus deterministically page by page.
  const pagedLinks = links.slice(input.offset);
  // This optional limit allows full scans by default while still supporting explicit bounded probes.
  const sample = typeof input.limit === 'number' ? pagedLinks.slice(0, input.limit) : pagedLinks;
  const previousStates = context.db.listLinkHealthStates(
    context.principal.userId,
    sample.map((link) => link.id)
  );
  const previousByLinkId = new Map<number, LinkHealthState>(previousStates.map((state) => [state.linkId, state]));
  const now = Date.now();
  const offlineThresholdMs = resolvedOfflineDays * 24 * 60 * 60 * 1000;
  const checked: Array<{
    linkId: number;
    url: string;
    status: 'up' | 'down';
    httpStatus: number | null;
    consecutiveFailures: number;
    firstFailureAt: string | null;
    eligibleForAction: boolean;
    error: string | null;
  }> = [];

  for (const link of sample) {
    const probe = await checkLinkAvailability(link.url, input.timeoutMs);
    const checkedAtIso = new Date().toISOString();
    const nextState = computeNextHealthState(
      context.principal.userId,
      link,
      previousByLinkId.get(link.id),
      probe,
      checkedAtIso
    );

    context.db.upsertLinkHealthState(nextState);
    previousByLinkId.set(link.id, nextState);

    const isEligible =
      nextState.lastStatus === 'down' &&
      nextState.firstFailureAt !== null &&
      now - new Date(nextState.firstFailureAt).getTime() >= offlineThresholdMs &&
      nextState.consecutiveFailures >= resolvedMinConsecutiveFailures &&
      nextState.archivedAt === null;

    checked.push({
      linkId: link.id,
      url: link.url,
      status: nextState.lastStatus,
      httpStatus: nextState.lastHttpStatus,
      consecutiveFailures: nextState.consecutiveFailures,
      firstFailureAt: nextState.firstFailureAt,
      eligibleForAction: isEligible,
      error: nextState.lastError
    });
  }

  const eligibleLinkIds = checked.filter((item) => item.eligibleForAction).map((item) => item.linkId);

  if (input.dryRun) {
    const payload: Record<string, unknown> = {
      dryRun: true,
      summary: {
        scanned: sample.length,
        up: checked.filter((item) => item.status === 'up').length,
        down: checked.filter((item) => item.status === 'down').length,
        eligibleForAction: eligibleLinkIds.length
      },
      policy: {
        offlineDays: resolvedOfflineDays,
        minConsecutiveFailures: resolvedMinConsecutiveFailures,
        action: resolvedAction,
        archiveCollectionId: resolvedArchiveCollectionId ?? null
      },
      paging: {
        offset: input.offset,
        limit: input.limit ?? null,
        totalMatched: links.length
      },
      eligibleLinkIds,
      checked
    };

    // This optional debug branch exposes scope-loading diagnostics for paging investigations.
    if (input.debug) {
      payload.debug = {
        scopeLoad: loaded.diagnostics,
        scopeWarning: loaded.warning ?? null
      };
    }

    return mcpResult(payload);
  }

  assertWriteAccess(context);
  if (resolvedAction === 'archive' && !resolvedArchiveCollectionId) {
    throw new AppError(
      400,
      'validation_error',
      'archiveCollectionId is required when policy action is archive and dryRun=false.'
    );
  }

  if (eligibleLinkIds.length === 0 || resolvedAction === 'none') {
    const payload: Record<string, unknown> = {
      dryRun: false,
      summary: {
        scanned: sample.length,
        up: checked.filter((item) => item.status === 'up').length,
        down: checked.filter((item) => item.status === 'down').length,
        action: resolvedAction,
        processed: 0,
        failures: 0
      },
      paging: {
        offset: input.offset,
        limit: input.limit ?? null,
        totalMatched: links.length
      },
      processedLinkIds: [],
      failures: []
    };

    // This optional debug branch exposes scope-loading diagnostics for paging investigations.
    if (input.debug) {
      payload.debug = {
        scopeLoad: loaded.diagnostics,
        scopeWarning: loaded.warning ?? null
      };
    }

    return mcpResult(payload);
  }

  const processedLinkIds: number[] = [];
  const failures: Array<{ linkId: number; message: string }> = [];

  for (const linkId of eligibleLinkIds) {
    try {
      if (resolvedAction === 'archive') {
        await client.updateLink(linkId, { collectionId: resolvedArchiveCollectionId });
      } else if (resolvedAction === 'delete') {
        await client.deleteLink(linkId);
      }

      context.db.markLinkHealthArchived(context.principal.userId, linkId);
      processedLinkIds.push(linkId);
    } catch (error) {
      failures.push({
        linkId,
        message: error instanceof Error ? error.message : 'offline action failed'
      });
    }
  }

  context.db.insertAudit({
    actor: context.actor,
    toolName: 'linkwarden_monitor_offline_links',
    targetType: 'link',
    targetIds: eligibleLinkIds,
    beforeSummary: 'offline monitor snapshot',
    afterSummary: JSON.stringify({
      action: resolvedAction,
      archiveCollectionId: resolvedArchiveCollectionId ?? null,
      processed: processedLinkIds.length,
      failures: failures.length
    }),
    outcome: failures.length === 0 ? 'success' : 'failed',
    details: withActorDetails(context, {
      offlineDays: resolvedOfflineDays,
      minConsecutiveFailures: resolvedMinConsecutiveFailures
    })
  });

  const payload: Record<string, unknown> = {
    dryRun: false,
      summary: {
        scanned: sample.length,
        up: checked.filter((item) => item.status === 'up').length,
        down: checked.filter((item) => item.status === 'down').length,
        action: resolvedAction,
        processed: processedLinkIds.length,
        failures: failures.length
      },
      paging: {
        offset: input.offset,
        limit: input.limit ?? null,
        totalMatched: links.length
      },
      processedLinkIds,
      failures
    };

  // This optional debug branch exposes scope-loading diagnostics for paging investigations.
  if (input.debug) {
    payload.debug = {
      scopeLoad: loaded.diagnostics,
      scopeWarning: loaded.warning ?? null
    };
  }

  return mcpResult(payload);
}

// This function orchestrates daily maintenance as one flow (reorg + offline monitor) with safe apply gating.
async function handleRunDailyMaintenance(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = runDailyMaintenanceSchema.parse(args);
  if (!input.reorg && !input.offline) {
    throw new AppError(
      400,
      'validation_error',
      'At least one section is required: reorg and/or offline for linkwarden_run_daily_maintenance.'
    );
  }

  if (input.apply && input.confirm !== 'APPLY') {
    throw new AppError(
      400,
      'validation_error',
      'confirm=APPLY is required when apply=true for linkwarden_run_daily_maintenance.'
    );
  }

  if (input.apply) {
    assertWriteAccess(context);
  }
  const lockToken = randomUUID();
  const lockAcquired = context.db.acquireMaintenanceLock(context.principal.userId, lockToken, 1800);
  if (!lockAcquired) {
    const activeLock = context.db.getActiveMaintenanceLock(context.principal.userId);
    throw new AppError(
      409,
      'maintenance_locked',
      `A maintenance run is already active for this user until ${activeLock?.expiresAt ?? 'unknown'}.`
    );
  }

  let runId: number | null = null;
  const mode: 'dry_run' | 'apply' = input.apply ? 'apply' : 'dry_run';
  const result: Record<string, unknown> = {
    dryRun: !input.apply,
    steps: [] as string[]
  };
  const steps = result.steps as string[];
  const runItems: Array<{
    itemType: MaintenanceRunItem['itemType'];
    linkId?: number | null;
    action: string;
    outcome: MaintenanceRunItem['outcome'];
    details?: Record<string, unknown>;
  }> = [];
  let hasFailures = false;

  try {
    runId = context.db.createMaintenanceRun({
      userId: context.principal.userId,
      mode
    });
    result.run_id = runId;

    if (input.reorg) {
      steps.push('reorg');
      const planResponse = await handlePlanReorg(
        {
          strategy: input.reorg.strategy,
          parameters: input.reorg.parameters,
          scope: input.reorg.scope,
          previewLimit: input.reorg.previewLimit,
          dryRun: true
        },
        context
      );

      const planPayload = planResponse.structuredContent as Record<string, unknown>;
      const reorgSummary: Record<string, unknown> = {
        plan: planPayload
      };

      runItems.push({
        itemType: 'reorg',
        action: 'plan_created',
        outcome: 'success',
        details: {
          plan_id: planPayload.plan_id,
          summary: planPayload.summary,
          warnings: planPayload.warnings
        }
      });

      if (typeof planPayload.plan_id === 'string') {
        context.db.setMaintenanceRunReorgPlanId(runId, planPayload.plan_id);
      }

      if (input.apply) {
        const planId = planPayload.plan_id;
        if (typeof planId !== 'string' || planId.length < 8) {
          throw new AppError(500, 'plan_apply_failed', 'Generated plan_id is missing or invalid.');
        }

        const applyResponse = await handleApplyPlan(
          {
            plan_id: planId,
            confirm: 'APPLY'
          },
          context
        );

        const applyPayload = applyResponse.structuredContent as Record<string, unknown>;
        const applyFailures = readFailureCount(applyPayload);
        if (applyFailures > 0) {
          hasFailures = true;
        }

        runItems.push({
          itemType: 'reorg',
          action: 'plan_applied',
          outcome: applyFailures > 0 ? 'failed' : 'success',
          details: applyPayload
        });

        reorgSummary.apply = applyPayload;
      }

      result.reorg = reorgSummary;
    }

    if (input.offline) {
      steps.push('offline');
      const monitorResponse = await handleMonitorOfflineLinks(
        {
          scope: input.offline.scope,
          offset: input.offline.offset,
          limit: input.offline.limit,
          timeoutMs: input.offline.timeoutMs,
          offlineDays: input.offline.offlineDays,
          minConsecutiveFailures: input.offline.minConsecutiveFailures,
          action: input.offline.action,
          archiveCollectionId: input.offline.archiveCollectionId,
          dryRun: !input.apply
        },
        context
      );

      const monitorPayload = monitorResponse.structuredContent as Record<string, unknown>;
      const offlineFailures = readFailureCount(monitorPayload);
      if (offlineFailures > 0) {
        hasFailures = true;
      }

      runItems.push({
        itemType: 'offline',
        action: input.apply ? 'monitor_and_archive' : 'monitor_dry_run',
        outcome: offlineFailures > 0 ? 'failed' : 'success',
        details: monitorPayload
      });

      result.offline = monitorPayload;
    }

    if (runItems.length > 0) {
      context.db.insertMaintenanceRunItems(runId, runItems);
    }

    context.db.finishMaintenanceRun({
      runId,
      status: hasFailures ? 'failed' : 'success',
      summary: result
    });

    return mcpResult(result);
  } catch (error) {
    if (runId !== null) {
      if (runItems.length > 0) {
        context.db.insertMaintenanceRunItems(runId, runItems);
      }

      context.db.finishMaintenanceRun({
        runId,
        status: 'failed',
        summary: result,
        error: {
          message: error instanceof Error ? error.message : 'unknown',
          detail: sanitizeForLog(error)
        }
      });
    }
    throw error;
  } finally {
    context.db.releaseMaintenanceLock(context.principal.userId, lockToken);
  }
}

const toolHandlers: Record<string, (args: unknown, context: ToolRuntimeContext) => Promise<ToolCallResult>> = {
  search: handleConnectorSearch,
  fetch: handleConnectorFetch,
  linkwarden_get_server_info: handleGetServerInfo,
  linkwarden_search_links: handleSearchLinks,
  linkwarden_list_collections: handleListCollections,
  linkwarden_create_collection: handleCreateCollection,
  linkwarden_update_collection: handleUpdateCollection,
  linkwarden_delete_collection: handleDeleteCollection,
  linkwarden_list_tags: handleListTags,
  linkwarden_create_tag: handleCreateTag,
  linkwarden_delete_tag: handleDeleteTag,
  linkwarden_assign_tags: handleAssignTags,
  linkwarden_get_link: handleGetLink,
  linkwarden_plan_reorg: handlePlanReorg,
  linkwarden_apply_plan: handleApplyPlan,
  linkwarden_update_link: handleUpdateLink,
  linkwarden_set_links_collection: handleSetLinksCollection,
  linkwarden_set_links_pinned: handleSetLinksPinned,
  linkwarden_bulk_update_links: handleBulkUpdate,
  linkwarden_clean_link_urls: handleCleanLinkUrls,
  linkwarden_suggest_taxonomy: handleSuggestTaxonomy,
  linkwarden_capture_chat_links: handleCaptureChatLinks,
  linkwarden_monitor_offline_links: handleMonitorOfflineLinks,
  linkwarden_run_daily_maintenance: handleRunDailyMaintenance
};

// This function dispatches validated tool calls and normalizes validation errors.
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
    context.logger.warn(
      {
        event: 'mcp_tool_not_found',
        toolName,
        actor: context.actor
      },
      'mcp_tool_not_found'
    );
    throw new AppError(404, 'tool_not_found', `Unknown tool: ${toolName}`);
  }

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
