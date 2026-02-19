// This module executes the native new-links auto-routine and exposes status/schedule helpers for MCP, UI, and scheduler use.

import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { createUserLinkwardenClient } from '../linkwarden/runtime.js';
import type {
  AuthenticatedPrincipal,
  LinkItem,
  NewLinksCursor,
  NewLinksRoutineModule,
  NewLinksRoutineSettings,
  NewLinksRoutineStatus
} from '../types/domain.js';
import { errorForLog } from '../utils/logger.js';
import { cleanTrackedUrl } from '../utils/url-cleaner.js';

export interface NewLinksRoutineExecutionContext {
  actor: string;
  principal: AuthenticatedPrincipal;
  configStore: ConfigStore;
  db: SqliteStore;
  logger: FastifyBaseLogger;
}

export interface NewLinksRoutineToolExecutorResult {
  structuredContent: Record<string, unknown>;
}

export type NewLinksRoutineToolExecutor = (
  toolName: string,
  args: Record<string, unknown>,
  context: NewLinksRoutineExecutionContext
) => Promise<NewLinksRoutineToolExecutorResult>;

export interface NewLinksRoutineStatusOptions {
  includeBacklogEstimate?: boolean;
  now?: Date;
}

export interface NewLinksRoutineRunOptions {
  ignoreSchedule?: boolean;
}

export interface NewLinksRoutineFailure {
  itemId: number | string;
  module: NewLinksRoutineModule | 'scheduler';
  code: string;
  message: string;
  retryable: boolean;
}

export interface NewLinksRoutineRunResult {
  ok: boolean;
  userId: number;
  status: 'success' | 'partial_failure' | 'failed' | 'skipped' | 'locked';
  cursorBefore: NewLinksCursor | null;
  cursorAfter: NewLinksCursor | null;
  warnings: string[];
  backlogCount: number | null;
  modules: NewLinksRoutineModule[];
  summary: {
    scanned: number;
    candidates: number;
    processed: number;
    failed: number;
  };
  failures: NewLinksRoutineFailure[];
}

interface CursorComparableLink {
  linkId: number;
  createdAt: string;
  createdAtMs: number;
}

// This constant defines one deterministic module execution order independent of user payload order.
const ROUTINE_MODULE_ORDER: NewLinksRoutineModule[] = ['governed_tagging', 'normalize_urls', 'dedupe'];

// This helper returns one deterministic run schedule state from routine settings and optional clock override.
export function evaluateNewLinksRoutineSchedule(
  settings: NewLinksRoutineSettings,
  now = new Date()
): { due: boolean; nextDueAt: string | null } {
  if (!settings.enabled) {
    return {
      due: false,
      nextDueAt: null
    };
  }

  if (!settings.lastRunAt) {
    return {
      due: true,
      nextDueAt: now.toISOString()
    };
  }

  const intervalMs = Math.max(1, settings.intervalMinutes) * 60 * 1000;
  const lastRunMs = new Date(settings.lastRunAt).getTime();
  if (!Number.isFinite(lastRunMs)) {
    return {
      due: true,
      nextDueAt: now.toISOString()
    };
  }

  const nextDueMs = lastRunMs + intervalMs;
  return {
    due: now.getTime() >= nextDueMs,
    nextDueAt: new Date(nextDueMs).toISOString()
  };
}

// This helper converts links to strict createdAt/id cursor tuples and drops malformed records.
function toCursorComparableLink(link: LinkItem): CursorComparableLink | null {
  if (!link.createdAt) {
    return null;
  }

  const createdAtMs = new Date(link.createdAt).getTime();
  if (!Number.isFinite(createdAtMs)) {
    return null;
  }

  return {
    linkId: link.id,
    createdAt: link.createdAt,
    createdAtMs
  };
}

// This helper sorts cursor tuples strictly by createdAt ascending and id ascending for deterministic delta scans.
function compareCursorComparableLinks(left: CursorComparableLink, right: CursorComparableLink): number {
  if (left.createdAtMs !== right.createdAtMs) {
    return left.createdAtMs - right.createdAtMs;
  }

  return left.linkId - right.linkId;
}

// This helper checks strict tuple progression and only returns true for entries greater than the stored cursor.
function isAfterCursor(link: CursorComparableLink, cursor: NewLinksCursor | null): boolean {
  if (!cursor) {
    return true;
  }

  const cursorCreatedAtMs = new Date(cursor.createdAt).getTime();
  if (!Number.isFinite(cursorCreatedAtMs)) {
    return true;
  }

  return (
    link.createdAtMs > cursorCreatedAtMs ||
    (link.createdAtMs === cursorCreatedAtMs && link.linkId > cursor.linkId)
  );
}

// This helper derives a canonical URL string used for deterministic dedupe grouping.
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

// This helper resolves the active routine modules and keeps execution order deterministic.
function resolveOrderedModules(modules: NewLinksRoutineModule[]): NewLinksRoutineModule[] {
  const moduleSet = new Set(modules);
  return ROUTINE_MODULE_ORDER.filter((module) => moduleSet.has(module));
}

// This helper converts tool failure payloads into one normalized routine failure list.
function parseToolFailures(
  module: NewLinksRoutineModule,
  payload: Record<string, unknown>
): NewLinksRoutineFailure[] {
  const failuresRaw = Array.isArray(payload.failures) ? payload.failures : [];
  return failuresRaw.map((entry, index) => {
    const normalized = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {};
    const rawItemId = normalized.itemId;
    const itemId =
      typeof rawItemId === 'number' || typeof rawItemId === 'string'
        ? rawItemId
        : `unknown-${module}-${index}`;
    return {
      itemId,
      module,
      code: typeof normalized.code === 'string' ? normalized.code : `${module}_failed`,
      message: typeof normalized.message === 'string' ? normalized.message : `${module} failed`,
      retryable: Boolean(normalized.retryable)
    };
  });
}

// This helper builds merge groups that include at least one candidate id and keep the lowest id by strategy.
function buildDedupeGroups(allLinks: LinkItem[], candidateIds: Set<number>): Array<{ canonicalUrl: string; linkIds: number[] }> {
  const grouped = new Map<string, number[]>();

  for (const link of allLinks) {
    const canonicalUrl = canonicalizeUrl(link.url);
    const ids = grouped.get(canonicalUrl) ?? [];
    ids.push(link.id);
    grouped.set(canonicalUrl, ids);
  }

  const groups: Array<{ canonicalUrl: string; linkIds: number[] }> = [];
  for (const [canonicalUrl, linkIdsRaw] of grouped.entries()) {
    const linkIds = [...new Set(linkIdsRaw)].sort((left, right) => left - right);
    if (linkIds.length < 2) {
      continue;
    }
    if (!linkIds.some((id) => candidateIds.has(id))) {
      continue;
    }
    groups.push({
      canonicalUrl,
      linkIds
    });
  }

  return groups.sort((left, right) => left.canonicalUrl.localeCompare(right.canonicalUrl));
}

// This helper applies optional collection-scope restrictions from the calling principal to routine candidate sets.
function applyPrincipalCollectionScope(links: LinkItem[], principal: AuthenticatedPrincipal): LinkItem[] {
  const scopedCollections = principal.collectionScopes ?? [];
  if (scopedCollections.length === 0) {
    return links;
  }

  const allowed = new Set(scopedCollections);
  return links.filter((link) => typeof link.collection?.id === 'number' && allowed.has(link.collection.id));
}

// This helper resolves one user's routine status with optional backlog estimation for confirmation workflows.
export async function getNewLinksRoutineStatus(
  context: NewLinksRoutineExecutionContext,
  options?: NewLinksRoutineStatusOptions
): Promise<NewLinksRoutineStatus> {
  const settings = context.db.getUserNewLinksRoutineSettings(context.principal.userId);
  const schedule = evaluateNewLinksRoutineSchedule(settings, options?.now);
  const warnings: string[] = [];
  let backlogCount: number | null = null;

  if (!context.db.hasUserLinkwardenToken(context.principal.userId)) {
    warnings.push('linkwarden_token_missing');
  }

  if (settings.backfillRequested && !settings.backfillConfirmed) {
    warnings.push('backlog_pending_confirmation');
  }

  if ((options?.includeBacklogEstimate ?? true) && settings.backfillRequested && !settings.backfillConfirmed) {
    try {
      if (context.db.hasUserLinkwardenToken(context.principal.userId)) {
        const client = createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
        const allLinks = applyPrincipalCollectionScope(await client.loadLinksForScope(undefined), context.principal);
        const entries = allLinks
          .map((link) => toCursorComparableLink(link))
          .filter((entry): entry is CursorComparableLink => entry !== null)
          .map((entry) => ({
            createdAt: entry.createdAt,
            linkId: entry.linkId
          }));
        backlogCount = context.db.estimateUserNewLinksBacklog(context.principal.userId, settings.cursor, entries);
      }
    } catch (error) {
      warnings.push('backlog_estimate_failed');
      context.logger.warn(
        {
          event: 'new_links_routine_backlog_estimate_failed',
          userId: context.principal.userId,
          error: errorForLog(error)
        },
        'new_links_routine_backlog_estimate_failed'
      );
    }
  }

  return {
    userId: context.principal.userId,
    settings,
    due: schedule.due,
    nextDueAt: schedule.nextDueAt,
    backlogCount,
    warnings
  };
}

// This helper runs one routine module through the shared MCP executor and records normalized failures.
async function executeRoutineModule(
  module: NewLinksRoutineModule,
  candidateIds: number[],
  context: NewLinksRoutineExecutionContext,
  toolExecutor: NewLinksRoutineToolExecutor
): Promise<NewLinksRoutineFailure[]> {
  if (candidateIds.length === 0) {
    return [];
  }

  if (module === 'governed_tagging') {
    const result = await toolExecutor(
      'linkwarden_governed_tag_links',
      {
        linkIds: candidateIds,
        dryRun: false,
        previewLimit: Math.min(candidateIds.length, 200)
      },
      context
    );
    return parseToolFailures(module, result.structuredContent);
  }

  if (module === 'normalize_urls') {
    const result = await toolExecutor(
      'linkwarden_normalize_urls',
      {
        linkIds: candidateIds,
        dryRun: false,
        previewLimit: Math.min(candidateIds.length, 200)
      },
      context
    );
    return parseToolFailures(module, result.structuredContent);
  }

  const client = createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
  const allLinks = applyPrincipalCollectionScope(await client.loadLinksForScope(undefined), context.principal);
  const groups = buildDedupeGroups(allLinks, new Set(candidateIds));
  if (groups.length === 0) {
    return [];
  }

  const result = await toolExecutor(
    'linkwarden_merge_duplicates',
    {
      groups,
      keepStrategy: 'lowestId',
      deleteMode: 'soft',
      dryRun: false
    },
    context
  );
  return parseToolFailures(module, result.structuredContent);
}

// This helper advances cursor state only across the leading successful prefix so failed items are not skipped.
function computeCursorAdvance(
  candidates: CursorComparableLink[],
  failedLinkIds: Set<number>,
  cursorBefore: NewLinksCursor | null
): NewLinksCursor | null {
  let cursorAfter = cursorBefore;
  for (const candidate of candidates) {
    if (failedLinkIds.has(candidate.linkId)) {
      break;
    }

    cursorAfter = {
      createdAt: candidate.createdAt,
      linkId: candidate.linkId
    };
  }
  return cursorAfter;
}

// This function executes the full new-link routine for one user with locking, module pipeline, and strict cursor progression.
export async function runNewLinksRoutineNow(
  context: NewLinksRoutineExecutionContext,
  toolExecutor: NewLinksRoutineToolExecutor,
  options?: NewLinksRoutineRunOptions
): Promise<NewLinksRoutineRunResult> {
  const settings = context.db.getUserNewLinksRoutineSettings(context.principal.userId);
  const schedule = evaluateNewLinksRoutineSchedule(settings);
  const warnings: string[] = [];
  const modules = resolveOrderedModules(settings.modules);
  const cursorBefore = settings.cursor;

  if (!settings.enabled) {
    return {
      ok: true,
      userId: context.principal.userId,
      status: 'skipped',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings: ['routine_disabled'],
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: []
    };
  }

  if (!options?.ignoreSchedule && !schedule.due) {
    return {
      ok: true,
      userId: context.principal.userId,
      status: 'skipped',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings: ['routine_not_due'],
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: []
    };
  }

  if (!context.db.hasUserLinkwardenToken(context.principal.userId)) {
    context.db.setUserNewLinksRoutineRunState(context.principal.userId, 'failed', 'Linkwarden token missing.');
    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings: ['linkwarden_token_missing'],
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: []
    };
  }

  const userSettings = context.db.getUserSettings(context.principal.userId);
  if (!userSettings.writeModeEnabled) {
    context.db.setUserNewLinksRoutineRunState(context.principal.userId, 'failed', 'Write mode disabled.');
    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings: ['write_mode_disabled'],
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: []
    };
  }

  const lockToken = randomUUID();
  const acquired = context.db.acquireMaintenanceLock(context.principal.userId, lockToken, 1800);
  if (!acquired) {
    return {
      ok: false,
      userId: context.principal.userId,
      status: 'locked',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings: ['routine_locked'],
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: []
    };
  }

  context.db.setUserNewLinksRoutineRunState(context.principal.userId, 'running', null);

  try {
    const client = createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
    const allLinks = await client.loadLinksForScope(undefined);
    const scopedLinks = applyPrincipalCollectionScope(allLinks, context.principal);
    const comparableLinks = scopedLinks
      .map((link) => toCursorComparableLink(link))
      .filter((link): link is CursorComparableLink => link !== null)
      .sort(compareCursorComparableLinks);

    const invalidCreatedAtCount = scopedLinks.length - comparableLinks.length;
    if (invalidCreatedAtCount > 0) {
      warnings.push(`skipped_links_without_created_at:${invalidCreatedAtCount}`);
    }

    let backlogCount: number | null = null;
    if (settings.backfillRequested && !settings.backfillConfirmed) {
      warnings.push('backlog_pending_confirmation');
      backlogCount = context.db.estimateUserNewLinksBacklog(
        context.principal.userId,
        settings.cursor,
        comparableLinks.map((link) => ({
          createdAt: link.createdAt,
          linkId: link.linkId
        }))
      );
    }

    const candidates = comparableLinks
      .filter((link) => isAfterCursor(link, settings.cursor))
      .slice(0, settings.batchSize);
    const candidateIds = candidates.map((candidate) => candidate.linkId);
    const failures: NewLinksRoutineFailure[] = [];
    const failedLinkIds = new Set<number>();

    for (const module of modules) {
      try {
        const moduleFailures = await executeRoutineModule(module, candidateIds, context, toolExecutor);
        failures.push(...moduleFailures);
        for (const failure of moduleFailures) {
          if (typeof failure.itemId === 'number') {
            failedLinkIds.add(failure.itemId);
          }
        }
      } catch (error) {
        failures.push({
          itemId: `module:${module}`,
          module,
          code: `${module}_execution_failed`,
          message: error instanceof Error ? error.message : `${module} execution failed`,
          retryable: true
        });

        // This branch marks all candidates as failed when a module aborts globally to avoid skipping unprocessed links.
        for (const candidateId of candidateIds) {
          failedLinkIds.add(candidateId);
        }
      }
    }

    const cursorAfter = computeCursorAdvance(candidates, failedLinkIds, settings.cursor);
    if (
      (settings.cursor?.createdAt ?? null) !== (cursorAfter?.createdAt ?? null) ||
      (settings.cursor?.linkId ?? null) !== (cursorAfter?.linkId ?? null)
    ) {
      context.db.updateUserNewLinksRoutineCursor(context.principal.userId, cursorAfter);
    }

    const failed = failures.filter((failure) => typeof failure.itemId === 'number').length;
    const processed = Math.max(0, candidates.length - failed);
    const finalStatus: NewLinksRoutineRunResult['status'] = failures.length > 0 ? 'partial_failure' : 'success';
    context.db.setUserNewLinksRoutineRunState(
      context.principal.userId,
      finalStatus,
      failures.length > 0 ? `${failures.length} failure(s)` : null
    );

    return {
      ok: failures.length === 0,
      userId: context.principal.userId,
      status: finalStatus,
      cursorBefore,
      cursorAfter,
      warnings,
      backlogCount,
      modules,
      summary: {
        scanned: comparableLinks.length,
        candidates: candidates.length,
        processed,
        failed
      },
      failures
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'routine execution failed';
    context.db.setUserNewLinksRoutineRunState(context.principal.userId, 'failed', message);
    context.logger.error(
      {
        event: 'new_links_routine_failed',
        userId: context.principal.userId,
        error: errorForLog(error)
      },
      'new_links_routine_failed'
    );

    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      cursorBefore,
      cursorAfter: cursorBefore,
      warnings,
      backlogCount: null,
      modules,
      summary: {
        scanned: 0,
        candidates: 0,
        processed: 0,
        failed: 0
      },
      failures: [
        {
          itemId: 'run',
          module: 'scheduler',
          code: 'routine_failed',
          message,
          retryable: true
        }
      ]
    };
  } finally {
    context.db.releaseMaintenanceLock(context.principal.userId, lockToken);
  }
}
