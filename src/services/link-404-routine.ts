// This module executes the native 404-monitor routine and exposes status/schedule helpers for MCP, UI, and scheduler use.

import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { createUserLinkwardenClient } from '../linkwarden/runtime.js';
import type {
  AiChangeActionType,
  AuthenticatedPrincipal,
  Link404MonitorInterval,
  Link404MonitorSettings,
  Link404MonitorStatus,
  Link404ToDeleteAfter,
  LinkHealthState,
  LinkItem
} from '../types/domain.js';
import { errorForLog } from '../utils/logger.js';

export interface Link404RoutineExecutionContext {
  actor: string;
  principal: AuthenticatedPrincipal;
  configStore: ConfigStore;
  db: SqliteStore;
  logger: FastifyBaseLogger;
}

export interface Link404RoutineStatusOptions {
  now?: Date;
}

export interface Link404RoutineRunOptions {
  ignoreSchedule?: boolean;
}

export interface Link404RoutineFailure {
  itemId: number | string;
  code: string;
  message: string;
  retryable: boolean;
}

export interface Link404RoutineRunResult {
  ok: boolean;
  userId: number;
  status: 'success' | 'partial_failure' | 'failed' | 'skipped' | 'locked';
  operationId: string | null;
  warnings: string[];
  summary: {
    scanned: number;
    checked: number;
    flagged404: number;
    taggedToDelete: number;
    recovered: number;
    updated: number;
    failed: number;
    createdTags: number;
  };
  failures: Link404RoutineFailure[];
}

interface UrlProbeResult {
  statusCode: number | null;
  error: string | null;
}

interface TagResolutionResult {
  tag404Id: number;
  tagToDeleteId: number;
  createdTags: string[];
  tagNameById: Map<number, string>;
}

interface PendingAiLogEntry {
  operationItemId: number;
  actionType: AiChangeActionType;
  linkId: number;
  linkTitle: string | null;
  urlBefore: string | null;
  urlAfter: string | null;
  trackingTrimmed: boolean;
  collectionFromId: number | null;
  collectionFromName: string | null;
  collectionToId: number | null;
  collectionToName: string | null;
  tagsAdded: string[];
  tagsRemoved: string[];
  undoStatus: 'pending';
  meta: Record<string, unknown>;
}

// This constant defines the deterministic undo window for routine-generated operation records.
const LINK_404_MONITOR_UNDO_DAYS = 7;

// This helper keeps date arithmetic calendar-aware by clamping month overflows to target-month end.
function addUtcMonthsClamped(source: Date, months: number): Date {
  const year = source.getUTCFullYear();
  const month = source.getUTCMonth();
  const day = source.getUTCDate();
  const hours = source.getUTCHours();
  const minutes = source.getUTCMinutes();
  const seconds = source.getUTCSeconds();
  const milliseconds = source.getUTCMilliseconds();

  const targetMonthIndex = month + months;
  const targetYear = year + Math.floor(targetMonthIndex / 12);
  const normalizedTargetMonth = ((targetMonthIndex % 12) + 12) % 12;

  const lastDayOfTargetMonth = new Date(Date.UTC(targetYear, normalizedTargetMonth + 1, 0)).getUTCDate();
  const clampedDay = Math.min(day, lastDayOfTargetMonth);

  return new Date(
    Date.UTC(targetYear, normalizedTargetMonth, clampedDay, hours, minutes, seconds, milliseconds)
  );
}

// This helper advances one timestamp by a configured periodic 404-monitor interval.
function addInterval(from: Date, interval: Link404MonitorInterval): Date {
  if (interval === 'daily') {
    return new Date(from.getTime() + 24 * 60 * 60 * 1000);
  }
  if (interval === 'weekly') {
    return new Date(from.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
  if (interval === 'biweekly') {
    return new Date(from.getTime() + 14 * 24 * 60 * 60 * 1000);
  }
  if (interval === 'monthly') {
    return addUtcMonthsClamped(from, 1);
  }
  if (interval === 'semiannual') {
    return addUtcMonthsClamped(from, 6);
  }
  return addUtcMonthsClamped(from, 12);
}

// This helper resolves the to-delete escalation threshold from first-failure timestamp and user preset.
function computeToDeleteThreshold(firstFailureAt: string, escalation: Link404ToDeleteAfter): Date | null {
  const parsed = new Date(firstFailureAt);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  if (escalation === 'after_1_month') {
    return addUtcMonthsClamped(parsed, 1);
  }
  if (escalation === 'after_6_months') {
    return addUtcMonthsClamped(parsed, 6);
  }
  return addUtcMonthsClamped(parsed, 12);
}

// This helper checks strict HTTP reachability and reports only transport/runtime errors separately from status codes.
async function probeUrlStatus(url: string, timeoutMs: number): Promise<UrlProbeResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal
    });
    return {
      statusCode: response.status,
      error: null
    };
  } catch (error) {
    return {
      statusCode: null,
      error: error instanceof Error ? error.message : 'health check failed'
    };
  } finally {
    clearTimeout(timer);
  }
}

// This helper filters links against collection scopes for principals with restricted collection permissions.
function applyPrincipalCollectionScope(links: LinkItem[], principal: AuthenticatedPrincipal): LinkItem[] {
  const scopedCollections = principal.collectionScopes ?? [];
  if (scopedCollections.length === 0) {
    return links;
  }

  const allowed = new Set(scopedCollections);
  return links.filter((link) => typeof link.collection?.id === 'number' && allowed.has(link.collection.id));
}

// This helper normalizes tag ids and guarantees deterministic ascending uniqueness.
function normalizeTagIds(tagIds: number[]): number[] {
  return [...new Set(tagIds.filter((tagId) => Number.isInteger(tagId) && tagId > 0))].sort((left, right) => left - right);
}

// This helper computes deterministic tag deltas between current and next link tag-id states.
function diffTagIds(currentTagIds: number[], nextTagIds: number[]): { added: number[]; removed: number[] } {
  const currentSet = new Set(currentTagIds);
  const nextSet = new Set(nextTagIds);
  return {
    added: nextTagIds.filter((tagId) => !currentSet.has(tagId)),
    removed: currentTagIds.filter((tagId) => !nextSet.has(tagId))
  };
}

// This helper derives one action type for AI change-log rows based on tag deltas.
function resolveActionType(addedCount: number, removedCount: number): AiChangeActionType {
  if (addedCount > 0 && removedCount === 0) {
    return 'tag_add';
  }
  if (removedCount > 0 && addedCount === 0) {
    return 'tag_remove';
  }
  return 'update_link';
}

// This helper resolves required tags for 404 monitoring and creates missing tags deterministically.
async function resolve404MonitorTags(client: ReturnType<typeof createUserLinkwardenClient>): Promise<TagResolutionResult> {
  const allTags = await client.listAllTags();
  const tagNameById = new Map<number, string>();
  for (const tag of allTags) {
    tagNameById.set(tag.id, tag.name);
  }

  // This helper picks one deterministic tag by case-insensitive match and lowest id.
  const resolveExisting = (name: string): number | null => {
    const normalized = name.trim().toLowerCase();
    const matches = allTags
      .filter((tag) => tag.name.trim().toLowerCase() === normalized)
      .sort((left, right) => left.id - right.id);
    return matches.length > 0 ? matches[0].id : null;
  };

  const createdTags: string[] = [];
  let tag404Id = resolveExisting('404');
  if (tag404Id === null) {
    const created = await client.createTag('404');
    tag404Id = created.id;
    createdTags.push(created.name);
    allTags.push(created);
    tagNameById.set(created.id, created.name);
  }

  let tagToDeleteId = resolveExisting('to-delete');
  if (tagToDeleteId === null) {
    const created = await client.createTag('to-delete');
    tagToDeleteId = created.id;
    createdTags.push(created.name);
    allTags.push(created);
    tagNameById.set(created.id, created.name);
  }

  return {
    tag404Id,
    tagToDeleteId,
    createdTags,
    tagNameById
  };
}

// This helper evaluates due-state and next schedule timestamp for one user's 404 monitor settings.
export function evaluateLink404MonitorSchedule(
  settings: Link404MonitorSettings,
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

  const lastRunAt = new Date(settings.lastRunAt);
  if (Number.isNaN(lastRunAt.getTime())) {
    return {
      due: true,
      nextDueAt: now.toISOString()
    };
  }

  const nextDueAt = addInterval(lastRunAt, settings.interval);
  return {
    due: now.getTime() >= nextDueAt.getTime(),
    nextDueAt: nextDueAt.toISOString()
  };
}

// This helper resolves status payload for one user's 404 monitor without mutating runtime state.
export async function getLink404MonitorStatus(
  context: Link404RoutineExecutionContext,
  options?: Link404RoutineStatusOptions
): Promise<Link404MonitorStatus> {
  const settings = context.db.getUserLink404MonitorSettings(context.principal.userId);
  const schedule = evaluateLink404MonitorSchedule(settings, options?.now);
  const warnings: string[] = [];

  if (!context.db.hasUserLinkwardenToken(context.principal.userId)) {
    warnings.push('linkwarden_token_missing');
  }

  return {
    userId: context.principal.userId,
    settings,
    due: schedule.due,
    nextDueAt: schedule.nextDueAt,
    warnings
  };
}

// This helper converts a link item into the deterministic operation snapshot format used by undo.
function snapshotForUndo(link: LinkItem, tagIds: number[]): Record<string, unknown> {
  return {
    title: link.title,
    url: link.url,
    description: link.description ?? null,
    collectionId: link.collection?.id ?? null,
    tagIds,
    pinned: Boolean(link.pinned),
    archived: Boolean(link.archived)
  };
}

// This helper finalizes operation and AI-log writes for all successful tag mutations in one monitor run.
function persistOperationArtifacts(
  context: Link404RoutineExecutionContext,
  operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }>,
  aiLogEntries: PendingAiLogEntry[],
  summary: Record<string, unknown>
): string | null {
  if (operationItems.length === 0) {
    return null;
  }

  const operationId = randomUUID();
  const undoUntil = new Date(Date.now() + LINK_404_MONITOR_UNDO_DAYS * 24 * 60 * 60 * 1000).toISOString();
  context.db.createOperation({
    id: operationId,
    userId: context.principal.userId,
    toolName: 'linkwarden_run_link_404_monitor_now',
    summary,
    undoUntil
  });
  context.db.insertOperationItems(operationId, operationItems);

  try {
    context.db.appendAiChangeLogEntries({
      userId: context.principal.userId,
      operationId,
      toolName: 'linkwarden_run_link_404_monitor_now',
      entries: aiLogEntries
    });
  } catch (error) {
    context.logger.warn(
      {
        event: 'link_404_monitor_ai_change_log_append_failed',
        userId: context.principal.userId,
        operationId,
        error: errorForLog(error)
      },
      'link_404_monitor_ai_change_log_append_failed'
    );
  }

  return operationId;
}

// This function executes the 404-monitor routine with strict 404 detection, recovery untagging, and escalation tagging.
export async function runLink404MonitorNow(
  context: Link404RoutineExecutionContext,
  options?: Link404RoutineRunOptions
): Promise<Link404RoutineRunResult> {
  const settings = context.db.getUserLink404MonitorSettings(context.principal.userId);
  const schedule = evaluateLink404MonitorSchedule(settings);
  const warnings: string[] = [];
  const failures: Link404RoutineFailure[] = [];

  if (!settings.enabled) {
    return {
      ok: true,
      userId: context.principal.userId,
      status: 'skipped',
      operationId: null,
      warnings: ['monitor_disabled'],
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
      },
      failures: []
    };
  }

  if (!options?.ignoreSchedule && !schedule.due) {
    return {
      ok: true,
      userId: context.principal.userId,
      status: 'skipped',
      operationId: null,
      warnings: ['monitor_not_due'],
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
      },
      failures: []
    };
  }

  if (!context.db.hasUserLinkwardenToken(context.principal.userId)) {
    context.db.setUserLink404MonitorRunState(context.principal.userId, 'failed', 'Linkwarden token missing.');
    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      operationId: null,
      warnings: ['linkwarden_token_missing'],
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
      },
      failures: []
    };
  }

  const userSettings = context.db.getUserSettings(context.principal.userId);
  if (!userSettings.writeModeEnabled) {
    context.db.setUserLink404MonitorRunState(context.principal.userId, 'failed', 'Write mode disabled.');
    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      operationId: null,
      warnings: ['write_mode_disabled'],
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
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
      operationId: null,
      warnings: ['monitor_locked'],
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
      },
      failures: []
    };
  }

  context.db.setUserLink404MonitorRunState(context.principal.userId, 'running', null);

  try {
    const client = createUserLinkwardenClient(context.configStore, context.db, context.principal.userId, context.logger);
    const links = applyPrincipalCollectionScope(
      await client.loadLinksForScope({
        archived: false
      }),
      context.principal
    );
    const linkIds = links.map((link) => link.id);
    const healthStates = context.db.listLinkHealthStates(context.principal.userId, linkIds);
    const healthByLinkId = new Map<number, LinkHealthState>(healthStates.map((state) => [state.linkId, state]));
    const tagResolution = await resolve404MonitorTags(client);
    const requestTimeoutMs = Math.min(30_000, Math.max(2_000, context.configStore.getRuntimeConfig().requestTimeoutMs));

    const operationItems: Array<{ itemType: string; itemId: number; before: Record<string, unknown>; after: Record<string, unknown> }> =
      [];
    const pendingAiLogEntries: PendingAiLogEntry[] = [];

    const summary = {
      scanned: links.length,
      checked: 0,
      flagged404: 0,
      taggedToDelete: 0,
      recovered: 0,
      updated: 0,
      failed: 0,
      createdTags: tagResolution.createdTags.length
    };

    for (const link of links) {
      const checkedAt = new Date().toISOString();
      const existing = healthByLinkId.get(link.id);
      const probe = await probeUrlStatus(link.url, requestTimeoutMs);
      const currentTagIds = normalizeTagIds(link.tags.map((tag) => tag.id));

      if (probe.error) {
        failures.push({
          itemId: link.id,
          code: 'health_check_failed',
          message: probe.error,
          retryable: true
        });
        summary.failed += 1;

        // This write updates check diagnostics while intentionally preserving failure timing state on transport errors.
        context.db.upsertLinkHealthState({
          userId: context.principal.userId,
          linkId: link.id,
          url: link.url,
          firstFailureAt: existing?.firstFailureAt ?? null,
          lastFailureAt: existing?.lastFailureAt ?? null,
          consecutiveFailures: existing?.consecutiveFailures ?? 0,
          lastStatus: existing?.lastStatus ?? 'up',
          lastCheckedAt: checkedAt,
          lastHttpStatus: null,
          lastError: probe.error,
          archivedAt: existing?.archivedAt ?? null
        });
        continue;
      }

      summary.checked += 1;

      if (probe.statusCode === 404) {
        summary.flagged404 += 1;
        const firstFailureAt = existing?.firstFailureAt ?? checkedAt;
        const lastFailureAt = checkedAt;
        const consecutiveFailures = (existing?.consecutiveFailures ?? 0) + 1;
        const threshold = computeToDeleteThreshold(firstFailureAt, settings.toDeleteAfter);
        const shouldTagToDelete = threshold !== null && Date.now() >= threshold.getTime();

        if (shouldTagToDelete) {
          summary.taggedToDelete += 1;
        }

        const nextTagIds = normalizeTagIds(
          shouldTagToDelete
            ? [...currentTagIds, tagResolution.tag404Id, tagResolution.tagToDeleteId]
            : [...currentTagIds, tagResolution.tag404Id]
        );
        const tagDiff = diffTagIds(currentTagIds, nextTagIds);

        if (tagDiff.added.length > 0 || tagDiff.removed.length > 0) {
          try {
            await client.updateLink(link.id, {
              tagIds: nextTagIds
            });
            summary.updated += 1;

            operationItems.push({
              itemType: 'link',
              itemId: link.id,
              before: snapshotForUndo(link, currentTagIds),
              after: snapshotForUndo(link, nextTagIds)
            });

            pendingAiLogEntries.push({
              operationItemId: link.id,
              actionType: resolveActionType(tagDiff.added.length, tagDiff.removed.length),
              linkId: link.id,
              linkTitle: link.title ?? null,
              urlBefore: link.url,
              urlAfter: link.url,
              trackingTrimmed: false,
              collectionFromId: link.collection?.id ?? null,
              collectionFromName: link.collection?.name ?? null,
              collectionToId: link.collection?.id ?? null,
              collectionToName: link.collection?.name ?? null,
              tagsAdded: tagDiff.added.map((tagId) => tagResolution.tagNameById.get(tagId) ?? `tag:${tagId}`),
              tagsRemoved: tagDiff.removed.map((tagId) => tagResolution.tagNameById.get(tagId) ?? `tag:${tagId}`),
              undoStatus: 'pending',
              meta: {
                routine: 'link_404_monitor',
                httpStatus: 404
              }
            });
          } catch (error) {
            const message = error instanceof Error ? error.message : 'link update failed';
            failures.push({
              itemId: link.id,
              code: 'tag_update_failed',
              message,
              retryable: true
            });
            summary.failed += 1;
          }
        }

        // This write persists deterministic 404-state tracking for future escalation checks.
        context.db.upsertLinkHealthState({
          userId: context.principal.userId,
          linkId: link.id,
          url: link.url,
          firstFailureAt,
          lastFailureAt,
          consecutiveFailures,
          lastStatus: 'down',
          lastCheckedAt: checkedAt,
          lastHttpStatus: 404,
          lastError: null,
          archivedAt: existing?.archivedAt ?? null
        });
        continue;
      }

      const hadFailureHistory = Boolean(existing?.firstFailureAt);
      const nextTagIds = normalizeTagIds(
        currentTagIds.filter((tagId) => tagId !== tagResolution.tag404Id && tagId !== tagResolution.tagToDeleteId)
      );
      const tagDiff = diffTagIds(currentTagIds, nextTagIds);

      if (tagDiff.added.length > 0 || tagDiff.removed.length > 0) {
        try {
          await client.updateLink(link.id, {
            tagIds: nextTagIds
          });
          summary.updated += 1;
          summary.recovered += 1;

          operationItems.push({
            itemType: 'link',
            itemId: link.id,
            before: snapshotForUndo(link, currentTagIds),
            after: snapshotForUndo(link, nextTagIds)
          });

          pendingAiLogEntries.push({
            operationItemId: link.id,
            actionType: resolveActionType(tagDiff.added.length, tagDiff.removed.length),
            linkId: link.id,
            linkTitle: link.title ?? null,
            urlBefore: link.url,
            urlAfter: link.url,
            trackingTrimmed: false,
            collectionFromId: link.collection?.id ?? null,
            collectionFromName: link.collection?.name ?? null,
            collectionToId: link.collection?.id ?? null,
            collectionToName: link.collection?.name ?? null,
            tagsAdded: tagDiff.added.map((tagId) => tagResolution.tagNameById.get(tagId) ?? `tag:${tagId}`),
            tagsRemoved: tagDiff.removed.map((tagId) => tagResolution.tagNameById.get(tagId) ?? `tag:${tagId}`),
            undoStatus: 'pending',
            meta: {
              routine: 'link_404_monitor',
              httpStatus: probe.statusCode
            }
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'link update failed';
          failures.push({
            itemId: link.id,
            code: 'tag_update_failed',
            message,
            retryable: true
          });
          summary.failed += 1;
        }
      } else if (hadFailureHistory) {
        summary.recovered += 1;
      }

      // This write resets persisted failure tracking after non-404 checks and keeps last successful status visible.
      context.db.upsertLinkHealthState({
        userId: context.principal.userId,
        linkId: link.id,
        url: link.url,
        firstFailureAt: null,
        lastFailureAt: null,
        consecutiveFailures: 0,
        lastStatus: 'up',
        lastCheckedAt: checkedAt,
        lastHttpStatus: probe.statusCode,
        lastError: null,
        archivedAt: existing?.archivedAt ?? null
      });
    }

    const operationId = persistOperationArtifacts(
      context,
      operationItems,
      pendingAiLogEntries,
      {
        scanned: summary.scanned,
        updated: summary.updated,
        failed: summary.failed
      }
    );

    if (operationId) {
      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_run_link_404_monitor_now',
        targetType: 'link',
        targetIds: operationItems.map((item) => item.itemId),
        beforeSummary: '404 monitor tag update',
        afterSummary: JSON.stringify({
          operationId,
          updated: summary.updated,
          failed: summary.failed
        }),
        outcome: summary.failed === 0 ? 'success' : 'failed',
        details: {
          userId: context.principal.userId,
          createdTags: tagResolution.createdTags
        }
      });
    }

    const finalStatus: Link404RoutineRunResult['status'] = failures.length > 0 ? 'partial_failure' : 'success';
    context.db.setUserLink404MonitorRunState(
      context.principal.userId,
      finalStatus,
      failures.length > 0 ? `${failures.length} failure(s)` : null
    );

    return {
      ok: failures.length === 0,
      userId: context.principal.userId,
      status: finalStatus,
      operationId,
      warnings,
      summary,
      failures
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : '404 monitor execution failed';
    context.db.setUserLink404MonitorRunState(context.principal.userId, 'failed', message);
    context.logger.error(
      {
        event: 'link_404_monitor_failed',
        userId: context.principal.userId,
        error: errorForLog(error)
      },
      'link_404_monitor_failed'
    );

    return {
      ok: false,
      userId: context.principal.userId,
      status: 'failed',
      operationId: null,
      warnings,
      summary: {
        scanned: 0,
        checked: 0,
        flagged404: 0,
        taggedToDelete: 0,
        recovered: 0,
        updated: 0,
        failed: 0,
        createdTags: 0
      },
      failures: [
        {
          itemId: 'run',
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
