// This module implements all MCP tool handlers with validation, safety guards, and audit logging.

import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { LinkwardenClient } from '../linkwarden/client.js';
import { createValidatedLinkwardenClient } from '../linkwarden/runtime.js';
import { computeReorgPlan } from '../planning/reorg.js';
import type { AuthenticatedPrincipal, BulkUpdateRequest, LinkItem, PlanItem, PlanScope } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import {
  bulkUpdateSchema,
  applyPlanSchema,
  getLinkSchema,
  listCollectionsSchema,
  listTagsSchema,
  planReorgSchema,
  searchLinksSchema,
  suggestTaxonomySchema,
  updateLinkSchema
} from './tool-schemas.js';

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

// This helper enforces role and write-mode policy before mutating operations.
function assertWriteAccess(context: ToolRuntimeContext): void {
  if (context.principal.role !== 'admin' && context.principal.role !== 'user') {
    throw new AppError(403, 'forbidden', 'Role is not allowed to execute write operations.');
  }

  const settings = context.db.getUserSettings(context.principal.userId);
  if (!settings.writeModeEnabled) {
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
  return createValidatedLinkwardenClient(context.configStore, context.db);
}

// This function handles linkwarden_search_links with bounded output and paging metadata.
async function handleSearchLinks(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = searchLinksSchema.parse(args);
  const client = getClient(context);
  const result = await client.searchLinks(input);

  return mcpResult({
    links: result.items.map((item) => ({
      id: item.id,
      title: item.title,
      url: item.url,
      description: item.description,
      tags: item.tags,
      collection: item.collection,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    })),
    paging: {
      limit: input.limit,
      offset: input.offset,
      returned: result.items.length,
      total: result.total
    }
  });
}

// This function handles linkwarden_list_collections with paging controls.
async function handleListCollections(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listCollectionsSchema.parse(args);
  const client = getClient(context);
  const result = await client.listCollections(input);

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

// This function handles linkwarden_list_tags with paging controls.
async function handleListTags(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = listTagsSchema.parse(args);
  const client = getClient(context);
  const result = await client.listTags(input);

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

  const planData = context.db.getPlanWithItems(input.plan_id);
  if (!planData) {
    throw new AppError(404, 'plan_not_found', `Plan ${input.plan_id} not found.`);
  }

  if (planData.plan.status !== 'draft') {
    throw new AppError(409, 'plan_not_applicable', `Plan status is ${planData.plan.status}, expected draft.`);
  }

  if (new Date(planData.plan.expiresAt).getTime() < Date.now()) {
    context.db.updatePlanStatus(input.plan_id, 'expired');
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
      if (group.linkIds.length > 1) {
        try {
          await client.bulkReplaceLinks({
            linkIds: group.linkIds,
            updates: {
              collectionId: group.collectionId ?? undefined,
              tagIds: group.tagIds
            }
          });

          applied += group.linkIds.length;
          context.db.insertAudit({
            actor: context.actor,
            toolName: 'linkwarden_apply_plan',
            targetType: 'link',
            targetIds: group.linkIds,
            beforeSummary: 'plan-item-snapshots',
            afterSummary: `bulk replace tags=${JSON.stringify(group.tagIds ?? [])} collection=${String(group.collectionId)}`,
            outcome: 'success',
            details: withActorDetails(context, {
              planId: input.plan_id,
              mode: 'bulk-replace'
            })
          });
        } catch (error) {
          for (const linkId of group.linkIds) {
            if (failures.length < 100) {
              failures.push({
                linkId,
                message: error instanceof Error ? error.message : 'bulk apply failed'
              });
            }
          }

          context.db.insertAudit({
            actor: context.actor,
            toolName: 'linkwarden_apply_plan',
            targetType: 'link',
            targetIds: group.linkIds,
            beforeSummary: 'plan-item-snapshots',
            afterSummary: 'bulk replace failed',
            outcome: 'failed',
            details: withActorDetails(context, {
              planId: input.plan_id,
              mode: 'bulk-replace',
              error: error instanceof Error ? error.message : 'unknown'
            })
          });
        }

        continue;
      }

      const linkId = group.linkIds[0]!;
      try {
        const updates: Record<string, unknown> = {};
        if (group.tagIds) {
          updates.tagIds = group.tagIds;
        }
        if (group.collectionId !== undefined) {
          updates.collectionId = group.collectionId;
        }

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
            mode: 'single-patch'
          })
        });
      } catch (error) {
        if (failures.length < 100) {
          failures.push({
            linkId,
            message: error instanceof Error ? error.message : 'link update failed'
          });
        }

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
            mode: 'single-patch',
            error: error instanceof Error ? error.message : 'unknown'
          })
        });
      }
    }

    if (failures.length === 0) {
      context.db.updatePlanStatus(input.plan_id, 'applied');
      context.db.finishPlanRun(runId, 'success', { applied, failures: [] });
    } else {
      context.db.updatePlanStatus(input.plan_id, 'failed');
      context.db.finishPlanRun(runId, 'failed', { applied, failures });
    }

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
      updatedAt: updated.updatedAt
    }
  });
}

// This function handles linkwarden_bulk_update_links with dry-run preview and optional apply.
async function handleBulkUpdate(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = bulkUpdateSchema.parse(args);
  const client = getClient(context);

  const sampledLinks = await Promise.all(input.linkIds.map((linkId) => client.getLink(linkId)));

  const preview = sampledLinks.map((link) => {
    const currentTags = link.tags.map((tag) => tag.id);
    const nextTags = computeBulkTagResult(currentTags, input.updates.tagIds, input.mode);

    return {
      linkId: link.id,
      before: {
        collectionId: link.collection?.id ?? null,
        tagIds: currentTags
      },
      after: {
        collectionId: input.updates.collectionId ?? link.collection?.id ?? null,
        tagIds: nextTags
      }
    };
  });

  if (input.dryRun) {
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

  if (input.mode === 'replace' || !input.updates.tagIds) {
    try {
      await client.bulkReplaceLinks({
        linkIds: input.linkIds,
        updates: {
          collectionId: input.updates.collectionId,
          tagIds:
            input.mode === 'replace'
              ? (input.updates.tagIds ? normalizeTagIds(input.updates.tagIds) : undefined)
              : undefined
        }
      });
      applied = input.linkIds.length;

      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_bulk_update_links',
        targetType: 'link',
        targetIds: input.linkIds,
        beforeSummary: 'bulk preview snapshot',
        afterSummary: JSON.stringify(input.updates),
        outcome: 'success',
        details: withActorDetails(context, {
          mode: input.mode
        })
      });
    } catch (error) {
      for (const linkId of input.linkIds.slice(0, 100)) {
        failures.push({
          linkId,
          message: error instanceof Error ? error.message : 'bulk update failed'
        });
      }

      context.db.insertAudit({
        actor: context.actor,
        toolName: 'linkwarden_bulk_update_links',
        targetType: 'link',
        targetIds: input.linkIds,
        beforeSummary: 'bulk preview snapshot',
        afterSummary: 'bulk update failed',
        outcome: 'failed',
        details: withActorDetails(context, {
          mode: input.mode,
          error: error instanceof Error ? error.message : 'unknown'
        })
      });
    }
  } else {
    for (const link of sampledLinks) {
      const currentTags = link.tags.map((tag) => tag.id);
      const nextTags = computeBulkTagResult(currentTags, input.updates.tagIds, input.mode);

      try {
        await client.updateLink(link.id, {
          tagIds: nextTags,
          collectionId: input.updates.collectionId ?? link.collection?.id ?? null
        });
        applied += 1;
      } catch (error) {
        if (failures.length < 100) {
          failures.push({
            linkId: link.id,
            message: error instanceof Error ? error.message : 'update failed'
          });
        }
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
  }

  return mcpResult({
    dryRun: false,
    applied,
    failures
  });
}

// This function handles linkwarden_suggest_taxonomy as a pure analysis feature without writes.
async function handleSuggestTaxonomy(args: unknown, context: ToolRuntimeContext): Promise<ToolCallResult> {
  const input = suggestTaxonomySchema.parse(args);
  const client = getClient(context);
  const links = await client.loadLinksForScope({ query: input.query }, 100);
  const subset = links.slice(0, input.limit);
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

const toolHandlers: Record<string, (args: unknown, context: ToolRuntimeContext) => Promise<ToolCallResult>> = {
  linkwarden_search_links: handleSearchLinks,
  linkwarden_list_collections: handleListCollections,
  linkwarden_list_tags: handleListTags,
  linkwarden_get_link: handleGetLink,
  linkwarden_plan_reorg: handlePlanReorg,
  linkwarden_apply_plan: handleApplyPlan,
  linkwarden_update_link: handleUpdateLink,
  linkwarden_bulk_update_links: handleBulkUpdate,
  linkwarden_suggest_taxonomy: handleSuggestTaxonomy
};

// This function dispatches validated tool calls and normalizes validation errors.
export async function executeTool(
  toolName: string,
  args: unknown,
  context: ToolRuntimeContext
): Promise<ToolCallResult> {
  const handler = toolHandlers[toolName];
  if (!handler) {
    throw new AppError(404, 'tool_not_found', `Unknown tool: ${toolName}`);
  }

  try {
    return await handler(args, context);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new AppError(400, 'validation_error', 'Tool input validation failed.', error.flatten());
    }

    throw error;
  }
}
