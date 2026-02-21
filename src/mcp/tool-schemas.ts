// This module defines alpha MCP tool contracts with deterministic selectors, cursor paging, and compact response controls.

import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import type { McpTool } from '../types/mcp.js';

// This enum keeps output verbosity explicit so agents can optimize token usage deterministically.
export const verbositySchema = z.enum(['minimal', 'normal', 'debug']).default('minimal');

// This helper validates IANA time zone identifiers with the runtime Intl implementation.
function isValidTimeZone(value: string): boolean {
  try {
    Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

// This schema models relative created-at windows for natural date filters.
const createdAtRelativeSchema = z.object({
  amount: z.number().int().min(1).max(120),
  unit: z.enum(['day', 'week', 'month', 'year']),
  mode: z.enum(['rolling', 'previous_calendar'])
});

// This schema provides one shared selector language across query, mutate, delete, and rule tools.
export const selectorSchema = z
  .object({
    query: z.string().trim().min(1).optional(),
    ids: z.array(z.number().int().positive()).min(1).optional(),
    collectionId: z.number().int().positive().optional(),
    collectionNamesAny: z.array(z.string().trim().min(1).max(160)).min(1).max(200).optional(),
    includeDescendants: z.boolean().default(false),
    tagIdsAny: z.array(z.number().int().positive()).max(200).optional(),
    tagIdsAll: z.array(z.number().int().positive()).max(200).optional(),
    tagNamesAny: z.array(z.string().trim().min(1).max(80)).min(1).max(200).optional(),
    tagNamesAll: z.array(z.string().trim().min(1).max(80)).min(1).max(200).optional(),
    archived: z.boolean().optional(),
    pinned: z.boolean().optional(),
    changedSince: z.string().datetime().optional(),
    createdAtFrom: z.string().trim().min(1).max(80).optional(),
    createdAtTo: z.string().trim().min(1).max(80).optional(),
    createdAtRelative: createdAtRelativeSchema.optional(),
    timeZone: z.string().trim().min(1).max(100).optional()
  })
  .superRefine((payload, ctx) => {
    // This rule prevents mixed relative and absolute created-at filters in one selector.
    if (payload.createdAtRelative && (payload.createdAtFrom || payload.createdAtTo)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['createdAtRelative'],
        message: 'createdAtRelative cannot be combined with createdAtFrom/createdAtTo.'
      });
    }

    // This rule keeps tag any-filter semantics deterministic between id and name modes.
    if (payload.tagIdsAny && payload.tagNamesAny) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['tagNamesAny'],
        message: 'Use either tagIdsAny or tagNamesAny, not both.'
      });
    }

    // This rule keeps tag all-filter semantics deterministic between id and name modes.
    if (payload.tagIdsAll && payload.tagNamesAll) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['tagNamesAll'],
        message: 'Use either tagIdsAll or tagNamesAll, not both.'
      });
    }

    // This rule avoids mixing collection ids and collection names in one selector axis.
    if (payload.collectionId && payload.collectionNamesAny) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['collectionNamesAny'],
        message: 'Use either collectionId or collectionNamesAny, not both.'
      });
    }

    // This rule validates timezone identifiers early so runtime filtering stays deterministic.
    if (payload.timeZone && !isValidTimeZone(payload.timeZone)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['timeZone'],
        message: 'timeZone must be a valid IANA identifier.'
      });
    }
  });

// This schema validates one compact field projection list for token-efficient reads.
export const fieldsSchema = z.array(z.string().trim().min(1).max(80)).max(100).default([]);

export const serverInfoSchema = z.object({});

export const getStatsSchema = z.object({
  selector: selectorSchema.optional()
});

export const queryLinksSchema = z.object({
  selector: selectorSchema.optional(),
  limit: z.number().int().min(1).max(500).default(50),
  cursor: z.string().min(8).optional(),
  fields: fieldsSchema,
  verbosity: verbositySchema
});

export const aggregateLinksSchema = z.object({
  selector: selectorSchema.optional(),
  groupBy: z.enum(['collection', 'tag', 'domain', 'pinned', 'archived']).default('collection'),
  topN: z.number().int().min(1).max(500).default(50)
});

export const getLinkSchema = z.object({
  id: z.number().int().positive(),
  fields: fieldsSchema,
  verbosity: verbositySchema
});

// This schema captures one deterministic link mutation payload for selector-based batch writes.
export const mutateLinksSchema = z
  .object({
    selector: selectorSchema.optional(),
    ids: z.array(z.number().int().positive()).min(1).optional(),
    updates: z
      .object({
        title: z.string().trim().min(1).max(2000).optional(),
        url: z.string().url().optional(),
        description: z.string().max(4000).optional(),
        collectionId: z.number().int().positive().nullable().optional(),
        pinned: z.boolean().optional(),
        archived: z.boolean().optional(),
        tagMode: z.enum(['replace', 'add', 'remove']).default('add'),
        tagNames: z.array(z.string().trim().min(1).max(80)).max(200).optional(),
        createMissingTags: z.boolean().default(true)
      })
      .refine((value) => Object.keys(value).length > 0, 'At least one update field must be provided.'),
    dryRun: z.boolean().default(true),
    previewLimit: z.number().int().min(1).max(200).default(20),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.selector) || Boolean(value.ids), 'Either selector or ids must be provided.');

export const deleteLinksSchema = z
  .object({
    selector: selectorSchema.optional(),
    ids: z.array(z.number().int().positive()).min(1).optional(),
    mode: z.enum(['soft', 'hard']).default('soft'),
    dryRun: z.boolean().default(true),
    archiveCollectionId: z.number().int().positive().optional(),
    markTagName: z.string().trim().min(1).max(80).default('to-delete'),
    previewLimit: z.number().int().min(1).max(200).default(20),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.selector) || Boolean(value.ids), 'Either selector or ids must be provided.');

export const listCollectionsSchema = z.object({
  limit: z.number().int().min(1).max(500).default(100),
  offset: z.number().int().min(0).default(0)
});

export const createCollectionSchema = z.object({
  name: z.string().trim().min(1).max(160),
  parentId: z.number().int().positive().nullable().optional()
});

export const updateCollectionSchema = z.object({
  id: z.number().int().positive(),
  updates: z
    .object({
      name: z.string().trim().min(1).max(160).optional(),
      parentId: z.number().int().positive().nullable().optional()
    })
    .refine((value) => Object.keys(value).length > 0, 'At least one update field must be provided.')
});

export const deleteCollectionSchema = z.object({
  id: z.number().int().positive()
});

export const listTagsSchema = z.object({
  limit: z.number().int().min(1).max(500).default(100),
  offset: z.number().int().min(0).default(0)
});

export const createTagSchema = z.object({
  name: z.string().trim().min(1).max(80)
});

export const deleteTagSchema = z.object({
  id: z.number().int().positive()
});

export const assignTagsSchema = z
  .object({
    selector: selectorSchema.optional(),
    linkIds: z.array(z.number().int().positive()).min(1).optional(),
    tagNames: z.array(z.string().trim().min(1).max(80)).min(1).max(200),
    mode: z.enum(['replace', 'add', 'remove']).default('add'),
    createMissingTags: z.boolean().default(true),
    dryRun: z.boolean().default(true),
    previewLimit: z.number().int().min(1).max(200).default(20),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.selector) || Boolean(value.linkIds), 'Either selector or linkIds must be provided.');

export const governedTagLinksSchema = z
  .object({
    selector: selectorSchema.optional(),
    linkIds: z.array(z.number().int().positive()).min(1).optional(),
    dryRun: z.boolean().default(true),
    previewLimit: z.number().int().min(1).max(200).default(50),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.selector) || Boolean(value.linkIds), 'Either selector or linkIds must be provided.');

export const normalizeUrlsSchema = z
  .object({
    selector: selectorSchema.optional(),
    linkIds: z.array(z.number().int().positive()).min(1).optional(),
    removeUtm: z.boolean().default(true),
    removeKnownTracking: z.boolean().default(true),
    keepParams: z.array(z.string().trim().min(1).max(120)).max(200).default([]),
    extraTrackingParams: z.array(z.string().trim().min(1).max(120)).max(200).default([]),
    dryRun: z.boolean().default(true),
    previewLimit: z.number().int().min(1).max(200).default(20),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.selector) || Boolean(value.linkIds), 'Either selector or linkIds must be provided.');

export const findDuplicatesSchema = z.object({
  selector: selectorSchema.optional(),
  includeArchived: z.boolean().default(true),
  topN: z.number().int().min(1).max(500).default(100)
});

export const mergeDuplicatesSchema = z.object({
  groups: z
    .array(
      z.object({
        canonicalUrl: z.string().url(),
        linkIds: z.array(z.number().int().positive()).min(2),
        keepId: z.number().int().positive().optional()
      })
    )
    .min(1),
  keepStrategy: z.enum(['lowestId', 'highestId']).default('lowestId'),
  deleteMode: z.enum(['soft', 'hard']).default('soft'),
  archiveCollectionId: z.number().int().positive().optional(),
  markTagName: z.string().trim().min(1).max(80).default('to-delete'),
  dryRun: z.boolean().default(true),
  idempotencyKey: z.string().trim().min(8).max(128).optional()
});

export const createRuleSchema = z.object({
  name: z.string().trim().min(1).max(160),
  selector: selectorSchema,
  action: z.record(z.string(), z.unknown()),
  schedule: z.record(z.string(), z.unknown()).default({}),
  enabled: z.boolean().default(true)
});

export const testRuleSchema = z.object({
  id: z.string().min(8),
  limit: z.number().int().min(1).max(500).default(50)
});

export const applyRuleSchema = z.object({
  id: z.string().min(8),
  dryRun: z.boolean().default(true),
  idempotencyKey: z.string().trim().min(8).max(128).optional()
});

export const runRulesNowSchema = z.object({
  ids: z.array(z.string().min(8)).optional(),
  dryRun: z.boolean().default(true)
});

export const getNewLinksRoutineStatusSchema = z.object({});

export const runNewLinksRoutineNowSchema = z.object({});

export const getLink404MonitorStatusSchema = z.object({});

export const runLink404MonitorNowSchema = z.object({});

// This schema captures one chat-link capture request with optional URL extraction from chat text.
export const captureChatLinksSchema = z
  .object({
    urls: z.array(z.string().url()).min(1).max(500).optional(),
    chatText: z.string().max(200_000).optional(),
    aiName: z.string().trim().min(1).max(120).default('ChatGPT'),
    // This field should be set to the current chat title whenever the calling client can provide it.
    chatName: z
      .string()
      .trim()
      .min(1)
      .max(160)
      .default('Current Chat')
      .describe('Preferred target chat collection name. Use the current chat title whenever available.'),
    // These aliases keep compatibility with clients that expose conversation metadata under alternative keys.
    chatTitle: z.string().trim().min(1).max(160).optional(),
    conversationTitle: z.string().trim().min(1).max(160).optional(),
    threadTitle: z.string().trim().min(1).max(160).optional(),
    dryRun: z.boolean().default(false),
    previewLimit: z.number().int().min(1).max(200).default(50),
    idempotencyKey: z.string().trim().min(8).max(128).optional()
  })
  .refine((value) => Boolean(value.chatText) || Boolean(value.urls && value.urls.length > 0), {
    message: 'Either urls or chatText must be provided.'
  });

export const listRulesSchema = z.object({
  enabledOnly: z.boolean().default(false)
});

export const deleteRuleSchema = z.object({
  id: z.string().min(8)
});

export const createSavedQuerySchema = z.object({
  name: z.string().trim().min(1).max(160),
  selector: selectorSchema.default({ includeDescendants: false }),
  fields: fieldsSchema,
  verbosity: verbositySchema
});

export const listSavedQueriesSchema = z.object({});

export const runSavedQuerySchema = z.object({
  id: z.string().min(8),
  limit: z.number().int().min(1).max(500).default(50),
  cursor: z.string().min(8).optional()
});

export const getAuditSchema = z.object({
  limit: z.number().int().min(1).max(500).default(100),
  offset: z.number().int().min(0).default(0)
});

export const undoOperationSchema = z.object({
  operationId: z.string().min(8)
});

// This registry maps tool names to runtime schemas for strict MCP argument validation.
export const toolSchemas = {
  linkwarden_get_server_info: serverInfoSchema,
  linkwarden_get_stats: getStatsSchema,
  linkwarden_query_links: queryLinksSchema,
  linkwarden_aggregate_links: aggregateLinksSchema,
  linkwarden_get_link: getLinkSchema,
  linkwarden_mutate_links: mutateLinksSchema,
  linkwarden_delete_links: deleteLinksSchema,
  linkwarden_list_collections: listCollectionsSchema,
  linkwarden_create_collection: createCollectionSchema,
  linkwarden_update_collection: updateCollectionSchema,
  linkwarden_delete_collection: deleteCollectionSchema,
  linkwarden_list_tags: listTagsSchema,
  linkwarden_create_tag: createTagSchema,
  linkwarden_delete_tag: deleteTagSchema,
  linkwarden_assign_tags: assignTagsSchema,
  linkwarden_governed_tag_links: governedTagLinksSchema,
  linkwarden_normalize_urls: normalizeUrlsSchema,
  linkwarden_find_duplicates: findDuplicatesSchema,
  linkwarden_merge_duplicates: mergeDuplicatesSchema,
  linkwarden_create_rule: createRuleSchema,
  linkwarden_test_rule: testRuleSchema,
  linkwarden_apply_rule: applyRuleSchema,
  linkwarden_run_rules_now: runRulesNowSchema,
  linkwarden_capture_chat_links: captureChatLinksSchema,
  linkwarden_get_new_links_routine_status: getNewLinksRoutineStatusSchema,
  linkwarden_run_new_links_routine_now: runNewLinksRoutineNowSchema,
  linkwarden_get_link_404_monitor_status: getLink404MonitorStatusSchema,
  linkwarden_run_link_404_monitor_now: runLink404MonitorNowSchema,
  linkwarden_list_rules: listRulesSchema,
  linkwarden_delete_rule: deleteRuleSchema,
  linkwarden_create_saved_query: createSavedQuerySchema,
  linkwarden_list_saved_queries: listSavedQueriesSchema,
  linkwarden_run_saved_query: runSavedQuerySchema,
  linkwarden_get_audit: getAuditSchema,
  linkwarden_undo_operation: undoOperationSchema
} as const;

// This helper exports MCP tool metadata so discovery always reflects the alpha tool surface.
export function buildToolList(): McpTool[] {
  const entries: Array<{ name: keyof typeof toolSchemas; description: string }> = [
    { name: 'linkwarden_get_server_info', description: 'Return MCP server metadata and protocol info.' },
    { name: 'linkwarden_get_stats', description: 'Return hard counters for links, collections, tags, pinned, and archived.' },
    { name: 'linkwarden_query_links', description: 'Query links with deterministic cursor paging, selector filters, and projection.' },
    { name: 'linkwarden_aggregate_links', description: 'Aggregate links by collection, tag, domain, pinned, or archived state.' },
    { name: 'linkwarden_get_link', description: 'Return one link by id with optional field projection and verbosity controls.' },
    { name: 'linkwarden_mutate_links', description: 'Mutate links selected by ids/selector with dry-run and idempotency support.' },
    { name: 'linkwarden_delete_links', description: 'Delete links in soft or hard mode with dry-run and idempotency support.' },
    { name: 'linkwarden_list_collections', description: 'List collections with deterministic offset paging.' },
    { name: 'linkwarden_create_collection', description: 'Create one collection and optionally assign a parent.' },
    { name: 'linkwarden_update_collection', description: 'Rename or move one collection.' },
    { name: 'linkwarden_delete_collection', description: 'Delete one collection by id.' },
    { name: 'linkwarden_list_tags', description: 'List tags with deterministic offset paging.' },
    { name: 'linkwarden_create_tag', description: 'Create one tag by name.' },
    { name: 'linkwarden_delete_tag', description: 'Delete one tag by id.' },
    { name: 'linkwarden_assign_tags', description: 'Assign, replace, or remove tags on selected links.' },
    {
      name: 'linkwarden_governed_tag_links',
      description:
        'Scan links, reuse existing taxonomy, create bounded new tags, and assign tags in one governed run.'
    },
    { name: 'linkwarden_normalize_urls', description: 'Normalize URLs by removing tracking parameters with dry-run/apply.' },
    { name: 'linkwarden_find_duplicates', description: 'Find duplicate links by canonical URL grouping.' },
    { name: 'linkwarden_merge_duplicates', description: 'Merge duplicate groups and delete redundant items.' },
    { name: 'linkwarden_create_rule', description: 'Create one persisted automation rule.' },
    { name: 'linkwarden_test_rule', description: 'Test one rule in read-only preview mode.' },
    { name: 'linkwarden_apply_rule', description: 'Apply one rule immediately in dry-run or write mode.' },
    { name: 'linkwarden_run_rules_now', description: 'Run all or selected rules now with per-user locking.' },
    {
      name: 'linkwarden_capture_chat_links',
      description:
        'Capture links from AI chat text or URL lists into AI Chats > <AI Name> > <Chat Name> with deterministic dedupe. Always pass the current chat title as chatName when available.'
    },
    {
      name: 'linkwarden_get_new_links_routine_status',
      description: 'Return user-specific status, schedule, and warnings for automatic processing of newly created links.'
    },
    {
      name: 'linkwarden_run_new_links_routine_now',
      description: 'Run the user-specific new-links routine immediately via the native scheduler service.'
    },
    {
      name: 'linkwarden_get_link_404_monitor_status',
      description: 'Return user-specific status, schedule, and warnings for automatic 404 link monitoring.'
    },
    {
      name: 'linkwarden_run_link_404_monitor_now',
      description: 'Run the user-specific 404 monitor immediately via the native scheduler service.'
    },
    { name: 'linkwarden_list_rules', description: 'List persisted rules for the current user.' },
    { name: 'linkwarden_delete_rule', description: 'Delete one rule by id.' },
    { name: 'linkwarden_create_saved_query', description: 'Create one persisted saved query for short-id execution.' },
    { name: 'linkwarden_list_saved_queries', description: 'List saved queries for the current user.' },
    { name: 'linkwarden_run_saved_query', description: 'Execute one saved query by id with cursor paging.' },
    { name: 'linkwarden_get_audit', description: 'Return audit and operation history for the current user.' },
    { name: 'linkwarden_undo_operation', description: 'Undo one previously recorded operation by id when still eligible.' }
  ];

  return entries.map((entry) => ({
    name: entry.name,
    description: entry.description,
    inputSchema: zodToJsonSchema(toolSchemas[entry.name], entry.name) as Record<string, unknown>
  }));
}
