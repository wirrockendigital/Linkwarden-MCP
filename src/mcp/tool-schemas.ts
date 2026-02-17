// This module defines all MCP tool contracts with strict input validation and safe defaults.

import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import type { McpTool } from '../types/mcp.js';

// This schema keeps paging flexible so tools can process full datasets when limit is omitted.
const pagingSchema = {
  limit: z.number().int().min(1).optional(),
  offset: z.number().int().min(0).default(0)
};

export const searchLinksSchema = z.object({
  query: z.string().min(1),
  limit: pagingSchema.limit,
  offset: pagingSchema.offset,
  collectionId: z.number().int().positive().optional(),
  collection_id: z.number().int().positive().optional(),
  tagIds: z.array(z.number().int().positive()).max(50).optional(),
  tag_ids: z.array(z.number().int().positive()).max(50).optional(),
  archived: z.boolean().optional(),
  pinned: z.boolean().optional(),
  debug: z.boolean().optional()
});

// This schema keeps the generic connector search tool aligned with OpenAI search/fetch expectations.
export const connectorSearchSchema = z.object({
  query: z.string().min(1)
});

// This schema keeps the generic connector fetch tool input compact and deterministic.
export const connectorFetchSchema = z.object({
  id: z.string().min(1)
});

// This schema keeps server info retrieval argument-free and deterministic.
export const serverInfoSchema = z.object({});

export const listCollectionsSchema = z.object({
  limit: pagingSchema.limit,
  offset: pagingSchema.offset
});

// This schema creates one collection and supports optional parent assignment for nested trees.
export const createCollectionSchema = z.object({
  name: z.string().trim().min(1).max(160),
  parentId: z.number().int().positive().nullable().optional()
});

// This schema updates one collection for rename and/or move operations.
export const updateCollectionSchema = z.object({
  id: z.number().int().positive(),
  updates: z
    .object({
      name: z.string().trim().min(1).max(160).optional(),
      parentId: z.number().int().positive().nullable().optional()
    })
    .refine((data) => Object.keys(data).length > 0, 'At least one update field must be provided.')
});

// This schema deletes one collection by id.
export const deleteCollectionSchema = z.object({
  id: z.number().int().positive()
});

export const listTagsSchema = z.object({
  limit: pagingSchema.limit,
  offset: pagingSchema.offset
});

// This schema creates one tag and keeps naming constraints explicit for deterministic automation flows.
export const createTagSchema = z.object({
  name: z.string().trim().min(1).max(80)
});

// This schema deletes one tag by id.
export const deleteTagSchema = z.object({
  id: z.number().int().positive()
});

// This schema assigns tags to links by tag names and can auto-create missing tags when requested.
export const assignTagsSchema = z.object({
  linkIds: z.array(z.number().int().positive()).min(1),
  tagNames: z.array(z.string().trim().min(1).max(80)).min(1).max(50),
  mode: z.enum(['replace', 'add', 'remove']).default('add'),
  createMissingTags: z.boolean().default(true),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

export const getLinkSchema = z.object({
  id: z.number().int().positive()
});

const planScopeSchema = z.object({
  query: z.string().min(1).optional(),
  collectionId: z.number().int().positive().optional(),
  tagIds: z.array(z.number().int().positive()).max(50).optional(),
  archived: z.boolean().optional(),
  pinned: z.boolean().optional()
});

export const planReorgSchema = z.object({
  strategy: z.enum(['tag-by-keywords', 'move-to-collection', 'rename-tags', 'dedupe-tags']),
  parameters: z.record(z.string(), z.unknown()),
  scope: planScopeSchema.optional(),
  dryRun: z.literal(true).default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

export const applyPlanSchema = z.object({
  plan_id: z.string().min(8),
  confirm: z.literal('APPLY')
});

export const updateLinkSchema = z.object({
  id: z.number().int().positive(),
  updates: z
    .object({
      title: z.string().min(1).optional(),
      url: z.string().url().optional(),
      description: z.string().max(4000).optional(),
      collectionId: z.number().int().positive().nullable().optional(),
      tagIds: z.array(z.number().int().positive()).max(100).optional(),
      archived: z.boolean().optional(),
      pinned: z.boolean().optional()
    })
    .refine((data) => Object.keys(data).length > 0, 'At least one update field must be provided.')
});

// This schema assigns one collection (or null) to multiple links with dry-run preview support.
export const setLinksCollectionSchema = z.object({
  linkIds: z.array(z.number().int().positive()).min(1),
  collectionId: z.number().int().positive().nullable(),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

// This schema pins or unpins multiple links with dry-run preview support.
export const setLinksPinnedSchema = z.object({
  linkIds: z.array(z.number().int().positive()).min(1),
  pinned: z.boolean(),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

export const bulkUpdateSchema = z.object({
  // This array stays unbounded so batch operations can target every matching link.
  linkIds: z.array(z.number().int().positive()).min(1),
  updates: z
    .object({
      collectionId: z.number().int().positive().nullable().optional(),
      tagIds: z.array(z.number().int().positive()).max(100).optional()
    })
    .refine((data) => Object.keys(data).length > 0, 'At least one update field must be provided.'),
  mode: z.enum(['replace', 'add', 'remove']).default('replace'),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

// This schema removes tracking parameters from link URLs while keeping a dry-run preview by default.
export const cleanLinkUrlsSchema = z.object({
  linkIds: z.array(z.number().int().positive()).min(1),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20),
  removeUtm: z.boolean().default(true),
  removeKnownTracking: z.boolean().default(true),
  keepParams: z.array(z.string().trim().min(1).max(120)).max(200).default([]),
  extraTrackingParams: z.array(z.string().trim().min(1).max(120)).max(200).default([])
});

export const suggestTaxonomySchema = z.object({
  query: z.string().optional(),
  limit: z.number().int().min(1).optional()
});

export const captureChatLinksSchema = z.object({
  chatName: z.string().min(1).max(160),
  text: z.string().min(1).max(250_000),
  parentCollectionName: z.string().min(1).max(160).default('ChatGPT Chats'),
  dedupeByUrl: z.boolean().default(true),
  // This optional cap lets callers decide whether to ingest all extracted URLs or only a subset.
  maxLinks: z.number().int().min(1).optional(),
  dryRun: z.boolean().default(false)
});

export const monitorOfflineLinksSchema = z.object({
  scope: planScopeSchema.optional(),
  offset: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).optional(),
  timeoutMs: z.number().int().min(1000).max(15000).default(5000),
  offlineDays: z.number().int().min(1).max(365).optional(),
  minConsecutiveFailures: z.number().int().min(1).max(30).optional(),
  action: z.enum(['archive', 'delete', 'none']).optional(),
  archiveCollectionId: z.number().int().positive().optional(),
  dryRun: z.boolean().default(true),
  debug: z.boolean().optional()
});

export const runDailyMaintenanceSchema = z.object({
  reorg: z
    .object({
      strategy: z.enum(['tag-by-keywords', 'move-to-collection', 'rename-tags', 'dedupe-tags']),
      parameters: z.record(z.string(), z.unknown()),
      scope: planScopeSchema.optional(),
      previewLimit: z.number().int().min(1).max(100).default(20)
    })
    .optional(),
  offline: z
    .object({
      scope: planScopeSchema.optional(),
      offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).optional(),
      timeoutMs: z.number().int().min(1000).max(15000).default(5000),
      offlineDays: z.number().int().min(1).max(365).optional(),
      minConsecutiveFailures: z.number().int().min(1).max(30).optional(),
      action: z.enum(['archive', 'delete', 'none']).optional(),
      archiveCollectionId: z.number().int().positive().optional()
    })
    .optional(),
  apply: z.boolean().default(false),
  confirm: z.literal('APPLY').optional()
});

// This registry maps tool names to runtime schemas.
export const toolSchemas = {
  search: connectorSearchSchema,
  fetch: connectorFetchSchema,
  linkwarden_get_server_info: serverInfoSchema,
  linkwarden_search_links: searchLinksSchema,
  linkwarden_list_collections: listCollectionsSchema,
  linkwarden_create_collection: createCollectionSchema,
  linkwarden_update_collection: updateCollectionSchema,
  linkwarden_delete_collection: deleteCollectionSchema,
  linkwarden_list_tags: listTagsSchema,
  linkwarden_create_tag: createTagSchema,
  linkwarden_delete_tag: deleteTagSchema,
  linkwarden_assign_tags: assignTagsSchema,
  linkwarden_get_link: getLinkSchema,
  linkwarden_plan_reorg: planReorgSchema,
  linkwarden_apply_plan: applyPlanSchema,
  linkwarden_update_link: updateLinkSchema,
  linkwarden_set_links_collection: setLinksCollectionSchema,
  linkwarden_set_links_pinned: setLinksPinnedSchema,
  linkwarden_bulk_update_links: bulkUpdateSchema,
  linkwarden_clean_link_urls: cleanLinkUrlsSchema,
  linkwarden_suggest_taxonomy: suggestTaxonomySchema,
  linkwarden_capture_chat_links: captureChatLinksSchema,
  linkwarden_monitor_offline_links: monitorOfflineLinksSchema,
  linkwarden_run_daily_maintenance: runDailyMaintenanceSchema
} as const;

// This helper exports tool metadata used by MCP tools/list responses.
export function buildToolList(): McpTool[] {
  return [
    {
      name: 'search',
      description: 'Connector-compatible search tool that returns results[] with id, title, and url.',
      inputSchema: zodToJsonSchema(connectorSearchSchema, 'search') as Record<string, unknown>
    },
    {
      name: 'fetch',
      description: 'Connector-compatible fetch tool that returns one document by id.',
      inputSchema: zodToJsonSchema(connectorFetchSchema, 'fetch') as Record<string, unknown>
    },
    {
      name: 'linkwarden_get_server_info',
      description: 'Return MCP server name, version, and protocol metadata.',
      inputSchema: zodToJsonSchema(serverInfoSchema, 'linkwarden_get_server_info') as Record<string, unknown>
    },
    {
      name: 'linkwarden_search_links',
      description: 'Search links by text query with optional collection/tag/archive filters and paging.',
      inputSchema: zodToJsonSchema(searchLinksSchema, 'linkwarden_search_links') as Record<string, unknown>
    },
    {
      name: 'linkwarden_list_collections',
      description: 'List collections with paging.',
      inputSchema: zodToJsonSchema(listCollectionsSchema, 'linkwarden_list_collections') as Record<string, unknown>
    },
    {
      name: 'linkwarden_create_collection',
      description: 'Create one collection (optionally nested under parentId). Requires write mode.',
      inputSchema: zodToJsonSchema(createCollectionSchema, 'linkwarden_create_collection') as Record<string, unknown>
    },
    {
      name: 'linkwarden_update_collection',
      description: 'Rename or move one collection by id. Requires write mode.',
      inputSchema: zodToJsonSchema(updateCollectionSchema, 'linkwarden_update_collection') as Record<string, unknown>
    },
    {
      name: 'linkwarden_delete_collection',
      description: 'Delete one collection by id. Requires write mode.',
      inputSchema: zodToJsonSchema(deleteCollectionSchema, 'linkwarden_delete_collection') as Record<string, unknown>
    },
    {
      name: 'linkwarden_list_tags',
      description: 'List tags with paging.',
      inputSchema: zodToJsonSchema(listTagsSchema, 'linkwarden_list_tags') as Record<string, unknown>
    },
    {
      name: 'linkwarden_create_tag',
      description: 'Create one tag by name (idempotent by normalized name). Requires write mode.',
      inputSchema: zodToJsonSchema(createTagSchema, 'linkwarden_create_tag') as Record<string, unknown>
    },
    {
      name: 'linkwarden_delete_tag',
      description: 'Delete one tag by id. Requires write mode.',
      inputSchema: zodToJsonSchema(deleteTagSchema, 'linkwarden_delete_tag') as Record<string, unknown>
    },
    {
      name: 'linkwarden_assign_tags',
      description:
        'Assign tags to links by tag names with replace/add/remove mode and optional auto-create for missing tags.',
      inputSchema: zodToJsonSchema(assignTagsSchema, 'linkwarden_assign_tags') as Record<string, unknown>
    },
    {
      name: 'linkwarden_get_link',
      description: 'Get one link by id with bounded details.',
      inputSchema: zodToJsonSchema(getLinkSchema, 'linkwarden_get_link') as Record<string, unknown>
    },
    {
      name: 'linkwarden_plan_reorg',
      description:
        'Create a dry-run reorganization plan (tag-by-keywords, move-to-collection, rename-tags, dedupe-tags).',
      inputSchema: zodToJsonSchema(planReorgSchema, 'linkwarden_plan_reorg') as Record<string, unknown>
    },
    {
      name: 'linkwarden_apply_plan',
      description: 'Apply a stored plan_id after explicit confirm=APPLY.',
      inputSchema: zodToJsonSchema(applyPlanSchema, 'linkwarden_apply_plan') as Record<string, unknown>
    },
    {
      name: 'linkwarden_update_link',
      description: 'Update one link. Requires write mode.',
      inputSchema: zodToJsonSchema(updateLinkSchema, 'linkwarden_update_link') as Record<string, unknown>
    },
    {
      name: 'linkwarden_set_links_collection',
      description: 'Assign or clear collection for multiple links with dry-run preview. Requires write mode.',
      inputSchema: zodToJsonSchema(setLinksCollectionSchema, 'linkwarden_set_links_collection') as Record<string, unknown>
    },
    {
      name: 'linkwarden_set_links_pinned',
      description: 'Pin or unpin multiple links with dry-run preview. Requires write mode.',
      inputSchema: zodToJsonSchema(setLinksPinnedSchema, 'linkwarden_set_links_pinned') as Record<string, unknown>
    },
    {
      name: 'linkwarden_bulk_update_links',
      description: 'Bulk update links with replace/add/remove tag mode and optional dry-run preview.',
      inputSchema: zodToJsonSchema(bulkUpdateSchema, 'linkwarden_bulk_update_links') as Record<string, unknown>
    },
    {
      name: 'linkwarden_clean_link_urls',
      description: 'Remove tracker parameters from link URLs with dry-run preview and optional apply.',
      inputSchema: zodToJsonSchema(cleanLinkUrlsSchema, 'linkwarden_clean_link_urls') as Record<string, unknown>
    },
    {
      name: 'linkwarden_suggest_taxonomy',
      description: 'Suggest a taxonomy from scoped links without writing any data.',
      inputSchema: zodToJsonSchema(suggestTaxonomySchema, 'linkwarden_suggest_taxonomy') as Record<string, unknown>
    },
    {
      name: 'linkwarden_capture_chat_links',
      description: 'Extract URLs from chat text and store them under ChatGPT Chats > Chat Name.',
      inputSchema: zodToJsonSchema(captureChatLinksSchema, 'linkwarden_capture_chat_links') as Record<string, unknown>
    },
    {
      name: 'linkwarden_monitor_offline_links',
      description: 'Check link reachability, track failure streaks, and optionally archive long-offline links.',
      inputSchema: zodToJsonSchema(monitorOfflineLinksSchema, 'linkwarden_monitor_offline_links') as Record<string, unknown>
    },
    {
      name: 'linkwarden_run_daily_maintenance',
      description: 'Run reorg + offline checks in one flow with safe dry-run defaults and optional apply.',
      inputSchema: zodToJsonSchema(runDailyMaintenanceSchema, 'linkwarden_run_daily_maintenance') as Record<string, unknown>
    }
  ];
}
