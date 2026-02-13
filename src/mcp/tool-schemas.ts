// This module defines all MCP tool contracts with strict input validation and bounded defaults.

import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import type { McpTool } from '../types/mcp.js';

// This schema keeps paging bounded for all list/search tools.
const pagingSchema = {
  limit: z.number().int().min(1).max(100).default(20),
  offset: z.number().int().min(0).default(0)
};

export const searchLinksSchema = z.object({
  query: z.string().min(1),
  limit: pagingSchema.limit,
  offset: pagingSchema.offset,
  collectionId: z.number().int().positive().optional(),
  tagIds: z.array(z.number().int().positive()).max(50).optional(),
  archived: z.boolean().optional()
});

export const listCollectionsSchema = z.object({
  limit: pagingSchema.limit,
  offset: pagingSchema.offset
});

export const listTagsSchema = z.object({
  limit: pagingSchema.limit,
  offset: pagingSchema.offset
});

export const getLinkSchema = z.object({
  id: z.number().int().positive()
});

const planScopeSchema = z.object({
  query: z.string().min(1).optional(),
  collectionId: z.number().int().positive().optional(),
  tagIds: z.array(z.number().int().positive()).max(50).optional(),
  archived: z.boolean().optional()
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
      archived: z.boolean().optional()
    })
    .refine((data) => Object.keys(data).length > 0, 'At least one update field must be provided.')
});

export const bulkUpdateSchema = z.object({
  linkIds: z.array(z.number().int().positive()).min(1).max(500),
  updates: z
    .object({
      collectionId: z.number().int().positive().optional(),
      tagIds: z.array(z.number().int().positive()).max(100).optional()
    })
    .refine((data) => Object.keys(data).length > 0, 'At least one update field must be provided.'),
  mode: z.enum(['replace', 'add', 'remove']).default('replace'),
  dryRun: z.boolean().default(true),
  previewLimit: z.number().int().min(1).max(100).default(20)
});

export const suggestTaxonomySchema = z.object({
  query: z.string().optional(),
  limit: z.number().int().min(1).max(200).default(100)
});

// This registry maps tool names to runtime schemas.
export const toolSchemas = {
  linkwarden_search_links: searchLinksSchema,
  linkwarden_list_collections: listCollectionsSchema,
  linkwarden_list_tags: listTagsSchema,
  linkwarden_get_link: getLinkSchema,
  linkwarden_plan_reorg: planReorgSchema,
  linkwarden_apply_plan: applyPlanSchema,
  linkwarden_update_link: updateLinkSchema,
  linkwarden_bulk_update_links: bulkUpdateSchema,
  linkwarden_suggest_taxonomy: suggestTaxonomySchema
} as const;

// This helper exports tool metadata used by MCP tools/list responses.
export function buildToolList(): McpTool[] {
  return [
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
      name: 'linkwarden_list_tags',
      description: 'List tags with paging.',
      inputSchema: zodToJsonSchema(listTagsSchema, 'linkwarden_list_tags') as Record<string, unknown>
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
      name: 'linkwarden_bulk_update_links',
      description: 'Bulk update links with replace/add/remove tag mode and optional dry-run preview.',
      inputSchema: zodToJsonSchema(bulkUpdateSchema, 'linkwarden_bulk_update_links') as Record<string, unknown>
    },
    {
      name: 'linkwarden_suggest_taxonomy',
      description: 'Suggest a taxonomy from scoped links without writing any data.',
      inputSchema: zodToJsonSchema(suggestTaxonomySchema, 'linkwarden_suggest_taxonomy') as Record<string, unknown>
    }
  ];
}
