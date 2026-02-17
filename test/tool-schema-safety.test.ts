// This test suite verifies strict safety contracts for confirm-gated and bounded tools.

import { describe, expect, it } from 'vitest';
import {
  assignTagsSchema,
  applyPlanSchema,
  buildToolList,
  bulkUpdateSchema,
  captureChatLinksSchema,
  cleanLinkUrlsSchema,
  connectorFetchSchema,
  connectorSearchSchema,
  createCollectionSchema,
  createTagSchema,
  deleteCollectionSchema,
  deleteTagSchema,
  listCollectionsSchema,
  monitorOfflineLinksSchema,
  runDailyMaintenanceSchema,
  setLinksCollectionSchema,
  setLinksPinnedSchema,
  serverInfoSchema,
  searchLinksSchema
} from '../src/mcp/tool-schemas.js';

describe('tool schema safety', () => {
  it('requires exact APPLY confirmation', () => {
    expect(() =>
      applyPlanSchema.parse({
        plan_id: '12345678',
        confirm: 'apply'
      })
    ).toThrow();

    expect(
      applyPlanSchema.parse({
        plan_id: '12345678',
        confirm: 'APPLY'
      })
    ).toMatchObject({ confirm: 'APPLY' });
  });

  it('defaults bulk updates to dry-run mode', () => {
    const parsed = bulkUpdateSchema.parse({
      linkIds: [1, 2],
      updates: {
        tagIds: [8, 9]
      }
    });

    expect(parsed.dryRun).toBe(true);
    expect(parsed.mode).toBe('replace');
  });

  it('validates connector-compatible search and fetch inputs', () => {
    expect(() =>
      connectorSearchSchema.parse({
        query: ''
      })
    ).toThrow();

    expect(() =>
      connectorFetchSchema.parse({
        id: ''
      })
    ).toThrow();

    expect(
      connectorSearchSchema.parse({
        query: 'mail security'
      })
    ).toMatchObject({
      query: 'mail security'
    });

    expect(
      connectorFetchSchema.parse({
        id: '42'
      })
    ).toMatchObject({
      id: '42'
    });
  });

  it('lists connector-compatible search/fetch tools for ChatGPT connectors', () => {
    const toolNames = buildToolList().map((tool) => tool.name);

    expect(toolNames).toContain('search');
    expect(toolNames).toContain('fetch');
    expect(toolNames).toContain('linkwarden_get_server_info');
    expect(toolNames).toContain('linkwarden_capture_chat_links');
    expect(toolNames).toContain('linkwarden_monitor_offline_links');
    expect(toolNames).toContain('linkwarden_run_daily_maintenance');
    expect(toolNames).toContain('linkwarden_create_tag');
    expect(toolNames).toContain('linkwarden_delete_tag');
    expect(toolNames).toContain('linkwarden_assign_tags');
    expect(toolNames).toContain('linkwarden_create_collection');
    expect(toolNames).toContain('linkwarden_update_collection');
    expect(toolNames).toContain('linkwarden_delete_collection');
    expect(toolNames).toContain('linkwarden_set_links_collection');
    expect(toolNames).toContain('linkwarden_set_links_pinned');
    expect(toolNames).toContain('linkwarden_clean_link_urls');
  });

  it('validates server info tool input as empty object', () => {
    expect(serverInfoSchema.parse({})).toMatchObject({});
  });

  it('defaults chat capture and offline monitor tools to safe modes', () => {
    const captureParsed = captureChatLinksSchema.parse({
      chatName: 'SEO Ideen',
      text: 'https://example.com/a https://example.com/b'
    });

    expect(captureParsed.dryRun).toBe(false);
    expect(captureParsed.parentCollectionName).toBe('ChatGPT Chats');

    const monitorParsed = monitorOfflineLinksSchema.parse({});
    expect(monitorParsed.dryRun).toBe(true);
    expect(monitorParsed.offlineDays).toBeUndefined();
    expect(monitorParsed.minConsecutiveFailures).toBeUndefined();
    expect(monitorParsed.action).toBeUndefined();
    expect(monitorParsed.offset).toBe(0);
    expect(monitorParsed.limit).toBeUndefined();
  });

  it('keeps daily maintenance in dry-run mode by default', () => {
    const parsed = runDailyMaintenanceSchema.parse({
      reorg: {
        strategy: 'dedupe-tags',
        parameters: {}
      }
    });

    expect(parsed.apply).toBe(false);
    expect(parsed.confirm).toBeUndefined();

    // This assertion ensures offline paging defaults remain deterministic when the section is present.
    const parsedWithOffline = runDailyMaintenanceSchema.parse({
      offline: {}
    });
    expect(parsedWithOffline.offline?.offset).toBe(0);
  });

  it('supports unlimited mode when limit is omitted', () => {
    const searchParsed = searchLinksSchema.parse({
      query: 'hotel'
    });
    expect(searchParsed.limit).toBeUndefined();
    expect(searchParsed.offset).toBe(0);
    expect(searchParsed.pinned).toBeUndefined();

    const pinnedSearchParsed = searchLinksSchema.parse({
      query: '*',
      pinned: true
    });
    expect(pinnedSearchParsed.pinned).toBe(true);

    const collectionsParsed = listCollectionsSchema.parse({});
    expect(collectionsParsed.limit).toBeUndefined();
    expect(collectionsParsed.offset).toBe(0);
  });

  it('validates tag create/delete and name-based assignment schemas', () => {
    expect(
      createTagSchema.parse({
        name: '  Security  '
      })
    ).toMatchObject({
      name: 'Security'
    });

    expect(
      deleteTagSchema.parse({
        id: 42
      })
    ).toMatchObject({
      id: 42
    });

    const assignParsed = assignTagsSchema.parse({
      linkIds: [1, 2, 3],
      tagNames: ['Security', 'DNS']
    });
    expect(assignParsed.mode).toBe('add');
    expect(assignParsed.createMissingTags).toBe(true);
    expect(assignParsed.dryRun).toBe(true);
  });

  it('validates collection and link utility schemas with safe dry-run defaults', () => {
    expect(
      createCollectionSchema.parse({
        name: '  Service  ',
        parentId: null
      })
    ).toMatchObject({
      name: 'Service',
      parentId: null
    });

    expect(
      deleteCollectionSchema.parse({
        id: 77
      })
    ).toMatchObject({
      id: 77
    });

    const setCollectionParsed = setLinksCollectionSchema.parse({
      linkIds: [1, 2],
      collectionId: null
    });
    expect(setCollectionParsed.dryRun).toBe(true);

    const setPinnedParsed = setLinksPinnedSchema.parse({
      linkIds: [1],
      pinned: true
    });
    expect(setPinnedParsed.dryRun).toBe(true);

    const cleanParsed = cleanLinkUrlsSchema.parse({
      linkIds: [1, 2, 3]
    });
    expect(cleanParsed.dryRun).toBe(true);
    expect(cleanParsed.removeUtm).toBe(true);
    expect(cleanParsed.removeKnownTracking).toBe(true);
  });
});
