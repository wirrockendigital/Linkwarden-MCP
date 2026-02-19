// This test suite verifies core alpha schema defaults and tool discovery contracts.

import { describe, expect, it } from 'vitest';
import {
  aggregateLinksSchema,
  assignTagsSchema,
  buildToolList,
  createRuleSchema,
  createSavedQuerySchema,
  deleteLinksSchema,
  getNewLinksRoutineStatusSchema,
  governedTagLinksSchema,
  mutateLinksSchema,
  normalizeUrlsSchema,
  queryLinksSchema,
  runNewLinksRoutineNowSchema,
  runRulesNowSchema,
  selectorSchema,
  serverInfoSchema
} from '../src/mcp/tool-schemas.js';

describe('tool schema safety (alpha)', () => {
  it('validates server info tool input as empty object', () => {
    expect(serverInfoSchema.parse({})).toMatchObject({});
  });

  it('applies deterministic defaults for selector and query schemas', () => {
    const selector = selectorSchema.parse({});
    expect(selector.includeDescendants).toBe(false);

    const query = queryLinksSchema.parse({});
    expect(query.limit).toBe(50);
    expect(query.fields).toEqual([]);
    expect(query.verbosity).toBe('minimal');
  });

  it('rejects conflicting selector date and name/id axis filters', () => {
    expect(() =>
      selectorSchema.parse({
        createdAtFrom: '2026-01-01',
        createdAtRelative: {
          amount: 1,
          unit: 'month',
          mode: 'previous_calendar'
        }
      })
    ).toThrow();

    expect(() =>
      selectorSchema.parse({
        tagIdsAny: [1],
        tagNamesAny: ['wohnmobil']
      })
    ).toThrow();

    expect(() =>
      selectorSchema.parse({
        collectionId: 4,
        collectionNamesAny: ['Wohnmobil']
      })
    ).toThrow();
  });

  it('rejects invalid selector time zones', () => {
    expect(() =>
      selectorSchema.parse({
        timeZone: 'Invalid/Timezone'
      })
    ).toThrow();
  });

  it('keeps mutate and delete tools in dry-run mode by default', () => {
    const mutate = mutateLinksSchema.parse({
      ids: [1, 2],
      updates: {
        tagNames: ['alpha']
      }
    });
    expect(mutate.dryRun).toBe(true);
    expect(mutate.updates.tagMode).toBe('add');
    expect(mutate.updates.createMissingTags).toBe(true);

    const remove = deleteLinksSchema.parse({
      ids: [1, 2]
    });
    expect(remove.mode).toBe('soft');
    expect(remove.dryRun).toBe(true);
    expect(remove.markTagName).toBe('to-delete');
  });

  it('enforces selector-or-ids guardrails for write tools', () => {
    expect(() =>
      mutateLinksSchema.parse({
        updates: {
          title: 'x'
        }
      })
    ).toThrow();

    expect(() =>
      assignTagsSchema.parse({
        tagNames: ['x']
      })
    ).toThrow();
  });

  it('keeps governed-tagging, normalization and rule-run tools safe by default', () => {
    const governed = governedTagLinksSchema.parse({
      linkIds: [1]
    });
    expect(governed.dryRun).toBe(true);
    expect(governed.previewLimit).toBe(50);

    const normalize = normalizeUrlsSchema.parse({
      linkIds: [1]
    });
    expect(normalize.dryRun).toBe(true);
    expect(normalize.removeUtm).toBe(true);
    expect(normalize.removeKnownTracking).toBe(true);

    const runRules = runRulesNowSchema.parse({});
    expect(runRules.dryRun).toBe(true);

    expect(getNewLinksRoutineStatusSchema.parse({})).toEqual({});
    expect(runNewLinksRoutineNowSchema.parse({})).toEqual({});
  });

  it('validates aggregate and saved-query schemas with stable defaults', () => {
    const aggregate = aggregateLinksSchema.parse({});
    expect(aggregate.groupBy).toBe('collection');
    expect(aggregate.topN).toBe(50);

    const saved = createSavedQuerySchema.parse({
      name: 'Important',
      selector: {},
      fields: []
    });
    expect(saved.verbosity).toBe('minimal');
  });

  it('lists only alpha tool names (no legacy search/fetch/reorg names)', () => {
    const names = buildToolList().map((tool) => tool.name);
    expect(names).toHaveLength(32);
    expect(names).toContain('linkwarden_query_links');
    expect(names).toContain('linkwarden_governed_tag_links');
    expect(names).toContain('linkwarden_mutate_links');
    expect(names).toContain('linkwarden_delete_links');
    expect(names).toContain('linkwarden_create_rule');
    expect(names).toContain('linkwarden_run_rules_now');
    expect(names).toContain('linkwarden_get_new_links_routine_status');
    expect(names).toContain('linkwarden_run_new_links_routine_now');
    expect(names).toContain('linkwarden_create_saved_query');
    expect(names).toContain('linkwarden_get_audit');
    expect(names).toContain('linkwarden_undo_operation');

    expect(names).not.toContain('search');
    expect(names).not.toContain('fetch');
    expect(names).not.toContain('linkwarden_suggest_tags');
    expect(names).not.toContain('linkwarden_classify_links');
    expect(names).not.toContain('linkwarden_plan_reorg');
    expect(names).not.toContain('linkwarden_apply_plan');
    expect(names).not.toContain('linkwarden_run_daily_maintenance');
  });

  it('requires rule creation payload with deterministic shape', () => {
    const parsed = createRuleSchema.parse({
      name: 'Archive 404',
      selector: {
        tagIdsAny: [9]
      },
      action: {
        type: 'move-to-collection',
        collectionId: 778
      }
    });

    expect(parsed.enabled).toBe(true);
    expect(parsed.schedule).toEqual({});
  });
});
