// This test suite verifies strict safety contracts for confirm-gated and bounded tools.

import { describe, expect, it } from 'vitest';
import { applyPlanSchema, bulkUpdateSchema } from '../src/mcp/tool-schemas.js';

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
});
