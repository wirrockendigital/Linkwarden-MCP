// This test suite verifies that planning logic is deterministic and strategy behavior is stable.

import { describe, expect, it } from 'vitest';
import { computeReorgPlan } from '../src/planning/reorg.js';
import type { LinkItem } from '../src/types/domain.js';

const links: LinkItem[] = [
  {
    id: 2,
    title: 'DMARC and DKIM guide',
    url: 'https://example.com/dkim',
    description: 'mail security hardening',
    tags: [{ id: 11, name: 'mail' }],
    collection: { id: 5, name: 'Inbox', parentId: null }
  },
  {
    id: 1,
    title: 'SPF records explained',
    url: 'https://example.com/spf',
    description: 'domain auth',
    tags: [{ id: 10, name: 'dns' }],
    collection: { id: 5, name: 'Inbox', parentId: null }
  }
];

describe('computeReorgPlan', () => {
  it('produces deterministic output for tag-by-keywords strategy', () => {
    const params = {
      keywordTagRules: [
        {
          keywords: ['spf', 'dkim', 'dmarc'],
          tagId: 20
        }
      ]
    };

    const first = computeReorgPlan('tag-by-keywords', params, links);
    const second = computeReorgPlan('tag-by-keywords', params, links);

    expect(first).toEqual(second);
    expect(first.summary.scanned).toBe(2);
    expect(first.summary.changes).toBe(2);
    expect(first.items.map((item) => item.linkId)).toEqual([1, 2]);
  });

  it('renames tag ids according to mapping', () => {
    const result = computeReorgPlan(
      'rename-tags',
      {
        renameMap: [{ fromTagId: 11, toTagId: 12 }]
      },
      links
    );

    expect(result.summary.changes).toBe(1);
    expect(result.items[0]?.after).toMatchObject({ tagIds: [12] });
  });
});
