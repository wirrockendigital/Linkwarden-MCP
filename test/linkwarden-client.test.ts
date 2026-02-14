// This test suite verifies request-shape behavior for Linkwarden client write operations.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { LinkwardenClient } from '../src/linkwarden/client.js';
import type { RuntimeConfig } from '../src/types/domain.js';

const runtimeConfig: RuntimeConfig = {
  requestTimeoutMs: 10_000,
  maxRetries: 0,
  retryBaseDelayMs: 50,
  planTtlHours: 24
};

describe('linkwarden client', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses PUT for updateLink to match Linkwarden update endpoint semantics', async () => {
    // This mock keeps the response minimal while exercising the request method path.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        id: 7,
        title: 'Updated link',
        url: 'https://example.com/updated',
        description: 'updated',
        tags: [],
        collection: null
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.updateLink(7, { title: 'Updated link' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string } | undefined;
    expect(fetchOptions?.method).toBe('PUT');
  });
});
