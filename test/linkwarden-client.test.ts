// This test suite verifies native Linkwarden client behavior without fallback paths.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { LinkwardenClient } from '../src/linkwarden/client.js';
import type { RuntimeConfig } from '../src/types/domain.js';
import { AppError } from '../src/utils/errors.js';

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

  it('uses native PUT /api/v1/links/{id} body contract for updateLink', async () => {
    // This mock keeps the response minimal while exercising the request method path.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/v1/links/7') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 7,
              name: 'Current link',
              url: 'https://example.com/current',
              description: 'current',
              tags: [],
              collection: {
                id: 9,
                ownerId: 2
              }
            }
          })
        };
      }

      if (url.includes('/api/v1/tags') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: [
              { id: 11, name: 'alpha' },
              { id: 12, name: 'beta' }
            ],
            total: 2
          })
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true })
      };
    });

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.updateLink(7, { title: 'Updated link', tagIds: [11, 12] });

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(String(fetchMock.mock.calls[2]?.[0])).toContain('/api/v1/links/7');
    const fetchOptions = fetchMock.mock.calls[2]?.[1] as { method?: string; body?: string } | undefined;
    expect(fetchOptions?.method).toBe('PUT');
    expect(fetchOptions?.body).toContain('"id":7');
    expect(fetchOptions?.body).toContain('"name":"Updated link"');
    expect(fetchOptions?.body).toContain('"collection":{"id":9,"ownerId":2}');
    expect(fetchOptions?.body).toContain('"tags":[{"id":11,"name":"alpha"},{"id":12,"name":"beta"}]');
  });

  it('throws validation_error when updateLink receives unknown tag ids', async () => {
    // This mock returns one known tag so one requested id stays unresolved.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/v1/links/7') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 7,
              name: 'Current link',
              url: 'https://example.com/current',
              description: '',
              tags: [],
              collection: {
                id: 9,
                ownerId: 2
              }
            }
          })
        };
      }

      if (url.includes('/api/v1/tags') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: [{ id: 11, name: 'alpha' }],
            total: 1
          })
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true })
      };
    });

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');

    await expect(client.updateLink(7, { tagIds: [11, 9999] })).rejects.toBeInstanceOf(AppError);
    await expect(client.updateLink(7, { tagIds: [11, 9999] })).rejects.toMatchObject({
      code: 'validation_error'
    });

    // This assertion ensures no write request is sent when tag id validation fails.
    const issuedPutUpdate = fetchMock.mock.calls.some((call) => {
      const url = String(call[0]);
      const options = call[1] as RequestInit | undefined;
      return url.includes('/api/v1/links/7') && options?.method === 'PUT';
    });
    expect(issuedPutUpdate).toBe(false);
  });

  it('uses object-based tags payload for native POST /api/v1/links createLink', async () => {
    // This mock verifies create-link payload shape and returns one minimal native link payload.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/v1/tags') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: [
              { id: 11, name: 'AI Chat' },
              { id: 12, name: 'ChatGPT' }
            ],
            total: 2
          })
        };
      }

      if (url.includes('/api/v1/links') && init?.method === 'POST') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 91,
              name: 'Example',
              url: 'https://example.com',
              description: '',
              tags: [
                { id: 11, name: 'AI Chat' },
                { id: 12, name: 'ChatGPT' }
              ],
              collection: { id: 5, name: 'Thread', parentId: null },
              pinnedBy: [],
              archived: false,
              createdAt: '2026-02-20T10:00:00.000Z',
              updatedAt: '2026-02-20T10:00:00.000Z'
            }
          })
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true })
      };
    });

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.createLink({
      url: 'https://example.com',
      collectionId: 5,
      tagIds: [12, 11]
    });

    const createLinkCall = fetchMock.mock.calls.find((call) => {
      const url = String(call[0]);
      const options = call[1] as RequestInit | undefined;
      return url.includes('/api/v1/links') && options?.method === 'POST';
    });
    const createLinkRequest = createLinkCall?.[1] as { body?: string } | undefined;
    expect(createLinkRequest?.body).toContain('"tags":[{"id":11,"name":"AI Chat"},{"id":12,"name":"ChatGPT"}]');
    expect(createLinkRequest?.body).toContain('"collection":{"id":5}');
    expect(createLinkRequest?.body).not.toContain('"tags":[11,12]');
    expect(createLinkRequest?.body).not.toContain('"collectionId":5');
  });

  it('uses native POST /api/v1/tags for createTag', async () => {
    // This mock verifies the native tag creation request shape.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: [{ id: 99, name: 'Security' }]
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const created = await client.createTag('Security');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/tags');
    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string; body?: string } | undefined;
    expect(fetchOptions?.method).toBe('POST');
    expect(fetchOptions?.body).toBe(JSON.stringify({ tags: [{ label: 'Security' }] }));
    expect(created).toMatchObject({ id: 99, name: 'Security' });
  });

  it('uses native DELETE /api/v1/tags/{id} for deleteTag', async () => {
    // This mock verifies the native tag deletion request shape.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.deleteTag(99);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/tags/99');
    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string } | undefined;
    expect(fetchOptions?.method).toBe('DELETE');
  });

  it('uses native GET+PUT /api/v1/collections/{id} contract for updateCollection', async () => {
    // This mock emulates collection read and update responses with required members metadata.
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: {
            id: 8,
            name: 'Service',
            parentId: null,
            members: [
              {
                userId: 2,
                canCreate: true,
                canUpdate: true,
                canDelete: true
              }
            ]
          }
        })
      }))
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: {
            id: 8,
            name: 'Service New',
            parentId: 11
          }
        })
      }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const updated = await client.updateCollection(8, {
      name: 'Service New',
      parentId: 11
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/collections/8');
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain('/api/v1/collections/8');
    const fetchOptions = fetchMock.mock.calls[1]?.[1] as { method?: string; body?: string } | undefined;
    expect(fetchOptions?.method).toBe('PUT');
    expect(fetchOptions?.body).toContain('"id":8');
    expect(fetchOptions?.body).toContain('"name":"Service New"');
    expect(fetchOptions?.body).toContain('"parentId":11');
    expect(updated).toMatchObject({
      id: 8,
      name: 'Service New',
      parentId: 11
    });
  });

  it('uses native DELETE /api/v1/collections/{id} for deleteCollection', async () => {
    // This mock verifies the native collection deletion request shape.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.deleteCollection(8);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/collections/8');
    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string } | undefined;
    expect(fetchOptions?.method).toBe('DELETE');
  });

  it('applies local paging window for collections when upstream ignores limit and offset', async () => {
    // This mock emulates unpaged collection responses even when limit/offset are requested.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: [
          { id: 1, name: 'A', parentId: null },
          { id: 2, name: 'B', parentId: null },
          { id: 3, name: 'C', parentId: null }
        ]
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const page = await client.listCollections({ limit: 1, offset: 1 });

    expect(page.items).toHaveLength(1);
    expect(page.items[0]?.id).toBe(2);
    expect(page.total).toBe(3);
  });

  it('omits parentId in createCollection payload when caller passes null', async () => {
    // This mock verifies root-level collection creation payload compatibility.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: {
          id: 991,
          name: 'Root Test',
          parentId: null
        }
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.createCollection({
      name: 'Root Test',
      parentId: null
    });

    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string; body?: string } | undefined;
    expect(fetchOptions?.method).toBe('POST');
    expect(fetchOptions?.body).toBe(JSON.stringify({ name: 'Root Test' }));
  });

  it('applies local paging window for tags when upstream ignores limit and offset', async () => {
    // This mock emulates unpaged tag responses even when limit/offset are requested.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: [
          { id: 10, name: 'alpha' },
          { id: 11, name: 'beta' },
          { id: 12, name: 'gamma' }
        ]
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const page = await client.listTags({ limit: 2, offset: 1 });

    expect(page.items).toHaveLength(2);
    expect(page.items[0]?.id).toBe(11);
    expect(page.items[1]?.id).toBe(12);
    expect(page.total).toBe(3);
  });

  it('uses native DELETE /api/v1/links/{id} for deleteLink', async () => {
    // This mock verifies the native link deletion request shape.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    await client.deleteLink(13);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/links/13');
    const fetchOptions = fetchMock.mock.calls[0]?.[1] as { method?: string } | undefined;
    expect(fetchOptions?.method).toBe('DELETE');
  });

  it('uses native pinnedBy relation payload for setLinkPinned', async () => {
    // This mock emulates the full pin workflow including tag-name resolution for native update payloads.
    let linkReadCount = 0;
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);

      if (url.includes('/api/v1/users/me') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 42
            }
          })
        };
      }

      if (url.includes('/api/v1/tags') && init?.method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: [
              {
                id: 10,
                name: 'news'
              }
            ],
            total: 1
          })
        };
      }

      if (url.includes('/api/v1/links/7') && init?.method === 'GET') {
        linkReadCount += 1;
        if (linkReadCount === 1) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              response: {
                id: 7,
                name: 'Pin me',
                url: 'https://example.com/pin',
                description: '',
                collection: {
                  id: 5,
                  ownerId: 42
                },
                tags: [
                  {
                    id: 10,
                    name: 'news'
                  }
                ]
              }
            })
          };
        }

        return {
          ok: true,
          status: 200,
          json: async () => ({
            response: {
              id: 7,
              name: 'Pin me',
              url: 'https://example.com/pin',
              collection: {
                id: 5
              },
              tags: [],
              pinnedBy: [{ id: 42 }]
            }
          })
        };
      }

      if (url.includes('/api/v1/links/7') && init?.method === 'PUT') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ ok: true })
        };
      }

      throw new Error(`Unexpected fetch call in test: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const updated = await client.setLinkPinned(7, true);

    expect(fetchMock).toHaveBeenCalledTimes(5);
    const calledUrls = fetchMock.mock.calls.map((call) => String(call[0]));
    expect(calledUrls.some((url) => url.includes('/api/v1/users/me'))).toBe(true);
    expect(calledUrls.filter((url) => url.includes('/api/v1/links/7')).length).toBe(3);
    expect(calledUrls.some((url) => url.includes('/api/v1/tags'))).toBe(true);

    const updateCall = fetchMock.mock.calls.find((call) => {
      const url = String(call[0]);
      const options = call[1] as RequestInit | undefined;
      return url.includes('/api/v1/links/7') && options?.method === 'PUT';
    });
    const updateOptions = updateCall?.[1] as { method?: string; body?: string } | undefined;
    expect(updateOptions?.method).toBe('PUT');
    expect(updateOptions?.body).toContain('"pinnedBy":[{"id":42}]');
    expect(updated).toMatchObject({
      id: 7
    });
  });

  it('uses native /api/v1/links for wildcard queries with total propagation', async () => {
    // This mock emulates list responses for wildcard queries.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: [
          {
            id: 1,
            name: 'One',
            url: 'https://example.com/one',
            tags: [],
            collection: null
          }
        ],
        total: 1162
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const result = await client.searchLinks({
      query: '*',
      limit: 1000,
      offset: 0,
      pinned: true
    });

    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/links?');
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('pinned=true');
    expect(result.items).toHaveLength(1);
    expect(result.total).toBe(1162);
  });

  it('uses native /api/v1/search for non-wildcard queries without link-list fallback', async () => {
    // This mock emulates one native search response page.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        results: [
          {
            id: 9001,
            title: 'Hotel K7',
            url: 'https://hotelk7.de/',
            tags: [],
            collection: null
          }
        ],
        total: 1
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const result = await client.searchLinks({
      query: 'hotel',
      limit: 20,
      offset: 0
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/api/v1/search?');
    expect(result.total).toBe(1);
    expect(result.items[0]?.title).toBe('Hotel K7');
  });

  it('maps pinned state from both pinned and pinnedBy payloads', async () => {
    // This mock verifies both pinned payload variants from Linkwarden.
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: [
            {
              id: 10,
              name: 'Pinned bool',
              url: 'https://example.com/a',
              pinned: true,
              tags: [],
              collection: null
            }
          ]
        })
      }))
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: [
            {
              id: 11,
              name: 'Pinned array',
              url: 'https://example.com/b',
              pinnedBy: [{ id: 2 }],
              tags: [],
              collection: null
            }
          ]
        })
      }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');

    const first = await client.listLinks({ limit: 10, offset: 0 });
    const second = await client.listLinks({ limit: 10, offset: 0 });

    expect(first.items[0]?.pinned).toBe(true);
    expect(second.items[0]?.pinned).toBe(true);
  });

  it('defaults pinned to false when upstream omits pinned fields', async () => {
    // This mock verifies deterministic pinned defaults for payloads without pin metadata.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: [
          {
            id: 12,
            name: 'No pin metadata',
            url: 'https://example.com/c',
            tags: [],
            collection: null
          }
        ]
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const first = await client.listLinks({ limit: 10, offset: 0 });

    expect(first.items[0]?.pinned).toBe(false);
  });

  it('applies pinned scope filtering locally when loading full scope pages', async () => {
    // This mock emulates an upstream page that ignores pinned query filtering.
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: [
            {
              id: 20,
              name: 'Pinned link',
              url: 'https://example.com/pinned',
              pinnedBy: [{ id: 2 }],
              tags: [],
              collection: null
            },
            {
              id: 21,
              name: 'Not pinned link',
              url: 'https://example.com/unpinned',
              tags: [],
              collection: null
            }
          ],
          total: 2
        })
      }))
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          response: [],
          total: 2
        })
      }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const loaded = await client.loadLinksForScopeDetailed({ query: '*', pinned: true }, 100);

    expect(loaded.items).toHaveLength(1);
    expect(loaded.items[0]?.id).toBe(20);
  });

  it('stops on repeated cursor pages without duplicating collected links', async () => {
    // This mock simulates an upstream cursor loop that repeats the same link page.
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            links: [
              {
                id: 30,
                name: 'Loop page link',
                url: 'https://example.com/loop',
                tags: [],
                collection: null
              }
            ],
            nextCursor: 50
          }
        })
      }))
      .mockImplementationOnce(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            links: [
              {
                id: 30,
                name: 'Loop page link',
                url: 'https://example.com/loop',
                tags: [],
                collection: null
              }
            ],
            nextCursor: 100
          }
        })
      }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const loaded = await client.loadLinksForScopeDetailed({ query: '*' }, 100);

    expect(loaded.items).toHaveLength(1);
    expect(loaded.items[0]?.id).toBe(30);
  });

  it('unwraps response-wrapped payloads for single-link reads', async () => {
    // This mock emulates single-link endpoints that wrap payloads in response objects.
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        response: {
          id: 2279,
          name: 'Wrapped link',
          url: 'https://example.com/wrapped',
          description: 'wrapped payload',
          tags: [],
          collection: null
        }
      })
    }));

    vi.stubGlobal('fetch', fetchMock);

    const client = new LinkwardenClient('http://linkwarden:3000', runtimeConfig, 'token-value');
    const link = await client.getLink(2279);

    expect(link.id).toBe(2279);
    expect(link.title).toBe('Wrapped link');
    expect(link.url).toBe('https://example.com/wrapped');
  });
});
