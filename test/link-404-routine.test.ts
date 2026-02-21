// This test suite verifies 404-monitor runtime behavior for tagging, escalation, recovery, and transport failures.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const createUserLinkwardenClientMock = vi.fn();

vi.mock('../src/linkwarden/runtime.js', () => ({
  createUserLinkwardenClient: (...args: unknown[]) => createUserLinkwardenClientMock(...args)
}));

import { runLink404MonitorNow } from '../src/services/link-404-routine.js';

function makeLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn(function () {
      return this;
    })
  };
}

function makeContext(overrides?: Record<string, unknown>): any {
  const db = {
    getUserLink404MonitorSettings: vi.fn(() => ({
      userId: 2,
      enabled: true,
      interval: 'monthly',
      toDeleteAfter: 'after_1_year',
      lastRunAt: null,
      lastStatus: null,
      lastError: null,
      updatedAt: '2026-02-21T00:00:00.000Z'
    })),
    hasUserLinkwardenToken: vi.fn(() => true),
    getUserSettings: vi.fn(() => ({
      userId: 2,
      writeModeEnabled: true
    })),
    acquireMaintenanceLock: vi.fn(() => true),
    releaseMaintenanceLock: vi.fn(() => undefined),
    setUserLink404MonitorRunState: vi.fn(() => undefined),
    listLinkHealthStates: vi.fn(() => []),
    upsertLinkHealthState: vi.fn(() => undefined),
    createOperation: vi.fn(() => undefined),
    insertOperationItems: vi.fn(() => undefined),
    appendAiChangeLogEntries: vi.fn(() => undefined),
    insertAudit: vi.fn(() => undefined)
  };

  return {
    actor: 'eric#key1',
    principal: {
      userId: 2,
      username: 'eric',
      role: 'user',
      apiKeyId: 'key1',
      toolScopes: ['*'],
      collectionScopes: []
    },
    configStore: {
      getRuntimeConfig: vi.fn(() => ({
        requestTimeoutMs: 5000
      }))
    },
    db,
    logger: makeLogger(),
    ...(overrides ?? {})
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-03-01T12:00:00.000Z'));
  createUserLinkwardenClientMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('link 404 routine', () => {
  it('sets the 404 tag on strict HTTP 404 responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 404
      }))
    );

    const client = {
      loadLinksForScope: vi.fn(async () => [
        {
          id: 101,
          title: 'Example',
          url: 'https://example.com',
          description: null,
          tags: [],
          collection: { id: 7, name: 'Inbox', parentId: null },
          pinned: false,
          archived: false
        }
      ]),
      listAllTags: vi.fn(async () => [
        { id: 10, name: '404' },
        { id: 11, name: 'to-delete' }
      ]),
      createTag: vi.fn(),
      updateLink: vi.fn(async () => undefined)
    };
    createUserLinkwardenClientMock.mockReturnValue(client);

    const context = makeContext();
    const result = await runLink404MonitorNow(context, { ignoreSchedule: true });

    expect(result.status).toBe('success');
    expect(result.summary.flagged404).toBe(1);
    expect(result.summary.taggedToDelete).toBe(0);
    expect(result.summary.updated).toBe(1);
    expect(client.updateLink).toHaveBeenCalledWith(101, { tagIds: [10] });
    expect(context.db.upsertLinkHealthState).toHaveBeenCalledWith(
      expect.objectContaining({
        linkId: 101,
        lastStatus: 'down',
        lastHttpStatus: 404
      })
    );
  });

  it('adds to-delete when 404 persists beyond configured threshold', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 404
      }))
    );

    const client = {
      loadLinksForScope: vi.fn(async () => [
        {
          id: 102,
          title: 'Old Failure',
          url: 'https://old.example.com',
          description: null,
          tags: [{ id: 10, name: '404' }],
          collection: { id: 7, name: 'Inbox', parentId: null },
          pinned: false,
          archived: false
        }
      ]),
      listAllTags: vi.fn(async () => [
        { id: 10, name: '404' },
        { id: 11, name: 'to-delete' }
      ]),
      createTag: vi.fn(),
      updateLink: vi.fn(async () => undefined)
    };
    createUserLinkwardenClientMock.mockReturnValue(client);

    const context = makeContext();
    context.db.getUserLink404MonitorSettings.mockReturnValue({
      userId: 2,
      enabled: true,
      interval: 'monthly',
      toDeleteAfter: 'after_1_month',
      lastRunAt: null,
      lastStatus: null,
      lastError: null,
      updatedAt: '2026-02-21T00:00:00.000Z'
    });
    context.db.listLinkHealthStates.mockReturnValue([
      {
        userId: 2,
        linkId: 102,
        url: 'https://old.example.com',
        firstFailureAt: '2026-01-01T12:00:00.000Z',
        lastFailureAt: '2026-02-01T12:00:00.000Z',
        consecutiveFailures: 4,
        lastStatus: 'down',
        lastCheckedAt: '2026-02-01T12:00:00.000Z',
        lastHttpStatus: 404,
        lastError: null,
        archivedAt: null
      }
    ]);

    const result = await runLink404MonitorNow(context, { ignoreSchedule: true });

    expect(result.status).toBe('success');
    expect(result.summary.taggedToDelete).toBe(1);
    expect(client.updateLink).toHaveBeenCalledWith(102, { tagIds: [10, 11] });
  });

  it('removes 404 and to-delete tags when link recovers', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        status: 200
      }))
    );

    const client = {
      loadLinksForScope: vi.fn(async () => [
        {
          id: 103,
          title: 'Recovered',
          url: 'https://ok.example.com',
          description: null,
          tags: [
            { id: 10, name: '404' },
            { id: 11, name: 'to-delete' },
            { id: 12, name: 'important' }
          ],
          collection: { id: 7, name: 'Inbox', parentId: null },
          pinned: false,
          archived: false
        }
      ]),
      listAllTags: vi.fn(async () => [
        { id: 10, name: '404' },
        { id: 11, name: 'to-delete' },
        { id: 12, name: 'important' }
      ]),
      createTag: vi.fn(),
      updateLink: vi.fn(async () => undefined)
    };
    createUserLinkwardenClientMock.mockReturnValue(client);

    const context = makeContext();
    context.db.listLinkHealthStates.mockReturnValue([
      {
        userId: 2,
        linkId: 103,
        url: 'https://ok.example.com',
        firstFailureAt: '2026-01-01T12:00:00.000Z',
        lastFailureAt: '2026-02-01T12:00:00.000Z',
        consecutiveFailures: 4,
        lastStatus: 'down',
        lastCheckedAt: '2026-02-01T12:00:00.000Z',
        lastHttpStatus: 404,
        lastError: null,
        archivedAt: null
      }
    ]);

    const result = await runLink404MonitorNow(context, { ignoreSchedule: true });

    expect(result.status).toBe('success');
    expect(result.summary.recovered).toBe(1);
    expect(result.summary.updated).toBe(1);
    expect(client.updateLink).toHaveBeenCalledWith(103, { tagIds: [12] });
    expect(context.db.upsertLinkHealthState).toHaveBeenCalledWith(
      expect.objectContaining({
        linkId: 103,
        firstFailureAt: null,
        lastStatus: 'up',
        lastHttpStatus: 200
      })
    );
  });

  it('keeps tags unchanged on transport errors and records failure diagnostics', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      })
    );

    const client = {
      loadLinksForScope: vi.fn(async () => [
        {
          id: 104,
          title: 'Transport Failure',
          url: 'https://fail.example.com',
          description: null,
          tags: [{ id: 10, name: '404' }],
          collection: { id: 7, name: 'Inbox', parentId: null },
          pinned: false,
          archived: false
        }
      ]),
      listAllTags: vi.fn(async () => [
        { id: 10, name: '404' },
        { id: 11, name: 'to-delete' }
      ]),
      createTag: vi.fn(),
      updateLink: vi.fn(async () => undefined)
    };
    createUserLinkwardenClientMock.mockReturnValue(client);

    const context = makeContext();
    const result = await runLink404MonitorNow(context, { ignoreSchedule: true });

    expect(result.status).toBe('partial_failure');
    expect(result.summary.failed).toBe(1);
    expect(result.summary.updated).toBe(0);
    expect(client.updateLink).not.toHaveBeenCalled();
    expect(context.db.upsertLinkHealthState).toHaveBeenCalledWith(
      expect.objectContaining({
        linkId: 104,
        lastError: 'network down',
        lastHttpStatus: null
      })
    );
  });
});
