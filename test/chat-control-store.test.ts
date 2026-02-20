// This test suite verifies per-user chat-control archive defaults and persistence behavior in SQLite store.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated store instance backed by a temporary SQLite file.
function createStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-chat-control-store-'));
  tempDirs.push(dir);
  return new SqliteStore(join(dir, 'state.db'));
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('chat control store', () => {
  it('returns deterministic archive defaults for each user', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'chat-default-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const settings = store.getUserChatControlSettings(userId);
    expect(settings.archiveCollectionName).toBe('Archive');
    expect(settings.archiveCollectionParentId).toBeNull();
    expect(settings.chatCaptureTagName).toBe('AI Chat');
    expect(settings.chatCaptureTagAiChatEnabled).toBe(true);
    expect(settings.chatCaptureTagAiNameEnabled).toBe(true);
    expect(settings.aiActivityRetentionDays).toBe(180);
  });

  it('stores per-user archive collection name and optional parent id', () => {
    const store = createStore();
    const userId = store.createUser({
      username: 'chat-custom-user',
      role: 'user',
      passwordSalt: 'salt',
      passwordHash: 'hash',
      passwordKdf: 'scrypt',
      passwordIterations: 16384,
      writeModeEnabled: false
    });

    const updated = store.setUserChatControlSettings(userId, {
      archiveCollectionName: 'Archive Team',
      archiveCollectionParentId: 42,
      chatCaptureTagName: 'My AI Chat',
      chatCaptureTagAiChatEnabled: false,
      chatCaptureTagAiNameEnabled: true,
      aiActivityRetentionDays: 365
    });

    expect(updated.archiveCollectionName).toBe('Archive Team');
    expect(updated.archiveCollectionParentId).toBe(42);
    expect(updated.chatCaptureTagName).toBe('My AI Chat');
    expect(updated.chatCaptureTagAiChatEnabled).toBe(false);
    expect(updated.chatCaptureTagAiNameEnabled).toBe(true);
    expect(updated.aiActivityRetentionDays).toBe(365);

    const persisted = store.getUserChatControlSettings(userId);
    expect(persisted.archiveCollectionName).toBe('Archive Team');
    expect(persisted.archiveCollectionParentId).toBe(42);
    expect(persisted.chatCaptureTagName).toBe('My AI Chat');
    expect(persisted.chatCaptureTagAiChatEnabled).toBe(false);
    expect(persisted.chatCaptureTagAiNameEnabled).toBe(true);
    expect(persisted.aiActivityRetentionDays).toBe(365);
  });
});
