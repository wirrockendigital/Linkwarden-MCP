// This test suite verifies ConfigStore defaults and persistence for oauthSessionLifetime.

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { ConfigStore } from '../src/config/config-store.js';
import { SqliteStore } from '../src/db/database.js';

const tempDirs: string[] = [];

// This helper creates one isolated ConfigStore + SqliteStore pair for setup tests.
function createStores() {
  const dir = mkdtempSync(join(tmpdir(), 'linkwarden-mcp-config-store-'));
  tempDirs.push(dir);
  const db = new SqliteStore(join(dir, 'state.db'));
  const configStore = new ConfigStore({
    configPath: join(dir, 'config.enc'),
    db
  });
  return { db, configStore };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('config store oauth session lifetime', () => {
  it('defaults oauthSessionLifetime to permanent when setup payload omits it', () => {
    const { configStore } = createStores();
    configStore.initialize({
      masterPassphrase: 'this-is-a-very-strong-passphrase',
      adminUsername: 'admin',
      adminPassword: 'another-very-strong-password',
      linkwardenBaseUrl: 'https://linkwarden.example',
      linkwardenApiToken: 'token-token-token-token-token',
      adminWriteModeDefault: false
    });

    const runtime = configStore.getRuntimeConfig();
    expect(runtime.oauthSessionLifetime).toBe('permanent');
  });

  it('persists explicit oauthSessionLifetime values from setup payload', () => {
    const { configStore } = createStores();
    configStore.initialize({
      masterPassphrase: 'this-is-a-very-strong-passphrase',
      adminUsername: 'admin',
      adminPassword: 'another-very-strong-password',
      linkwardenBaseUrl: 'https://linkwarden.example',
      linkwardenApiToken: 'token-token-token-token-token',
      oauthSessionLifetime: 30,
      adminWriteModeDefault: false
    });

    const runtime = configStore.getRuntimeConfig();
    expect(runtime.oauthSessionLifetime).toBe(30);
  });
});
