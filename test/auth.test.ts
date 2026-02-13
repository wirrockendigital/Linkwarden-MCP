// This test suite verifies bearer token auth parsing and multi-user middleware gate behavior.

import { describe, expect, it } from 'vitest';
import { authenticateSession, createMcpAuthGuard, extractBearerToken, requireCsrf } from '../src/http/auth.js';
import { AppError } from '../src/utils/errors.js';

describe('auth helpers', () => {
  it('extracts bearer token from header', () => {
    expect(extractBearerToken('Bearer abc123')).toBe('abc123');
    expect(extractBearerToken('bearer abc123')).toBe('abc123');
    expect(extractBearerToken('Basic abc123')).toBeNull();
    expect(extractBearerToken(undefined)).toBeNull();
  });

  it('rejects access when setup is not initialized', async () => {
    const configStore = {
      isInitialized: () => false,
      isUnlocked: () => false,
      getRuntimeConfig: () => ({})
    } as any;

    const db = {
      authenticateOAuthAccessToken: () => null,
      authenticateByTokenHash: () => null
    } as any;

    const guard = createMcpAuthGuard(configStore, db);

    const request = { headers: {} } as any;
    const reply = { header: () => undefined } as any;

    await expect(guard(request, reply)).rejects.toBeInstanceOf(AppError);
  });

  it('accepts valid database token when initialized and unlocked', async () => {
    const configStore = {
      isInitialized: () => true,
      isUnlocked: () => true,
      getRuntimeConfig: () => ({})
    } as any;

    const db = {
      authenticateOAuthAccessToken: () => null,
      authenticateByTokenHash: () => ({
        userId: 2,
        username: 'alice',
        role: 'admin',
        apiKeyId: 'abc123'
      })
    } as any;

    const guard = createMcpAuthGuard(configStore, db);

    const request = { headers: { authorization: 'Bearer expected-token', host: 'localhost:8080' }, protocol: 'http' } as any;
    const reply = { header: () => undefined } as any;

    await expect(guard(request, reply)).resolves.toMatchObject({
      principal: {
        username: 'alice'
      }
    });
  });

  it('accepts valid oauth token when initialized and unlocked', async () => {
    const configStore = {
      isInitialized: () => true,
      isUnlocked: () => true,
      getRuntimeConfig: () => ({})
    } as any;

    const db = {
      authenticateOAuthAccessToken: () => ({
        userId: 7,
        username: 'oauth-user',
        role: 'user',
        apiKeyId: 'oauth:token-1'
      }),
      authenticateByTokenHash: () => null
    } as any;

    const guard = createMcpAuthGuard(configStore, db);

    const request = { headers: { authorization: 'Bearer oauth-token', host: 'localhost:8080' }, protocol: 'http' } as any;
    const reply = { header: () => undefined } as any;

    await expect(guard(request, reply)).resolves.toMatchObject({
      principal: {
        username: 'oauth-user',
        apiKeyId: 'oauth:token-1'
      }
    });
  });

  it('returns oauth bearer challenge when bearer token is missing', async () => {
    const configStore = {
      isInitialized: () => true,
      isUnlocked: () => true,
      getRuntimeConfig: () => ({})
    } as any;

    const db = {
      authenticateOAuthAccessToken: () => null,
      authenticateByTokenHash: () => null
    } as any;

    const headers: Record<string, string> = {};
    const reply = {
      header: (name: string, value: string) => {
        headers[name] = value;
      }
    } as any;

    const guard = createMcpAuthGuard(configStore, db);
    const request = { headers: { host: 'localhost:8080' }, protocol: 'http' } as any;

    await expect(guard(request, reply)).rejects.toBeInstanceOf(AppError);
    expect(headers['WWW-Authenticate']).toContain('resource_metadata=');
  });

  it('reads session principal from cookie token hash', () => {
    const db = {
      authenticateSessionByTokenHash: (tokenHash: string) => ({
        sessionId: 'sess-1',
        userId: 3,
        username: 'bob',
        role: 'user',
        tokenHashSeen: tokenHash
      })
    } as any;

    const request = {
      headers: {
        cookie: 'mcp_session=my-session-token; mcp_csrf=abc'
      }
    } as any;

    const principal = authenticateSession(request, db);
    expect(principal).toMatchObject({
      userId: 3,
      username: 'bob',
      role: 'user'
    });
  });

  it('rejects csrf when header token mismatches cookie', () => {
    const request = {
      headers: {
        cookie: 'mcp_csrf=good-token',
        'x-csrf-token': 'bad-token'
      }
    } as any;

    expect(() => requireCsrf(request)).toThrowError(AppError);
  });
});
