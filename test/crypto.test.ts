// This test suite verifies encryption/decryption correctness and passphrase verifier behavior.

import { describe, expect, it } from 'vitest';
import {
  decryptRuntimeConfig,
  encryptRuntimeConfig,
  createPassphraseVerifier,
  verifyPassphrase,
  encryptSecret,
  decryptSecret
} from '../src/config/crypto.js';
import type { RuntimeConfig } from '../src/types/domain.js';
import { AppError } from '../src/utils/errors.js';

describe('crypto helpers', () => {
  const config: RuntimeConfig = {
    requestTimeoutMs: 10000,
    maxRetries: 3,
    retryBaseDelayMs: 350,
    planTtlHours: 24,
    oauthSessionLifetime: 'permanent',
    oauthClientId: 'chatgpt-client',
    oauthClientSecret: 'chatgpt-secret-value'
  };

  it('encrypts and decrypts config round-trip', () => {
    const payload = encryptRuntimeConfig(config, 'this-is-a-strong-passphrase');
    const decrypted = decryptRuntimeConfig(payload, 'this-is-a-strong-passphrase');

    expect(decrypted).toEqual(config);
  });

  it('rejects wrong passphrase', () => {
    const payload = encryptRuntimeConfig(config, 'this-is-a-strong-passphrase');

    expect(() => decryptRuntimeConfig(payload, 'wrong-passphrase')).toThrowError(AppError);
  });

  it('verifies passphrase hashes with constant output', () => {
    const verifier = createPassphraseVerifier('this-is-a-strong-passphrase');

    expect(verifyPassphrase('this-is-a-strong-passphrase', verifier)).toBe(true);
    expect(verifyPassphrase('this-is-not-correct', verifier)).toBe(false);
  });

  it('encrypts and decrypts secrets round-trip', () => {
    const payload = encryptSecret('linkwarden-secret-token', 'this-is-a-strong-passphrase');
    const decrypted = decryptSecret(payload, 'this-is-a-strong-passphrase');

    expect(decrypted).toBe('linkwarden-secret-token');
  });

  it('defaults missing oauthSessionLifetime from legacy payloads to permanent', () => {
    // This cast simulates old config.enc payloads that were created before oauthSessionLifetime existed.
    const payload = encryptRuntimeConfig(
      {
        requestTimeoutMs: config.requestTimeoutMs,
        maxRetries: config.maxRetries,
        retryBaseDelayMs: config.retryBaseDelayMs,
        planTtlHours: config.planTtlHours,
        oauthClientId: config.oauthClientId,
        oauthClientSecret: config.oauthClientSecret
      } as RuntimeConfig,
      'this-is-a-strong-passphrase'
    );

    const decrypted = decryptRuntimeConfig(payload, 'this-is-a-strong-passphrase');
    expect(decrypted.oauthSessionLifetime).toBe('permanent');
  });
});
