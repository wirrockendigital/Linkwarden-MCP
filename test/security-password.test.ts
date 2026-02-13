// This test suite verifies password hashing and verification behavior for local user auth.

import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../src/utils/security.js';

describe('password hashing helpers', () => {
  it('verifies a correct password against generated hash', () => {
    const password = 'super-strong-password-123';
    const record = hashPassword(password);

    expect(record.kdf).toBe('scrypt');
    expect(verifyPassword(password, record)).toBe(true);
  });

  it('rejects wrong password for generated hash', () => {
    const record = hashPassword('correct-password');
    expect(verifyPassword('wrong-password', record)).toBe(false);
  });
});
