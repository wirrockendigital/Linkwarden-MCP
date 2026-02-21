// This module handles encryption-at-rest for secrets and passphrase verifier creation.

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { AppError } from '../utils/errors.js';
import type { EncryptedConfig, RuntimeConfig } from '../types/domain.js';

// This constant defines the key size for AES-256-GCM.
const KEY_LENGTH = 32;
const ALLOWED_OAUTH_SESSION_LIFETIMES = new Set<RuntimeConfig['oauthSessionLifetime']>([
  'permanent',
  1,
  7,
  30,
  180,
  365
]);

// This helper keeps runtime config migration deterministic for legacy config.enc files.
function normalizeOAuthSessionLifetime(value: unknown): RuntimeConfig['oauthSessionLifetime'] {
  if (ALLOWED_OAUTH_SESSION_LIFETIMES.has(value as RuntimeConfig['oauthSessionLifetime'])) {
    return value as RuntimeConfig['oauthSessionLifetime'];
  }
  return 'permanent';
}

// This helper derives a symmetric key from the user passphrase with PBKDF2.
function deriveKey(passphrase: string, salt: Buffer, iterations: number): Buffer {
  return pbkdf2Sync(passphrase, salt, iterations, KEY_LENGTH, 'sha512');
}

// This helper performs strict base64 decoding and reports malformed payloads clearly.
function decodeBase64(value: string, label: string): Buffer {
  try {
    return Buffer.from(value, 'base64');
  } catch {
    throw new AppError(400, 'invalid_encrypted_payload', `Invalid base64 encoding in ${label}.`);
  }
}

// This function encrypts runtime config values into a portable envelope stored on disk.
export function encryptRuntimeConfig(
  config: RuntimeConfig,
  passphrase: string,
  iterations = 210_000
): EncryptedConfig {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt, iterations);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(config), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    version: 1,
    cipher: 'aes-256-gcm',
    kdf: 'pbkdf2-sha512',
    iterations,
    saltB64: salt.toString('base64'),
    ivB64: iv.toString('base64'),
    ciphertextB64: encrypted.toString('base64'),
    authTagB64: authTag.toString('base64')
  };
}

// This function decrypts the encrypted payload and validates that required config fields exist.
export function decryptRuntimeConfig(payload: EncryptedConfig, passphrase: string): RuntimeConfig {
  if (payload.version !== 1 || payload.cipher !== 'aes-256-gcm' || payload.kdf !== 'pbkdf2-sha512') {
    throw new AppError(400, 'unsupported_config_format', 'Unsupported encrypted config format.');
  }

  const salt = decodeBase64(payload.saltB64, 'saltB64');
  const iv = decodeBase64(payload.ivB64, 'ivB64');
  const ciphertext = decodeBase64(payload.ciphertextB64, 'ciphertextB64');
  const authTag = decodeBase64(payload.authTagB64, 'authTagB64');

  try {
    const key = deriveKey(passphrase, salt, payload.iterations);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(decrypted.toString('utf8')) as Partial<RuntimeConfig>;

    return {
      requestTimeoutMs: Number.isFinite(parsed.requestTimeoutMs)
        ? Number(parsed.requestTimeoutMs)
        : 10_000,
      maxRetries: Number.isFinite(parsed.maxRetries) ? Number(parsed.maxRetries) : 3,
      retryBaseDelayMs: Number.isFinite(parsed.retryBaseDelayMs) ? Number(parsed.retryBaseDelayMs) : 350,
      planTtlHours: Number.isFinite(parsed.planTtlHours) ? Number(parsed.planTtlHours) : 24,
      oauthSessionLifetime: normalizeOAuthSessionLifetime(parsed.oauthSessionLifetime),
      oauthClientId:
        typeof parsed.oauthClientId === 'string' && parsed.oauthClientId.trim().length > 0
          ? parsed.oauthClientId.trim()
          : undefined,
      oauthClientSecret:
        typeof parsed.oauthClientSecret === 'string' && parsed.oauthClientSecret.trim().length > 0
          ? parsed.oauthClientSecret.trim()
          : undefined
    };
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }

    throw new AppError(401, 'invalid_passphrase', 'Passphrase is invalid or config is corrupted.');
  }
}

// This function encrypts an arbitrary secret string for storage in SQLite.
export function encryptSecret(value: string, passphrase: string, iterations = 210_000): EncryptedConfig {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt, iterations);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(value, 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    version: 1,
    cipher: 'aes-256-gcm',
    kdf: 'pbkdf2-sha512',
    iterations,
    saltB64: salt.toString('base64'),
    ivB64: iv.toString('base64'),
    ciphertextB64: encrypted.toString('base64'),
    authTagB64: authTag.toString('base64')
  };
}

// This function decrypts a stored secret string using the master passphrase.
export function decryptSecret(payload: EncryptedConfig, passphrase: string): string {
  if (payload.version !== 1 || payload.cipher !== 'aes-256-gcm' || payload.kdf !== 'pbkdf2-sha512') {
    throw new AppError(400, 'unsupported_secret_format', 'Unsupported encrypted secret format.');
  }

  const salt = decodeBase64(payload.saltB64, 'saltB64');
  const iv = decodeBase64(payload.ivB64, 'ivB64');
  const ciphertext = decodeBase64(payload.ciphertextB64, 'ciphertextB64');
  const authTag = decodeBase64(payload.authTagB64, 'authTagB64');

  try {
    const key = deriveKey(passphrase, salt, payload.iterations);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }

    throw new AppError(401, 'invalid_passphrase', 'Passphrase is invalid or secret is corrupted.');
  }
}

export interface PassphraseVerifier {
  saltB64: string;
  iterations: number;
  hashB64: string;
}

// This function creates a passphrase verifier hash used for protected setup unlock checks.
export function createPassphraseVerifier(passphrase: string, iterations = 180_000): PassphraseVerifier {
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(passphrase, salt, iterations, KEY_LENGTH, 'sha512');

  return {
    saltB64: salt.toString('base64'),
    iterations,
    hashB64: hash.toString('base64')
  };
}

// This function validates a passphrase against the stored verifier using constant-time comparison.
export function verifyPassphrase(passphrase: string, verifier: PassphraseVerifier): boolean {
  const salt = decodeBase64(verifier.saltB64, 'verifier.saltB64');
  const expectedHash = decodeBase64(verifier.hashB64, 'verifier.hashB64');
  const candidateHash = pbkdf2Sync(passphrase, salt, verifier.iterations, KEY_LENGTH, 'sha512');

  return timingSafeEqual(expectedHash, candidateHash);
}
