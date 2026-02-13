// This module centralizes structured logging configuration and safe payload shaping.

import { createHash } from 'node:crypto';
import pino, { type LoggerOptions } from 'pino';

const MAX_LOG_DEPTH = 5;
const MAX_LOG_STRING_LENGTH = 1024;
const MAX_LOG_ARRAY_ITEMS = 30;
const MAX_LOG_OBJECT_KEYS = 30;

// This list ensures that obvious secrets are redacted before writing JSON logs.
const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers.x-api-key',
  'headers.authorization',
  'headers.cookie',
  '*.authorization',
  '*.cookie',
  '*.token',
  '*.tokenHash',
  '*.password',
  '*.passwordHash',
  '*.passwordSalt',
  '*.masterPassphrase',
  '*.linkwardenApiToken',
  '*.apiKey',
  '*.bootstrapAdminApiToken'
];

// This helper returns true for field names that should never be logged in cleartext.
function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase();
  return (
    normalized.includes('token') ||
    normalized.includes('password') ||
    normalized.includes('passphrase') ||
    normalized.includes('authorization') ||
    normalized.includes('cookie') ||
    normalized.includes('secret') ||
    normalized.includes('api_key') ||
    normalized.includes('apikey') ||
    normalized.includes('hash')
  );
}

// This helper truncates large strings so high-volume logs stay bounded and readable.
function truncateString(value: string): string {
  if (value.length <= MAX_LOG_STRING_LENGTH) {
    return value;
  }

  return `${value.slice(0, MAX_LOG_STRING_LENGTH)}...[truncated:${value.length - MAX_LOG_STRING_LENGTH}]`;
}

// This helper returns a stable short hash to correlate sensitive identifiers without exposing raw values.
function shortHash(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

// This helper sanitizes arbitrary payloads recursively while preserving debug utility.
export function sanitizeForLog(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (depth > MAX_LOG_DEPTH) {
    return '[depth-limited]';
  }

  if (typeof value === 'string') {
    return truncateString(value);
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    const truncatedArray = value.slice(0, MAX_LOG_ARRAY_ITEMS).map((item) => sanitizeForLog(item, depth + 1));
    if (value.length > MAX_LOG_ARRAY_ITEMS) {
      truncatedArray.push(`[truncated-items:${value.length - MAX_LOG_ARRAY_ITEMS}]`);
    }
    return truncatedArray;
  }

  if (typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const entries = Object.entries(source).slice(0, MAX_LOG_OBJECT_KEYS);
    const target: Record<string, unknown> = {};

    for (const [key, entryValue] of entries) {
      if (isSensitiveKey(key)) {
        const serialized = typeof entryValue === 'string' ? entryValue : JSON.stringify(entryValue ?? '');
        target[key] = `[redacted:${shortHash(serialized)}]`;
        continue;
      }

      target[key] = sanitizeForLog(entryValue, depth + 1);
    }

    if (Object.keys(source).length > MAX_LOG_OBJECT_KEYS) {
      target.__truncatedKeys = Object.keys(source).length - MAX_LOG_OBJECT_KEYS;
    }

    return target;
  }

  return String(value);
}

// This helper normalizes unknown errors into a compact, structured shape for logs.
export function errorForLog(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack
    };
  }

  return {
    message: String(error)
  };
}

// This helper builds one Fastify-compatible logger configuration with strict redaction.
export function buildLoggerOptions(): LoggerOptions {
  return {
    level: process.env.LOG_LEVEL ?? 'info',
    base: {
      service: 'linkwarden-mcp'
    },
    redact: {
      paths: REDACT_PATHS,
      remove: true
    },
    timestamp: pino.stdTimeFunctions.isoTime
  };
}
