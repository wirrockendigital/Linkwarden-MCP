// This module builds a Linkwarden client using runtime config and per-user token.

import type { FastifyBaseLogger } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError } from '../utils/errors.js';
import { LinkwardenClient } from './client.js';

// This helper builds one validated Linkwarden client from runtime config, target, and token.
export function createValidatedLinkwardenClientWithToken(
  configStore: ConfigStore,
  db: SqliteStore,
  token: string,
  logger?: FastifyBaseLogger
): LinkwardenClient {
  const runtimeConfig = configStore.getRuntimeConfig();
  const target = db.getLinkwardenTarget();

  if (!target) {
    throw new AppError(503, 'linkwarden_target_missing', 'Linkwarden target is not configured.');
  }

  logger?.debug(
    {
      event: 'linkwarden_runtime_client_built',
      baseUrl: target.baseUrl,
      requestTimeoutMs: runtimeConfig.requestTimeoutMs,
      maxRetries: runtimeConfig.maxRetries
    },
    'linkwarden_runtime_client_built'
  );

  return new LinkwardenClient(target.baseUrl, runtimeConfig, token, logger);
}

// This helper builds a Linkwarden client for a specific authenticated user.
export function createUserLinkwardenClient(
  configStore: ConfigStore,
  db: SqliteStore,
  userId: number,
  logger?: FastifyBaseLogger
): LinkwardenClient {
  const tokenEnc = db.getUserLinkwardenToken(userId);
  if (!tokenEnc) {
    throw new AppError(409, 'linkwarden_token_missing', 'Linkwarden API token is not configured for this user.');
  }

  const token = configStore.decryptSecret(tokenEnc);
  return createValidatedLinkwardenClientWithToken(configStore, db, token, logger);
}
