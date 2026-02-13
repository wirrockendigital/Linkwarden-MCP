// This module builds a Linkwarden client only when the configured target is allowlisted.

import type { FastifyBaseLogger } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError } from '../utils/errors.js';
import { assertBaseUrlWhitelisted } from '../utils/whitelist.js';
import { LinkwardenClient } from './client.js';

// This helper builds one validated Linkwarden client from runtime config, target, and whitelist.
export function createValidatedLinkwardenClient(
  configStore: ConfigStore,
  db: SqliteStore,
  logger?: FastifyBaseLogger
): LinkwardenClient {
  const runtimeConfig = configStore.getRuntimeConfig();
  const target = db.getLinkwardenTarget();
  const whitelist = db.listWhitelist();

  if (!target) {
    throw new AppError(503, 'linkwarden_target_missing', 'Linkwarden target is not configured.');
  }

  assertBaseUrlWhitelisted(target.baseUrl, whitelist);
  logger?.debug(
    {
      event: 'linkwarden_runtime_client_built',
      baseUrl: target.baseUrl,
      whitelistCount: whitelist.length,
      requestTimeoutMs: runtimeConfig.requestTimeoutMs,
      maxRetries: runtimeConfig.maxRetries
    },
    'linkwarden_runtime_client_built'
  );

  return new LinkwardenClient(target.baseUrl, runtimeConfig, logger);
}
