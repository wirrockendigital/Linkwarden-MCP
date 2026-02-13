// This module builds a Linkwarden client only when the configured target is allowlisted.

import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError } from '../utils/errors.js';
import { assertBaseUrlWhitelisted } from '../utils/whitelist.js';
import { LinkwardenClient } from './client.js';

// This helper builds one validated Linkwarden client from runtime config, target, and whitelist.
export function createValidatedLinkwardenClient(configStore: ConfigStore, db: SqliteStore): LinkwardenClient {
  const runtimeConfig = configStore.getRuntimeConfig();
  const target = db.getLinkwardenTarget();
  const whitelist = db.listWhitelist();

  if (!target) {
    throw new AppError(503, 'linkwarden_target_missing', 'Linkwarden target is not configured.');
  }

  assertBaseUrlWhitelisted(target.baseUrl, whitelist);
  return new LinkwardenClient(target.baseUrl, runtimeConfig);
}
