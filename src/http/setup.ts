// This module exposes first-run initialization and optional unlock endpoints.

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError } from '../utils/errors.js';
import { hashPassword, generateApiToken, hashApiToken } from '../utils/security.js';
import { assertBaseUrlWhitelisted, normalizeWhitelistEntry } from '../utils/whitelist.js';
import type { LinkwardenWhitelistEntry } from '../types/domain.js';

const whitelistEntrySchema = z.object({
  type: z.enum(['domain', 'ip', 'cidr']),
  value: z.string().min(1).max(255)
});

const initializeSchema = z.object({
  masterPassphrase: z.string().min(12),
  adminUsername: z.string().min(3).max(50),
  adminPassword: z.string().min(12).max(200),
  linkwardenBaseUrl: z.string().url(),
  linkwardenApiToken: z.string().min(20),
  whitelistEntries: z.array(whitelistEntrySchema).min(1).max(200),
  adminWriteModeDefault: z.boolean().default(false),
  issueAdminApiKey: z.boolean().default(true),
  requestTimeoutMs: z.number().int().min(1000).max(60000).optional(),
  maxRetries: z.number().int().min(0).max(8).optional(),
  retryBaseDelayMs: z.number().int().min(50).max(5000).optional(),
  planTtlHours: z.number().int().min(1).max(168).optional()
});

const unlockSchema = z.object({
  passphrase: z.string().min(12)
});

// This helper normalizes and validates all whitelist entries before persistence.
function normalizeWhitelistEntries(entries: z.infer<typeof whitelistEntrySchema>[]): Array<{
  type: 'domain' | 'ip' | 'cidr';
  value: string;
}> {
  const normalized = entries.map((entry) => normalizeWhitelistEntry(entry.type, entry.value));

  const deduped = new Map<string, (typeof normalized)[number]>();
  for (const entry of normalized) {
    deduped.set(`${entry.type}:${entry.value}`, entry);
  }

  return [...deduped.values()];
}

// This helper adapts setup whitelist entries to the whitelist validator contract.
function toStoredWhitelistEntries(
  entries: Array<{ type: 'domain' | 'ip' | 'cidr'; value: string }>
): LinkwardenWhitelistEntry[] {
  const now = new Date().toISOString();

  return entries.map((entry, index) => ({
    id: index + 1,
    type: entry.type,
    value: entry.value,
    createdAt: now
  }));
}

// This helper generates and stores one API key for the given user.
function issueApiKey(db: SqliteStore, userId: number, label: string): { token: string; keyId: string } {
  const generated = generateApiToken();
  db.createApiKey(userId, label, generated.keyId, hashApiToken(generated.token));
  return generated;
}

// This function registers setup endpoints used by first-run deployment and recovery workflows.
export function registerSetupRoutes(fastify: FastifyInstance, configStore: ConfigStore, db: SqliteStore): void {
  fastify.get('/setup/status', async (request) => {
    request.log.debug(
      {
        event: 'setup_status_requested',
        initialized: configStore.isInitialized(),
        unlocked: configStore.isUnlocked(),
        hasUsers: db.hasAnyUser()
      },
      'setup_status_requested'
    );

    return {
      ok: true,
      initialized: configStore.isInitialized(),
      unlocked: configStore.isUnlocked(),
      hasUsers: db.hasAnyUser()
    };
  });

  fastify.post('/setup/initialize', async (request, reply) => {
    request.log.info(
      {
        event: 'setup_initialize_requested',
        ip: request.ip
      },
      'setup_initialize_requested'
    );

    if (configStore.isInitialized()) {
      request.log.warn(
        {
          event: 'setup_initialize_rejected_already_initialized'
        },
        'setup_initialize_rejected_already_initialized'
      );
      throw new AppError(409, 'already_initialized', 'Server setup has already been completed.');
    }

    if (db.hasAnyUser()) {
      request.log.warn(
        {
          event: 'setup_initialize_rejected_existing_users'
        },
        'setup_initialize_rejected_existing_users'
      );
      throw new AppError(
        409,
        'existing_users_detected',
        'User records already exist while setup is uninitialized. Clean persisted data before re-initializing.'
      );
    }

    const parsed = initializeSchema.safeParse(request.body);
    if (!parsed.success) {
      request.log.warn(
        {
          event: 'setup_initialize_validation_failed',
          details: parsed.error.flatten()
        },
        'setup_initialize_validation_failed'
      );
      throw new AppError(400, 'validation_error', 'Invalid setup payload.', parsed.error.flatten());
    }

    request.log.info(
      {
        event: 'setup_initialize_payload_valid',
        adminUsername: parsed.data.adminUsername,
        whitelistCount: parsed.data.whitelistEntries.length,
        adminWriteModeDefault: parsed.data.adminWriteModeDefault,
        issueAdminApiKey: parsed.data.issueAdminApiKey,
        requestTimeoutMs: parsed.data.requestTimeoutMs ?? 10_000,
        maxRetries: parsed.data.maxRetries ?? 3,
        retryBaseDelayMs: parsed.data.retryBaseDelayMs ?? 350,
        planTtlHours: parsed.data.planTtlHours ?? 24
      },
      'setup_initialize_payload_valid'
    );

    const normalizedWhitelist = normalizeWhitelistEntries(parsed.data.whitelistEntries);
    if (normalizedWhitelist.length === 0) {
      request.log.warn(
        {
          event: 'setup_initialize_invalid_whitelist_empty'
        },
        'setup_initialize_invalid_whitelist_empty'
      );
      throw new AppError(400, 'invalid_whitelist', 'Whitelist cannot be empty.');
    }

    assertBaseUrlWhitelisted(parsed.data.linkwardenBaseUrl, toStoredWhitelistEntries(normalizedWhitelist));

    configStore.initialize({
      masterPassphrase: parsed.data.masterPassphrase,
      adminUsername: parsed.data.adminUsername,
      adminPassword: parsed.data.adminPassword,
      linkwardenBaseUrl: parsed.data.linkwardenBaseUrl,
      linkwardenApiToken: parsed.data.linkwardenApiToken,
      whitelistEntries: normalizedWhitelist,
      adminWriteModeDefault: parsed.data.adminWriteModeDefault,
      requestTimeoutMs: parsed.data.requestTimeoutMs,
      maxRetries: parsed.data.maxRetries,
      retryBaseDelayMs: parsed.data.retryBaseDelayMs,
      planTtlHours: parsed.data.planTtlHours
    });

    const passwordRecord = hashPassword(parsed.data.adminPassword);
    const adminUserId = db.createUser({
      username: parsed.data.adminUsername,
      role: 'admin',
      passwordSalt: passwordRecord.salt,
      passwordHash: passwordRecord.hash,
      passwordKdf: passwordRecord.kdf,
      passwordIterations: 16384,
      writeModeEnabled: parsed.data.adminWriteModeDefault
    });

    db.setLinkwardenTarget(parsed.data.linkwardenBaseUrl);
    db.replaceWhitelist(normalizedWhitelist);

    const bootstrapToken = parsed.data.issueAdminApiKey ? issueApiKey(db, adminUserId, 'bootstrap-admin') : undefined;

    request.log.info(
      {
        event: 'setup_initialize_completed',
        adminUserId,
        adminUsername: parsed.data.adminUsername,
        whitelistCount: normalizedWhitelist.length,
        linkwardenBaseUrl: parsed.data.linkwardenBaseUrl,
        bootstrapTokenIssued: Boolean(bootstrapToken)
      },
      'setup_initialize_completed'
    );

    reply.code(201).send({
      ok: true,
      initialized: true,
      adminUserId,
      adminUsername: parsed.data.adminUsername,
      bootstrapAdminApiToken: bootstrapToken?.token,
      bootstrapAdminApiKeyId: bootstrapToken?.keyId,
      message:
        'Setup completed. Save bootstrapAdminApiToken now if shown. It is displayed only once and cannot be recovered.'
    });
  });

  fastify.post('/setup/unlock', async (request, reply) => {
    request.log.info(
      {
        event: 'setup_unlock_requested',
        ip: request.ip
      },
      'setup_unlock_requested'
    );

    if (!configStore.isInitialized()) {
      request.log.warn(
        {
          event: 'setup_unlock_rejected_not_initialized'
        },
        'setup_unlock_rejected_not_initialized'
      );
      throw new AppError(400, 'not_initialized', 'Server setup has not been completed yet.');
    }

    const parsed = unlockSchema.safeParse(request.body);
    if (!parsed.success) {
      request.log.warn(
        {
          event: 'setup_unlock_validation_failed',
          details: parsed.error.flatten()
        },
        'setup_unlock_validation_failed'
      );
      throw new AppError(400, 'validation_error', 'Invalid unlock payload.', parsed.error.flatten());
    }

    configStore.unlock(parsed.data.passphrase);

    request.log.info(
      {
        event: 'setup_unlock_success'
      },
      'setup_unlock_success'
    );

    reply.send({
      ok: true,
      unlocked: true,
      message: 'Runtime configuration unlocked.'
    });
  });
}
