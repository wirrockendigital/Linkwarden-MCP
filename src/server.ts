// This module wires all HTTP routes, middleware behavior, and lifecycle resources.

import Fastify, { type FastifyInstance } from 'fastify';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ConfigStore } from './config/config-store.js';
import { SqliteStore } from './db/database.js';
import { registerSetupRoutes } from './http/setup.js';
import { registerUiRoutes } from './http/ui.js';
import { createValidatedLinkwardenClient } from './linkwarden/runtime.js';
import { registerMcpRoutes } from './mcp/protocol.js';
import { AppError, normalizeError } from './utils/errors.js';

export interface ServerResources {
  app: FastifyInstance;
  db: SqliteStore;
  configStore: ConfigStore;
}

// This function builds and configures the full HTTP application.
export function createServer(): ServerResources {
  const dataDir = process.env.DATA_DIR ?? '/data';
  const dbPath = process.env.STATE_DB_PATH ?? join(dataDir, 'state.db');
  const configPath = process.env.CONFIG_ENC_PATH ?? join(dataDir, 'config.enc');
  const masterPassphraseFile = process.env.MCP_MASTER_PASSPHRASE_FILE;

  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? 'info'
    },
    bodyLimit: 1024 * 1024,
    trustProxy: true
  });

  const db = new SqliteStore(dbPath);
  const configStore = new ConfigStore({
    configPath,
    db
  });

  // This startup step unlocks encrypted runtime config automatically when a passphrase file is configured.
  if (configStore.isInitialized() && !configStore.isUnlocked() && masterPassphraseFile) {
    try {
      const passphrase = readFileSync(masterPassphraseFile, 'utf8').trim();
      if (!passphrase) {
        throw new Error('Passphrase file is empty.');
      }

      configStore.unlock(passphrase);
      app.log.info({ masterPassphraseFile }, 'auto_unlock_success');
    } catch (error) {
      app.log.error(
        {
          masterPassphraseFile,
          message: error instanceof Error ? error.message : 'unknown'
        },
        'auto_unlock_failed'
      );
    }
  }

  // This hook enriches request logs with consistent route and request-id metadata.
  app.addHook('onRequest', async (request) => {
    request.log.info(
      {
        requestId: request.id,
        method: request.method,
        path: request.url
      },
      'request_start'
    );
  });

  // This hook logs response completion including status for auditability.
  app.addHook('onResponse', async (request, reply) => {
    request.log.info(
      {
        requestId: request.id,
        statusCode: reply.statusCode,
        method: request.method,
        path: request.url
      },
      'request_complete'
    );
  });

  // This endpoint exposes a lightweight liveness signal.
  app.get('/health', async () => {
    return {
      ok: true,
      status: 'alive',
      ts: new Date().toISOString()
    };
  });

  // This endpoint indicates whether setup, unlock, user bootstrap, and Linkwarden reachability are ready.
  app.get('/ready', async () => {
    const initialized = configStore.isInitialized();
    const unlocked = configStore.isUnlocked();
    const hasUsers = db.hasAnyUser();
    const target = db.getLinkwardenTarget();
    const whitelistCount = db.listWhitelist().length;

    if (!initialized || !unlocked || !hasUsers || !target || whitelistCount === 0) {
      return {
        ok: false,
        initialized,
        unlocked,
        hasUsers,
        linkwardenTargetConfigured: Boolean(target),
        whitelistConfigured: whitelistCount > 0,
        upstreamReachable: false
      };
    }

    let upstreamReachable = false;
    try {
      const client = createValidatedLinkwardenClient(configStore, db);
      await client.listTags({ limit: 1, offset: 0 });
      upstreamReachable = true;
    } catch {
      upstreamReachable = false;
    }

    return {
      ok: initialized && unlocked && hasUsers && Boolean(target) && whitelistCount > 0 && upstreamReachable,
      initialized,
      unlocked,
      hasUsers,
      linkwardenTargetConfigured: Boolean(target),
      whitelistConfigured: whitelistCount > 0,
      upstreamReachable
    };
  });

  registerUiRoutes(app, configStore, db);
  registerSetupRoutes(app, configStore, db);
  registerMcpRoutes(app, { configStore, db });

  // This handler maps internal exceptions into structured JSON errors.
  app.setErrorHandler((error, request, reply) => {
    const normalized = normalizeError(error);
    const status = normalized.statusCode;

    request.log.error(
      {
        requestId: request.id,
        code: normalized.code,
        details: normalized.details,
        message: normalized.message,
        stack: error instanceof Error ? error.stack : undefined
      },
      'request_failed'
    );

    reply.status(status).send({
      ok: false,
      error: {
        code: normalized.code,
        message: normalized.message,
        details: normalized.details
      }
    });
  });

  app.setNotFoundHandler((request, reply) => {
    const error = new AppError(404, 'not_found', `Route not found: ${request.method} ${request.url}`);
    reply.status(404).send({
      ok: false,
      error: {
        code: error.code,
        message: error.message
      }
    });
  });

  return {
    app,
    db,
    configStore
  };
}
