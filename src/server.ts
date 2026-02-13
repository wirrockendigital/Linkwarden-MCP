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
import { buildLoggerOptions, errorForLog, sanitizeForLog } from './utils/logger.js';

export interface ServerResources {
  app: FastifyInstance;
  db: SqliteStore;
  configStore: ConfigStore;
}

// This symbol stores high-resolution request start time on Fastify request objects.
const REQUEST_START_TIME = Symbol('request-start-time');

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
    logger: buildLoggerOptions(),
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
      app.log.info({ event: 'config_auto_unlock_success', masterPassphraseFile }, 'config_auto_unlock_success');
    } catch (error) {
      app.log.error(
        {
          event: 'config_auto_unlock_failed',
          masterPassphraseFile,
          error: errorForLog(error)
        },
        'config_auto_unlock_failed'
      );
    }
  }

  // This hook enriches request logs with consistent route and request-id metadata.
  app.addHook('onRequest', async (request) => {
    (request as any)[REQUEST_START_TIME] = process.hrtime.bigint();

    request.log.info(
      {
        event: 'http_request_start',
        requestId: request.id,
        method: request.method,
        path: request.url,
        ip: request.ip,
        userAgent: request.headers['user-agent'] ?? null,
        contentLength: request.headers['content-length'] ?? null
      },
      'http_request_start'
    );
  });

  // This hook logs response completion including status and duration for request tracing.
  app.addHook('onResponse', async (request, reply) => {
    const startTime = (request as any)[REQUEST_START_TIME] as bigint | undefined;
    const durationMs = startTime ? Number(process.hrtime.bigint() - startTime) / 1_000_000 : undefined;

    request.log.info(
      {
        event: 'http_request_complete',
        requestId: request.id,
        statusCode: reply.statusCode,
        method: request.method,
        path: request.url,
        durationMs,
        responseContentLength: reply.getHeader('content-length') ?? null
      },
      'http_request_complete'
    );
  });

  // This hook emits explicit timeout events to simplify debugging of stalled requests.
  app.addHook('onTimeout', async (request) => {
    request.log.warn(
      {
        event: 'http_request_timeout',
        requestId: request.id,
        method: request.method,
        path: request.url
      },
      'http_request_timeout'
    );
  });

  // This endpoint exposes a lightweight liveness signal.
  app.get('/health', async () => {
    app.log.debug({ event: 'health_check' }, 'health_check');

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
      app.log.info(
        {
          event: 'readiness_failed_local_state',
          initialized,
          unlocked,
          hasUsers,
          linkwardenTargetConfigured: Boolean(target),
          whitelistConfigured: whitelistCount > 0
        },
        'readiness_failed_local_state'
      );

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
      const client = createValidatedLinkwardenClient(configStore, db, app.log);
      await client.listTags({ limit: 1, offset: 0 });
      upstreamReachable = true;
    } catch {
      app.log.warn(
        {
          event: 'readiness_upstream_unreachable'
        },
        'readiness_upstream_unreachable'
      );
      upstreamReachable = false;
    }

    app.log.info(
      {
        event: 'readiness_evaluated',
        initialized,
        unlocked,
        hasUsers,
        linkwardenTargetConfigured: Boolean(target),
        whitelistConfigured: whitelistCount > 0,
        upstreamReachable
      },
      'readiness_evaluated'
    );

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
        event: 'http_request_failed',
        requestId: request.id,
        code: normalized.code,
        details: sanitizeForLog(normalized.details),
        error: errorForLog(error)
      },
      'http_request_failed'
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

    request.log.warn(
      {
        event: 'http_route_not_found',
        requestId: request.id,
        method: request.method,
        path: request.url
      },
      'http_route_not_found'
    );

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
