// This module wires all HTTP routes, middleware behavior, and lifecycle resources.

import Fastify, { type FastifyInstance } from 'fastify';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ConfigStore } from './config/config-store.js';
import { SqliteStore } from './db/database.js';
import { registerOAuthRoutes } from './http/oauth.js';
import { registerSetupRoutes } from './http/setup.js';
import { registerUiRoutes } from './http/ui.js';
import { createValidatedLinkwardenClientWithToken } from './linkwarden/runtime.js';
import { registerMcpRoutes } from './mcp/protocol.js';
import { executeTool } from './mcp/tools.js';
import { runLink404MonitorNow } from './services/link-404-routine.js';
import { runNewLinksRoutineNow } from './services/new-links-routine.js';
import type { AuthenticatedPrincipal } from './types/domain.js';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, formatProtocolVersionWithTimestamp } from './version.js';
import { AppError, normalizeError } from './utils/errors.js';
import { buildLoggerOptions, errorForLog, sanitizeForLog } from './utils/logger.js';

export interface ServerResources {
  app: FastifyInstance;
  db: SqliteStore;
  configStore: ConfigStore;
}

// This symbol stores high-resolution request start time on Fastify request objects.
const REQUEST_START_TIME = Symbol('request-start-time');

// This helper builds a safe header snapshot for request diagnostics without leaking secrets.
function buildRequestHeaderSnapshot(headers: Record<string, unknown>): Record<string, unknown> {
  return sanitizeForLog({
    host: headers.host ?? null,
    'x-forwarded-host': headers['x-forwarded-host'] ?? null,
    'x-forwarded-proto': headers['x-forwarded-proto'] ?? null,
    'x-forwarded-for': headers['x-forwarded-for'] ?? null,
    'x-forwarded-port': headers['x-forwarded-port'] ?? null,
    'x-real-ip': headers['x-real-ip'] ?? null,
    'user-agent': headers['user-agent'] ?? null,
    accept: headers.accept ?? null,
    'content-type': headers['content-type'] ?? null,
    'content-length': headers['content-length'] ?? null
  }) as Record<string, unknown>;
}

// This helper validates internal next paths and prevents open redirects from root bridge handling.
function normalizeInternalNextPath(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) {
    return null;
  }

  return trimmed;
}

// This helper builds one internal principal used by scheduler-triggered routine runs.
function buildSchedulerPrincipal(user: { userId: number; username: string; role: AuthenticatedPrincipal['role'] }): AuthenticatedPrincipal {
  return {
    userId: user.userId,
    username: user.username,
    role: user.role,
    apiKeyId: 'scheduler',
    toolScopes: ['*'],
    collectionScopes: []
  };
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
    logger: buildLoggerOptions(),
    bodyLimit: 1024 * 1024,
    trustProxy: true
  });

  // This parser enables OAuth token endpoint requests using application/x-www-form-urlencoded payloads.
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (request, body, done) => {
      try {
        const raw = typeof body === 'string' ? body : '';
        const params = new URLSearchParams(raw);
        const normalized: Record<string, string> = {};

        for (const [key, value] of params.entries()) {
          normalized[key] = value;
        }

        done(null, normalized);
      } catch (error) {
        done(error as Error, undefined);
      }
    }
  );

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

    request.log.info(
      {
        event: 'http_request_headers',
        requestId: request.id,
        method: request.method,
        path: request.url,
        headers: buildRequestHeaderSnapshot(request.headers as Record<string, unknown>),
        query: sanitizeForLog(request.query ?? null)
      },
      'http_request_headers'
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

  // This endpoint keeps root machine-facing and only bridges OAuth login bootstrap to /admin when needed.
  app.get('/', async (request, reply) => {
    const query = (request.query ?? {}) as Record<string, unknown>;
    const nextPath = normalizeInternalNextPath(query.next);
    if (nextPath) {
      reply.redirect(`/admin?next=${encodeURIComponent(nextPath)}`);
      return;
    }

    return {
      ok: true,
      service: 'linkwarden-mcp',
      mcpEndpoint: '/mcp'
    };
  });

  // This endpoint indicates whether setup, unlock, user bootstrap, and Linkwarden reachability are ready.
  app.get('/ready', async () => {
    const initialized = configStore.isInitialized();
    const unlocked = configStore.isUnlocked();
    const hasUsers = db.hasAnyUser();
    const target = db.getLinkwardenTarget();

    if (!initialized || !unlocked || !hasUsers || !target) {
      app.log.info(
        {
          event: 'readiness_failed_local_state',
          initialized,
          unlocked,
          hasUsers,
          linkwardenTargetConfigured: Boolean(target)
        },
        'readiness_failed_local_state'
      );

      return {
        ok: false,
        initialized,
        unlocked,
        hasUsers,
        linkwardenTargetConfigured: Boolean(target),
        upstreamReachable: false
      };
    }

    let upstreamReachable = false;
    try {
      const tokenOwner = db.getAnyUserWithLinkwardenToken();
      if (!tokenOwner) {
        app.log.warn(
          {
            event: 'readiness_missing_user_token'
          },
          'readiness_missing_user_token'
        );
        upstreamReachable = false;
      } else {
        const tokenEnc = db.getUserLinkwardenToken(tokenOwner.userId);
        if (!tokenEnc) {
          upstreamReachable = false;
        } else {
          const token = configStore.decryptSecret(tokenEnc);
          const client = createValidatedLinkwardenClientWithToken(configStore, db, token, app.log);
          await client.listTags({ limit: 1, offset: 0 });
          upstreamReachable = true;
        }
      }
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
        upstreamReachable
      },
      'readiness_evaluated'
    );

    return {
      ok: initialized && unlocked && hasUsers && Boolean(target) && upstreamReachable,
      initialized,
      unlocked,
      hasUsers,
      linkwardenTargetConfigured: Boolean(target),
      upstreamReachable
    };
  });

  // This endpoint exposes canonical server and protocol version metadata for external monitoring and debugging.
  app.get('/version', async () => {
    return {
      ok: true,
      name: MCP_SERVER_NAME,
      version: MCP_SERVER_VERSION,
      protocolVersion: formatProtocolVersionWithTimestamp()
    };
  });

  registerUiRoutes(app, configStore, db);
  registerSetupRoutes(app, configStore, db);
  registerOAuthRoutes(app, { configStore, db });
  registerMcpRoutes(app, { configStore, db });

  let newLinksRoutineSchedulerTimer: NodeJS.Timeout | null = null;
  let newLinksRoutineSchedulerRunning = false;
  let link404MonitorSchedulerRunning = false;
  const schedulerTickMs = 60 * 1000;

  // This helper executes one scheduler tick and triggers due user routines with shared service logic.
  const runNewLinksRoutineSchedulerTick = async (): Promise<void> => {
    if (newLinksRoutineSchedulerRunning) {
      app.log.debug(
        {
          event: 'new_links_routine_scheduler_tick_skipped_running'
        },
        'new_links_routine_scheduler_tick_skipped_running'
      );
      return;
    }

    if (!configStore.isInitialized() || !configStore.isUnlocked()) {
      return;
    }

    newLinksRoutineSchedulerRunning = true;
    try {
      const candidates = db.listUsersWithEnabledNewLinksRoutine();
      for (const candidate of candidates) {
        const principal = buildSchedulerPrincipal({
          userId: candidate.userId,
          username: candidate.username,
          role: candidate.role
        });

        const result = await runNewLinksRoutineNow(
          {
            actor: `scheduler#user:${candidate.userId}`,
            principal,
            configStore,
            db,
            logger: app.log
          },
          executeTool,
          {
            ignoreSchedule: false
          }
        );

        app.log.info(
          {
            event: 'new_links_routine_scheduler_user_completed',
            userId: candidate.userId,
            status: result.status,
            summary: result.summary,
            warnings: result.warnings,
            failures: result.failures.length
          },
          'new_links_routine_scheduler_user_completed'
        );
      }
    } catch (error) {
      app.log.error(
        {
          event: 'new_links_routine_scheduler_tick_failed',
          error: errorForLog(error)
        },
        'new_links_routine_scheduler_tick_failed'
      );
    } finally {
      newLinksRoutineSchedulerRunning = false;
    }
  };

  // This helper executes one scheduler tick and triggers due user 404-monitor routines with shared service logic.
  const runLink404MonitorSchedulerTick = async (): Promise<void> => {
    if (link404MonitorSchedulerRunning) {
      app.log.debug(
        {
          event: 'link_404_monitor_scheduler_tick_skipped_running'
        },
        'link_404_monitor_scheduler_tick_skipped_running'
      );
      return;
    }

    if (!configStore.isInitialized() || !configStore.isUnlocked()) {
      return;
    }

    link404MonitorSchedulerRunning = true;
    try {
      const candidates = db.listUsersWithEnabledLink404Monitor();
      for (const candidate of candidates) {
        const principal = buildSchedulerPrincipal({
          userId: candidate.userId,
          username: candidate.username,
          role: candidate.role
        });

        const result = await runLink404MonitorNow(
          {
            actor: `scheduler#user:${candidate.userId}`,
            principal,
            configStore,
            db,
            logger: app.log
          },
          {
            ignoreSchedule: false
          }
        );

        app.log.info(
          {
            event: 'link_404_monitor_scheduler_user_completed',
            userId: candidate.userId,
            status: result.status,
            summary: result.summary,
            warnings: result.warnings,
            failures: result.failures.length
          },
          'link_404_monitor_scheduler_user_completed'
        );
      }
    } catch (error) {
      app.log.error(
        {
          event: 'link_404_monitor_scheduler_tick_failed',
          error: errorForLog(error)
        },
        'link_404_monitor_scheduler_tick_failed'
      );
    } finally {
      link404MonitorSchedulerRunning = false;
    }
  };

  // This startup task enables one in-process scheduler loop so no external cron dependency is required.
  newLinksRoutineSchedulerTimer = setInterval(() => {
    void runNewLinksRoutineSchedulerTick();
    void runLink404MonitorSchedulerTick();
  }, schedulerTickMs);
  void runNewLinksRoutineSchedulerTick();
  void runLink404MonitorSchedulerTick();

  // This shutdown hook clears scheduler timers so app close remains deterministic.
  app.addHook('onClose', async () => {
    if (newLinksRoutineSchedulerTimer) {
      clearInterval(newLinksRoutineSchedulerTimer);
      newLinksRoutineSchedulerTimer = null;
    }
  });

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
