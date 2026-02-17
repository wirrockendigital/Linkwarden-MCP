// This module implements a streamable HTTP JSON-RPC endpoint for MCP tool discovery and execution.

import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError, normalizeError } from '../utils/errors.js';
import type { JsonRpcRequest, JsonRpcResponse } from '../types/mcp.js';
import { createMcpAuthGuard } from '../http/auth.js';
import { buildToolList } from './tool-schemas.js';
import { executeTool } from './tools.js';
import type { AuthenticatedPrincipal } from '../types/domain.js';
import { errorForLog, sanitizeForLog } from '../utils/logger.js';
import { MCP_PROTOCOL_VERSION, MCP_SERVER_NAME, MCP_SERVER_VERSION } from '../version.js';

interface McpRouteDeps {
  configStore: ConfigStore;
  db: SqliteStore;
}

// This helper creates a canonical JSON-RPC error payload.
function rpcError(id: string | number | null, code: number, message: string, data?: unknown): JsonRpcResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      data
    }
  };
}

// This helper validates that a payload is structurally a JSON-RPC request.
function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const request = value as Partial<JsonRpcRequest>;
  return request.jsonrpc === '2.0' && typeof request.method === 'string';
}

// This helper maps internal application errors into JSON-RPC error code ranges.
function mapAppErrorToRpc(error: AppError): { code: number; message: string; data?: unknown } {
  if (error.code === 'validation_error') {
    return { code: -32602, message: error.message, data: error.details };
  }

  if (error.code === 'tool_not_found') {
    return { code: -32601, message: error.message };
  }

  if (error.statusCode === 401 || error.statusCode === 403) {
    return { code: -32001, message: error.message };
  }

  if (error.statusCode === 404) {
    return { code: -32004, message: error.message };
  }

  if (error.statusCode === 409) {
    return { code: -32009, message: error.message };
  }

  if (error.statusCode >= 500) {
    return { code: -32000, message: error.message };
  }

  return { code: -32002, message: error.message, data: error.details };
}

// This function handles one JSON-RPC request and returns either a response object or null for notifications.
async function handleRpcRequest(
  request: JsonRpcRequest,
  deps: McpRouteDeps,
  actor: string,
  principal: AuthenticatedPrincipal,
  logger: FastifyBaseLogger
): Promise<JsonRpcResponse | null> {
  const requestId = request.id ?? null;
  const startedAt = Date.now();
  const rpcTraceId = randomUUID();

  logger.info(
    {
      event: 'mcp_rpc_request_received',
      rpcTraceId,
      rpcRequestId: requestId,
      method: request.method,
      actor,
      userId: principal.userId,
      apiKeyId: principal.apiKeyId
    },
    'mcp_rpc_request_received'
  );

  try {
    switch (request.method) {
      case 'initialize': {
        return {
          jsonrpc: '2.0',
          id: requestId,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {
              tools: {
                listChanged: false
              }
            },
            serverInfo: {
              name: MCP_SERVER_NAME,
              version: MCP_SERVER_VERSION
            }
          }
        };
      }

      case 'notifications/initialized': {
        // This method is a notification in most clients and intentionally yields no body.
        return request.id === undefined
          ? null
          : {
              jsonrpc: '2.0',
              id: requestId,
              result: {}
            };
      }

      case 'ping': {
        return {
          jsonrpc: '2.0',
          id: requestId,
          result: {
            pong: true
          }
        };
      }

      case 'tools/list': {
        return {
          jsonrpc: '2.0',
          id: requestId,
          result: {
            tools: buildToolList()
          }
        };
      }

      case 'tools/call': {
        const name = request.params?.name;
        const args = request.params?.arguments;

        if (typeof name !== 'string') {
          logger.warn(
            {
              event: 'mcp_tool_call_invalid_name',
              rpcTraceId,
              rpcRequestId: requestId,
              providedNameType: typeof name
            },
            'mcp_tool_call_invalid_name'
          );
          return rpcError(requestId, -32602, 'tools/call requires params.name as string.');
        }

        logger.info(
          {
            event: 'mcp_tool_call_requested',
            rpcTraceId,
            rpcRequestId: requestId,
            toolName: name,
            arguments: sanitizeForLog(args ?? {})
          },
          'mcp_tool_call_requested'
        );

        const result = await executeTool(name, args ?? {}, {
          actor,
          principal,
          configStore: deps.configStore,
          db: deps.db,
          logger
        });

        return {
          jsonrpc: '2.0',
          id: requestId,
          result
        };
      }

      default:
        return rpcError(requestId, -32601, `Unknown method: ${request.method}`);
    }
  } catch (error) {
    const appError = normalizeError(error);
    const mapped = mapAppErrorToRpc(appError);

    logger.error(
      {
        event: 'mcp_rpc_request_failed',
        rpcTraceId,
        rpcRequestId: requestId,
        method: request.method,
        actor,
        code: appError.code,
        statusCode: appError.statusCode,
        details: sanitizeForLog(appError.details),
        error: errorForLog(error),
        durationMs: Date.now() - startedAt
      },
      'mcp_rpc_request_failed'
    );

    return rpcError(requestId, mapped.code, mapped.message, mapped.data);
  } finally {
    logger.info(
      {
        event: 'mcp_rpc_request_completed',
        rpcTraceId,
        rpcRequestId: requestId,
        method: request.method,
        actor,
        durationMs: Date.now() - startedAt
      },
      'mcp_rpc_request_completed'
    );
  }
}

// This function registers streamable HTTP MCP routes with auth and protocol handling.
export function registerMcpRoutes(fastify: FastifyInstance, deps: McpRouteDeps): void {
  const authGuard = createMcpAuthGuard(deps.configStore, deps.db);

  fastify.get('/mcp', async (request, reply) => {
    const authContext = await authGuard(request, reply);

    request.log.info(
      {
        event: 'mcp_transport_discovery',
        userId: authContext.principal.userId,
        username: authContext.principal.username,
        apiKeyId: authContext.principal.apiKeyId
      },
      'mcp_transport_discovery'
    );

    reply.send({
      name: 'linkwarden-mcp',
      transport: 'streamable-http',
      endpoint: '/mcp',
      methods: ['initialize', 'tools/list', 'tools/call', 'ping'],
      authenticatedAs: authContext.principal.username
    });
  });

  fastify.post('/mcp', async (request: FastifyRequest, reply: FastifyReply) => {
    const authContext = await authGuard(request, reply);
    const actor = `${authContext.principal.username}#${authContext.principal.apiKeyId}`;
    const requestLogger = request.log.child({
      component: 'mcp',
      actor,
      userId: authContext.principal.userId,
      apiKeyId: authContext.principal.apiKeyId
    });

    const payload = request.body as unknown;
    if (!payload) {
      requestLogger.warn(
        {
          event: 'mcp_post_missing_payload'
        },
        'mcp_post_missing_payload'
      );
      reply.code(400).send(rpcError(null, -32600, 'Missing JSON-RPC request payload.'));
      return;
    }

    if (Array.isArray(payload)) {
      requestLogger.info(
        {
          event: 'mcp_post_batch_received',
          batchSize: payload.length
        },
        'mcp_post_batch_received'
      );

      const responses: JsonRpcResponse[] = [];

      for (const item of payload) {
        if (!isJsonRpcRequest(item)) {
          requestLogger.warn(
            {
              event: 'mcp_post_batch_invalid_item'
            },
            'mcp_post_batch_invalid_item'
          );
          responses.push(rpcError(null, -32600, 'Invalid JSON-RPC request object.'));
          continue;
        }

        const response = await handleRpcRequest(item, deps, actor, authContext.principal, requestLogger);
        if (response) {
          responses.push(response);
        }
      }

      if (responses.length === 0) {
        reply.code(202).send();
        return;
      }

      reply.send(responses);
      return;
    }

    if (!isJsonRpcRequest(payload)) {
      requestLogger.warn(
        {
          event: 'mcp_post_invalid_request_object'
        },
        'mcp_post_invalid_request_object'
      );
      reply.code(400).send(rpcError(null, -32600, 'Invalid JSON-RPC request object.'));
      return;
    }

    requestLogger.info(
      {
        event: 'mcp_post_single_request_received',
        method: payload.method,
        rpcRequestId: payload.id ?? null
      },
      'mcp_post_single_request_received'
    );

    const response = await handleRpcRequest(payload, deps, actor, authContext.principal, requestLogger);
    if (!response) {
      reply.code(202).send();
      return;
    }

    reply.send(response);
  });

  // This route keeps SSE transport disabled because this service uses Streamable HTTP.
  fastify.get('/mcp/sse', async (_request, reply) => {
    fastify.log.info(
      {
        event: 'mcp_sse_disabled_requested'
      },
      'mcp_sse_disabled_requested'
    );

    reply.code(410).send({
      error: 'sse_disabled',
      message: 'SSE transport is disabled. Use Streamable HTTP at /mcp.'
    });
  });
}
