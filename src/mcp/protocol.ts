// This module implements a streamable HTTP JSON-RPC endpoint for MCP tool discovery and execution.

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { AppError, normalizeError } from '../utils/errors.js';
import type { JsonRpcRequest, JsonRpcResponse } from '../types/mcp.js';
import { createMcpAuthGuard } from '../http/auth.js';
import { buildToolList } from './tool-schemas.js';
import { executeTool } from './tools.js';
import type { AuthenticatedPrincipal } from '../types/domain.js';

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
  logger: FastifyInstance['log']
): Promise<JsonRpcResponse | null> {
  const requestId = request.id ?? null;

  try {
    switch (request.method) {
      case 'initialize': {
        return {
          jsonrpc: '2.0',
          id: requestId,
          result: {
            protocolVersion: '2025-03-26',
            capabilities: {
              tools: {
                listChanged: false
              }
            },
            serverInfo: {
              name: 'linkwarden-mcp',
              version: '0.1.0'
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
          return rpcError(requestId, -32602, 'tools/call requires params.name as string.');
        }

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

    return rpcError(requestId, mapped.code, mapped.message, mapped.data);
  }
}

// This function registers streamable HTTP MCP routes with auth and protocol handling.
export function registerMcpRoutes(fastify: FastifyInstance, deps: McpRouteDeps): void {
  const authGuard = createMcpAuthGuard(deps.configStore, deps.db);

  fastify.get('/mcp', async (request, reply) => {
    const authContext = await authGuard(request, reply);

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

    const payload = request.body as unknown;
    if (!payload) {
      reply.code(400).send(rpcError(null, -32600, 'Missing JSON-RPC request payload.'));
      return;
    }

    if (Array.isArray(payload)) {
      const responses: JsonRpcResponse[] = [];

      for (const item of payload) {
        if (!isJsonRpcRequest(item)) {
          responses.push(rpcError(null, -32600, 'Invalid JSON-RPC request object.'));
          continue;
        }

        const response = await handleRpcRequest(item, deps, actor, authContext.principal, fastify.log);
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
      reply.code(400).send(rpcError(null, -32600, 'Invalid JSON-RPC request object.'));
      return;
    }

    const response = await handleRpcRequest(payload, deps, actor, authContext.principal, fastify.log);
    if (!response) {
      reply.code(202).send();
      return;
    }

    reply.send(response);
  });

  // This route keeps SSE transport disabled because this service uses Streamable HTTP.
  fastify.get('/mcp/sse', async (_request, reply) => {
    reply.code(410).send({
      error: 'sse_disabled',
      message: 'SSE transport is disabled. Use Streamable HTTP at /mcp.'
    });
  });
}
