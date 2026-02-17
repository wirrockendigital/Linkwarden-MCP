// This module exposes OAuth 2.0 authorization-server and protected-resource endpoints for MCP clients.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import { authenticateSession } from './auth.js';
import { AppError } from '../utils/errors.js';
import { sanitizeForLog } from '../utils/logger.js';
import {
  assertAcceptedResource,
  assertValidCodeVerifier,
  assertValidRedirectUri,
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  computeS256CodeChallenge,
  generateAccessToken,
  generateAuthorizationCode,
  generateRefreshToken,
  normalizeScope
} from '../utils/oauth.js';
import { hashApiToken } from '../utils/security.js';

interface OAuthRouteDeps {
  configStore: ConfigStore;
  db: SqliteStore;
}

const authorizeQuerySchema = z.object({
  response_type: z.string().default('code'),
  client_id: z.string().min(1).max(255),
  redirect_uri: z.string().url(),
  scope: z.string().optional(),
  state: z.string().max(2000).optional(),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.string().default('S256'),
  resource: z.string().optional()
});

const tokenBodySchema = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token']),
  client_id: z.string().min(1).max(255).optional(),
  client_secret: z.string().min(1).max(500).optional(),
  code: z.string().min(10).max(500).optional(),
  redirect_uri: z.string().url().optional(),
  code_verifier: z.string().min(43).max(128).optional(),
  refresh_token: z.string().min(20).max(1000).optional(),
  scope: z.string().optional(),
  resource: z.string().optional()
});

const registerBodySchema = z.object({
  client_name: z.string().min(1).max(200).optional(),
  redirect_uris: z.array(z.string().url()).min(1).max(20),
  token_endpoint_auth_method: z.enum(['none', 'client_secret_post']).default('none')
});

// This helper creates one OAuth-compatible JSON error response with optional status override.
function sendOAuthError(reply: FastifyReply, statusCode: number, error: string, description: string): void {
  reply
    .code(statusCode)
    .header('cache-control', 'no-store')
    .header('pragma', 'no-cache')
    .send({
      error,
      error_description: description
    });
}

// This helper validates one code challenge and restricts to safe PKCE character ranges.
function assertValidCodeChallenge(value: string): void {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(value)) {
    throw new AppError(400, 'invalid_code_challenge', 'Invalid code_challenge format.');
  }
}

// This helper compares two strings in constant time when lengths match.
function constantTimeEquals(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

// This helper parses form-encoded or JSON token/register payloads consistently.
function normalizeObjectBody(input: unknown): Record<string, unknown> {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    return input as Record<string, unknown>;
  }

  return {};
}

// This helper returns one absolute login redirect target for session bootstrap.
function buildLoginRedirectTarget(request: FastifyRequest): string {
  if (request.url.startsWith('/admin')) {
    const next = encodeURIComponent(request.url);
    return `/admin?next=${next}`;
  }

  const next = encodeURIComponent(request.url);
  return `/?next=${next}`;
}

// This helper resolves one OAuth client policy from static config or persisted registrations.
function resolveClientPolicy(
  configStore: ConfigStore,
  db: SqliteStore,
  input: {
    clientId: string;
    redirectUri?: string;
    allowDynamicRegistration: boolean;
  }
): {
  clientId: string;
  tokenEndpointAuthMethod: 'none' | 'client_secret_post';
  clientSecretHash?: string;
  redirectUris: string[];
} {
  const runtime = configStore.getRuntimeConfig();
  const configuredClientId = runtime.oauthClientId?.trim();
  const configuredClientSecret = runtime.oauthClientSecret?.trim();

  if (configuredClientId) {
    if (input.clientId !== configuredClientId) {
      throw new AppError(401, 'invalid_client', 'Unknown client_id.');
    }

    return {
      clientId: configuredClientId,
      tokenEndpointAuthMethod: configuredClientSecret ? 'client_secret_post' : 'none',
      clientSecretHash: configuredClientSecret ? hashApiToken(configuredClientSecret) : undefined,
      redirectUris: input.redirectUri ? [input.redirectUri] : []
    };
  }

  const existing = db.getOAuthClient(input.clientId);
  if (existing) {
    if (input.redirectUri && !existing.redirectUris.includes(input.redirectUri)) {
      throw new AppError(400, 'invalid_redirect_uri', 'redirect_uri is not registered for this client.');
    }

    return {
      clientId: existing.clientId,
      tokenEndpointAuthMethod: existing.tokenEndpointAuthMethod,
      clientSecretHash: existing.clientSecretHash,
      redirectUris: existing.redirectUris
    };
  }

  if (!input.allowDynamicRegistration) {
    throw new AppError(401, 'invalid_client', 'Unknown client_id.');
  }

  if (!input.redirectUri) {
    throw new AppError(400, 'invalid_redirect_uri', 'redirect_uri is required for dynamic OAuth clients.');
  }

  const created = db.upsertOAuthClient({
    clientId: input.clientId,
    clientName: 'dynamic-client',
    redirectUris: [input.redirectUri],
    tokenEndpointAuthMethod: 'none'
  });

  return {
    clientId: created.clientId,
    tokenEndpointAuthMethod: created.tokenEndpointAuthMethod,
    clientSecretHash: created.clientSecretHash,
    redirectUris: created.redirectUris
  };
}

// This helper validates token endpoint client authentication according to configured method.
function assertClientAuthentication(
  policy: {
    tokenEndpointAuthMethod: 'none' | 'client_secret_post';
    clientSecretHash?: string;
  },
  clientSecret: string | undefined
): void {
  if (policy.tokenEndpointAuthMethod === 'none') {
    return;
  }

  if (!clientSecret || !policy.clientSecretHash) {
    throw new AppError(401, 'invalid_client', 'Missing client authentication.');
  }

  if (!constantTimeEquals(hashApiToken(clientSecret), policy.clientSecretHash)) {
    throw new AppError(401, 'invalid_client', 'Invalid client credentials.');
  }
}

// This helper creates and persists one fresh OAuth token pair for a user/client binding.
function issueTokenPair(
  db: SqliteStore,
  input: {
    userId: number;
    clientId: string;
    scope: string;
    resource: string;
  }
): { accessToken: string; refreshToken: string; expiresIn: number } {
  const accessTtlSeconds = clampTtlSeconds(process.env.OAUTH_ACCESS_TOKEN_TTL_SECONDS, 300, 86_400, 1_800);
  const refreshTtlSeconds = clampTtlSeconds(
    process.env.OAUTH_REFRESH_TOKEN_TTL_SECONDS,
    3_600,
    365 * 24 * 3_600,
    30 * 24 * 3_600
  );
  const accessExpiresAt = new Date(Date.now() + accessTtlSeconds * 1000).toISOString();
  const refreshExpiresAt = new Date(Date.now() + refreshTtlSeconds * 1000).toISOString();
  const access = generateAccessToken();
  const refresh = generateRefreshToken();

  db.createOAuthToken({
    tokenId: access.tokenId,
    accessTokenHash: hashApiToken(access.token),
    refreshTokenHash: hashApiToken(refresh),
    userId: input.userId,
    clientId: input.clientId,
    scope: input.scope,
    resource: input.resource,
    accessExpiresAt,
    refreshExpiresAt
  });

  return {
    accessToken: access.token,
    refreshToken: refresh,
    expiresIn: accessTtlSeconds
  };
}

// This helper parses and clamps integer TTL values from env vars.
function clampTtlSeconds(raw: string | undefined, min: number, max: number, fallback: number): number {
  const value = Number(raw ?? '');
  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.max(min, Math.min(max, Math.floor(value)));
}

// This helper checks whether one scope string is a subset of an already granted scope set.
function isScopeSubset(requestedScope: string, grantedScope: string): boolean {
  const requested = new Set(requestedScope.split(/\s+/).filter(Boolean));
  const granted = new Set(grantedScope.split(/\s+/).filter(Boolean));

  for (const scope of requested) {
    if (!granted.has(scope)) {
      return false;
    }
  }

  return true;
}

// This function registers OAuth discovery, authorization, token, and dynamic registration endpoints.
export function registerOAuthRoutes(fastify: FastifyInstance, deps: OAuthRouteDeps): void {
  // Serve discovery metadata at standard and MCP-relative paths for client compatibility.
  const sendProtectedResourceMetadata = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    reply.header('cache-control', 'no-store');
    reply.send(buildProtectedResourceMetadata(request));
  };

  const sendAuthorizationServerMetadata = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const runtime = deps.configStore.isUnlocked() ? deps.configStore.getRuntimeConfig() : null;
    const methods: Array<'none' | 'client_secret_post'> =
      runtime?.oauthClientSecret && runtime.oauthClientSecret.trim().length > 0 ? ['client_secret_post'] : ['none'];

    reply.header('cache-control', 'no-store');
    reply.send(buildAuthorizationServerMetadata(request, methods));
  };

  fastify.get('/.well-known/oauth-protected-resource', sendProtectedResourceMetadata);
  fastify.get('/.well-known/oauth-authorization-server', sendAuthorizationServerMetadata);
  fastify.get('/.well-known/openid-configuration', sendAuthorizationServerMetadata);

  fastify.get('/mcp/.well-known/oauth-protected-resource', sendProtectedResourceMetadata);
  fastify.get('/mcp/.well-known/oauth-authorization-server', sendAuthorizationServerMetadata);
  fastify.get('/mcp/.well-known/openid-configuration', sendAuthorizationServerMetadata);

  fastify.post('/register', async (request, reply) => {
    if (!deps.configStore.isInitialized()) {
      sendOAuthError(reply, 503, 'server_error', 'Server setup has not been completed.');
      return;
    }

    if (!deps.configStore.isUnlocked()) {
      sendOAuthError(reply, 503, 'server_error', 'Server is locked.');
      return;
    }

    const runtime = deps.configStore.getRuntimeConfig();
    if (runtime.oauthClientId?.trim()) {
      sendOAuthError(reply, 403, 'access_denied', 'Dynamic client registration is disabled.');
      return;
    }

    const parsed = registerBodySchema.safeParse(normalizeObjectBody(request.body));
    if (!parsed.success) {
      sendOAuthError(reply, 400, 'invalid_client_metadata', 'Invalid dynamic client registration payload.');
      return;
    }

    const redirectUris = parsed.data.redirect_uris.map((value) => value.trim());
    for (const redirectUri of redirectUris) {
      assertValidRedirectUri(redirectUri);
    }

    const clientId = `lwclient_${randomClientId()}`;
    const clientName = parsed.data.client_name?.trim() || 'dynamic-client';
    const clientSecret =
      parsed.data.token_endpoint_auth_method === 'client_secret_post'
        ? `lwsecret_${randomClientId()}${randomClientId()}`
        : undefined;

    const client = deps.db.upsertOAuthClient({
      clientId,
      clientName,
      redirectUris,
      tokenEndpointAuthMethod: parsed.data.token_endpoint_auth_method,
      clientSecretHash: clientSecret ? hashApiToken(clientSecret) : undefined
    });

    request.log.info(
      {
        event: 'oauth_client_registered',
        clientId: client.clientId,
        authMethod: client.tokenEndpointAuthMethod,
        redirectUris: client.redirectUris
      },
      'oauth_client_registered'
    );

    reply.code(201).header('cache-control', 'no-store').send({
      client_id: client.clientId,
      client_name: client.clientName,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret: clientSecret,
      client_secret_expires_at: clientSecret ? 0 : undefined
    });
  });

  fastify.get('/authorize', async (request, reply) => {
    if (!deps.configStore.isInitialized()) {
      sendOAuthError(reply, 503, 'server_error', 'Server setup has not been completed.');
      return;
    }

    if (!deps.configStore.isUnlocked()) {
      sendOAuthError(reply, 503, 'server_error', 'Server is locked.');
      return;
    }

    const parsed = authorizeQuerySchema.safeParse(request.query ?? {});
    if (!parsed.success) {
      sendOAuthError(reply, 400, 'invalid_request', 'Invalid authorization request.');
      return;
    }

    if (parsed.data.response_type !== 'code') {
      sendOAuthError(reply, 400, 'unsupported_response_type', 'Only response_type=code is supported.');
      return;
    }

    if (parsed.data.code_challenge_method !== 'S256') {
      sendOAuthError(reply, 400, 'invalid_request', 'Only PKCE code_challenge_method S256 is supported.');
      return;
    }

    assertValidRedirectUri(parsed.data.redirect_uri);
    assertValidCodeChallenge(parsed.data.code_challenge);
    const resource = assertAcceptedResource(parsed.data.resource, request);
    const scope = normalizeScope(parsed.data.scope);

    const policy = resolveClientPolicy(deps.configStore, deps.db, {
      clientId: parsed.data.client_id,
      redirectUri: parsed.data.redirect_uri,
      allowDynamicRegistration: true
    });

    if (!policy.redirectUris.includes(parsed.data.redirect_uri)) {
      sendOAuthError(reply, 400, 'invalid_redirect_uri', 'redirect_uri is not registered for this client.');
      return;
    }

    const principal = authenticateSession(request, deps.db);
    if (!principal) {
      reply.redirect(buildLoginRedirectTarget(request));
      return;
    }

    const code = generateAuthorizationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    deps.db.createOAuthAuthorizationCode({
      codeHash: hashApiToken(code),
      userId: principal.userId,
      clientId: policy.clientId,
      redirectUri: parsed.data.redirect_uri,
      codeChallenge: parsed.data.code_challenge,
      codeChallengeMethod: 'S256',
      scope,
      resource,
      expiresAt
    });

    const redirect = new URL(parsed.data.redirect_uri);
    redirect.searchParams.set('code', code);
    if (parsed.data.state) {
      redirect.searchParams.set('state', parsed.data.state);
    }

    request.log.info(
      {
        event: 'oauth_authorize_issued_code',
        userId: principal.userId,
        username: principal.username,
        clientId: policy.clientId,
        redirectUri: parsed.data.redirect_uri,
        scope,
        resource
      },
      'oauth_authorize_issued_code'
    );

    reply
      .header('cache-control', 'no-store')
      .header('pragma', 'no-cache')
      .redirect(redirect.toString());
  });

  fastify.post('/token', async (request, reply) => {
    if (!deps.configStore.isInitialized()) {
      sendOAuthError(reply, 503, 'server_error', 'Server setup has not been completed.');
      return;
    }

    if (!deps.configStore.isUnlocked()) {
      sendOAuthError(reply, 503, 'server_error', 'Server is locked.');
      return;
    }

    const parsed = tokenBodySchema.safeParse(normalizeObjectBody(request.body));
    if (!parsed.success) {
      request.log.warn(
        {
          event: 'oauth_token_validation_failed',
          details: sanitizeForLog(parsed.error.flatten())
        },
        'oauth_token_validation_failed'
      );
      sendOAuthError(reply, 400, 'invalid_request', 'Invalid token request payload.');
      return;
    }

    try {
      // This normalization keeps grant-specific client handling deterministic for optional refresh client_id.
      const requestedClientId = parsed.data.client_id?.trim() ? parsed.data.client_id.trim() : undefined;

      if (parsed.data.grant_type === 'authorization_code') {
        if (!requestedClientId) {
          throw new AppError(401, 'invalid_client', 'client_id is required.');
        }

        if (!parsed.data.code || !parsed.data.redirect_uri || !parsed.data.code_verifier) {
          throw new AppError(400, 'invalid_request', 'Missing code, redirect_uri, or code_verifier.');
        }

        assertValidRedirectUri(parsed.data.redirect_uri);
        assertValidCodeVerifier(parsed.data.code_verifier);

        const policy = resolveClientPolicy(deps.configStore, deps.db, {
          clientId: requestedClientId,
          redirectUri: parsed.data.redirect_uri,
          allowDynamicRegistration: false
        });
        assertClientAuthentication(policy, parsed.data.client_secret);

        const consumed = deps.db.consumeOAuthAuthorizationCode(
          hashApiToken(parsed.data.code),
          policy.clientId,
          parsed.data.redirect_uri
        );
        if (!consumed) {
          throw new AppError(400, 'invalid_grant', 'Authorization code is invalid or expired.');
        }

        const expectedChallenge = computeS256CodeChallenge(parsed.data.code_verifier);
        if (!constantTimeEquals(expectedChallenge, consumed.codeChallenge)) {
          throw new AppError(400, 'invalid_grant', 'PKCE verification failed.');
        }

        if (parsed.data.resource && parsed.data.resource.trim().length > 0) {
          const requestedResource = assertAcceptedResource(parsed.data.resource, request);
          if (requestedResource !== consumed.resource) {
            throw new AppError(400, 'invalid_target', 'Resource mismatch for authorization code.');
          }
        }

        const issued = issueTokenPair(deps.db, {
          userId: consumed.userId,
          clientId: consumed.clientId,
          scope: consumed.scope,
          resource: consumed.resource
        });

        reply
          .header('cache-control', 'no-store')
          .header('pragma', 'no-cache')
          .send({
            access_token: issued.accessToken,
            token_type: 'Bearer',
            expires_in: issued.expiresIn,
            refresh_token: issued.refreshToken,
            scope: consumed.scope
          });
        return;
      }

      if (!parsed.data.refresh_token) {
        throw new AppError(400, 'invalid_request', 'Missing refresh_token.');
      }

      const refreshTokenHash = hashApiToken(parsed.data.refresh_token);
      const refreshRecord = deps.db.getOAuthRefreshToken(refreshTokenHash);
      if (!refreshRecord) {
        throw new AppError(400, 'invalid_grant', 'Refresh token is invalid or expired.');
      }

      // This fallback allows standards-compliant refresh requests that omit client_id and use token-bound client identity.
      const effectiveClientId = requestedClientId ?? refreshRecord.clientId;
      const policy = resolveClientPolicy(deps.configStore, deps.db, {
        clientId: effectiveClientId,
        allowDynamicRegistration: false
      });
      assertClientAuthentication(policy, parsed.data.client_secret);

      if (refreshRecord.clientId !== policy.clientId) {
        throw new AppError(400, 'invalid_grant', 'Refresh token does not belong to this client.');
      }

      if (parsed.data.resource && parsed.data.resource.trim().length > 0) {
        const requestedResource = assertAcceptedResource(parsed.data.resource, request);
        if (requestedResource !== refreshRecord.resource) {
          throw new AppError(400, 'invalid_target', 'Resource mismatch for refresh token.');
        }
      }

      const scope = parsed.data.scope?.trim() ? normalizeScope(parsed.data.scope) : refreshRecord.scope;
      if (!isScopeSubset(scope, refreshRecord.scope)) {
        throw new AppError(400, 'invalid_scope', 'Requested scope exceeds originally granted scope.');
      }

      // This final consume step enforces rotation only after all client/resource/scope checks pass.
      const consumedRefresh = deps.db.consumeOAuthRefreshToken(refreshTokenHash, policy.clientId);
      if (!consumedRefresh) {
        throw new AppError(400, 'invalid_grant', 'Refresh token is invalid or expired.');
      }

      const issued = issueTokenPair(deps.db, {
        userId: consumedRefresh.userId,
        clientId: consumedRefresh.clientId,
        scope,
        resource: consumedRefresh.resource
      });

      reply
        .header('cache-control', 'no-store')
        .header('pragma', 'no-cache')
        .send({
          access_token: issued.accessToken,
          token_type: 'Bearer',
          expires_in: issued.expiresIn,
          refresh_token: issued.refreshToken,
          scope
        });
    } catch (error) {
      const normalized = error instanceof AppError ? error : new AppError(500, 'server_error', 'Token request failed.');
      request.log.warn(
        {
          event: 'oauth_token_failed',
          code: normalized.code,
          details: sanitizeForLog(normalized.details)
        },
        'oauth_token_failed'
      );

      if (normalized.code === 'invalid_client') {
        sendOAuthError(reply, 401, 'invalid_client', normalized.message);
        return;
      }

      if (
        normalized.code === 'invalid_grant' ||
        normalized.code === 'invalid_scope' ||
        normalized.code === 'invalid_target' ||
        normalized.code === 'invalid_request' ||
        normalized.code === 'invalid_redirect_uri' ||
        normalized.code === 'invalid_code_verifier'
      ) {
        sendOAuthError(reply, 400, normalized.code, normalized.message);
        return;
      }

      sendOAuthError(reply, 500, 'server_error', 'Token request failed.');
    }
  });
}

// This helper returns one compact random id segment for OAuth client identifiers.
function randomClientId(): string {
  return randomBytes(10).toString('hex');
}
