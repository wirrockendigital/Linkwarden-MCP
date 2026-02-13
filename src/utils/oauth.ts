// This module provides OAuth helpers for discovery metadata, PKCE validation, and token generation.

import { createHash, randomBytes } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { AppError } from './errors.js';

const DEFAULT_SCOPES = ['mcp.read', 'mcp.write', 'offline_access'] as const;

// This function resolves one stable public base URL using env override or forwarded request headers.
export function getPublicBaseUrl(request: FastifyRequest): string {
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) {
    return stripTrailingSlash(configured);
  }

  const forwardedProto = headerAsString(request.headers['x-forwarded-proto']);
  const forwardedHost = headerAsString(request.headers['x-forwarded-host']);
  const protocol = forwardedProto || request.protocol || 'http';
  const host = forwardedHost || request.headers.host;

  if (!host) {
    throw new AppError(500, 'missing_host_header', 'Cannot build public OAuth metadata without Host header.');
  }

  return stripTrailingSlash(`${protocol}://${host}`);
}

// This function returns one canonical MCP resource URL used for OAuth resource binding.
export function getMcpResourceUrl(request: FastifyRequest): string {
  return `${getPublicBaseUrl(request)}/mcp`;
}

// This function returns one list of acceptable resource values for strict token resource checks.
export function getAcceptedResources(request: FastifyRequest): string[] {
  const base = getPublicBaseUrl(request);
  const mcp = `${base}/mcp`;
  return [mcp, base];
}

// This function builds OAuth protected-resource metadata as defined by RFC 9728.
export function buildProtectedResourceMetadata(request: FastifyRequest): Record<string, unknown> {
  const base = getPublicBaseUrl(request);
  const mcpResource = `${base}/mcp`;
  return {
    resource: mcpResource,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
    scopes_supported: [...DEFAULT_SCOPES]
  };
}

// This function builds OAuth authorization-server metadata used by OAuth clients.
export function buildAuthorizationServerMetadata(
  request: FastifyRequest,
  tokenEndpointAuthMethods: Array<'none' | 'client_secret_post'>
): Record<string, unknown> {
  const base = getPublicBaseUrl(request);

  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: tokenEndpointAuthMethods,
    scopes_supported: [...DEFAULT_SCOPES]
  };
}

// This function creates one opaque OAuth authorization code.
export function generateAuthorizationCode(): string {
  return `lwac_${randomBytes(24).toString('base64url')}`;
}

// This function creates one opaque OAuth access token.
export function generateAccessToken(): { tokenId: string; token: string } {
  const tokenId = randomBytes(8).toString('hex');
  return {
    tokenId,
    token: `lwa_${tokenId}.${randomBytes(32).toString('base64url')}`
  };
}

// This function creates one opaque OAuth refresh token.
export function generateRefreshToken(): string {
  return `lwr_${randomBytes(40).toString('base64url')}`;
}

// This function computes one PKCE S256 code challenge from a code verifier.
export function computeS256CodeChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier, 'utf8').digest('base64url');
}

// This function validates one PKCE code verifier shape according to RFC 7636 limits.
export function assertValidCodeVerifier(codeVerifier: string): void {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
    throw new AppError(400, 'invalid_code_verifier', 'Invalid code_verifier format.');
  }
}

// This function parses one OAuth scope string and enforces supported scope names.
export function normalizeScope(scopeRaw: string | undefined): string {
  const source = scopeRaw?.trim() ? scopeRaw : DEFAULT_SCOPES.join(' ');
  const scopes = source
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
  const unique = [...new Set(scopes)];

  if (unique.length === 0) {
    throw new AppError(400, 'invalid_scope', 'At least one scope is required.');
  }

  const unsupported = unique.filter((scope) => !DEFAULT_SCOPES.includes(scope as (typeof DEFAULT_SCOPES)[number]));
  if (unsupported.length > 0) {
    throw new AppError(400, 'invalid_scope', `Unsupported scopes requested: ${unsupported.join(', ')}`);
  }

  return unique.join(' ');
}

// This function validates one redirect URI for safe OAuth browser redirects.
export function assertValidRedirectUri(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AppError(400, 'invalid_redirect_uri', 'redirect_uri must be a valid absolute URL.');
  }

  const isHttps = parsed.protocol === 'https:';
  const isLocalhostLoopback =
    parsed.protocol === 'http:' &&
    (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1');
  if (!isHttps && !isLocalhostLoopback) {
    throw new AppError(400, 'invalid_redirect_uri', 'redirect_uri must use https or localhost loopback.');
  }
}

// This function validates one resource value against this MCP server resource set.
export function assertAcceptedResource(resource: string | undefined, request: FastifyRequest): string {
  if (!resource || resource.trim().length === 0) {
    throw new AppError(400, 'invalid_resource', 'resource parameter is required.');
  }

  const accepted = getAcceptedResources(request);
  const normalized = normalizeUrl(resource);
  if (!accepted.map((value) => normalizeUrl(value)).includes(normalized)) {
    throw new AppError(400, 'invalid_resource', 'Requested resource is not served by this MCP server.');
  }

  return accepted.find((value) => normalizeUrl(value) === normalized) ?? accepted[0];
}

// This function creates one RFC 6750 WWW-Authenticate header with resource metadata hint.
export function buildBearerChallenge(request: FastifyRequest, error?: string, description?: string): string {
  const base = getPublicBaseUrl(request);
  const parts = [`resource_metadata="${base}/.well-known/oauth-protected-resource"`];
  if (error) {
    parts.push(`error="${error}"`);
  }
  if (description) {
    parts.push(`error_description="${description.replace(/"/g, "'")}"`);
  }
  return `Bearer ${parts.join(', ')}`;
}

// This helper reads one header value and converts arrays to the first string.
function headerAsString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

// This helper strips one optional trailing slash for canonical URL comparisons.
function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

// This helper normalizes one URL for strict equality checks.
function normalizeUrl(value: string): string {
  return stripTrailingSlash(value.trim());
}
