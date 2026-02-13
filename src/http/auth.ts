// This module contains bearer token and browser session authentication guards.

import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { ConfigStore } from '../config/config-store.js';
import { SqliteStore } from '../db/database.js';
import type { AuthenticatedPrincipal, SessionPrincipal } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { hashApiToken, parseCookies } from '../utils/security.js';

export interface AuthContext {
  principal: AuthenticatedPrincipal;
}

// This helper extracts bearer tokens from Authorization headers.
export function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) {
    return null;
  }

  const [scheme, token] = authHeader.split(' ', 2);
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return null;
  }

  return token;
}

// This helper compares secrets in constant time to reduce timing side-channel leakage.
export function constantTimeEquals(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

// This guard ensures MCP access is denied until setup is complete and runtime secrets are unlocked.
export function createMcpAuthGuard(configStore: ConfigStore, db: SqliteStore) {
  return async function mcpAuthGuard(request: FastifyRequest, reply: FastifyReply): Promise<AuthContext> {
    if (!configStore.isInitialized()) {
      throw new AppError(503, 'not_initialized', 'Server setup has not been completed.');
    }

    if (!configStore.isUnlocked()) {
      throw new AppError(503, 'config_locked', 'Server is locked. Unlock setup first.');
    }

    const token = extractBearerToken(request.headers.authorization);
    if (!token) {
      reply.header('WWW-Authenticate', 'Bearer');
      throw new AppError(401, 'unauthorized', 'Missing MCP access token.');
    }

    const principal = db.authenticateByTokenHash(hashApiToken(token));
    if (principal) {
      return { principal };
    }

    reply.header('WWW-Authenticate', 'Bearer');
    throw new AppError(401, 'unauthorized', 'Invalid MCP access token.');
  };
}

// This helper resolves session cookie authentication for browser routes.
export function authenticateSession(request: FastifyRequest, db: SqliteStore): SessionPrincipal | null {
  const cookies = parseCookies(request.headers.cookie);
  const sessionToken = cookies.mcp_session;

  if (!sessionToken) {
    return null;
  }

  return db.authenticateSessionByTokenHash(hashApiToken(sessionToken));
}

// This helper asserts an authenticated browser session and raises a 401 otherwise.
export function requireSession(request: FastifyRequest, db: SqliteStore): SessionPrincipal {
  const principal = authenticateSession(request, db);
  if (!principal) {
    throw new AppError(401, 'session_expired', 'Session missing or expired.');
  }

  return principal;
}

// This helper enforces admin role for privileged UI actions.
export function requireAdminSession(principal: SessionPrincipal): void {
  if (principal.role !== 'admin') {
    throw new AppError(403, 'forbidden', 'Admin role required for this operation.');
  }
}

// This helper enforces CSRF tokens for session-based state-changing requests.
export function requireCsrf(request: FastifyRequest): void {
  const cookies = parseCookies(request.headers.cookie);
  const cookieToken = cookies.mcp_csrf;
  const headerToken = request.headers['x-csrf-token'];
  const normalizedHeader = Array.isArray(headerToken) ? headerToken[0] : headerToken;

  if (!cookieToken || !normalizedHeader || !constantTimeEquals(cookieToken, normalizedHeader)) {
    throw new AppError(403, 'csrf_invalid', 'Missing or invalid CSRF token.');
  }
}
