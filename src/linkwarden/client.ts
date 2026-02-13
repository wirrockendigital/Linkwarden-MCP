// This module wraps Linkwarden API calls with timeout, retry, and defensive response mapping.

import { setTimeout as sleep } from 'node:timers/promises';
import type { FastifyBaseLogger } from 'fastify';
import type { LinkCollection, LinkItem, LinkTag, PagingInput, PlanScope, RuntimeConfig } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { errorForLog, sanitizeForLog } from '../utils/logger.js';

interface ApiListResult<T> {
  items: T[];
  total?: number;
}

interface SearchInput extends PagingInput {
  query: string;
  collectionId?: number;
  tagIds?: number[];
  archived?: boolean;
}

interface BulkReplaceInput {
  linkIds: number[];
  updates: {
    collectionId?: number;
    tagIds?: number[];
  };
}

// This class executes authenticated Linkwarden REST operations.
export class LinkwardenClient {
  private readonly baseUrl: string;
  private readonly config: RuntimeConfig;
  private readonly token: string;
  private readonly logger?: FastifyBaseLogger;

  public constructor(baseUrl: string, config: RuntimeConfig, token: string, logger?: FastifyBaseLogger) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    this.config = config;
    this.token = token;
    this.logger = logger?.child({
      component: 'linkwarden_client'
    });
  }

  // This helper applies exponential backoff with jitter between retries.
  private async waitWithBackoff(attempt: number): Promise<number> {
    const jitter = Math.floor(Math.random() * 100);
    const delay = this.config.retryBaseDelayMs * 2 ** attempt + jitter;
    await sleep(delay);
    return delay;
  }

  // This helper writes one structured client event only when a logger is available.
  private log(
    level: 'debug' | 'info' | 'warn' | 'error',
    event: string,
    details?: Record<string, unknown>
  ): void {
    const sanitizedDetails = (sanitizeForLog(details) ?? {}) as Record<string, unknown>;
    this.logger?.[level](
      {
        event,
        ...sanitizedDetails
      },
      event
    );
  }

  // This helper builds canonical endpoint URLs against the configured Linkwarden base URL.
  private buildUrl(path: string, query?: Record<string, string | number | boolean | undefined>): URL {
    const url = new URL(`${this.baseUrl}${path}`);

    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    return url;
  }

  // This helper executes one HTTP request with timeout and bounded retry policy for transient failures.
  private async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH',
    path: string,
    options?: {
      query?: Record<string, string | number | boolean | undefined>;
      body?: unknown;
    }
  ): Promise<T> {
    const maxAttempts = Math.max(1, this.config.maxRetries + 1);
    const startedAt = Date.now();

    this.log('info', 'linkwarden_request_started', {
      method,
      path,
      query: options?.query,
      hasBody: options?.body !== undefined,
      maxAttempts
    });

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const abortController = new AbortController();
      const timer = setTimeout(() => abortController.abort(), this.config.requestTimeoutMs);
      const attemptStartedAt = Date.now();
      const attemptNumber = attempt + 1;

      this.log('debug', 'linkwarden_request_attempt_started', {
        method,
        path,
        attempt: attemptNumber,
        maxAttempts
      });

      try {
        const response = await fetch(this.buildUrl(path, options?.query), {
          method,
          headers: {
            Authorization: `Bearer ${this.token}`,
            'Content-Type': 'application/json'
          },
          body: options?.body ? JSON.stringify(options.body) : undefined,
          signal: abortController.signal
        });

        this.log('debug', 'linkwarden_request_attempt_response', {
          method,
          path,
          attempt: attemptNumber,
          status: response.status,
          durationMs: Date.now() - attemptStartedAt
        });

        if (response.status === 429 || (response.status >= 500 && response.status <= 599)) {
          if (attempt < maxAttempts - 1) {
            const delayMs = await this.waitWithBackoff(attempt);
            this.log('warn', 'linkwarden_request_retry_scheduled', {
              method,
              path,
              attempt: attemptNumber,
              status: response.status,
              delayMs
            });
            continue;
          }
        }

        if (!response.ok) {
          const message = await response.text();
          this.log('error', 'linkwarden_request_http_error', {
            method,
            path,
            attempt: attemptNumber,
            status: response.status,
            bodyPreview: message
          });
          throw new AppError(response.status, 'linkwarden_api_error', message || 'Linkwarden API request failed.');
        }

        if (response.status === 204) {
          this.log('info', 'linkwarden_request_completed', {
            method,
            path,
            attemptsUsed: attemptNumber,
            durationMs: Date.now() - startedAt,
            status: response.status
          });
          return {} as T;
        }

        const payload = (await response.json()) as T;
        this.log('info', 'linkwarden_request_completed', {
          method,
          path,
          attemptsUsed: attemptNumber,
          durationMs: Date.now() - startedAt,
          status: response.status
        });
        return payload;
      } catch (error) {
        if (error instanceof AppError) {
          this.log('error', 'linkwarden_request_failed_app_error', {
            method,
            path,
            attempt: attemptNumber,
            durationMs: Date.now() - attemptStartedAt,
            error: errorForLog(error)
          });
          throw error;
        }

        if (attempt >= maxAttempts - 1) {
          const message = error instanceof Error ? error.message : 'unknown transport error';
          this.log('error', 'linkwarden_request_failed_transport', {
            method,
            path,
            attempt: attemptNumber,
            durationMs: Date.now() - attemptStartedAt,
            error: errorForLog(error)
          });
          throw new AppError(502, 'linkwarden_unreachable', `Linkwarden request failed: ${message}`);
        }

        const delayMs = await this.waitWithBackoff(attempt);
        this.log('warn', 'linkwarden_request_retry_transport', {
          method,
          path,
          attempt: attemptNumber,
          delayMs,
          error: errorForLog(error)
        });
      } finally {
        clearTimeout(timer);
      }
    }

    this.log('error', 'linkwarden_request_failed_after_retries', {
      method,
      path,
      maxAttempts,
      totalDurationMs: Date.now() - startedAt
    });
    throw new AppError(502, 'linkwarden_unreachable', 'Linkwarden request failed after retries.');
  }

  // This helper maps loosely-typed Linkwarden tag payloads into strict output objects.
  private mapTag(raw: any): LinkTag {
    return {
      id: Number(raw.id),
      name: String(raw.name ?? '')
    };
  }

  // This helper maps collection payloads and keeps parent reference when provided.
  private mapCollection(raw: any): LinkCollection {
    return {
      id: Number(raw.id),
      name: String(raw.name ?? ''),
      parentId: raw.parentId !== undefined && raw.parentId !== null ? Number(raw.parentId) : null
    };
  }

  // This helper maps link payloads while excluding large archive body fields from output.
  private mapLink(raw: any): LinkItem {
    return {
      id: Number(raw.id),
      title: String(raw.title ?? ''),
      url: String(raw.url ?? ''),
      description: raw.description ? String(raw.description) : null,
      tags: Array.isArray(raw.tags) ? raw.tags.map((tag: any) => this.mapTag(tag)) : [],
      collection: raw.collection ? this.mapCollection(raw.collection) : null,
      archived: typeof raw.archived === 'boolean' ? raw.archived : undefined,
      createdAt: raw.createdAt ? String(raw.createdAt) : undefined,
      updatedAt: raw.updatedAt ? String(raw.updatedAt) : undefined
    };
  }

  // This method performs text search in Linkwarden with strict paging and optional filters.
  public async searchLinks(input: SearchInput): Promise<ApiListResult<LinkItem>> {
    const query: Record<string, string | number | boolean | undefined> = {
      query: input.query,
      limit: input.limit,
      offset: input.offset,
      collectionId: input.collectionId,
      archived: input.archived
    };

    if (input.tagIds && input.tagIds.length > 0) {
      query.tagIds = input.tagIds.join(',');
    }

    const response = await this.request<any>('GET', '/api/v1/search', { query });
    const items = Array.isArray(response?.results)
      ? response.results.map((raw: any) => this.mapLink(raw))
      : Array.isArray(response)
        ? response.map((raw: any) => this.mapLink(raw))
        : [];

    return {
      items,
      total: typeof response?.total === 'number' ? response.total : undefined
    };
  }

  // This method lists collections with paging limits to avoid oversized responses.
  public async listCollections(input: PagingInput): Promise<ApiListResult<LinkCollection>> {
    const response = await this.request<any>('GET', '/api/v1/collections', {
      query: {
        limit: input.limit,
        offset: input.offset
      }
    });

    const rawItems = Array.isArray(response?.results)
      ? response.results
      : Array.isArray(response)
        ? response
        : [];

    return {
      items: rawItems.map((raw: any) => this.mapCollection(raw)),
      total: typeof response?.total === 'number' ? response.total : undefined
    };
  }

  // This method lists tags with bounded paging.
  public async listTags(input: PagingInput): Promise<ApiListResult<LinkTag>> {
    const response = await this.request<any>('GET', '/api/v1/tags', {
      query: {
        limit: input.limit,
        offset: input.offset
      }
    });

    const rawItems = Array.isArray(response?.results)
      ? response.results
      : Array.isArray(response)
        ? response
        : [];

    return {
      items: rawItems.map((raw: any) => this.mapTag(raw)),
      total: typeof response?.total === 'number' ? response.total : undefined
    };
  }

  // This method fetches one link by id and returns bounded details.
  public async getLink(id: number): Promise<LinkItem> {
    const response = await this.request<any>('GET', `/api/v1/links/${id}`);
    return this.mapLink(response);
  }

  // This method patches a single link and returns normalized output.
  public async updateLink(id: number, updates: Record<string, unknown>): Promise<LinkItem> {
    const response = await this.request<any>('PATCH', `/api/v1/links/${id}`, {
      body: updates
    });

    return this.mapLink(response);
  }

  // This method attempts a bulk replace operation for collection and full tag set replacement.
  public async bulkReplaceLinks(input: BulkReplaceInput): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('PUT', '/api/v1/links', {
      body: {
        linkIds: input.linkIds,
        updates: input.updates
      }
    });
  }

  // This method loads all links in a scope in pages for planning operations.
  public async loadLinksForScope(scope: PlanScope | undefined, pageSize = 100): Promise<LinkItem[]> {
    const all: LinkItem[] = [];
    let offset = 0;

    while (true) {
      const response = await this.searchLinks({
        query: scope?.query ?? '',
        limit: pageSize,
        offset,
        collectionId: scope?.collectionId,
        tagIds: scope?.tagIds,
        archived: scope?.archived
      });

      all.push(...response.items);

      if (response.items.length < pageSize) {
        break;
      }

      offset += pageSize;
    }

    all.sort((a, b) => a.id - b.id);
    return all;
  }
}
