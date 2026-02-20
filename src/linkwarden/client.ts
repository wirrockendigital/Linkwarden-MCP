// This module wraps Linkwarden API calls with timeout, retry, and defensive response mapping.

import { setTimeout as sleep } from 'node:timers/promises';
import type { FastifyBaseLogger } from 'fastify';
import type { LinkCollection, LinkItem, LinkTag, PagingInput, PlanScope, RuntimeConfig } from '../types/domain.js';
import { AppError } from '../utils/errors.js';
import { errorForLog, sanitizeForLog } from '../utils/logger.js';

interface ApiListResult<T> {
  items: T[];
  total?: number;
  warning?: string;
}

interface SearchInput extends PagingInput {
  query: string;
  collectionId?: number;
  tagIds?: number[];
  archived?: boolean;
  pinned?: boolean;
}

interface LinkListFilters extends PagingInput {
  collectionId?: number;
  tagIds?: number[];
  archived?: boolean;
  pinned?: boolean;
}

interface ScopedLinkLoadResult {
  items: LinkItem[];
  warning?: string;
  diagnostics: {
    mode: 'list_scan' | 'search_scan';
    pageSize: number;
    pagesScanned: number;
    fallbackPageSizeApplied: number | null;
  };
}

interface CreateCollectionInput {
  name: string;
  parentId?: number | null;
}

interface UpdateCollectionInput {
  name?: string;
  parentId?: number | null;
}

interface CreateLinkInput {
  url: string;
  title?: string;
  description?: string;
  collectionId?: number;
  tagIds?: number[];
  archived?: boolean;
}

// This class executes authenticated Linkwarden REST operations.
export class LinkwardenClient {
  private readonly baseUrl: string;
  private readonly config: RuntimeConfig;
  private readonly token: string;
  private readonly logger?: FastifyBaseLogger;
  private currentUserIdCache?: number;
  private tagNameByIdCache?: Map<number, string>;

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
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
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
      name: String(raw.name ?? raw.label ?? '')
    };
  }

  // This helper maps collection payloads and keeps parent reference when provided.
  private mapCollection(raw: any): LinkCollection {
    return {
      id: Number(raw.id),
      name: String(raw.name ?? ''),
      parentId: raw.parentId !== undefined && raw.parentId !== null ? Number(raw.parentId) : null,
      ownerId: raw.ownerId !== undefined && raw.ownerId !== null ? Number(raw.ownerId) : undefined
    };
  }

  // This helper extracts one normalized member permission record for collection update payloads.
  private mapCollectionMemberForUpdate(raw: any): {
    userId: number;
    canCreate: boolean;
    canUpdate: boolean;
    canDelete: boolean;
  } | null {
    const userIdValue = raw?.userId ?? raw?.user?.id;
    const userId = Number(userIdValue);
    if (!Number.isInteger(userId) || userId <= 0) {
      return null;
    }

    return {
      userId,
      canCreate: Boolean(raw?.canCreate),
      canUpdate: Boolean(raw?.canUpdate),
      canDelete: Boolean(raw?.canDelete)
    };
  }

  // This helper normalizes tag id lists for deterministic payload generation.
  private normalizeTagIds(tagIds: number[]): number[] {
    return [...new Set(tagIds.filter((tagId) => Number.isInteger(tagId) && tagId > 0))].sort((a, b) => a - b);
  }

  // This helper resolves and caches Linkwarden tag names required by native link update payloads.
  private async getTagNameByIdMap(forceRefresh = false): Promise<Map<number, string>> {
    if (this.tagNameByIdCache && !forceRefresh) {
      return this.tagNameByIdCache;
    }

    const tags = await this.listAllTags();
    const map = new Map<number, string>();

    for (const tag of tags) {
      const tagId = Number(tag.id);
      const tagName = String(tag.name ?? '').trim();
      if (!Number.isInteger(tagId) || tagId <= 0 || tagName.length === 0) {
        continue;
      }
      map.set(tagId, tagName);
    }

    this.tagNameByIdCache = map;
    return map;
  }

  // This helper converts tag ids into Linkwarden-native tag payload entries including required names.
  private async resolveTagPayload(tagIds: number[]): Promise<Array<{ id: number; name: string }>> {
    const normalizedTagIds = this.normalizeTagIds(tagIds);
    if (normalizedTagIds.length === 0) {
      return [];
    }

    let tagById = await this.getTagNameByIdMap(false);
    let missingTagIds = normalizedTagIds.filter((tagId) => !tagById.has(tagId));

    // This retry refreshes cached tag metadata when new tags were created earlier in the same client lifecycle.
    if (missingTagIds.length > 0) {
      tagById = await this.getTagNameByIdMap(true);
      missingTagIds = normalizedTagIds.filter((tagId) => !tagById.has(tagId));
    }

    if (missingTagIds.length > 0) {
      throw new AppError(
        400,
        'validation_error',
        `Unknown tag ids in link update payload: ${missingTagIds.join(', ')}.`
      );
    }

    return normalizedTagIds.map((tagId) => ({
      id: tagId,
      name: tagById.get(tagId) as string
    }));
  }

  // This helper unwraps list payloads because Linkwarden responses vary by endpoint/version.
  private extractListItems(response: any): any[] {
    if (Array.isArray(response?.results)) {
      return response.results;
    }

    if (Array.isArray(response?.response)) {
      return response.response;
    }

    if (Array.isArray(response?.response?.items)) {
      return response.response.items;
    }

    if (Array.isArray(response?.items)) {
      return response.items;
    }

    if (Array.isArray(response?.data)) {
      return response.data;
    }

    if (Array.isArray(response)) {
      return response;
    }

    return [];
  }

  // This helper unwraps single-entity payloads because Linkwarden responses vary by endpoint/version.
  private extractSingleItem(response: any): any {
    if (response && typeof response === 'object') {
      if (response.link && typeof response.link === 'object' && !Array.isArray(response.link)) {
        return response.link;
      }
      if (response.item && typeof response.item === 'object' && !Array.isArray(response.item)) {
        return response.item;
      }
      if (response.result && typeof response.result === 'object' && !Array.isArray(response.result)) {
        return response.result;
      }
      if (response.response && typeof response.response === 'object' && !Array.isArray(response.response)) {
        return response.response;
      }
      if (response.data && typeof response.data === 'object' && !Array.isArray(response.data)) {
        return response.data;
      }
    }
    return response;
  }

  // This helper derives a total count from known Linkwarden list metadata fields.
  private extractTotal(response: any): number | undefined {
    const candidates = [
      response?.total,
      response?.count,
      response?.totalCount,
      response?.paging?.total,
      response?.pagination?.total,
      response?.meta?.total,
      response?.response?.total,
      response?.response?.count,
      response?.response?.pagination?.total
    ];

    for (const value of candidates) {
      if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
      }
    }

    return undefined;
  }

  // This helper unwraps search payload arrays from modern Linkwarden /api/v1/search responses.
  private extractSearchItems(response: any): any[] {
    if (Array.isArray(response?.data?.links)) {
      return response.data.links;
    }

    return this.extractListItems(response);
  }

  // This helper unwraps the search cursor value from modern Linkwarden /api/v1/search responses.
  private extractSearchNextCursor(response: any): number | undefined {
    const rawCursor = response?.data?.nextCursor ?? response?.nextCursor ?? response?.response?.nextCursor;

    if (rawCursor === null || rawCursor === undefined) {
      return undefined;
    }

    if (typeof rawCursor === 'number' && Number.isFinite(rawCursor)) {
      return rawCursor;
    }

    if (typeof rawCursor === 'string') {
      const parsed = Number(rawCursor);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }

    return undefined;
  }

  // This helper enforces MCP scope filters locally to stay deterministic when upstream filters are incomplete.
  private matchesScopeFilters(item: LinkItem, scope: PlanScope | undefined): boolean {
    if (scope?.collectionId !== undefined && item.collection?.id !== scope.collectionId) {
      return false;
    }

    if (Array.isArray(scope?.tagIds) && scope.tagIds.length > 0) {
      const allowedTagIds = new Set(scope.tagIds);
      const hasAllowedTag = item.tags.some((tag) => allowedTagIds.has(tag.id));
      if (!hasAllowedTag) {
        return false;
      }
    }

    if (typeof scope?.archived === 'boolean') {
      if ((item.archived ?? false) !== scope.archived) {
        return false;
      }
    }

    if (typeof scope?.pinned === 'boolean') {
      if ((item.pinned ?? false) !== scope.pinned) {
        return false;
      }
    }

    return true;
  }

  // This helper normalizes incoming search text to keep wildcard and whitespace inputs predictable.
  private normalizeQuery(query: string): string {
    return query.trim();
  }

  // This helper identifies wildcard-like search inputs that should use list-based retrieval.
  private isWildcardQuery(normalizedQuery: string): boolean {
    return normalizedQuery === '*' || normalizedQuery.length === 0;
  }

  // This helper creates one compact page fingerprint to detect repeated upstream pages.
  private buildPageSignature(items: Array<{ id: number }>): string {
    const head = items
      .slice(0, 5)
      .map((item) => item.id)
      .join(',');
    const tail = items
      .slice(-5)
      .map((item) => item.id)
      .join(',');
    return `${items.length}|${head}|${tail}`;
  }

  // This helper maps one raw link payload and skips invalid entities with explicit diagnostics.
  private mapLinkOrNull(raw: any): LinkItem | null {
    if (!raw || typeof raw !== 'object') {
      this.log('warn', 'linkwarden_link_payload_invalid_type', {
        payloadType: typeof raw
      });
      return null;
    }

    const id = Number(raw.id);
    const url = String(raw.url ?? '');
    if (!Number.isInteger(id) || id <= 0 || url.length === 0) {
      this.log('warn', 'linkwarden_link_payload_invalid_shape', {
        keys: Object.keys(raw),
        id: raw.id,
        hasUrl: typeof raw.url === 'string'
      });
      return null;
    }

    return {
      id,
      title: String(raw.title ?? raw.name ?? ''),
      url,
      description: raw.description ? String(raw.description) : null,
      tags: Array.isArray(raw.tags) ? raw.tags.map((tag: any) => this.mapTag(tag)) : [],
      collection: raw.collection ? this.mapCollection(raw.collection) : null,
      archived: typeof raw.archived === 'boolean' ? raw.archived : undefined,
      // This mapping keeps pinned compatibility across Linkwarden payload variants.
      pinned:
        typeof raw.pinned === 'boolean'
          ? raw.pinned
          : Array.isArray(raw.pinnedBy)
            ? raw.pinnedBy.length > 0
            : false,
      createdAt: raw.createdAt ? String(raw.createdAt) : undefined,
      updatedAt: raw.updatedAt ? String(raw.updatedAt) : undefined
    };
  }

  // This helper maps one raw link payload and throws when payload shape is invalid.
  private mapLink(raw: any): LinkItem {
    const mapped = this.mapLinkOrNull(raw);
    if (!mapped) {
      throw new AppError(502, 'linkwarden_api_error', 'Link payload shape is invalid.');
    }
    return mapped;
  }

  // This method performs text search in Linkwarden with strict paging and optional filters.
  public async searchLinks(input: SearchInput): Promise<ApiListResult<LinkItem>> {
    const normalizedQuery = this.normalizeQuery(input.query);
    // This branch keeps wildcard and empty queries on the native list endpoint.
    if (this.isWildcardQuery(normalizedQuery)) {
      return this.listLinks({
        limit: input.limit,
        offset: input.offset,
        collectionId: input.collectionId,
        tagIds: input.tagIds,
        archived: input.archived,
        pinned: input.pinned
      });
    }

    const query: Record<string, string | number | boolean | undefined> = {
      query: normalizedQuery,
      limit: input.limit,
      offset: input.offset,
      collectionId: input.collectionId,
      archived: input.archived,
      pinned: input.pinned
    };

    if (input.tagIds && input.tagIds.length > 0) {
      query.tagIds = input.tagIds.join(',');
    }

    const response = await this.request<any>('GET', '/api/v1/search', { query });
    const items = this.extractListItems(response)
      .map((raw: any) => this.mapLinkOrNull(raw))
      .filter((item): item is LinkItem => item !== null);
    return {
      items,
      total: this.extractTotal(response)
    };
  }

  // This method lists links with optional filters using the documented links endpoint.
  public async listLinks(input: LinkListFilters): Promise<ApiListResult<LinkItem>> {
    const query: Record<string, string | number | boolean | undefined> = {
      limit: input.limit,
      offset: input.offset,
      collectionId: input.collectionId,
      archived: input.archived,
      pinned: input.pinned
    };

    if (input.tagIds && input.tagIds.length > 0) {
      query.tagIds = input.tagIds.join(',');
    }

    const response = await this.request<any>('GET', '/api/v1/links', { query });
    const rawItems = this.extractListItems(response);
    const items = rawItems
      .map((raw: any) => this.mapLinkOrNull(raw))
      .filter((item): item is LinkItem => item !== null);
    const total = this.extractTotal(response);

    // This log keeps page-level telemetry visible so paging bugs can be diagnosed without dumping full payloads.
    this.log('debug', 'linkwarden_list_links_page_loaded', {
      requestedLimit: input.limit,
      requestedOffset: input.offset,
      returnedRawItems: rawItems.length,
      returnedItems: items.length,
      total,
      firstId: items[0]?.id,
      lastId: items[items.length - 1]?.id
    });

    return {
      items,
      total
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

    const rawItems = this.extractListItems(response);
    const mappedItems = rawItems.map((raw: any) => this.mapCollection(raw));
    const explicitTotal = this.extractTotal(response);
    const pagedItems = this.applyLocalPagingWindow(mappedItems, input);

    // This fallback keeps collection paging deterministic when upstream ignores limit/offset.
    const inferredTotal = explicitTotal ?? this.inferTotalFromWindow(rawItems.length, input);

    return {
      items: pagedItems,
      total: inferredTotal
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

    const rawItems = this.extractListItems(response);
    const mappedItems = rawItems.map((raw: any) => this.mapTag(raw));
    const explicitTotal = this.extractTotal(response);
    const pagedItems = this.applyLocalPagingWindow(mappedItems, input);

    // This fallback keeps tag paging deterministic when upstream ignores limit/offset.
    const inferredTotal = explicitTotal ?? this.inferTotalFromWindow(rawItems.length, input);

    return {
      items: pagedItems,
      total: inferredTotal
    };
  }

  // This helper applies one deterministic local paging window when upstream returns oversized pages.
  private applyLocalPagingWindow<T>(items: T[], input: PagingInput): T[] {
    if (typeof input.limit !== 'number') {
      return items.slice(input.offset);
    }

    // This branch handles ignored upstream paging by slicing from the requested offset locally.
    if (items.length > input.limit) {
      return items.slice(input.offset, input.offset + input.limit);
    }

    // This branch only enforces upper bound when upstream already applies offset paging.
    return items.slice(0, input.limit);
  }

  // This helper infers one stable total count when upstream omits total metadata.
  private inferTotalFromWindow(returnedCount: number, input: PagingInput): number | undefined {
    if (typeof input.limit !== 'number') {
      return input.offset + returnedCount;
    }

    // This condition indicates likely unpaged upstream responses where returnedCount reflects full dataset size.
    if (returnedCount > input.limit) {
      return returnedCount;
    }

    if (returnedCount < input.limit) {
      return input.offset + returnedCount;
    }

    if (input.offset === 0) {
      return returnedCount;
    }

    return undefined;
  }

  // This method creates one tag and returns a normalized tag record.
  public async createTag(name: string): Promise<LinkTag> {
    const response = await this.request<any>('POST', '/api/v1/tags', {
      body: {
        tags: [
          {
            label: name
          }
        ]
      }
    });
    const rawItems = this.extractListItems(response);
    if (rawItems.length > 0) {
      const created = this.mapTag(rawItems[0]);
      this.tagNameByIdCache = undefined;
      return created;
    }
    const created = this.mapTag(this.extractSingleItem(response));
    this.tagNameByIdCache = undefined;
    return created;
  }

  // This method deletes one tag by id through Linkwarden's native tag endpoint.
  public async deleteTag(id: number): Promise<void> {
    await this.request<any>('DELETE', `/api/v1/tags/${id}`);
    this.tagNameByIdCache = undefined;
  }

  // This method fetches one link by id and returns bounded details.
  public async getLink(id: number): Promise<LinkItem> {
    const response = await this.request<any>('GET', `/api/v1/links/${id}`);
    return this.mapLink(this.extractSingleItem(response));
  }

  // This method updates one link through Linkwarden's native PUT /api/v1/links/{id} contract.
  public async updateLink(id: number, updates: Record<string, unknown>): Promise<LinkItem> {
    const currentResponse = await this.request<any>('GET', `/api/v1/links/${id}`);
    const current = this.extractSingleItem(currentResponse);

    if (!current || typeof current !== 'object') {
      throw new AppError(502, 'linkwarden_api_error', 'Link payload shape is invalid.');
    }

    const body: Record<string, unknown> = {
      id,
      name: typeof updates.title === 'string' ? updates.title : String(current.name ?? current.title ?? ''),
      url: typeof updates.url === 'string' ? updates.url : String(current.url ?? ''),
      description:
        typeof updates.description === 'string' ? updates.description : String(current.description ?? ''),
      icon: current.icon ?? undefined,
      iconWeight: current.iconWeight ?? undefined,
      color: current.color ?? undefined
    };

    const hasCollectionUpdate = Object.prototype.hasOwnProperty.call(updates, 'collectionId');
    const requestedCollectionId = hasCollectionUpdate ? (updates.collectionId as number | null) : undefined;
    if (requestedCollectionId === null) {
      throw new AppError(400, 'validation_error', 'collectionId cannot be null for native Linkwarden updates.');
    }

    const targetCollectionId = requestedCollectionId ?? Number(current.collection?.id);
    if (!Number.isInteger(targetCollectionId) || targetCollectionId <= 0) {
      throw new AppError(400, 'validation_error', `Link ${id} has no valid target collection.`);
    }

    let targetOwnerId = Number(current.collection?.ownerId ?? current.collection?.owner?.id ?? current.ownerId);
    if (!Number.isInteger(targetOwnerId) || targetOwnerId <= 0 || requestedCollectionId !== undefined) {
      const targetCollectionResponse = await this.request<any>('GET', `/api/v1/collections/${targetCollectionId}`);
      const targetCollection = this.extractSingleItem(targetCollectionResponse);
      targetOwnerId = Number(targetCollection?.ownerId);
    }
    if (!Number.isInteger(targetOwnerId) || targetOwnerId <= 0) {
      throw new AppError(400, 'validation_error', `Target collection ${targetCollectionId} has no valid ownerId.`);
    }

    body.collection = {
      id: targetCollectionId,
      ownerId: targetOwnerId
    };

    // This mapping keeps tag updates compatible with Linkwarden's object-based tag payload.
    if (Array.isArray(updates.tagIds)) {
      body.tags = await this.resolveTagPayload(updates.tagIds.map((tagId) => Number(tagId)));
    } else if (Array.isArray(current.tags)) {
      const currentTagIds = this.normalizeTagIds(current.tags.map((tag: any) => Number(tag.id)));
      body.tags = await this.resolveTagPayload(currentTagIds);
    } else {
      body.tags = [];
    }

    // This mapping uses Linkwarden's native pinnedBy relation model for pin/unpin writes.
    if (typeof updates.pinned === 'boolean') {
      const currentUserId = await this.getCurrentUserId();
      body.pinnedBy = [updates.pinned ? { id: currentUserId } : {}];
    }

    await this.request<any>('PUT', `/api/v1/links/${id}`, {
      body
    });

    // This follow-up read keeps the response shape stable across Linkwarden versions.
    return this.getLink(id);
  }

  // This method creates one Linkwarden collection and returns a normalized collection record.
  public async createCollection(input: CreateCollectionInput): Promise<LinkCollection> {
    const body: Record<string, unknown> = {
      name: input.name
    };

    // This mapping omits parentId for root collections because Linkwarden rejects explicit null here.
    if (typeof input.parentId === 'number') {
      body.parentId = input.parentId;
    }

    const response = await this.request<any>('POST', '/api/v1/collections', {
      body
    });

    return this.mapCollection(this.extractSingleItem(response));
  }

  // This method reads one collection by id and returns normalized collection metadata.
  public async getCollection(id: number): Promise<LinkCollection> {
    const response = await this.request<any>('GET', `/api/v1/collections/${id}`);
    return this.mapCollection(this.extractSingleItem(response));
  }

  // This method updates one collection with native payload requirements for rename and move operations.
  public async updateCollection(id: number, updates: UpdateCollectionInput): Promise<LinkCollection> {
    const currentResponse = await this.request<any>('GET', `/api/v1/collections/${id}`);
    const current = this.extractSingleItem(currentResponse);

    if (!current || typeof current !== 'object') {
      throw new AppError(502, 'linkwarden_api_error', 'Collection payload shape is invalid.');
    }

    const members = Array.isArray(current.members)
      ? current.members
          .map((member: any) => this.mapCollectionMemberForUpdate(member))
          .filter(
            (
              member: any
            ): member is {
              userId: number;
              canCreate: boolean;
              canUpdate: boolean;
              canDelete: boolean;
            } => member !== null
          )
      : [];

    const body: Record<string, unknown> = {
      id,
      name: typeof updates.name === 'string' ? updates.name : String(current.name ?? ''),
      description: current.description ?? undefined,
      color: current.color ?? undefined,
      isPublic: typeof current.isPublic === 'boolean' ? current.isPublic : undefined,
      icon: current.icon ?? undefined,
      iconWeight: current.iconWeight ?? undefined,
      parentId: updates.parentId === null ? 'root' : updates.parentId ?? current.parentId ?? undefined,
      members
    };

    const updatedResponse = await this.request<any>('PUT', `/api/v1/collections/${id}`, {
      body
    });

    return this.mapCollection(this.extractSingleItem(updatedResponse));
  }

  // This method deletes one collection by id through Linkwarden's native collection endpoint.
  public async deleteCollection(id: number): Promise<void> {
    await this.request<any>('DELETE', `/api/v1/collections/${id}`);
  }

  // This method creates one URL link and returns normalized bounded link output.
  public async createLink(input: CreateLinkInput): Promise<LinkItem> {
    // This normalization keeps tag payload generation strict and deterministic for Linkwarden create requests.
    const normalizedTagIds = Array.isArray(input.tagIds) ? input.tagIds.map((tagId) => Number(tagId)) : [];
    const resolvedTags = normalizedTagIds.length > 0 ? await this.resolveTagPayload(normalizedTagIds) : [];

    // This debug event only logs payload shape metadata and never includes secrets or full payload content.
    this.log('debug', 'linkwarden_create_link_payload_shape', {
      hasTags: resolvedTags.length > 0,
      tagsCount: resolvedTags.length,
      firstTagType: resolvedTags.length > 0 ? typeof resolvedTags[0] : 'none',
      hasCollectionId: typeof input.collectionId === 'number',
      hasArchivedFlag: typeof input.archived === 'boolean'
    });

    const response = await this.request<any>('POST', '/api/v1/links', {
      body: {
        type: 'url',
        name: input.title ?? input.url,
        url: input.url,
        description: input.description ?? '',
        collectionId: input.collectionId,
        tags: resolvedTags,
        archived: input.archived
      }
    });

    return this.mapLink(this.extractSingleItem(response));
  }

  // This method deletes one link by id through Linkwarden's native link endpoint.
  public async deleteLink(id: number): Promise<void> {
    await this.request<any>('DELETE', `/api/v1/links/${id}`);
  }

  // This method toggles one link pin state by updating Linkwarden's pinnedBy relation with current user id.
  public async setLinkPinned(id: number, pinned: boolean): Promise<LinkItem> {
    const [currentUserId, currentResponse] = await Promise.all([
      this.getCurrentUserId(),
      this.request<any>('GET', `/api/v1/links/${id}`)
    ]);
    const current = this.extractSingleItem(currentResponse);

    if (!current || typeof current !== 'object') {
      throw new AppError(502, 'linkwarden_api_error', 'Link payload shape is invalid.');
    }

    const collectionId = Number(current.collection?.id);
    if (!Number.isInteger(collectionId) || collectionId <= 0) {
      throw new AppError(400, 'validation_error', `Link ${id} has no valid collection and cannot be pinned.`);
    }

    const ownerIdCandidate = Number(current.collection?.ownerId ?? current.collection?.owner?.id ?? current.ownerId);
    const ownerId = Number.isInteger(ownerIdCandidate) && ownerIdCandidate > 0 ? ownerIdCandidate : currentUserId;

    const currentTagIds = Array.isArray(current.tags)
      ? this.normalizeTagIds(current.tags.map((tag: any) => Number(tag.id)))
      : [];
    const tags = await this.resolveTagPayload(currentTagIds);

    const body: Record<string, unknown> = {
      id,
      name: String(current.name ?? current.title ?? ''),
      url: String(current.url ?? ''),
      description: String(current.description ?? ''),
      icon: current.icon ?? undefined,
      iconWeight: current.iconWeight ?? undefined,
      color: current.color ?? undefined,
      collection: {
        id: collectionId,
        ownerId
      },
      tags,
      pinnedBy: [pinned ? { id: currentUserId } : {}]
    };

    await this.request<any>('PUT', `/api/v1/links/${id}`, {
      body
    });

    return this.getLink(id);
  }

  // This method resolves and caches current Linkwarden user id for relation-based write payloads.
  public async getCurrentUserId(): Promise<number> {
    if (typeof this.currentUserIdCache === 'number') {
      return this.currentUserIdCache;
    }

    const response = await this.request<any>('GET', '/api/v1/users/me');
    const user = this.extractSingleItem(response);
    const userId = Number(user?.id);

    if (!Number.isInteger(userId) || userId <= 0) {
      throw new AppError(502, 'linkwarden_api_error', 'Current Linkwarden user id is missing in /api/v1/users/me.');
    }

    this.currentUserIdCache = userId;
    return userId;
  }

  // This method loads all collections in pages and can optionally stop after maxItems.
  public async listAllCollections(maxItems?: number): Promise<LinkCollection[]> {
    const all: LinkCollection[] = [];
    const seenPageSignatures = new Set<string>();
    let offset = 0;
    const pageSize = 100;
    const hasCap = typeof maxItems === 'number';

    while (true) {
      const result = await this.listCollections({
        limit: hasCap ? Math.min(pageSize, Math.max(0, maxItems - all.length)) : pageSize,
        offset
      });

      if (result.items.length === 0) {
        break;
      }

      // This guard prevents endless loops when upstream paging keeps returning the same collection page.
      const pageSignature = this.buildPageSignature(result.items);
      if (seenPageSignatures.has(pageSignature)) {
        this.log('warn', 'linkwarden_collection_pagination_repeated_page_detected', {
          offset,
          pageSignature
        });
        break;
      }
      seenPageSignatures.add(pageSignature);

      all.push(...result.items);
      if (hasCap && all.length >= maxItems) {
        all.length = maxItems;
        break;
      }
      if (typeof result.total === 'number' && all.length >= result.total) {
        break;
      }

      offset += result.items.length;
    }

    return all;
  }

  // This method loads all links in one collection with paging and optional cap.
  public async listLinksByCollection(collectionId: number, maxItems?: number): Promise<LinkItem[]> {
    const all: LinkItem[] = [];
    const seenPageSignatures = new Set<string>();
    let offset = 0;
    const pageSize = 100;
    const hasCap = typeof maxItems === 'number';

    while (true) {
      const result = await this.listLinks({
        collectionId,
        limit: hasCap ? Math.min(pageSize, Math.max(0, maxItems - all.length)) : pageSize,
        offset
      });

      if (result.items.length === 0) {
        break;
      }

      // This guard prevents endless loops when upstream paging keeps returning the same link page.
      const pageSignature = this.buildPageSignature(result.items);
      if (seenPageSignatures.has(pageSignature)) {
        this.log('warn', 'linkwarden_collection_links_pagination_repeated_page_detected', {
          collectionId,
          offset,
          pageSignature
        });
        break;
      }
      seenPageSignatures.add(pageSignature);

      all.push(...result.items);
      if (hasCap && all.length >= maxItems) {
        all.length = maxItems;
        break;
      }
      if (typeof result.total === 'number' && all.length >= result.total) {
        break;
      }

      offset += result.items.length;
    }

    return all;
  }

  // This method loads all tags in pages and can optionally stop after maxItems.
  public async listAllTags(maxItems?: number): Promise<LinkTag[]> {
    const all: LinkTag[] = [];
    const seenPageSignatures = new Set<string>();
    let offset = 0;
    const pageSize = 100;
    const hasCap = typeof maxItems === 'number';

    while (true) {
      const result = await this.listTags({
        limit: hasCap ? Math.min(pageSize, Math.max(0, maxItems - all.length)) : pageSize,
        offset
      });

      if (result.items.length === 0) {
        break;
      }

      // This guard prevents endless loops when upstream paging keeps returning the same tag page.
      const pageSignature = this.buildPageSignature(result.items);
      if (seenPageSignatures.has(pageSignature)) {
        this.log('warn', 'linkwarden_tag_pagination_repeated_page_detected', {
          offset,
          pageSignature
        });
        break;
      }
      seenPageSignatures.add(pageSignature);

      all.push(...result.items);
      if (hasCap && all.length >= maxItems) {
        all.length = maxItems;
        break;
      }
      if (typeof result.total === 'number' && all.length >= result.total) {
        break;
      }

      offset += result.items.length;
    }

    return all;
  }

  // This method loads links in scope and returns diagnostics so callers can surface paging issues.
  public async loadLinksForScopeDetailed(scope: PlanScope | undefined, pageSize = 100): Promise<ScopedLinkLoadResult> {
    const normalizedQuery = this.normalizeQuery(scope?.query ?? '');
    const all: LinkItem[] = [];
    const seenIds = new Set<number>();
    const seenPageSignatures = new Set<string>();
    const seenCursorKeys = new Set<string>();
    const mode: ScopedLinkLoadResult['diagnostics']['mode'] = this.isWildcardQuery(normalizedQuery)
      ? 'list_scan'
      : 'search_scan';
    const searchQueryString = this.isWildcardQuery(normalizedQuery) ? undefined : normalizedQuery;
    const tagId = Array.isArray(scope?.tagIds) && scope.tagIds.length === 1 ? scope.tagIds[0] : undefined;
    let cursor: number | undefined = undefined;
    let pagesScanned = 0;

    while (true) {
      const cursorKey = cursor === undefined ? '__initial__' : String(cursor);
      if (seenCursorKeys.has(cursorKey)) {
        this.log('warn', 'linkwarden_scope_search_cursor_cycle_detected', {
          mode,
          cursor: cursorKey
        });
        break;
      }
      seenCursorKeys.add(cursorKey);

      const response = await this.request<any>('GET', '/api/v1/search', {
        query: {
          searchQueryString,
          collectionId: scope?.collectionId,
          tagId,
          pinnedOnly: scope?.pinned === true ? true : undefined,
          cursor
        }
      });
      pagesScanned += 1;
      const pageItems = this.extractSearchItems(response)
        .map((raw: any) => this.mapLinkOrNull(raw))
        .filter((item): item is LinkItem => item !== null);

      if (pageItems.length === 0) {
        break;
      }

      // This guard prevents endless loops when upstream paging keeps returning the same page.
      const pageSignature = this.buildPageSignature(pageItems);
      if (seenPageSignatures.has(pageSignature)) {
        this.log('warn', 'linkwarden_scope_search_repeated_page_detected', {
          mode,
          cursor: cursorKey,
          pageSignature
        });
        break;
      }
      seenPageSignatures.add(pageSignature);

      for (const item of pageItems) {
        if (seenIds.has(item.id)) {
          continue;
        }
        if (!this.matchesScopeFilters(item, scope)) {
          continue;
        }
        seenIds.add(item.id);
        all.push(item);
      }

      const nextCursor = this.extractSearchNextCursor(response);
      if (nextCursor === undefined) {
        break;
      }
      cursor = nextCursor;
    }

    all.sort((a, b) => a.id - b.id);
    return {
      items: all,
      diagnostics: {
        mode,
        pageSize,
        pagesScanned,
        fallbackPageSizeApplied: null
      }
    };
  }

  // This method loads all links in a scope in pages for planning operations.
  public async loadLinksForScope(scope: PlanScope | undefined, pageSize = 100): Promise<LinkItem[]> {
    const loaded = await this.loadLinksForScopeDetailed(scope, pageSize);
    return loaded.items;
  }
}
