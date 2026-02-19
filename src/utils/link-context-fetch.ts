// This module fetches and sanitizes optional link context text under strict timeout and payload limits.

import type { FastifyBaseLogger } from 'fastify';

export interface LinkContextFetchOptions {
  timeoutMs: number;
  maxBytes: number;
  logger?: FastifyBaseLogger;
}

export interface LinkContextFetchResult {
  fetched: boolean;
  text: string;
  contentType: string | null;
  reason?: string;
}

// This helper normalizes text by removing scripts/styles/tags and reducing whitespace noise.
function sanitizeHtmlText(input: string): string {
  return input
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

// This helper clips a UTF-8 response to one deterministic upper byte bound.
function decodeBoundedBody(buffer: ArrayBuffer, maxBytes: number): string {
  const view = new Uint8Array(buffer);
  const clipped = view.byteLength > maxBytes ? view.slice(0, maxBytes) : view;
  return new TextDecoder('utf-8', { fatal: false }).decode(clipped);
}

// This function fetches one URL and returns sanitized text when response type is text-like.
export async function fetchLinkContext(url: string, options: LinkContextFetchOptions): Promise<LinkContextFetchResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        Accept: 'text/html, text/plain, application/xhtml+xml;q=0.9, */*;q=0.1',
        'User-Agent': 'linkwarden-mcp/0.2'
      }
    });

    if (!response.ok) {
      return {
        fetched: false,
        text: '',
        contentType: null,
        reason: `http_${response.status}`
      };
    }

    const contentType = response.headers.get('content-type');
    const textLike =
      typeof contentType === 'string' &&
      ['text/html', 'text/plain', 'application/xhtml+xml'].some((prefix) =>
        contentType.toLocaleLowerCase().startsWith(prefix)
      );

    if (!textLike) {
      return {
        fetched: false,
        text: '',
        contentType,
        reason: 'unsupported_content_type'
      };
    }

    const body = await response.arrayBuffer();
    const rawText = decodeBoundedBody(body, options.maxBytes);
    return {
      fetched: true,
      text: sanitizeHtmlText(rawText),
      contentType
    };
  } catch (error) {
    options.logger?.debug(
      {
        event: 'link_context_fetch_failed',
        url,
        reason: error instanceof Error ? error.message : 'unknown_error'
      },
      'link_context_fetch_failed'
    );
    return {
      fetched: false,
      text: '',
      contentType: null,
      reason: error instanceof Error ? error.message : 'unknown_error'
    };
  } finally {
    clearTimeout(timeout);
  }
}
