// This test suite verifies deterministic tracking-parameter cleanup for link URL updates.

import { describe, expect, it } from 'vitest';
import { cleanTrackedUrl } from '../src/utils/url-cleaner.js';

describe('url cleaner', () => {
  it('removes utm and known tracking params while keeping functional params', () => {
    const result = cleanTrackedUrl('https://example.com/path?utm_source=x&fbclid=abc&id=7', {
      removeUtm: true,
      removeKnownTracking: true,
      keepParams: [],
      extraTrackingParams: []
    });

    expect(result.changed).toBe(true);
    expect(result.cleanedUrl).toBe('https://example.com/path?id=7');
    expect(result.removedParams).toEqual(['utm_source', 'fbclid']);
  });

  it('respects keepParams even when names are known tracking parameters', () => {
    const result = cleanTrackedUrl('https://example.com/path?utm_source=x&ref_src=chatgpt', {
      removeUtm: true,
      removeKnownTracking: true,
      keepParams: ['ref_src'],
      extraTrackingParams: []
    });

    expect(result.cleanedUrl).toBe('https://example.com/path?ref_src=chatgpt');
    expect(result.removedParams).toEqual(['utm_source']);
  });
});
