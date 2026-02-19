// This test suite verifies OAuth resource resolution defaults and strict resource validation.

import { describe, expect, it } from 'vitest';
import { assertAcceptedResource, getPublicBaseUrl, normalizeResourceValue } from '../src/utils/oauth.js';
import { AppError } from '../src/utils/errors.js';

function makeRequest(): any {
  // This request stub keeps base URL resolution deterministic across tests.
  return {
    protocol: 'https',
    headers: {
      host: 'lwmcp.rocken.digital'
    }
  };
}

describe('oauth resource validation', () => {
  it('defaults to canonical /mcp resource when resource is missing', () => {
    const resolved = assertAcceptedResource(undefined, makeRequest());
    expect(resolved).toBe('https://lwmcp.rocken.digital/mcp');
  });

  it('accepts canonical base and mcp resources', () => {
    const request = makeRequest();
    expect(assertAcceptedResource('https://lwmcp.rocken.digital', request)).toBe('https://lwmcp.rocken.digital');
    expect(assertAcceptedResource('https://lwmcp.rocken.digital/mcp', request)).toBe('https://lwmcp.rocken.digital/mcp');
  });

  it('accepts equivalent resources with host casing and trailing slash variations', () => {
    const request = makeRequest();
    expect(assertAcceptedResource('HTTPS://LWMCP.ROCKEN.DIGITAL/mcp/', request)).toBe('https://lwmcp.rocken.digital/mcp');
    expect(normalizeResourceValue('https://LWMCP.ROCKEN.DIGITAL/mcp/?x=1#fragment')).toBe(
      'https://lwmcp.rocken.digital/mcp'
    );
  });

  it('rejects foreign resources', () => {
    expect(() => assertAcceptedResource('https://example.com/mcp', makeRequest())).toThrowError(AppError);
  });

  it('normalizes forwarded host/proto chains to first hop for stable public URL', () => {
    const request = {
      protocol: 'http',
      headers: {
        host: 'internal.service.local:8080',
        'x-forwarded-proto': 'https, http',
        'x-forwarded-host': 'lwmcp.rocken.digital, ingress.local'
      }
    } as any;

    expect(getPublicBaseUrl(request)).toBe('https://lwmcp.rocken.digital');
    expect(assertAcceptedResource('https://lwmcp.rocken.digital/mcp', request)).toBe('https://lwmcp.rocken.digital/mcp');
  });
});
