// This test suite verifies provider-key validation and response parsing for AI-assisted tag inference.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { inferTagTokensViaProvider } from '../src/utils/tag-inference-provider.js';
import { AppError } from '../src/utils/errors.js';

const BASE_LINK = {
  id: 1,
  title: 'Wohnmobil Stellplatz Europa',
  url: 'https://example.org/travel',
  description: 'Tipps für Routen und Camping',
  tags: [],
  collection: null
};

afterEach(() => {
  delete process.env.MCP_PERPLEXITY_API_KEY;
  delete process.env.MCP_MISTRAL_API_KEY;
  delete process.env.MCP_HUGGINGFACE_API_KEY;
  vi.unstubAllGlobals();
});

describe('tag inference provider utility', () => {
  it('throws explicit configuration error when provider key is missing', async () => {
    await expect(
      inferTagTokensViaProvider({
        provider: 'perplexity',
        model: null,
        link: BASE_LINK,
        contextText: 'camping europe route',
        timeoutMs: 1000
      })
    ).rejects.toBeInstanceOf(AppError);
  });

  it('requires explicit model id for huggingface provider', async () => {
    process.env.MCP_HUGGINGFACE_API_KEY = 'hf_test_token';

    await expect(
      inferTagTokensViaProvider({
        provider: 'huggingface',
        model: null,
        link: BASE_LINK,
        contextText: 'camping europe route',
        timeoutMs: 1000
      })
    ).rejects.toMatchObject({
      code: 'tag_inference_model_required'
    });
  });

  it('parses JSON-array content from OpenAI-compatible responses', async () => {
    process.env.MCP_MISTRAL_API_KEY = 'mistral_test_token';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: '["wohnmobil", "camping", "travel-guides"]'
                }
              }
            ]
          }),
          {
            status: 200,
            headers: {
              'content-type': 'application/json'
            }
          }
        )
      )
    );

    const tokens = await inferTagTokensViaProvider({
      provider: 'mistral',
      model: null,
      link: BASE_LINK,
      contextText: 'camping europe route',
      timeoutMs: 1000
    });

    expect(tokens).toEqual(['wohnmobil', 'camping', 'travel-guides']);
  });
});
