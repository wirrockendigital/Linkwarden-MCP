// This module calls optional external AI providers to extract normalized tag tokens from fetched link context.

import type { FastifyBaseLogger } from 'fastify';
import type { LinkItem, TaggingInferenceProvider } from '../types/domain.js';
import { AppError } from './errors.js';
import { errorForLog, sanitizeForLog } from './logger.js';

const OPENAI_COMPAT_ENDPOINTS: Record<Exclude<TaggingInferenceProvider, 'builtin'>, string> = {
  perplexity: 'https://api.perplexity.ai/chat/completions',
  mistral: 'https://api.mistral.ai/v1/chat/completions',
  huggingface: 'https://router.huggingface.co/v1/chat/completions'
};

const DEFAULT_MODELS: Record<'perplexity' | 'mistral', string> = {
  perplexity: 'sonar',
  mistral: 'mistral-small-latest'
};

const PROVIDER_API_KEY_ENV: Record<Exclude<TaggingInferenceProvider, 'builtin'>, string> = {
  perplexity: 'MCP_PERPLEXITY_API_KEY',
  mistral: 'MCP_MISTRAL_API_KEY',
  huggingface: 'MCP_HUGGINGFACE_API_KEY'
};

export interface TagInferenceInput {
  provider: Exclude<TaggingInferenceProvider, 'builtin'>;
  model: string | null;
  link: LinkItem;
  contextText: string;
  timeoutMs: number;
  logger?: FastifyBaseLogger;
}

// This helper normalizes token candidates into deterministic lowercase kebab-case values.
function normalizeCandidateToken(value: string): string {
  return value
    .trim()
    .toLocaleLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// This helper extracts one lowercase domain value from a URL for prompt context.
function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.toLocaleLowerCase();
  } catch {
    return '';
  }
}

// This helper resolves provider API keys from environment variables and raises explicit config errors.
function resolveProviderApiKey(provider: Exclude<TaggingInferenceProvider, 'builtin'>): string {
  const envName = PROVIDER_API_KEY_ENV[provider];
  const value = process.env[envName]?.trim();
  if (!value) {
    throw new AppError(
      400,
      'tag_inference_provider_not_configured',
      `${envName} is required when inferenceProvider=${provider}.`
    );
  }
  return value;
}

// This helper resolves one provider model id with deterministic defaults and strict Hugging Face requirements.
function resolveProviderModel(provider: Exclude<TaggingInferenceProvider, 'builtin'>, configuredModel: string | null): string {
  const normalized = configuredModel?.trim() ?? '';
  if (normalized.length > 0) {
    return normalized;
  }

  if (provider === 'huggingface') {
    throw new AppError(
      400,
      'tag_inference_model_required',
      'inferenceModel is required when inferenceProvider=huggingface.'
    );
  }

  return DEFAULT_MODELS[provider];
}

// This helper safely unwraps OpenAI-compatible chat content fields into plain text.
function readAssistantContent(payload: unknown): string {
  const choices = (payload as { choices?: unknown[] } | null)?.choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    throw new AppError(502, 'tag_inference_provider_parse_failed', 'Provider response does not contain choices.');
  }

  const message = (choices[0] as { message?: { content?: unknown } } | null)?.message;
  const content = message?.content;

  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    const parts = content
      .map((entry) => {
        if (typeof entry === 'string') {
          return entry;
        }
        if (entry && typeof entry === 'object' && 'text' in entry) {
          const maybeText = (entry as { text?: unknown }).text;
          return typeof maybeText === 'string' ? maybeText : '';
        }
        return '';
      })
      .filter((part) => part.length > 0);
    return parts.join('\n');
  }

  throw new AppError(502, 'tag_inference_provider_parse_failed', 'Provider response content is not supported.');
}

// This helper parses one strict JSON array response and returns sanitized token lists only.
function parseTokensFromModelContent(content: string): string[] {
  const tryParseArray = (raw: string): unknown[] | null => {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  };

  const direct = tryParseArray(content);
  const bracketFallback = direct
    ? direct
    : (() => {
        const match = content.match(/\[[\s\S]*\]/);
        return match ? tryParseArray(match[0]) : null;
      })();

  if (!bracketFallback) {
    throw new AppError(502, 'tag_inference_provider_parse_failed', 'Provider response is not a JSON array.');
  }

  const normalized = bracketFallback
    .filter((item): item is string => typeof item === 'string')
    .map((item) => normalizeCandidateToken(item))
    .filter((item) => item.length >= 2 && item.length <= 40);

  return [...new Set(normalized)].slice(0, 80);
}

// This function executes one provider request and returns deterministic tag tokens for governed tagging enrichment.
export async function inferTagTokensViaProvider(input: TagInferenceInput): Promise<string[]> {
  const apiKey = resolveProviderApiKey(input.provider);
  const model = resolveProviderModel(input.provider, input.model);
  const endpoint = OPENAI_COMPAT_ENDPOINTS[input.provider];

  const excerpt = input.contextText.slice(0, 10_000);
  const promptPayload = {
    url: input.link.url,
    domain: extractDomain(input.link.url),
    title: input.link.title,
    description: input.link.description ?? '',
    collection: input.link.collection?.name ?? '',
    excerpt
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), input.timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model,
        temperature: 0,
        max_tokens: 220,
        messages: [
          {
            role: 'system',
            content:
              'Return only a JSON array of concise tags. Use lowercase kebab-case strings, no duplicates, max 12 entries.'
          },
          {
            role: 'user',
            content: `Extract taxonomy tags from this link context: ${JSON.stringify(promptPayload)}`
          }
        ]
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      const body = await response.text();
      throw new AppError(
        502,
        'tag_inference_provider_error',
        `Provider ${input.provider} returned HTTP ${response.status}.`,
        sanitizeForLog({
          provider: input.provider,
          status: response.status,
          body
        })
      );
    }

    const payload = (await response.json()) as unknown;
    const content = readAssistantContent(payload);
    const tokens = parseTokensFromModelContent(content);
    input.logger?.debug(
      {
        event: 'tag_inference_provider_success',
        provider: input.provider,
        model,
        tokenCount: tokens.length
      },
      'tag_inference_provider_success'
    );
    return tokens;
  } catch (error) {
    input.logger?.warn(
      {
        event: 'tag_inference_provider_failed',
        provider: input.provider,
        model,
        details: sanitizeForLog(errorForLog(error))
      },
      'tag_inference_provider_failed'
    );
    if (error instanceof AppError) {
      throw error;
    }
    if (error instanceof Error && error.name === 'AbortError') {
      throw new AppError(504, 'tag_inference_provider_timeout', `Provider ${input.provider} request timed out.`);
    }
    throw new AppError(
      502,
      'tag_inference_provider_error',
      `Provider ${input.provider} request failed.`,
      sanitizeForLog(errorForLog(error))
    );
  } finally {
    clearTimeout(timeout);
  }
}
