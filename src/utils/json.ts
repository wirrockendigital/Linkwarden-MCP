// This utility module keeps JSON parse/stringify operations safe and explicit.

import { AppError } from './errors.js';

// This helper parses JSON from SQLite rows and emits a controlled error on malformed content.
export function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch (error) {
    throw new AppError(500, 'corrupt_state', `Failed to parse JSON for ${label}.`, {
      originalMessage: error instanceof Error ? error.message : 'unknown'
    });
  }
}
