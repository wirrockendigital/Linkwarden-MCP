// This module provides a typed application error that can be mapped into JSON-RPC and HTTP responses.

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: unknown;

  public constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

// This helper normalizes unknown failures into an AppError without leaking internals.
export function normalizeError(error: unknown): AppError {
  if (error instanceof AppError) {
    return error;
  }

  if (error instanceof Error) {
    return new AppError(500, 'internal_error', error.message);
  }

  return new AppError(500, 'internal_error', 'An unexpected error occurred.');
}
