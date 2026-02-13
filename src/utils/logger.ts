// This module builds a structured JSON logger instance used by Fastify and internal services.

import pino from 'pino';

// This logger emits compact JSON while redacting obvious secret fields.
export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      '*.linkwardenApiToken',
      '*.apiKey',
      '*.bootstrapAdminApiToken',
      '*.masterPassphrase'
    ],
    remove: true
  },
  timestamp: pino.stdTimeFunctions.isoTime
});
