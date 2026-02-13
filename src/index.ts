// This is the process entrypoint that starts the HTTP server and handles graceful shutdown.

import { createServer } from './server.js';

const host = process.env.HOST ?? '0.0.0.0';
const port = Number(process.env.PORT ?? 8080);

const { app, db } = createServer();

// This helper performs graceful shutdown to avoid SQLite corruption during container stop events.
async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, 'shutdown_started');

  try {
    await app.close();
  } finally {
    db.close();
  }

  app.log.info({ signal }, 'shutdown_completed');
  process.exit(0);
}

process.on('SIGTERM', () => {
  void shutdown('SIGTERM');
});

process.on('SIGINT', () => {
  void shutdown('SIGINT');
});

app
  .listen({ host, port })
  .then(() => {
    app.log.info({ host, port }, 'server_started');
  })
  .catch((error) => {
    app.log.error({ message: error.message, stack: error.stack }, 'server_start_failed');
    process.exit(1);
  });
