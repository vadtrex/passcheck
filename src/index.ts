import { createApp } from './app.js';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
// Bind to all interfaces so containers can reach the service
const host = process.env.HOST ?? '0.0.0.0';

const app = createApp();

const server = app.listen(port, host, () => {
  app.locals.logger.info({ host, port }, 'passcheck listening');
});

// Handle shutdown signals and allow in-flight requests to finish
const shutdown = (signal: NodeJS.Signals) => {
  app.locals.logger.info({ signal }, 'shutdown requested');
  server.close((error) => {
    if (error) {
      app.locals.logger.error({ error }, 'shutdown failed');
      process.exit(1);
    }

    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
