import express from 'express';

// Builds the Express app. Kept as a factory so tests can run
// isolated instances without starting a real HTTP server
export function createApp() {
  const app = express();

  // Placeholder until we implement pino logging
  // (index.ts already expects app.locals.logger to exist)
  // TODO: Replace with pino
  app.locals.logger = {
    info: (obj: object, msg?: string) => {
      if (msg) {
        console.log(msg, obj);
      } else {
        console.log(obj);
      }
    },
    error: (obj: object, msg?: string) => {
      if (msg) {
        console.error(msg, obj);
      } else {
        console.error(obj);
      }
    }
  };

  // Check if the request body is within the 1 KB limit (to prevent abuse)
  app.use(express.json({ limit: '1kb', strict: true }));

  // Docker health check
  app.get('/healthz', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });

  // Password evaluation endpoint
  app.post('/v1/password/evaluate', (request, response) => {
    response.json({
      received: Boolean(request.body?.password)
    });
  });

  // Handling of unknown routes
  app.use((_request, response) => {
    response.status(404).json({
      error: 'not_found',
      message: 'The requested resource was not found.'
    });
  });

  return app;
}
