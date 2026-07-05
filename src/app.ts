import express, { type ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';
import { createEvaluateRouter } from './routes/evaluate.js';
import { checkPwnedPassword, type BreachChecker } from './services/hibp.js';

export interface AppOptions {
  breachChecker?: BreachChecker;
}

// Builds the Express app. Kept as a factory so tests can run
// isolated instances without starting a real HTTP server
export function createApp(options: AppOptions = {}) {
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
  app.use(
    '/v1/check-password',
    createEvaluateRouter({
      breachChecker: options.breachChecker ?? checkPwnedPassword
    })
  );

  // Handling of unknown routes
  app.use((_request, response) => {
    response.status(404).json({
      error: 'not_found',
      message: 'The requested resource was not found.'
    });
  });

  // Error handler for converting thrown errors into consistent JSON responses
  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    if (response.headersSent) {
      return;
    }

    if (error instanceof SyntaxError && 'body' in error) {
      response.status(400).json({
        error: 'invalid_json',
        message: 'Request body must be valid JSON.'
      });
      return;
    }

    if (error instanceof ZodError) {
      response.status(400).json({
        error: 'validation_failed',
        details: error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message
        }))
      });
      return;
    }

    if (isHttpError(error) && error.type === 'entity.too.large') {
      response.status(413).json({
        error: 'payload_too_large',
        message: 'Request body must not exceed 1 KB.'
      });
      return;
    }

    app.locals.logger.error({ error }, 'unhandled request error');
    response.status(500).json({
      error: 'internal_error',
      message: 'Unexpected error while evaluating the password.'
    });
  };

  app.use(errorHandler);

  return app;
}

// Helper function to check if the error is an HTTP error
function isHttpError(error: unknown): error is { type?: string } {
  return typeof error === 'object' && error !== null && 'type' in error;
}
