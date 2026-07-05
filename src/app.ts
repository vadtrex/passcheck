import express, { type ErrorRequestHandler } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { pinoHttp } from 'pino-http';
import pino, { type DestinationStream } from 'pino';
import { ZodError } from 'zod';
import { createEvaluateRouter } from './routes/evaluate.js';
import { checkPwnedPassword, type BreachChecker } from './services/hibp.js';

export interface AppOptions {
  breachChecker?: BreachChecker;
  // Pass false in tests to keep output quiet
  logger?: boolean;
  // Optional stream for capturing logs in tests
  logStream?: DestinationStream;
  // Override rate limit settings (useful in tests)
  rateLimit?: {
    windowMs: number;
    limit: number;
  };
}

// Builds the Express app. Kept as a factory so tests can run
// isolated instances without starting a real HTTP server
export function createApp(options: AppOptions = {}) {
  const app = express();
  const loggerEnabled = options.logger ?? process.env.NODE_ENV !== 'test';

  const logger = pinoHttp({
    enabled: loggerEnabled,
    stream: options.logStream,
    serializers: {
      req(request) {
        const serialized = pino.stdSerializers.req(request);
        const body = request.raw?.body;

        return body === undefined ? serialized : { ...serialized, body };
      }
    },
    redact: {
      paths: [
        'req.body.password',
        'req.body.username',
        'req.body.email',
        'res.body.password',
        'password',
        '*.password',
        'username',
        '*.username',
        'email',
        '*.email',
        'req.headers.authorization'
      ],
      censor: '[REDACTED]'
    }
  });

  app.locals.logger = logger.logger;
  app.disable('x-powered-by');

  app.use(helmet());
  app.use(
    rateLimit({
      windowMs: options.rateLimit?.windowMs ?? 15 * 60 * 1000,
      limit: options.rateLimit?.limit ?? 100,
      standardHeaders: true,
      legacyHeaders: false
    })
  );
  // Check if the request body is within the 1 KB limit (to prevent abuse)
  app.use(express.json({ limit: '1kb', strict: true }));
  app.use(logger);

  // Docker health check
  app.get('/healthz', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });

  // Password evaluation endpoint
  app.use(
    '/v1/password',
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
  const errorHandler: ErrorRequestHandler = (error, request, response, _next) => {
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

    request.log.error({ error }, 'unhandled request error');
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
