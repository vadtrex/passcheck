import { Router } from 'express';
import { z } from 'zod';
import type { BreachChecker } from '../services/hibp.js';
import { evaluatePasswordStrength } from '../services/strength.js';

// Helper function to parse optional text ("" as undefined)
const optionalText = (maxLength: number) =>
  z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z.string().trim().max(maxLength).optional()
  );

// Request schema for the evaluate endpoint
const evaluateRequestSchema = z
  .object({
    password: z
      .string({ error: 'password must be a string' })
      .min(8, 'password must contain at least 8 characters')
      .max(256, 'password must contain at most 256 characters'),
    username: optionalText(256),
    email: z.preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.string().trim().email('email must be a valid email address').max(320).optional()
    )
  })
  .strict();

export interface EvaluateRouterOptions {
  breachChecker: BreachChecker;
}

export function createEvaluateRouter(options: EvaluateRouterOptions) {
  const router = Router();

  router.post('/evaluate', async (request, response, next) => {
    try {
      const input = evaluateRequestSchema.parse(request.body);
      const result = await evaluatePasswordStrength(input, options.breachChecker);
      response.status(200).json(result);
    } catch (error) {
      next(error);
    }
  });

  return router;
}
