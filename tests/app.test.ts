import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import type { BreachChecker } from '../src/services/hibp.js';

const evaluatePath = '/v1/check-password/evaluate';
const strongPassword = 'Panoramic-BlueOrbit-9341-walnut-vivid!';

describe('password strength API', () => {
  it('returns health status', async () => {
    const app = createApp({ logger: false });

    await request(app).get('/healthz').expect(200, { status: 'ok' });
  });

  it('rejects requests without a valid password', async () => {
    const app = createApp({ logger: false });

    const response = await request(app)
      .post(evaluatePath)
      .send({ username: 'okenobi' })
      .expect(400);

    expect(response.body.error).toBe('validation_failed');
    expect(response.body.details).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: 'password' })])
    );
  });

  it('rejects passwords longer than 256 characters', async () => {
    const app = createApp({ logger: false });

    const response = await request(app)
      .post(evaluatePath)
      .send({ password: 'a'.repeat(257) })
      .expect(400);

    expect(response.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ message: 'password must contain at most 256 characters' })
      ])
    );
  });

  it('accepts a strong password that was not breached', async () => {
    const breachChecker: BreachChecker = vi.fn().mockResolvedValue({
      checked: true,
      breached: false,
      occurrences: 0
    });
    const app = createApp({ breachChecker, logger: false });

    const response = await request(app)
      .post(evaluatePath)
      .send({ password: strongPassword })
      .expect(200);

    expect(response.body).toMatchObject({
      strength: expect.any(String),
      acceptable: true,
      breach: { checked: true, breached: false, occurrences: 0 },
      checks: { minLength: true, notBreached: true }
    });
    expect(response.body.score).toBeGreaterThanOrEqual(3);
    expect(breachChecker).toHaveBeenCalledWith(strongPassword);
  });

  it('marks a breached password as unacceptable regardless of local score', async () => {
    const app = createApp({
      logger: false,
      breachChecker: vi.fn().mockResolvedValue({
        checked: true,
        breached: true,
        occurrences: 12345
      })
    });

    const response = await request(app)
      .post(evaluatePath)
      .send({ password: strongPassword })
      .expect(200);

    expect(response.body.acceptable).toBe(false);
    expect(response.body.checks.notBreached).toBe(false);
    expect(response.body.feedback.warning).toBe('This password appeared in known data breaches.');
  });

  it('degrades gracefully when the breach check is unavailable', async () => {
    const app = createApp({
      logger: false,
      breachChecker: vi.fn().mockResolvedValue({
        checked: false,
        breached: false,
        occurrences: null
      })
    });

    const response = await request(app)
      .post(evaluatePath)
      .send({ password: strongPassword })
      .expect(200);

    expect(response.body.acceptable).toBe(true);
    expect(response.body.breach.checked).toBe(false);
    expect(response.body.checks.notBreached).toBe(true);
  });

  it('degrades gracefully when the breach checker throws', async () => {
    const app = createApp({
      logger: false,
      breachChecker: vi.fn().mockRejectedValue(new Error('HIBP timeout'))
    });

    const response = await request(app)
      .post(evaluatePath)
      .send({ password: strongPassword })
      .expect(200);

    expect(response.body.acceptable).toBe(true);
    expect(response.body.breach).toEqual({
      checked: false,
      breached: false,
      occurrences: null
    });
  });

  it('rejects request bodies larger than 1 KB', async () => {
    const app = createApp({ logger: false });

    const response = await request(app)
      .post(evaluatePath)
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ password: `${'a'.repeat(1200)}` }))
      .expect(413);

    expect(response.body.error).toBe('payload_too_large');
  });

  it('detects direct use of username or email parts', async () => {
    const app = createApp({
      logger: false,
      breachChecker: vi.fn().mockResolvedValue({
        checked: true,
        breached: false,
        occurrences: 0
      })
    });

    const response = await request(app)
      .post(evaluatePath)
      .send({
        username: 'okenobi',
        email: 'o.kenobi@jedi-council.com',
        password: 'okenobi-Panoramic-BlueOrbit-9341!'
      })
      .expect(200);

    expect(response.body.checks.noUserInfo).toBe(false);
  });
});
