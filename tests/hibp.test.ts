import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkPwnedPassword, parseRangeResponse } from '../src/services/hibp.js';

describe('HIBP client', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses a matching suffix count from a range response', () => {
    expect(parseRangeResponse('ABC:1\r\nDEF:42\r\n', 'def')).toBe(42);
    expect(parseRangeResponse('ABC:1\r\n', 'DEF')).toBe(0);
  });

  it('uses k-anonymity range lookup with Add-Padding enabled', async () => {
    const password = 'password';
    const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: vi.fn().mockResolvedValue(`${suffix}:42\r\n00000000000000000000000000000000000:0`)
    });

    vi.stubGlobal('fetch', fetchMock);

    await expect(checkPwnedPassword(password)).resolves.toEqual({
      checked: true,
      breached: true,
      occurrences: 42
    });

    expect(fetchMock).toHaveBeenCalledWith(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'Add-Padding': 'true'
        })
      })
    );
  });

  it('returns unchecked instead of failing on network errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unavailable')));

    await expect(checkPwnedPassword('anything secure enough')).resolves.toEqual({
      checked: false,
      breached: false,
      occurrences: null
    });
  });
});
