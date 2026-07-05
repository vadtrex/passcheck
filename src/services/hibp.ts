import { createHash } from 'node:crypto';

export const HIBP_TIMEOUT_MS = 3000;
export const HIBP_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range';

export type BreachResult =
  | {
      checked: true;
      breached: boolean;
      occurrences: number;
    }
  | {
      checked: false;
      breached: false;
      occurrences: null;
    };

export type BreachChecker = (password: string) => Promise<BreachResult>;

// K-anonymity lookup - only the first 5 SHA-1 hex chars leave the server
export async function checkPwnedPassword(password: string): Promise<BreachResult> {
  const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HIBP_TIMEOUT_MS);

  try {
    const response = await fetch(`${HIBP_RANGE_ENDPOINT}/${prefix}`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Add-Padding': 'true',
        'User-Agent': 'passcheck/1.0'
      }
    });

    if (!response.ok) {
      throw new Error(`HIBP responded with status ${response.status}`);
    }

    const body = await response.text();
    const occurrences = parseRangeResponse(body, suffix);

    return {
      checked: true,
      breached: occurrences > 0,
      occurrences
    };
  } catch {
    // Fallback to local-only scoring when HIBP doesn't respond
    return {
      checked: false,
      breached: false,
      occurrences: null
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function parseRangeResponse(body: string, suffix: string): number {
  const expectedSuffix = suffix.toUpperCase();

  for (const rawLine of body.split(/\r?\n/)) {
    const [hashSuffix, count] = rawLine.trim().split(':');

    if (hashSuffix?.toUpperCase() === expectedSuffix) {
      const parsed = Number.parseInt(count ?? '0', 10);
      return Number.isNaN(parsed) ? 0 : parsed;
    }
  }

  return 0;
}
