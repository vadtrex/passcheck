import { describe, expect, it } from 'vitest';
import { collectUserInputs } from '../src/services/strength.js';

describe('collectUserInputs', () => {
  it('includes username and full email when provided', () => {
    const inputs = collectUserInputs('okenobi', 'o.kenobi@jedi-council.com');

    expect(inputs).toEqual(expect.arrayContaining(['okenobi', 'o.kenobi@jedi-council.com']));
  });

  it('splits email local part and domain tokens', () => {
    const inputs = collectUserInputs(undefined, 'o.kenobi@jedi-council.com');

    expect(inputs).toEqual(
      expect.arrayContaining(['o.kenobi@jedi-council.com', 'o.kenobi', 'kenobi', 'jedi', 'council', 'com'])
    );
  });

  it('ignores tokens shorter than three characters', () => {
    const inputs = collectUserInputs('jo', 'ab@cd.co');

    expect(inputs).not.toContain('jo');
    expect(inputs).not.toContain('ab');
    expect(inputs).not.toContain('cd');
  });

  it('returns an empty list when no username or email is provided', () => {
    expect(collectUserInputs()).toEqual([]);
  });
});
