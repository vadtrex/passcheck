import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

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

export type StrengthLabel = 'very-weak' | 'weak' | 'fair' | 'strong' | 'very-strong';

export interface PasswordEvaluationInput {
  password: string;
  username?: string;
  email?: string;
}

export interface PasswordEvaluation {
  score: number;
  strength: StrengthLabel;
  acceptable: boolean;
  breach: BreachResult;
  checks: {
    minLength: boolean;
    notBreached: boolean;
    noUserInfo: boolean;
  };
  feedback: {
    warning: string | null;
    suggestions: string[];
  };
  estimatedCrackTime: string;
}

const strengthLabels: StrengthLabel[] = ['very-weak', 'weak', 'fair', 'strong', 'very-strong'];

// Setup zxcvbn options - English dictionaries and keyboard adjacency graphs
zxcvbnOptions.setOptions({
  translations: zxcvbnEnPackage.translations,
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary
  }
});

export async function evaluatePasswordStrength(
  input: PasswordEvaluationInput,
  breachChecker: BreachChecker
): Promise<PasswordEvaluation> {
  const userInputs = collectUserInputs(input.username, input.email);
  const zxcvbnResult = zxcvbn(input.password, userInputs);
  const breach = await safeBreachCheck(input.password, breachChecker);

  const minLength = input.password.length >= 8;
  const noUserInfo = !containsUserInfo(input.password, userInputs);
  const notBreached = breach.checked ? !breach.breached : true;
  // Only length, entropy, and breach status are considered (no composition rules as recommended by NIST)
  const acceptable = zxcvbnResult.score >= 3 && minLength && notBreached;

  return {
    score: zxcvbnResult.score,
    strength: strengthLabels[zxcvbnResult.score] ?? 'very-weak',
    acceptable,
    breach,
    checks: {
      minLength,
      notBreached,
      noUserInfo
    },
    feedback: buildFeedback(zxcvbnResult.feedback, breach),
    estimatedCrackTime: zxcvbnResult.crackTimesDisplay.offlineSlowHashing1e4PerSecond
  };
}

// Handles breach check failures gracefully
async function safeBreachCheck(password: string, breachChecker: BreachChecker): Promise<BreachResult> {
  try {
    return await breachChecker(password);
  } catch {
    return {
      checked: false,
      breached: false,
      occurrences: null
    };
  }
}

// Pull tokens from username and email so zxcvbn can penalize personal info.
export function collectUserInputs(username?: string, email?: string): string[] {
  const parts = new Set<string>();

  addInput(parts, username);
  addInput(parts, email);

  if (email) {
    const [localPart, domainPart] = email.split('@');
    addInput(parts, localPart);

    for (const token of localPart?.split(/[._+\-]+/) ?? []) {
      addInput(parts, token);
    }

    for (const token of domainPart?.split(/[.\-_]+/) ?? []) {
      addInput(parts, token);
    }
  }

  return [...parts];
}

// Skip very short tokens (e.g. "jo" matching inside "project" causes false positives)
function addInput(parts: Set<string>, value?: string) {
  const normalized = value?.trim().toLowerCase();

  if (normalized && normalized.length >= 3) {
    parts.add(normalized);
  }
}

function containsUserInfo(password: string, userInputs: string[]) {
  const normalizedPassword = password.toLowerCase();
  return userInputs.some((value) => normalizedPassword.includes(value));
}

function buildFeedback(
  feedback: { warning?: string | null; suggestions?: string[] },
  breach: BreachResult
): PasswordEvaluation['feedback'] {
  const suggestions = new Set(feedback.suggestions ?? []);
  let warning = feedback.warning && feedback.warning.length > 0 ? feedback.warning : null;

  if (breach.checked && breach.breached) {
    warning = 'This password appeared in known data breaches.';
    suggestions.add('Use a longer passphrase of unrelated words.');
    suggestions.add('Do not reuse passwords that may have been exposed elsewhere.');
  }

  // With the default unchecked breach checker this always fires for now.
  if (!breach.checked) {
    suggestions.add('The breach check was unavailable; avoid reusing passwords from other services.');
  }

  return {
    warning,
    suggestions: [...suggestions]
  };
}
