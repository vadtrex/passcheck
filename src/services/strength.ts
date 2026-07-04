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

// Evaluates the strength of a password
export async function evaluatePasswordStrength(
  input: PasswordEvaluationInput,
  breachChecker: BreachChecker
): Promise<PasswordEvaluation> {
  const breach = await safeBreachCheck(input.password, breachChecker);
  const minLength = input.password.length >= 8;
  const notBreached = breach.checked ? !breach.breached : true;

  // TODO: Implement zxcvbn scoring
  return {
    score: 0,
    strength: 'very-weak',
    acceptable: false,
    breach,
    checks: {
      minLength,
      notBreached,
      noUserInfo: true
    },
    feedback: {
      warning: null,
      suggestions: []
    },
    estimatedCrackTime: 'instant'
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
