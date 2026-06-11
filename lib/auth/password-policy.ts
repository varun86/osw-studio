/**
 * Password Policy Validation
 *
 * Enforces strong password requirements:
 * - Minimum 12 characters (up from 8)
 * - Maximum 128 characters (prevents bcrypt DoS)
 * - At least 3 of 4 character categories: uppercase, lowercase, digit, special
 *
 * Also used by admin user management for password resets.
 */

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  strength: 'weak' | 'fair' | 'good' | 'strong';
}

/**
 * Validate a password against the password policy
 *
 * @param password - The password to validate
 * @returns Validation result with errors and strength score
 */
export function validatePassword(password: string): PasswordValidationResult {
  const errors: string[] = [];

  // Length checks
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters');
  }

  if (password.length > 128) {
    errors.push('Password must be at most 128 characters');
  }

  // Character category checks
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  const categories = [hasUppercase, hasLowercase, hasDigit, hasSpecial];
  const categoryCount = categories.filter(Boolean).length;

  if (categoryCount < 3) {
    errors.push('Password must contain at least 3 of: uppercase letters, lowercase letters, digits, special characters');
  }

  // Strength assessment
  let strength: PasswordValidationResult['strength'] = 'weak';
  if (errors.length === 0) {
    if (categoryCount === 4 && password.length >= 16) {
      strength = 'strong';
    } else if (categoryCount === 4 || password.length >= 16) {
      strength = 'good';
    } else {
      strength = 'fair';
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    strength,
  };
}

/**
 * Get a human-readable description of the password policy
 */
export function getPasswordPolicyDescription(): string[] {
  return [
    'At least 12 characters',
    'At most 128 characters',
    'At least 3 of: uppercase, lowercase, digits, special characters',
  ];
}
