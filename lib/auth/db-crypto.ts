/**
 * Database Cryptography Utilities
 *
 * Provides safe validation and sanitization for database encryption
 * key operations. Prevents SQL injection via environment variable
 * interpolation into PRAGMA statements.
 *
 * @security CRITICAL - This module guards against SQL injection
 * in SQLite PRAGMA key statements. Any changes must be reviewed
 * with security implications in mind.
 */

/**
 * Allowed characters for database encryption keys.
 * Restricted to base64 characters (A-Z, a-z, 0-9, +, /, =) and
 * hexadecimal-only keys. This prevents SQL injection via PRAGMA
 * key interpolation by rejecting quotes, semicolons, spaces,
 * backslashes, and other SQL metacharacters.
 *
 * The critical character to block is the single quote (') which
 * would allow breaking out of the PRAGMA key='...' string literal.
 */
const DB_KEY_ALLOWED_PATTERN = /^[a-zA-Z0-9+/=]+$/;

/**
 * Maximum allowed length for the encryption key.
 * A 32-byte key base64-encoded is 44 characters (with padding).
 * We allow generous headroom for hex-encoded keys (64 chars).
 */
const DB_KEY_MAX_LENGTH = 256;

/**
 * Validate that a database encryption key is safe for use in
 * SQLite PRAGMA statements.
 *
 * The key must:
 * - Contain only alphanumeric characters (A-Z, a-z, 0-9), base64 symbols (+, /), and padding (=)
 * - Be at most 256 characters long
 * - Not be empty
 *
 * @param key - The encryption key from environment variable
 * @param source - Label for error messages (e.g., 'DB_ENCRYPTION_KEY')
 * @returns The validated key string
 * @throws Error if the key contains disallowed characters
 *
 * @example
 * ```ts
 * const key = validateDbEncryptionKey(process.env.DB_ENCRYPTION_KEY, 'DB_ENCRYPTION_KEY');
 * db.pragma(`key='${key}'`);  // Safe after validation
 * ```
 */
export function validateDbEncryptionKey(key: string, source: string = 'DB_ENCRYPTION_KEY'): string {
  if (!key || key.trim().length === 0) {
    throw new Error(`[${source}] Encryption key must not be empty`);
  }

  const trimmed = key.trim();

  if (trimmed.length > DB_KEY_MAX_LENGTH) {
    throw new Error(
      `[${source}] Encryption key exceeds maximum length of ${DB_KEY_MAX_LENGTH} characters ` +
      `(got ${trimmed.length}). This may indicate a misconfiguration.`
    );
  }

  if (!DB_KEY_ALLOWED_PATTERN.test(trimmed)) {
    // Identify the offending characters for a helpful error message
    const invalidChars = [...new Set(trimmed.split('').filter(c => !/[a-zA-Z0-9+/=]/.test(c)))];
    throw new Error(
      `[${source}] Encryption key contains disallowed characters: ${invalidChars.map(c => `'${c}'`).join(', ')}. ` +
      `Only alphanumeric characters (A-Z, a-z, 0-9), base64 symbols (+, /), and padding (=) are permitted. ` +
      `Generate a valid key with: openssl rand -base64 32`
    );
  }

  return trimmed;
}

/**
 * Safely apply the database encryption key to a SQLite connection.
 *
 * Validates the key before applying it to prevent SQL injection.
 * If the key is not set (undefined/empty), the database is opened
 * without encryption (plain text).
 *
 * @param db - The better-sqlite3 Database instance
 * @param key - The encryption key from environment variable
 * @param source - Label for error messages
 *
 * @example
 * ```ts
 * const db = new Database(dbPath);
 * applyEncryptionKey(db, process.env.DB_ENCRYPTION_KEY);
 * ```
 */
export function applyEncryptionKey(
  db: import('better-sqlite3').Database,
  key: string | undefined,
  source: string = 'DB_ENCRYPTION_KEY'
): void {
  if (!key) return;

  const validatedKey = validateDbEncryptionKey(key, source);
  // After validation, the key contains only [a-fA-F0-9+/=] characters,
  // which cannot break out of the single-quoted string in PRAGMA.
  // The single quote character (') is explicitly NOT in the allowed set.
  db.pragma(`key='${validatedKey}'`);
}

/**
 * Check if a database encryption key is configured and valid.
 * Returns the validated key or undefined if not set.
 * Logs a warning if the key is set but invalid.
 *
 * @param key - The encryption key from environment variable
 * @param source - Label for log messages
 * @returns The validated key string, or undefined if not set
 */
export function getValidatedDbEncryptionKey(
  key: string | undefined,
  source: string = 'DB_ENCRYPTION_KEY'
): string | undefined {
  if (!key) return undefined;

  try {
    return validateDbEncryptionKey(key, source);
  } catch (err) {
    // Re-throw with full context — invalid key is a startup-blocking error
    throw err;
  }
}
