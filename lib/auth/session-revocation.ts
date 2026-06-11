/**
 * Session Revocation Store
 *
 * Provides server-side session revocation so that JWT tokens can be
 * invalidated even before they expire. This is critical for:
 *
 * 1. Logout: when a user explicitly logs out, their JWT is immediately
 *    unusable even if an attacker has stolen the token.
 * 2. User deactivation: when an admin deactivates a user, all their
 *    sessions are revoked immediately.
 * 3. Security incidents: compromised sessions can be selectively revoked.
 *
 * Implementation:
 * - Uses the system SQLite database for persistence across restarts.
 * - Each session gets a unique `jti` (JWT ID) claim upon creation.
 * - Revoked JTIs are stored in a `revoked_sessions` table.
 * - A periodic cleanup removes expired revocations to prevent unbounded growth.
 *
 * @security CRITICAL - This module ensures JWT tokens can be revoked.
 * Any changes must be reviewed for security implications.
 */

import { getSystemDatabase } from './system-database';

// ---------------------------------------------------------------------------
// Date formatting utility
// ---------------------------------------------------------------------------

/**
 * Convert a JavaScript Date or epoch milliseconds to SQLite-compatible
 * datetime string format: 'YYYY-MM-DD HH:MM:SS'
 *
 * SQLite's datetime('now') produces this format, and string comparisons
 * (used for expires_at and revoked_at checks) only work correctly when
 * both sides use the same format.
 *
 * JavaScript's toISOString() produces 'YYYY-MM-DDTHH:MM:SS.sssZ' which
 * does NOT compare correctly with SQLite's format because 'T' > ' '
 * in ASCII, causing false comparisons.
 */
function toSqliteDateTime(dateOrMs: Date | number): string {
  const d = typeof dateOrMs === 'number' ? new Date(dateOrMs) : dateOrMs;
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS revoked_sessions (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT NOT NULL DEFAULT 'logout',
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_revoked_sessions_user
    ON revoked_sessions(user_id);

  CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expires
    ON revoked_sessions(expires_at);
`;

/**
 * Ensure the revoked_sessions table exists.
 * Safe to call multiple times (idempotent via CREATE IF NOT EXISTS).
 */
function ensureSchema(): void {
  const db = getSystemDatabase();
  db.exec(SCHEMA_SQL);
}

// ---------------------------------------------------------------------------
// Revocation operations
// ---------------------------------------------------------------------------

/**
 * Revoke a specific session by its JWT ID (jti).
 *
 * @param jti - The unique JWT ID claim
 * @param userId - The user who owns this session
 * @param sessionExpEpoch - The session's expiration time (epoch seconds),
 *   used to determine when the revocation record can be cleaned up
 * @param reason - Why the session was revoked ('logout', 'deactivation', 'security')
 */
export function revokeSession(
  jti: string,
  userId: string,
  sessionExpEpoch: number,
  reason: 'logout' | 'deactivation' | 'security' = 'logout'
): void {
  ensureSchema();
  const db = getSystemDatabase();

  const expiresAt = toSqliteDateTime(sessionExpEpoch * 1000);
  db.prepare(`
    INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(jti, userId, reason, expiresAt);
}

/**
 * Revoke ALL sessions for a given user.
 *
 * Used when an admin deactivates a user account or when a security
 * incident requires all sessions to be invalidated.
 *
 * Since we don't have all JTIs on hand, we add a user-level revocation
 * entry that blocks any session from that user created before now.
 *
 * @param userId - The user whose sessions should be revoked
 * @param reason - Why all sessions were revoked
 */
export function revokeAllUserSessions(
  userId: string,
  reason: 'deactivation' | 'security' = 'deactivation'
): void {
  ensureSchema();
  const db = getSystemDatabase();

  // Add a user-level revocation marker. The `jti` field stores a special
  // value `__user__:<userId>:<timestamp>` and `expires_at` is set far enough
  // in the future to cover any active session (24h from now).
  const expiresAt = toSqliteDateTime(Date.now() + 24 * 60 * 60 * 1000);
  const markerJti = `__user__:${userId}:${Date.now()}`;

  db.prepare(`
    INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(markerJti, userId, reason, expiresAt);
}

/**
 * Check if a session has been revoked.
 *
 * A session is considered revoked if:
 * 1. Its specific JTI is in the revoked_sessions table, OR
 * 2. There is a user-level revocation (`__user__:*`) for the same user
 *    that was created after this session was issued.
 *
 * @param jti - The JWT ID claim from the session
 * @param userId - The user ID from the session
 * @param iat - The 'issued at' timestamp (epoch seconds) from the session
 * @returns true if the session has been revoked
 */
export function isSessionRevoked(jti: string, userId: string, iat: number): boolean {
  ensureSchema();
  const db = getSystemDatabase();

  // Check 1: Is this specific JTI revoked?
  const specificRevocation = db.prepare(
    'SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1'
  ).get(jti);
  if (specificRevocation) return true;

  // Check 2: Is there a user-level revocation newer than this session?
  // A user-level revocation (__user__:*) issued after this session's
  // creation means this session should be considered revoked.
  const issuedAt = toSqliteDateTime(iat * 1000);
  const userRevocation = db.prepare(`
    SELECT 1 FROM revoked_sessions
    WHERE user_id = ?
      AND jti LIKE '__user__:%'
      AND revoked_at >= ?
    LIMIT 1
  `).get(userId, issuedAt);
  if (userRevocation) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/**
 * Remove expired revocation records.
 *
 * Revocation records are only needed until the session they block
 * would have naturally expired. After that, they can be safely removed.
 *
 * Should be called periodically (e.g., on startup, hourly via timer).
 * The cleanup is lightweight — it just deletes rows where expires_at
 * is in the past.
 */
export function cleanupExpiredRevocations(): void {
  try {
    ensureSchema();
    const db = getSystemDatabase();
    const result = db.prepare(
      "DELETE FROM revoked_sessions WHERE expires_at < datetime('now')"
    ).run();

    if (result.changes > 0) {
      console.warn(`[session-revocation] Cleaned up ${result.changes} expired revocation records`);
    }
  } catch (error) {
    // Non-critical: if cleanup fails (e.g., DB not initialized yet),
    // it will be retried next time
    console.error('[session-revocation] Cleanup failed:', error);
  }
}

// ---------------------------------------------------------------------------
// Auto-cleanup initialization (only in non-desktop server mode)
// ---------------------------------------------------------------------------

let _cleanupInitialized = false;

/**
 * Start the periodic revocation cleanup timer.
 * Called automatically on first module use, but can also be
 * called explicitly during server startup.
 *
 * Idempotent — calling it multiple times is safe.
 */
export function initRevocationCleanup(): void {
  if (_cleanupInitialized) return;
  _cleanupInitialized = true;

  // Delay initial cleanup slightly to let system database initialize first
  setTimeout(() => cleanupExpiredRevocations(), 5000);

  // Run cleanup every hour
  setInterval(() => cleanupExpiredRevocations(), 60 * 60 * 1000);
}

// Auto-initialize in server mode (not desktop, not test environment)
if (typeof process !== 'undefined' && process.env.OSW_DESKTOP !== 'true' && process.env.NODE_ENV !== 'test') {
  initRevocationCleanup();
}
