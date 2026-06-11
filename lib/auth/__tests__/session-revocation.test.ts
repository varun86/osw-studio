/**
 * Integration Tests for Session Revocation Store
 *
 * Uses a real in-memory SQLite database to test the revocation logic
 * end-to-end. This avoids mocking complexities and tests actual behavior.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import Database from 'better-sqlite3';

// Create an in-memory database for testing
let testDb: Database.Database;

/**
 * Convert epoch ms to SQLite-compatible datetime format.
 * Must match the format used in session-revocation.ts
 */
function toSqliteDateTime(dateOrMs: Date | number): string {
  const d = typeof dateOrMs === 'number' ? new Date(dateOrMs) : dateOrMs;
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
}

describe('session-revocation (SQL logic)', () => {
  beforeAll(() => {
    testDb = new Database(':memory:');
    // Create the schema — same as session-revocation.ts
    testDb.exec(`
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
    `);
  });

  beforeEach(() => {
    testDb.exec('DELETE FROM revoked_sessions');
  });

  describe('revokeSession (INSERT logic)', () => {
    it('should insert a specific JTI revocation record', () => {
      const jti = 'test-jti-123';
      const userId = 'user-abc';
      const reason = 'logout';
      const expiresAt = toSqliteDateTime(Date.now() + 3600 * 1000);

      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(jti, userId, reason, expiresAt);

      const row = testDb.prepare('SELECT * FROM revoked_sessions WHERE jti = ?').get(jti) as any;
      expect(row).toBeDefined();
      expect(row.jti).toBe(jti);
      expect(row.user_id).toBe(userId);
      expect(row.reason).toBe('logout');
    });

    it('should store "security" reason', () => {
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('jti-sec', 'user-1', 'security', toSqliteDateTime(Date.now() + 3600000));

      const row = testDb.prepare('SELECT reason FROM revoked_sessions WHERE jti = ?').get('jti-sec') as any;
      expect(row.reason).toBe('security');
    });

    it('should not fail on duplicate JTI (INSERT OR IGNORE)', () => {
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('dup-jti', 'user-1', 'logout', toSqliteDateTime(Date.now() + 3600000));

      // Insert again with same JTI — should not throw
      expect(() => {
        testDb.prepare(`
          INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
          VALUES (?, ?, ?, ?)
        `).run('dup-jti', 'user-1', 'logout', toSqliteDateTime(Date.now() + 3600000));
      }).not.toThrow();
    });
  });

  describe('revokeAllUserSessions (user-level marker)', () => {
    it('should insert a user-level revocation marker', () => {
      const userId = 'user-xyz';
      const markerJti = `__user__:${userId}:${Date.now()}`;
      const expiresAt = toSqliteDateTime(Date.now() + 24 * 60 * 60 * 1000);

      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(markerJti, userId, 'deactivation', expiresAt);

      const row = testDb.prepare(
        "SELECT * FROM revoked_sessions WHERE jti LIKE '__user__:%' AND user_id = ?"
      ).get(userId) as any;

      expect(row).toBeDefined();
      expect(row.jti).toMatch(/^__user__:user-xyz:\d+$/);
      expect(row.reason).toBe('deactivation');
    });
  });

  describe('isSessionRevoked (revocation check logic)', () => {
    it('should return true when specific JTI is revoked', () => {
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('revoked-jti', 'user-abc', 'logout', toSqliteDateTime(Date.now() + 3600000));

      const result = testDb.prepare(
        'SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1'
      ).get('revoked-jti');

      expect(result).toBeDefined();
    });

    it('should return false when JTI is not revoked', () => {
      const result = testDb.prepare(
        'SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1'
      ).get('nonexistent-jti');

      expect(result).toBeUndefined();
    });

    it('should return true when user has a user-level revocation newer than the session', () => {
      const userId = 'user-abc';
      // Add a user-level revocation with revoked_at = now (default)
      const markerJti = `__user__:${userId}:${Date.now()}`;
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(markerJti, userId, 'deactivation', toSqliteDateTime(Date.now() + 86400000));

      // Check: session issued 10 seconds ago (before revocation)
      const pastIat = toSqliteDateTime(Date.now() - 10000);
      const result = testDb.prepare(`
        SELECT 1 FROM revoked_sessions
        WHERE user_id = ?
          AND jti LIKE '__user__:%'
          AND revoked_at >= ?
        LIMIT 1
      `).get(userId, pastIat);

      expect(result).toBeDefined();
    });

    it('should return false for user-level revocation older than the session', () => {
      const userId = 'user-abc';
      // Add a user-level revocation with revoked_at explicitly in the past
      const markerJti = `__user__:${userId}:${Date.now()}`;
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, revoked_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(markerJti, userId, 'deactivation',
        toSqliteDateTime(Date.now() - 60000), // revoked 60s ago
        toSqliteDateTime(Date.now() + 86400000)
      );

      // Check: session issued just now (after the revocation)
      // Note: iat is epoch seconds, but toSqliteDateTime expects epoch ms
      const recentIat = toSqliteDateTime(Date.now());
      const result = testDb.prepare(`
        SELECT 1 FROM revoked_sessions
        WHERE user_id = ?
          AND jti LIKE '__user__:%'
          AND revoked_at >= ?
        LIMIT 1
      `).get(userId, recentIat);

      expect(result).toBeUndefined();
    });
  });

  describe('cleanupExpiredRevocations (DELETE logic)', () => {
    it('should delete expired revocation records', () => {
      // Insert an expired record (expired 1 hour ago)
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('expired-jti', 'user-1', 'logout', toSqliteDateTime(Date.now() - 3600000));

      // Insert a non-expired record
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('active-jti', 'user-1', 'logout', toSqliteDateTime(Date.now() + 3600000));

      const result = testDb.prepare(
        "DELETE FROM revoked_sessions WHERE expires_at < datetime('now')"
      ).run();

      expect(result.changes).toBe(1); // Only the expired one

      // Verify the active one remains
      const remaining = testDb.prepare('SELECT jti FROM revoked_sessions').all() as any[];
      expect(remaining).toHaveLength(1);
      expect(remaining[0].jti).toBe('active-jti');
    });

    it('should not delete non-expired records', () => {
      testDb.prepare(`
        INSERT OR IGNORE INTO revoked_sessions (jti, user_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
      `).run('active-jti-2', 'user-2', 'logout', toSqliteDateTime(Date.now() + 86400000));

      const result = testDb.prepare(
        "DELETE FROM revoked_sessions WHERE expires_at < datetime('now')"
      ).run();

      expect(result.changes).toBe(0);
    });
  });
});
