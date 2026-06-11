/**
 * Tests for DB Encryption Key Validation (db-crypto.ts)
 *
 * Validates that SQL injection via DB_ENCRYPTION_KEY is prevented.
 * Covers: valid keys, injection attempts, edge cases.
 */

import { describe, it, expect } from 'vitest';
import { validateDbEncryptionKey, applyEncryptionKey, getValidatedDbEncryptionKey } from '../db-crypto';

describe('validateDbEncryptionKey', () => {
  it('accepts a valid base64 key', () => {
    const key = 'gcBLEeGjdx8gbUMoAAlksvoKSREZlJ4l+GwKieTW2Og=';
    expect(validateDbEncryptionKey(key)).toBe(key);
  });

  it('accepts a valid hex key', () => {
    const key = 'a1b2c3d4e5f6789012345678abcdef01';
    expect(validateDbEncryptionKey(key)).toBe(key);
  });

  it('accepts a key with base64 characters (+, /, =)', () => {
    const key = 'abc+def/ghi==';
    expect(validateDbEncryptionKey(key)).toBe(key);
  });

  it('trims whitespace from valid keys', () => {
    const key = '  abc123==  ';
    expect(validateDbEncryptionKey(key)).toBe('abc123==');
  });

  it('rejects empty string', () => {
    expect(() => validateDbEncryptionKey('')).toThrow('must not be empty');
  });

  it('rejects whitespace-only string', () => {
    expect(() => validateDbEncryptionKey('   ')).toThrow('must not be empty');
  });

  it('rejects key with single quote (SQL injection attempt)', () => {
    // This was the original vulnerability: key='...''; ATTACH DATABASE ...
    const key = "'; ATTACH DATABASE '/tmp/evil.sqlite' AS evil; --";
    expect(() => validateDbEncryptionKey(key)).toThrow('disallowed characters');
  });

  it('rejects key with double quote', () => {
    expect(() => validateDbEncryptionKey('abc"def')).toThrow('disallowed characters');
  });

  it('rejects key with semicolon (SQL statement separator)', () => {
    expect(() => validateDbEncryptionKey('abc;def')).toThrow('disallowed characters');
  });

  it('rejects key with space (SQL injection attempt)', () => {
    expect(() => validateDbEncryptionKey('abc def')).toThrow('disallowed characters');
  });

  it('rejects key with backslash', () => {
    expect(() => validateDbEncryptionKey('abc\\def')).toThrow('disallowed characters');
  });

  it('rejects key with parentheses (SQL function injection)', () => {
    expect(() => validateDbEncryptionKey('abc(def)')).toThrow('disallowed characters');
  });

  it('rejects key with newline character', () => {
    expect(() => validateDbEncryptionKey('abc\ndef')).toThrow('disallowed characters');
  });

  it('rejects key with dash (could form SQL comments)', () => {
    expect(() => validateDbEncryptionKey('abc-def')).toThrow('disallowed characters');
  });

  it('rejects key exceeding maximum length', () => {
    const longKey = 'a'.repeat(257);
    expect(() => validateDbEncryptionKey(longKey)).toThrow('exceeds maximum length');
  });

  it('accepts key at exactly maximum length', () => {
    const key = 'a'.repeat(256);
    expect(validateDbEncryptionKey(key)).toBe(key);
  });

  it('includes source label in error messages', () => {
    expect(() => validateDbEncryptionKey("'; DROP TABLE", 'MY_KEY'))
      .toThrow('MY_KEY');
  });

  it('includes helpful suggestion in error for invalid characters', () => {
    try {
      validateDbEncryptionKey("hello world");
    } catch (err: any) {
      expect(err.message).toContain('openssl rand -base64 32');
    }
  });
});

describe('getValidatedDbEncryptionKey', () => {
  it('returns undefined for undefined input', () => {
    expect(getValidatedDbEncryptionKey(undefined)).toBeUndefined();
  });

  it('returns undefined for empty string', () => {
    expect(getValidatedDbEncryptionKey('')).toBeUndefined();
  });

  it('returns validated key for valid input', () => {
    const key = 'abc123+/=';
    expect(getValidatedDbEncryptionKey(key)).toBe(key);
  });

  it('throws for invalid key', () => {
    expect(() => getValidatedDbEncryptionKey("'; injection")).toThrow('disallowed characters');
  });
});

describe('applyEncryptionKey', () => {
  it('does nothing when key is undefined', () => {
    // Should not throw
    const mockDb = { pragma: () => {} } as any;
    expect(() => applyEncryptionKey(mockDb, undefined)).not.toThrow();
  });

  it('does nothing when key is empty string', () => {
    const mockDb = { pragma: () => {} } as any;
    expect(() => applyEncryptionKey(mockDb, '')).not.toThrow();
  });

  it('calls pragma with validated key for valid input', () => {
    const pragmaCalls: string[] = [];
    const mockDb = { pragma: (sql: string) => pragmaCalls.push(sql) } as any;

    applyEncryptionKey(mockDb, 'abc123==');

    expect(pragmaCalls).toHaveLength(1);
    expect(pragmaCalls[0]).toBe("key='abc123=='");
  });

  it('throws before calling pragma for invalid key', () => {
    const pragmaCalls: string[] = [];
    const mockDb = { pragma: (sql: string) => pragmaCalls.push(sql) } as any;

    expect(() => applyEncryptionKey(mockDb, "'; DROP TABLE")).toThrow('disallowed characters');
    expect(pragmaCalls).toHaveLength(0); // pragma was never called
  });
});
