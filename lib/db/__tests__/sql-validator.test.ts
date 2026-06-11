/**
 * Tests for centralized SQL Validator module
 *
 * Covers:
 * - Blocked statement keywords (ATTACH, DETACH, PRAGMA, VACUUM, REINDEX)
 * - Comment stripping (prevents comment-based bypass)
 * - System table protection (RuntimeDB)
 * - Forbidden table protection (Edge functions)
 * - DDL/DML allow/deny controls
 * - SQL length limits
 * - Table name extraction from complex queries (CTEs, subqueries, JOINs)
 * - Result row limits
 * - Edge function read-only mode
 */

import { describe, it, expect } from 'vitest';
import {
  validateSQL,
  validateRuntimeSQL,
  validateEdgeFunctionSQL,
  validateProjectSQL,
  stripSQLComments,
  extractTableNames,
  isTableForbidden,
  splitSQLStatements,
  getStatementKeyword,
  RUNTIME_SYSTEM_TABLES,
  EDGE_FORBIDDEN_TABLES,
  MAX_SQL_LENGTH,
  MAX_RESULT_ROWS,
  MAX_DDL_STATEMENTS,
} from '../sql-validator';

// ============================================
// Comment Stripping
// ============================================

describe('stripSQLComments', () => {
  it('should strip single-line comments', () => {
    const sql = 'SELECT * FROM users -- get all users';
    expect(stripSQLComments(sql)).toBe('SELECT * FROM users ');
  });

  it('should strip multi-line comments', () => {
    const sql = 'SELECT * /* all columns */ FROM users';
    expect(stripSQLComments(sql)).toBe('SELECT *  FROM users');
  });

  it('should NOT strip comments inside single-quoted strings', () => {
    const sql = "SELECT '-- not a comment' FROM users";
    expect(stripSQLComments(sql)).toBe("SELECT '-- not a comment' FROM users");
  });

  it('should NOT strip comments inside double-quoted identifiers', () => {
    const sql = 'SELECT "/* not a comment */" FROM users';
    expect(stripSQLComments(sql)).toBe('SELECT "/* not a comment */" FROM users');
  });

  it('should handle escaped single quotes inside strings', () => {
    const sql = "SELECT 'it''s -- not a comment' FROM users";
    expect(stripSQLComments(sql)).toBe("SELECT 'it''s -- not a comment' FROM users");
  });

  it('should handle multiple comment types', () => {
    const sql = 'SELECT * /* comment1 */ FROM users -- comment2';
    expect(stripSQLComments(sql)).toBe('SELECT *  FROM users ');
  });
});

// ============================================
// Statement Splitting
// ============================================

describe('splitSQLStatements', () => {
  it('should split on semicolons', () => {
    const sql = 'SELECT 1; SELECT 2; SELECT 3';
    const stmts = splitSQLStatements(sql);
    expect(stmts).toEqual(['SELECT 1', 'SELECT 2', 'SELECT 3']);
  });

  it('should NOT split semicolons inside string literals', () => {
    const sql = "SELECT 'a;b'; SELECT 2";
    const stmts = splitSQLStatements(sql);
    expect(stmts).toEqual(["SELECT 'a;b'", 'SELECT 2']);
  });

  it('should handle empty statements', () => {
    const sql = 'SELECT 1; ; SELECT 2';
    const stmts = splitSQLStatements(sql);
    expect(stmts).toEqual(['SELECT 1', 'SELECT 2']);
  });
});

// ============================================
// Statement Keyword Detection
// ============================================

describe('getStatementKeyword', () => {
  it('should detect SELECT', () => {
    expect(getStatementKeyword('SELECT * FROM users')).toBe('SELECT');
  });

  it('should detect keyword after leading whitespace', () => {
    expect(getStatementKeyword('   INSERT INTO users')).toBe('INSERT');
  });

  it('should detect keyword after comments', () => {
    expect(getStatementKeyword('-- comment\nDROP TABLE users')).toBe('DROP');
  });

  it('should return empty string for non-alpha start', () => {
    expect(getStatementKeyword('123')).toBe('');
  });
});

// ============================================
// Table Name Extraction
// ============================================

describe('extractTableNames', () => {
  it('should extract table from simple SELECT', () => {
    const tables = extractTableNames('SELECT * FROM users');
    expect(tables).toContain('users');
  });

  it('should extract table from INSERT INTO', () => {
    const tables = extractTableNames('INSERT INTO orders (id) VALUES (1)');
    expect(tables).toContain('orders');
  });

  it('should extract table from UPDATE', () => {
    const tables = extractTableNames('UPDATE products SET name = "x"');
    expect(tables).toContain('products');
  });

  it('should extract table from DELETE FROM', () => {
    const tables = extractTableNames('DELETE FROM logs WHERE id = 1');
    expect(tables).toContain('logs');
  });

  it('should extract tables from JOINs', () => {
    const tables = extractTableNames('SELECT * FROM users JOIN orders ON users.id = orders.user_id');
    expect(tables).toContain('users');
    expect(tables).toContain('orders');
  });

  it('should extract table from DROP TABLE', () => {
    const tables = extractTableNames('DROP TABLE IF EXISTS temp_data');
    expect(tables).toContain('temp_data');
  });

  it('should extract table from ALTER TABLE', () => {
    const tables = extractTableNames('ALTER TABLE users ADD COLUMN age INTEGER');
    expect(tables).toContain('users');
  });

  it('should extract table from CREATE TABLE', () => {
    const tables = extractTableNames('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY)');
    expect(tables).toContain('sessions');
  });

  it('should extract tables from CTEs', () => {
    const sql = 'WITH cte AS (SELECT * FROM users) SELECT * FROM cte JOIN orders ON cte.id = orders.user_id';
    const tables = extractTableNames(sql);
    expect(tables).toContain('users');
    expect(tables).toContain('orders');
    expect(tables).toContain('cte');
  });

  it('should extract tables from subqueries', () => {
    const sql = 'SELECT * FROM (SELECT * FROM users) AS sub JOIN orders ON sub.id = orders.user_id';
    const tables = extractTableNames(sql);
    expect(tables).toContain('users');
    expect(tables).toContain('orders');
  });
});

// ============================================
// Forbidden Table Checking
// ============================================

describe('isTableForbidden', () => {
  it('should match exact table names', () => {
    expect(isTableForbidden('secrets', RUNTIME_SYSTEM_TABLES)).toBe(true);
    expect(isTableForbidden('edge_functions', RUNTIME_SYSTEM_TABLES)).toBe(true);
    expect(isTableForbidden('users', RUNTIME_SYSTEM_TABLES)).toBe(false);
  });

  it('should match prefix-based entries (ending with _)', () => {
    expect(isTableForbidden('sqlite_master', ['sqlite_'])).toBe(true);
    expect(isTableForbidden('sqlite_sequence', ['sqlite_'])).toBe(true);
    expect(isTableForbidden('sql_server', ['sqlite_'])).toBe(false);
  });

  it('should be case-insensitive', () => {
    expect(isTableForbidden('SECRETS', RUNTIME_SYSTEM_TABLES)).toBe(true);
    expect(isTableForbidden('Secrets', RUNTIME_SYSTEM_TABLES)).toBe(true);
  });
});

// ============================================
// Core Validation - Blocked Keywords
// ============================================

describe('validateSQL - blocked keywords', () => {
  it('should block ATTACH DATABASE', () => {
    const result = validateSQL('ATTACH DATABASE "/etc/passwd" AS pw');
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('BLOCKED');
  });

  it('should block DETACH', () => {
    const result = validateSQL('DETACH DATABASE pw');
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('BLOCKED');
  });

  it('should block PRAGMA', () => {
    const result = validateSQL('PRAGMA journal_mode=WAL');
    expect(result.valid).toBe(false);
  });

  it('should block VACUUM', () => {
    const result = validateSQL('VACUUM');
    expect(result.valid).toBe(false);
  });

  it('should block REINDEX', () => {
    const result = validateSQL('REINDEX users');
    expect(result.valid).toBe(false);
  });
});

// ============================================
// Core Validation - DDL Controls
// ============================================

describe('validateSQL - DDL controls', () => {
  it('should block DDL when allowDDL is false', () => {
    const result = validateSQL('CREATE TABLE test (id INTEGER)', { allowDDL: false });
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('DDL');
  });

  it('should allow DDL when allowDDL is true', () => {
    const result = validateSQL('CREATE TABLE test (id INTEGER)', { allowDDL: true });
    expect(result.valid).toBe(true);
    expect(result.statementType).toBe('DDL');
  });

  it('should block DROP TABLE when allowDDL is false', () => {
    const result = validateSQL('DROP TABLE users', { allowDDL: false });
    expect(result.valid).toBe(false);
  });

  it('should allow DROP TABLE when allowDDL is true', () => {
    const result = validateSQL('DROP TABLE users', { allowDDL: true });
    expect(result.valid).toBe(true);
  });
});

// ============================================
// Core Validation - DML Controls
// ============================================

describe('validateSQL - DML controls', () => {
  it('should allow DML by default', () => {
    const result = validateSQL('INSERT INTO users (name) VALUES ("test")', { allowDDL: false });
    expect(result.valid).toBe(true);
    expect(result.statementType).toBe('DML');
  });

  it('should block DML when allowDML is false', () => {
    const result = validateSQL('INSERT INTO users (name) VALUES ("test")', { allowDML: false });
    expect(result.valid).toBe(false);
  });

  it('should block UPDATE when allowDML is false', () => {
    const result = validateSQL('UPDATE users SET name = "x"', { allowDML: false });
    expect(result.valid).toBe(false);
  });

  it('should block DELETE when allowDML is false', () => {
    const result = validateSQL('DELETE FROM users WHERE id = 1', { allowDML: false });
    expect(result.valid).toBe(false);
  });
});

// ============================================
// Core Validation - System Table Protection
// ============================================

describe('validateSQL - system table protection', () => {
  it('should block SELECT from system tables', () => {
    const result = validateSQL('SELECT * FROM secrets', { forbiddenTables: RUNTIME_SYSTEM_TABLES });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('secrets');
  });

  it('should block INSERT INTO system tables', () => {
    const result = validateSQL('INSERT INTO edge_functions (name) VALUES ("evil")', {
      allowDML: true,
      forbiddenTables: RUNTIME_SYSTEM_TABLES,
    });
    expect(result.valid).toBe(false);
  });

  it('should block UPDATE on system tables', () => {
    const result = validateSQL('UPDATE secrets SET value = "leaked"', {
      allowDML: true,
      forbiddenTables: RUNTIME_SYSTEM_TABLES,
    });
    expect(result.valid).toBe(false);
  });

  it('should block DELETE FROM system tables', () => {
    const result = validateSQL('DELETE FROM function_logs', {
      allowDML: true,
      forbiddenTables: RUNTIME_SYSTEM_TABLES,
    });
    expect(result.valid).toBe(false);
  });

  it('should block DROP TABLE on system tables', () => {
    const result = validateSQL('DROP TABLE site_info', {
      allowDDL: true,
      forbiddenTables: RUNTIME_SYSTEM_TABLES,
    });
    expect(result.valid).toBe(false);
  });

  it('should block system table access via CTE', () => {
    const result = validateSQL(
      'WITH leaked AS (SELECT * FROM secrets) SELECT * FROM leaked',
      { forbiddenTables: RUNTIME_SYSTEM_TABLES }
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('secrets');
  });

  it('should block system table access via JOIN', () => {
    const result = validateSQL(
      'SELECT u.*, s.value FROM users u JOIN secrets s ON u.id = s.id',
      { forbiddenTables: RUNTIME_SYSTEM_TABLES }
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('secrets');
  });

  it('should block system table access via subquery', () => {
    const result = validateSQL(
      'SELECT * FROM (SELECT * FROM secrets) AS sub',
      { forbiddenTables: RUNTIME_SYSTEM_TABLES }
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('secrets');
  });

  it('should block sqlite_ prefix tables in edge function context', () => {
    const result = validateSQL('SELECT * FROM sqlite_master', {
      forbiddenTables: EDGE_FORBIDDEN_TABLES,
    });
    expect(result.valid).toBe(false);
  });

  it('should allow SELECT from regular user tables', () => {
    const result = validateSQL('SELECT * FROM products WHERE price > 100', {
      forbiddenTables: RUNTIME_SYSTEM_TABLES,
    });
    expect(result.valid).toBe(true);
  });
});

// ============================================
// Core Validation - SQL Length Limits
// ============================================

describe('validateSQL - length limits', () => {
  it('should reject empty SQL', () => {
    const result = validateSQL('');
    expect(result.valid).toBe(false);
  });

  it('should reject non-string input', () => {
    const result = validateSQL(null as unknown as string);
    expect(result.valid).toBe(false);
  });

  it('should reject overly long SQL', () => {
    const longSQL = 'SELECT * FROM users WHERE id = ' + 'x'.repeat(MAX_SQL_LENGTH + 100);
    const result = validateSQL(longSQL);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('too long');
  });

  it('should accept SQL within length limit', () => {
    const sql = 'SELECT * FROM users';
    const result = validateSQL(sql);
    expect(result.valid).toBe(true);
  });
});

// ============================================
// Comment-Based Bypass Prevention
// ============================================

describe('validateSQL - comment bypass prevention', () => {
  it('should not be bypassed by comments before blocked keywords', () => {
    const sql = '-- innocent comment\nATTACH DATABASE "/etc/passwd" AS pw';
    const result = validateSQL(sql);
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('BLOCKED');
  });

  it('should not be bypassed by inline comments hiding blocked keywords', () => {
    const sql = 'SELECT * /* ATTACH */ FROM users';
    // This should still be valid because ATTACH is inside a comment
    // The keyword check is on the statement keyword, not comment content
    const result = validateSQL(sql);
    expect(result.valid).toBe(true); // ATTACH in comment is OK
  });

  it('should block PRAGMA hidden after a comment', () => {
    const sql = '/* setup */ PRAGMA journal_mode=WAL';
    const result = validateSQL(sql);
    expect(result.valid).toBe(false);
  });
});

// ============================================
// Runtime SQL Validation
// ============================================

describe('validateRuntimeSQL', () => {
  it('should block DDL by default', () => {
    const result = validateRuntimeSQL('CREATE TABLE test (id INTEGER)');
    expect(result.valid).toBe(false);
  });

  it('should allow DDL when explicitly enabled', () => {
    const result = validateRuntimeSQL('CREATE TABLE test (id INTEGER)', { allowDDL: true });
    expect(result.valid).toBe(true);
  });

  it('should allow SELECT from user tables', () => {
    const result = validateRuntimeSQL('SELECT * FROM products');
    expect(result.valid).toBe(true);
  });

  it('should block SELECT from system tables', () => {
    const result = validateRuntimeSQL('SELECT * FROM secrets');
    expect(result.valid).toBe(false);
  });

  it('should block ATTACH DATABASE', () => {
    const result = validateRuntimeSQL('ATTACH DATABASE "/tmp/evil" AS evil');
    expect(result.valid).toBe(false);
  });
});

// ============================================
// Edge Function SQL Validation
// ============================================

describe('validateEdgeFunctionSQL', () => {
  it('should allow SELECT in non-read-only mode', () => {
    const result = validateEdgeFunctionSQL('SELECT * FROM products', false);
    expect(result.valid).toBe(true);
  });

  it('should allow DML in non-read-only mode', () => {
    const result = validateEdgeFunctionSQL('INSERT INTO orders (id) VALUES (1)', false);
    expect(result.valid).toBe(true);
  });

  it('should block DDL unconditionally in edge functions (even in non-read-only mode)', () => {
    const result = validateEdgeFunctionSQL('CREATE TABLE test (id INTEGER)', false);
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('DDL');
  });

  it('should block DDL in read-only mode', () => {
    const result = validateEdgeFunctionSQL('CREATE TABLE test (id INTEGER)', true);
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('DDL');
  });

  it('should block DROP TABLE unconditionally in edge functions', () => {
    const result = validateEdgeFunctionSQL('DROP TABLE products', false);
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('DDL');
  });

  it('should block ALTER TABLE unconditionally in edge functions', () => {
    const result = validateEdgeFunctionSQL('ALTER TABLE products ADD COLUMN price REAL', false);
    expect(result.valid).toBe(false);
    expect(result.statementType).toBe('DDL');
  });

  it('should block DML in read-only mode', () => {
    const result = validateEdgeFunctionSQL('INSERT INTO orders (id) VALUES (1)', true);
    expect(result.valid).toBe(false);
  });

  it('should block SELECT from edge_forbidden tables', () => {
    const result = validateEdgeFunctionSQL('SELECT * FROM edge_functions', false);
    expect(result.valid).toBe(false);
  });

  it('should block SELECT from sqlite_ internal tables', () => {
    const result = validateEdgeFunctionSQL('SELECT * FROM sqlite_master', false);
    expect(result.valid).toBe(false);
  });

  it('should block SELECT from analytics tables', () => {
    const result = validateEdgeFunctionSQL('SELECT * FROM sessions', false);
    expect(result.valid).toBe(false);
  });

  it('should block system table access via JOIN', () => {
    const result = validateEdgeFunctionSQL(
      'SELECT * FROM products JOIN secrets ON products.key = secrets.name',
      false
    );
    expect(result.valid).toBe(false);
  });
});

// ============================================
// Project SQL Validation
// ============================================

describe('validateProjectSQL', () => {
  it('should allow DDL by default', () => {
    const result = validateProjectSQL('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)');
    expect(result.valid).toBe(true);
  });

  it('should allow DML', () => {
    const result = validateProjectSQL('INSERT INTO users (name) VALUES ("test")');
    expect(result.valid).toBe(true);
  });

  it('should block ATTACH DATABASE', () => {
    const result = validateProjectSQL('ATTACH DATABASE "/tmp/evil" AS evil');
    expect(result.valid).toBe(false);
  });

  it('should block PRAGMA', () => {
    const result = validateProjectSQL('PRAGMA table_info(users)');
    expect(result.valid).toBe(false);
  });

  it('should have no forbidden tables (project DBs are user-owned)', () => {
    const result = validateProjectSQL('SELECT * FROM secrets');
    expect(result.valid).toBe(true);
  });
});

// ============================================
// DDL Statement Count Limits
// ============================================

describe('validateSQL - DDL statement count limit', () => {
  it('should allow up to MAX_DDL_STATEMENTS DDL statements', () => {
    const statements = Array(MAX_DDL_STATEMENTS).fill('CREATE TABLE t (id INTEGER)').join('; ');
    const result = validateSQL(statements, { allowDDL: true });
    expect(result.valid).toBe(true);
  });

  it('should reject more than MAX_DDL_STATEMENTS DDL statements', () => {
    const statements = Array(MAX_DDL_STATEMENTS + 1).fill('CREATE TABLE t (id INTEGER)').join('; ');
    const result = validateSQL(statements, { allowDDL: true });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Too many DDL statements');
  });
});
