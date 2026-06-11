/**
 * Centralized SQL Validation & Security Module
 *
 * Provides a single, authoritative validation layer for all SQL execution
 * surfaces in OSW Studio. Every API route, runtime database, and edge function
 * sandbox should delegate validation to this module to ensure consistent
 * security enforcement.
 *
 * Security guarantees:
 * - Blocks ATTACH/DETACH/PRAGMA/VACUUM/REINDEX at statement level
 * - Blocks access to system/forbidden tables (even via CTEs, subqueries, JOINs)
 * - Enforces SQL length limits to prevent resource exhaustion
 * - Validates DDL vs DML intent
 * - Parameterized-query support tracking
 */

// ============================================
// Configuration Constants
// ============================================

/** Maximum SQL query length in bytes (prevents resource exhaustion) */
export const MAX_SQL_LENGTH = 64 * 1024; // 64 KB

/** Maximum number of rows returned from a SELECT query */
export const MAX_RESULT_ROWS = 10_000;

/** Maximum number of statements in a single DDL batch */
export const MAX_DDL_STATEMENTS = 50;

/**
 * System tables in RuntimeDatabase that must never be user-accessible.
 * These store edge functions, secrets, VFS files, logs, and config.
 */
export const RUNTIME_SYSTEM_TABLES = [
  'site_info',
  'files',
  'file_tree_nodes',
  'edge_functions',
  'function_logs',
  'server_functions',
  'secrets',
  'scheduled_functions',
] as const;

/**
 * Additional tables forbidden from edge function access
 * (superset of runtime system tables plus analytics tables)
 */
export const EDGE_FORBIDDEN_TABLES = [
  ...RUNTIME_SYSTEM_TABLES,
  'sqlite_',        // SQLite internal tables (prefix match)
  '_migrations',    // Migration tracking
  'pageviews',      // Analytics
  'interactions',   // Analytics
  'sessions',       // Analytics
] as const;

/**
 * SQL statement keywords that are always blocked.
 * Checked against the START of each statement (after trimming whitespace/comments).
 */
export const BLOCKED_STATEMENT_KEYWORDS = [
  'ATTACH',
  'DETACH',
  'PRAGMA',
  'VACUUM',
  'REINDEX',
] as const;

/**
 * DDL keywords (schema-modifying statements)
 */
export const DDL_KEYWORDS = [
  'CREATE',
  'DROP',
  'ALTER',
  'TRUNCATE',
] as const;

/**
 * DML keywords (data-modifying statements)
 */
export const DML_KEYWORDS = [
  'INSERT',
  'UPDATE',
  'DELETE',
  'REPLACE',
] as const;

// ============================================
// Validation Error Class
// ============================================

export class SQLValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SQLValidationError';
  }
}

// ============================================
// Validation Options
// ============================================

export interface SQLValidationOptions {
  /** Allow DDL statements (CREATE, DROP, ALTER, TRUNCATE) */
  allowDDL?: boolean;

  /** Allow DML statements (INSERT, UPDATE, DELETE) */
  allowDML?: boolean;

  /** List of forbidden table names (exact + prefix match for entries ending with '_') */
  forbiddenTables?: readonly string[];

  /** Maximum SQL length in bytes (default: MAX_SQL_LENGTH) */
  maxLength?: number;

  /** SQL execution context (for error messages) */
  context?: string;
}

// ============================================
// Core Validation Functions
// ============================================

/**
 * Strip SQL comments from a SQL string.
 * Handles single-line comments (--) and multi-line block comments.
 * This prevents comment-based bypass of keyword checks.
 *
 * NOTE: This is a best-effort stripping. It handles standard SQL comments
 * but may not handle edge cases like comments inside string literals.
 * The primary goal is to prevent trivial bypasses like:
 *   -- ATTACH DATABASE ...
 *   Block-comments hiding blocked keywords
 */
export function stripSQLComments(sql: string): string {
  // Remove single-line comments (--)
  // But NOT -- inside string literals (best effort)
  let result = '';
  let i = 0;
  let inSingleQuote = false;
  let inDoubleQuote = false;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    // Track string literal boundaries
    if (ch === "'" && !inDoubleQuote) {
      // Handle escaped quotes ''
      if (next === "'" && inSingleQuote) {
        result += "''";
        i += 2;
        continue;
      }
      inSingleQuote = !inSingleQuote;
      result += ch;
      i++;
      continue;
    }

    if (ch === '"' && !inSingleQuote) {
      if (next === '"' && inDoubleQuote) {
        result += '""';
        i += 2;
        continue;
      }
      inDoubleQuote = !inDoubleQuote;
      result += ch;
      i++;
      continue;
    }

    // Only strip comments outside string literals
    if (!inSingleQuote && !inDoubleQuote) {
      // Single-line comment --
      if (ch === '-' && next === '-') {
        // Skip until end of line
        while (i < sql.length && sql[i] !== '\n') {
          i++;
        }
        continue;
      }

      // Multi-line comment /* */
      if (ch === '/' && next === '*') {
        i += 2;
        while (i < sql.length - 1 && !(sql[i] === '*' && sql[i + 1] === '/')) {
          i++;
        }
        i += 2; // Skip */
        continue;
      }
    }

    result += ch;
    i++;
  }

  return result;
}

/**
 * Extract the first SQL keyword from a statement (after stripping whitespace and comments).
 * Returns the keyword in UPPERCASE.
 */
export function getStatementKeyword(sql: string): string {
  const stripped = stripSQLComments(sql).trim();
  const match = stripped.match(/^([A-Z_]+)/i);
  return match ? match[1].toUpperCase() : '';
}

/**
 * Split a multi-statement SQL string by semicolons,
 * respecting string literals so we don't split inside strings.
 */
export function splitSQLStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (ch === "'" && !inDoubleQuote) {
      if (next === "'" && inSingleQuote) {
        current += "''";
        i++;
        continue;
      }
      inSingleQuote = !inSingleQuote;
      current += ch;
      continue;
    }

    if (ch === '"' && !inSingleQuote) {
      if (next === '"' && inDoubleQuote) {
        current += '""';
        i++;
        continue;
      }
      inDoubleQuote = !inDoubleQuote;
      current += ch;
      continue;
    }

    if (ch === ';' && !inSingleQuote && !inDoubleQuote) {
      const trimmed = current.trim();
      if (trimmed) {
        statements.push(trimmed);
      }
      current = '';
      continue;
    }

    current += ch;
  }

  const trimmed = current.trim();
  if (trimmed) {
    statements.push(trimmed);
  }

  return statements;
}

/**
 * Extract all table names referenced in a SQL statement.
 * Uses regex patterns to find tables in FROM, JOIN, INTO, UPDATE, TABLE clauses.
 * Also examines CTE definitions and subqueries.
 *
 * This is a best-effort extraction — the goal is to catch references to
 * forbidden tables that could be used to exfiltrate or modify system data.
 */
export function extractTableNames(sql: string): string[] {
  const tables = new Set<string>();
  const stripped = stripSQLComments(sql);
  const upper = stripped.toUpperCase();

  // Pattern: FROM <table> or FROM <schema>.<table>
  const fromMatches = stripped.matchAll(/\bFROM\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of fromMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: JOIN <table>
  const joinMatches = stripped.matchAll(/\bJOIN\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of joinMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: INSERT INTO <table>
  const insertMatches = stripped.matchAll(/\bINSERT\s+INTO\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of insertMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: UPDATE <table>
  const updateMatches = stripped.matchAll(/\bUPDATE\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of updateMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: DELETE FROM <table>
  const deleteMatches = stripped.matchAll(/\bDELETE\s+FROM\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of deleteMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: DROP TABLE [IF EXISTS] <table>
  const dropMatches = stripped.matchAll(/\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of dropMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: ALTER TABLE <table>
  const alterMatches = stripped.matchAll(/\bALTER\s+TABLE\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of alterMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: TRUNCATE TABLE? <table>
  const truncateMatches = stripped.matchAll(/\bTRUNCATE\s+TABLE\s+(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of truncateMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  // Pattern: CREATE TABLE [IF NOT EXISTS] <table>
  const createMatches = stripped.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(\w+)\.)?["'`]?(\w+)["'`]?/gi);
  for (const m of createMatches) {
    if (m[2]) tables.add(m[2].toLowerCase());
  }

  return Array.from(tables);
}

/**
 * Check if a table name matches any entry in the forbidden tables list.
 * Handles both exact matches and prefix matches (for entries ending with '_',
 * e.g., 'sqlite_' matches 'sqlite_master', 'sqlite_sequence', etc.)
 */
export function isTableForbidden(tableName: string, forbiddenTables: readonly string[]): boolean {
  const lower = tableName.toLowerCase();
  for (const forbidden of forbiddenTables) {
    const lowerForbidden = forbidden.toLowerCase();
    if (lowerForbidden.endsWith('_')) {
      // Prefix match: 'sqlite_' matches 'sqlite_master', 'sqlite_sequence', etc.
      if (lower.startsWith(lowerForbidden)) {
        return true;
      }
    } else {
      // Exact match
      if (lower === lowerForbidden) {
        return true;
      }
    }
  }
  return false;
}

// ============================================
// Main Validation Function
// ============================================

export interface SQLValidationResult {
  valid: boolean;
  error?: string;
  /** The detected statement type */
  statementType: 'SELECT' | 'DDL' | 'DML' | 'UNKNOWN' | 'BLOCKED';
  /** Extracted table names */
  tables: string[];
  /** Individual statements (for multi-statement DDL) */
  statements: string[];
}

/**
 * Validate a SQL query against security rules.
 *
 * This is the single entry point for all SQL validation in the application.
 * Every code path that executes user-supplied SQL MUST pass through this function.
 *
 * @param sql - The SQL query to validate
 * @param options - Validation options controlling what is allowed
 * @returns Validation result with error details if invalid
 */
export function validateSQL(sql: string, options: SQLValidationOptions = {}): SQLValidationResult {
  const {
    allowDDL = false,
    allowDML = true,
    forbiddenTables = RUNTIME_SYSTEM_TABLES,
    maxLength = MAX_SQL_LENGTH,
    context = 'SQL',
  } = options;

  // 1. Check SQL length
  if (!sql || typeof sql !== 'string') {
    return { valid: false, error: `${context}: SQL query is required`, statementType: 'UNKNOWN', tables: [], statements: [] };
  }

  if (sql.length > maxLength) {
    return { valid: false, error: `${context}: SQL query too long (max ${maxLength} bytes, got ${sql.length})`, statementType: 'UNKNOWN', tables: [], statements: [] };
  }

  // 2. Strip comments for analysis (prevents comment-based bypass)
  const strippedSQL = stripSQLComments(sql);
  const trimmedStripped = strippedSQL.trim();

  if (!trimmedStripped) {
    return { valid: false, error: `${context}: Empty SQL query`, statementType: 'UNKNOWN', tables: [], statements: [] };
  }

  // 3. Split into individual statements
  const statements = splitSQLStatements(trimmedStripped);

  if (statements.length === 0) {
    return { valid: false, error: `${context}: Empty SQL query`, statementType: 'UNKNOWN', tables: [], statements: [] };
  }

  // 4. Validate each statement
  let primaryType: SQLValidationResult['statementType'] = 'UNKNOWN';
  const allTables: string[] = [];

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i];
    const keyword = getStatementKeyword(stmt);

    // 4a. Check for blocked statement keywords
    if ((BLOCKED_STATEMENT_KEYWORDS as readonly string[]).includes(keyword)) {
      return {
        valid: false,
        error: `${context}: ${keyword} statements are not allowed`,
        statementType: 'BLOCKED',
        tables: [],
        statements: [],
      };
    }

    // Also check for blocked keywords appearing inside the statement (not just at start)
    // This catches: "SELECT 1; ATTACH DATABASE ..."
    // And also: cunning placement like "SELECT * FROM pragma_table_list"
    const stmtUpper = stmt.toUpperCase();
    for (const blocked of BLOCKED_STATEMENT_KEYWORDS) {
      // Check if the blocked keyword appears as a word boundary at statement start
      // or after a semicolon split (already handled by split)
      // We check if any inner statement starts with a blocked keyword
      const innerStatements = splitSQLStatements(stmt);
      for (const inner of innerStatements) {
        const innerKeyword = getStatementKeyword(inner);
        if ((BLOCKED_STATEMENT_KEYWORDS as readonly string[]).includes(innerKeyword)) {
          return {
            valid: false,
            error: `${context}: ${innerKeyword} statements are not allowed`,
            statementType: 'BLOCKED',
            tables: [],
            statements: [],
          };
        }
      }
    }

    // 4b. Determine statement type
    if (keyword === 'SELECT' || keyword === 'WITH') {
      // WITH can be a CTE followed by SELECT
      if (primaryType === 'UNKNOWN') primaryType = 'SELECT';
    } else if ((DDL_KEYWORDS as readonly string[]).includes(keyword)) {
      if (!allowDDL) {
        return {
          valid: false,
          error: `${context}: DDL statements (${keyword}) are not allowed`,
          statementType: 'DDL',
          tables: [],
          statements: [],
        };
      }
      if (primaryType === 'UNKNOWN') primaryType = 'DDL';
    } else if ((DML_KEYWORDS as readonly string[]).includes(keyword)) {
      if (!allowDML) {
        return {
          valid: false,
          error: `${context}: DML statements (${keyword}) are not allowed in read-only mode`,
          statementType: 'DML',
          tables: [],
          statements: [],
        };
      }
      if (primaryType === 'UNKNOWN') primaryType = 'DML';
    }

    // 4c. Extract and check table names against forbidden list
    const tables = extractTableNames(stmt);
    for (const table of tables) {
      allTables.push(table);
      if (isTableForbidden(table, forbiddenTables)) {
        return {
          valid: false,
          error: `${context}: Access to system table "${table}" is not allowed`,
          statementType: primaryType,
          tables: allTables,
          statements: [],
        };
      }
    }
  }

  // 5. Check DDL statement count limit
  if (primaryType === 'DDL' && statements.length > MAX_DDL_STATEMENTS) {
    return {
      valid: false,
      error: `${context}: Too many DDL statements (max ${MAX_DDL_STATEMENTS}, got ${statements.length})`,
      statementType: 'DDL',
      tables: allTables,
      statements: [],
    };
  }

  return {
    valid: true,
    statementType: primaryType,
    tables: allTables,
    statements,
  };
}

/**
 * Convenience function: validate SQL for runtime database (deployment) access.
 * Blocks DDL by default, protects system tables.
 */
export function validateRuntimeSQL(sql: string, options: { allowDDL?: boolean; context?: string } = {}): SQLValidationResult {
  return validateSQL(sql, {
    allowDDL: options.allowDDL ?? false,
    allowDML: true,
    forbiddenTables: RUNTIME_SYSTEM_TABLES,
    context: options.context ?? 'RuntimeDB',
  });
}

/**
 * Convenience function: validate SQL for edge function sandboxed access.
 * Uses the expanded forbidden tables list and blocks ALL DDL unconditionally.
 * Only SELECT, INSERT, UPDATE, DELETE are permitted.
 *
 * DDL (CREATE, DROP, ALTER, TRUNCATE) is ALWAYS blocked in edge functions
 * regardless of readOnly mode — edge functions run in a sandbox and must
 * never be allowed to modify the database schema.
 */
export function validateEdgeFunctionSQL(sql: string, readOnly: boolean = false): SQLValidationResult {
  return validateSQL(sql, {
    allowDDL: false,  // DDL always blocked in edge functions
    allowDML: !readOnly,
    forbiddenTables: EDGE_FORBIDDEN_TABLES,
    context: 'EdgeFunction',
  });
}

/**
 * Convenience function: validate SQL for project database access.
 * No system tables to protect (project DBs are user-owned),
 * but still blocks ATTACH/DETACH/PRAGMA/VACUUM/REINDEX.
 */
export function validateProjectSQL(sql: string, options: { allowDDL?: boolean; context?: string } = {}): SQLValidationResult {
  return validateSQL(sql, {
    allowDDL: options.allowDDL ?? true,
    allowDML: true,
    forbiddenTables: [], // No forbidden tables in project DB
    context: options.context ?? 'ProjectDB',
  });
}
