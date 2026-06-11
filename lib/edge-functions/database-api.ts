/**
 * Sandboxed Database API for Edge Functions
 *
 * Provides a secure, limited interface to the deployment's SQLite database
 * for use within edge functions. Delegates validation to the centralized
 * SQL validator module for consistent security enforcement.
 *
 * Security features:
 * - Blocks access to all system and forbidden tables
 * - Blocks dangerous SQL keywords (ATTACH, DETACH, PRAGMA, VACUUM, REINDEX)
 * - Enforces query count limits per execution
 * - Supports read-only mode for GET-request edge functions
 * - Enforces SQL length limits
 */

import { RuntimeDatabase } from '@/lib/vfs/adapters/runtime-database';
import { DatabaseAPI, DatabaseAPIOptions } from './types';
import {
  validateEdgeFunctionSQL,
  MAX_SQL_LENGTH,
  MAX_RESULT_ROWS,
} from '@/lib/db/sql-validator';

/**
 * Create a sandboxed database API for edge function use
 *
 * @param deploymentDb The deployment's database instance
 * @param options Configuration options
 * @returns A DatabaseAPI that enforces security restrictions
 */
export function createDatabaseAPI(
  deploymentDb: RuntimeDatabase,
  options: DatabaseAPIOptions = {}
): DatabaseAPI {
  let queryCount = 0;
  const maxQueries = options.maxQueries ?? 100;
  const readOnly = options.readOnly ?? false;

  /**
   * Execute a query and convert results to objects
   */
  const executeQuery = <T>(sql: string, params?: unknown[]): T[] => {
    // Check query count limit
    queryCount++;
    if (queryCount > maxQueries) {
      throw new Error(`Query limit exceeded (max ${maxQueries} queries per execution)`);
    }

    // Delegate to centralized validator
    const validation = validateEdgeFunctionSQL(sql, readOnly);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    try {
      const result = deploymentDb.executeRawSQL(sql, params);

      // Enforce row limit
      const limitedRows = result.rows.slice(0, MAX_RESULT_ROWS);

      // Convert row arrays to objects
      return limitedRows.map(row => {
        const obj: Record<string, unknown> = {};
        result.columns.forEach((col, i) => {
          obj[col] = row[i];
        });
        return obj as T;
      });
    } catch (error) {
      // Re-throw with cleaner message
      const message = error instanceof Error ? error.message : 'Query failed';
      throw new Error(`Database error: ${message}`);
    }
  };

  /**
   * Execute a statement that modifies data
   */
  const executeRun = (sql: string, params?: unknown[]): { changes: number; lastInsertRowid: number | bigint } => {
    // Check query count limit
    queryCount++;
    if (queryCount > maxQueries) {
      throw new Error(`Query limit exceeded (max ${maxQueries} queries per execution)`);
    }

    if (readOnly) {
      throw new Error('Database is in read-only mode');
    }

    // Delegate to centralized validator
    const validation = validateEdgeFunctionSQL(sql, readOnly);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    try {
      const result = deploymentDb.executeRawSQL(sql, params);
      return {
        changes: result.rowsAffected,
        lastInsertRowid: 0, // SQLite doesn't expose this through our API currently
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Query failed';
      throw new Error(`Database error: ${message}`);
    }
  };

  return {
    query<T = Record<string, unknown>>(sql: string, params?: unknown[]): T[] {
      return executeQuery<T>(sql, params);
    },

    run(sql: string, params?: unknown[]): { changes: number; lastInsertRowid: number | bigint } {
      return executeRun(sql, params);
    },

    all<T = Record<string, unknown>>(sql: string, params?: unknown[]): T[] {
      return executeQuery<T>(sql, params);
    },
  };
}
