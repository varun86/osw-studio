/**
 * SQL Error Sanitization Utility
 *
 * Prevents leakage of database schema information (table names, column names,
 * constraint names, etc.) in error responses sent to clients.
 *
 * In production, SQL errors return a generic "Query failed" message.
 * The full error is logged server-side for debugging.
 *
 * In development, the original error message is returned for easier debugging.
 */

/**
 * Sanitize a database error for client consumption.
 * Returns a generic error message in production, original in development.
 *
 * @param error - The error from a database operation
 * @returns A safe error message for client responses
 */
export function sanitizeDbError(error: unknown): string {
  // In development, return the original error for debugging
  if (process.env.NODE_ENV === 'development') {
    return error instanceof Error ? error.message : 'Query failed';
  }

  // In production, return a generic message
  // The full error is logged server-side by the route handler
  return 'Query failed. Check your SQL syntax and try again.';
}

/**
 * Log a database error server-side with full details.
 * This should be called alongside sanitizeDbError to ensure
 * the full error is captured in server logs.
 *
 * @param context - A label for the route/context (e.g., 'AdminDBQuery')
 * @param error - The original error
 * @param sql - The SQL query that caused the error (optional, for debugging)
 */
export function logDbError(context: string, error: unknown, sql?: string): void {
  const message = error instanceof Error ? error.message : String(error);

  if (sql) {
    console.error(`[DB Error] ${context}: ${message} | SQL: ${sql.substring(0, 200)}`);
  } else {
    console.error(`[DB Error] ${context}: ${message}`);
  }
}
