/**
 * Generic Error Response Utility
 *
 * SECURITY (Step 39): In production, 500 error responses must use generic
 * messages to avoid leaking internal details (stack traces, file paths,
 * database errors, etc.). In development, the original error is preserved
 * for debugging.
 *
 * Usage in API route catch blocks:
 *   catch (err) {
 *     return NextResponse.json(...internalErrorResponse(err));
 *   }
 */

import { NextResponse } from 'next/server';

/**
 * Returns a JSON error response args for internal server errors.
 * In production: generic "Internal server error" message.
 * In development: includes the original error message for debugging.
 *
 * @param err - The error that was caught
 * @returns Spread into NextResponse.json() call: { error: string }, { status: 500 }
 */
export function internalErrorResponse(err: unknown): [{ error: string }, { status: number }] {
  const isProduction = process.env.NODE_ENV === 'production';

  if (isProduction) {
    // Generic message — no details leaked
    return [{ error: 'Internal server error' }, { status: 500 }];
  }

  // Development: include original error for debugging
  const message = err instanceof Error ? err.message : String(err);
  return [{ error: message || 'Internal server error' }, { status: 500 }];
}
