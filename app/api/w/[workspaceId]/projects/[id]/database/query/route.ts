/**
 * Workspace-Scoped Project Database Query API
 *
 * POST - Execute SQL query against project database
 *
 * Security: Uses centralized SQL validator to block:
 * - ATTACH/DETACH/PRAGMA/VACUUM/REINDEX statements
 * - Overly long SQL queries (resource exhaustion)
 * - DDL is allowed (project DBs are user-owned) but validated
 * - Result row limits enforced
 */

import { logger } from '@/lib/utils';
import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceContext } from '@/lib/api/workspace-context';
import { validateProjectSQL, MAX_RESULT_ROWS } from '@/lib/db/sql-validator';
import { sanitizeDbError, logDbError } from '@/lib/db/sanitize-error';
import { databaseQueryRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ workspaceId: string; id: string }> }
): Promise<NextResponse> {
  try {
    // Rate limiting — 20 requests per minute per user
    const identifier = getIdentifier(request);
    if (!databaseQueryRateLimiter.check(identifier, RATE_LIMIT_CONFIG.databaseQuery)) {
      const retryAfter = databaseQueryRateLimiter.getResetTime(identifier, RATE_LIMIT_CONFIG.databaseQuery);
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429, headers: { 'Retry-After': String(retryAfter) } }
      );
    }

    const { adapter } = await getWorkspaceContext(params);
    const { id: projectId } = await params;
    const body = await request.json();

    const { sql } = body;
    if (!sql || typeof sql !== 'string') {
      return NextResponse.json({ error: 'SQL query is required' }, { status: 400 });
    }

    // Validate SQL through centralized validator
    // Project DBs have no system tables but still block dangerous statements
    const validation = validateProjectSQL(sql, { context: 'ProjectDBQuery' });
    if (!validation.valid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const projectDb = adapter.getProjectDatabase(projectId);

    try {
      // Route DDL and DML/SELECT to appropriate methods
      if (validation.statementType === 'DDL') {
        projectDb.executeDDL(sql);
        return NextResponse.json({
          success: true,
          columns: [],
          rows: [],
          rowsAffected: 0,
        });
      }

      const result = projectDb.executeRawSQL(sql);

      // Enforce row limit
      const limitedRows = result.rows.slice(0, MAX_RESULT_ROWS);
      const truncated = result.rows.length > MAX_RESULT_ROWS;

      return NextResponse.json({
        success: true,
        columns: result.columns,
        rows: limitedRows,
        rowsAffected: result.rowsAffected,
        ...(truncated ? { warning: `Result truncated to ${MAX_RESULT_ROWS} rows (total: ${result.rows.length})` } : {}),
      });
    } catch (sqlError) {
      logDbError('ProjectDBQuery', sqlError, sql);
      const message = sanitizeDbError(sqlError);
      return NextResponse.json({ error: message }, { status: 400 });
    }
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (error instanceof Error && (error.message === 'Workspace access denied' || error.message === 'Insufficient workspace permissions')) {
      return NextResponse.json({ error: error.message }, { status: 403 });
    }
    logger.error('[Project Database API] Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
