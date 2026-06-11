/**
 * Workspace-Scoped Admin API: SQL Query Execution
 *
 * POST - Execute SQL query against deployment database
 *
 * Security: Uses centralized SQL validator to block:
 * - ATTACH/DETACH/PRAGMA/VACUUM/REINDEX statements
 * - Access to system tables (secrets, edge_functions, files, etc.)
 * - Overly long SQL queries (resource exhaustion)
 * - Result row limits enforced
 */

import { logger } from '@/lib/utils';
import { NextRequest, NextResponse } from 'next/server';
import { getWorkspaceContext } from '@/lib/api/workspace-context';
import { validateRuntimeSQL, MAX_SQL_LENGTH, MAX_RESULT_ROWS } from '@/lib/db/sql-validator';
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
    const { id: deploymentId } = await params;
    const body = await request.json();

    const { sql } = body;
    if (!sql || typeof sql !== 'string') {
      return NextResponse.json({ error: 'SQL query is required' }, { status: 400 });
    }

    // Validate SQL through centralized validator
    const validation = validateRuntimeSQL(sql, { context: 'AdminDBQuery' });
    if (!validation.valid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const deployment = await adapter.getDeployment?.(deploymentId);
    if (!deployment) {
      return NextResponse.json({ error: 'Deployment not found' }, { status: 404 });
    }
    if (!deployment.databaseEnabled) {
      return NextResponse.json({ error: 'Deployment database not enabled' }, { status: 400 });
    }

    const deploymentDb = adapter.getDeploymentDatabaseForAnalytics(deploymentId);
    if (!deploymentDb) {
      return NextResponse.json({ error: 'Deployment database not available' }, { status: 500 });
    }

    try {
      const result = deploymentDb.executeRawSQL(sql);

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
      logDbError('AdminDBQuery', sqlError, sql);
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
    logger.error('[Admin Database API] Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
