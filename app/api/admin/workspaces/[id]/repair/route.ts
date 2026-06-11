/**
 * Admin Workspace Repair API
 * POST /api/admin/workspaces/[id]/repair — detect and fix data issues
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import { getWorkspaceById, verifyWorkspaceAccess } from '@/lib/auth/system-database';
import { repairWorkspace } from '@/lib/auth/default-workspace';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin workspace repair routes */
function checkRateLimit(request: NextRequest): NextResponse | null {
  const identifier = getIdentifier(request);
  if (!adminRateLimiter.check(identifier, RATE_LIMIT_CONFIG.admin)) {
    const retryAfter = adminRateLimiter.getResetTime(identifier, RATE_LIMIT_CONFIG.admin);
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429, headers: { 'Retry-After': String(retryAfter) } }
    );
  }
  return null;
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    let session = apiSession;
    let isAdminOrApiKey = !!apiSession;

    if (!session) {
      try {
        session = await requireAdmin();
        isAdminOrApiKey = true;
      } catch {
        // Not an admin — check if workspace owner
        const { requireAuth } = await import('@/lib/auth/session');
        session = await requireAuth();
        isAdminOrApiKey = false;
      }
    }

    const { id } = await params;

    // Allow instance API keys, admins, or workspace owners
    if (!isAdminOrApiKey) {
      try {
        verifyWorkspaceAccess(session.userId, id, 'owner');
      } catch {
        return NextResponse.json({ error: 'Admin or workspace owner access required' }, { status: 403 });
      }
    }

    const workspace = getWorkspaceById(id);
    if (!workspace) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    const result = repairWorkspace(id);

    return NextResponse.json({
      success: true,
      repaired: result,
      summary: [
        result.legacyDbMigrated ? 'Migrated legacy database to workspace' : null,
        result.legacyProjectsMigrated > 0 ? `Migrated ${result.legacyProjectsMigrated} project database(s)` : null,
        result.deploymentRoutesCreated > 0 ? `Created ${result.deploymentRoutesCreated} deployment route(s)` : null,
        result.errors.length > 0 ? `${result.errors.length} error(s) occurred` : null,
      ].filter(Boolean),
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
