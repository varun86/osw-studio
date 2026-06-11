/**
 * Admin User Detail API
 * GET /api/admin/users/[id] - Get user details with deployments
 * PUT /api/admin/users/[id] - Update user
 * DELETE /api/admin/users/[id] - Delete user
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import { getUserById, updateUser, deactivateUser, listUserWorkspaces } from '@/lib/auth/system-database';
import { revokeAllUserSessions } from '@/lib/auth/session-revocation';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin user detail routes */
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


export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const { id } = await params;
    const user = getUserById(id);
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    return NextResponse.json({
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      isAdmin: user.is_admin === 1,
      active: user.active === 1,
      workspaces: listUserWorkspaces(user.id),
      createdAt: user.created_at,
      updatedAt: user.updated_at,
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const { id } = await params;
    const body = await request.json();

    const user = getUserById(id);
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    const deactivating = body.active === false || body.active === 0;

    updateUser(id, {
      active: body.active !== undefined ? (body.active ? 1 : 0) : undefined,
      display_name: body.displayName,
    });

    // If user is being deactivated, revoke all their sessions immediately
    if (deactivating) {
      revokeAllUserSessions(id, 'deactivation');
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const { id } = await params;

    // Prevent self-deletion
    if (id === session.userId) {
      return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 });
    }

    deactivateUser(id);

    // Revoke all sessions for this user so they are immediately logged out
    // on all devices, preventing continued access after deactivation.
    revokeAllUserSessions(id, 'deactivation');

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
