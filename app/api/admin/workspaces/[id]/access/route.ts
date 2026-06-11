/**
 * Admin Workspace Access API
 * POST   /api/admin/workspaces/[id]/access — grant access { userId, role } or { email, role }
 * DELETE /api/admin/workspaces/[id]/access — revoke access { userId }
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import {
  getWorkspaceById,
  grantWorkspaceAccess,
  revokeWorkspaceAccess,
  getUserByEmail,
  getUserById,
} from '@/lib/auth/system-database';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin workspace access routes */
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
    const session = apiSession || await requireAdmin();

    const { id } = await params;
    const ws = getWorkspaceById(id);
    if (!ws) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    const body = await request.json();
    const { userId, email, role } = body;

    if (!role || !['owner', 'editor', 'viewer'].includes(role)) {
      return NextResponse.json({ error: 'Valid role is required (owner, editor, viewer)' }, { status: 400 });
    }

    // Resolve user
    let resolvedUserId = userId;
    if (!resolvedUserId && email) {
      const user = getUserByEmail(email);
      if (!user) {
        return NextResponse.json({ error: `No user found with email: ${email}` }, { status: 404 });
      }
      resolvedUserId = user.id;
    }

    if (!resolvedUserId) {
      return NextResponse.json({ error: 'userId or email is required' }, { status: 400 });
    }

    // Verify the user exists
    const user = getUserById(resolvedUserId);
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    grantWorkspaceAccess(resolvedUserId, id, role as 'owner' | 'editor' | 'viewer');

    return NextResponse.json({ success: true }, { status: 201 });
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
    const ws = getWorkspaceById(id);
    if (!ws) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    const body = await request.json();
    const { userId } = body;

    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 });
    }

    // Prevent removing the workspace owner's access
    if (ws.owner_id === userId) {
      return NextResponse.json({ error: 'Cannot remove the workspace owner\'s access' }, { status: 400 });
    }

    revokeWorkspaceAccess(userId, id);

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
