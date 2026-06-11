/**
 * Admin Workspaces API
 * GET — list all workspaces with stats
 * POST — create a new workspace
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import {
  listWorkspaces,
  createWorkspace,
  grantWorkspaceAccess,
  getUserByEmail,
  getSystemDatabase,
  getWorkspaceProjectCount,
} from '@/lib/auth/system-database';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin workspace routes */
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

function getWorkspaceDeploymentCount(workspaceId: string): number {
  try {
    const sysDb = getSystemDatabase();
    const row = sysDb.prepare('SELECT COUNT(*) as count FROM deployment_routing WHERE workspace_id = ?').get(workspaceId) as { count: number };
    return row.count;
  } catch { return 0; }
}

function getWorkspaceMemberCount(workspaceId: string): number {
  try {
    const sysDb = getSystemDatabase();
    const row = sysDb.prepare('SELECT COUNT(*) as count FROM workspace_access WHERE workspace_id = ?').get(workspaceId) as { count: number };
    return row.count;
  } catch { return 0; }
}

function getWorkspaceOwnerEmail(ownerId: string): string | null {
  try {
    const sysDb = getSystemDatabase();
    const row = sysDb.prepare('SELECT email FROM users WHERE id = ?').get(ownerId) as { email: string } | undefined;
    return row?.email ?? null;
  } catch { return null; }
}

export async function GET(request: NextRequest) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const workspaces = listWorkspaces();

    const enriched = workspaces.map(ws => ({
      id: ws.id,
      name: ws.name,
      ownerId: ws.owner_id,
      ownerEmail: getWorkspaceOwnerEmail(ws.owner_id),
      maxProjects: ws.max_projects,
      maxDeployments: ws.max_deployments,
      maxStorageMb: ws.max_storage_mb,
      memberCount: getWorkspaceMemberCount(ws.id),
      projectCount: getWorkspaceProjectCount(ws.id),
      deploymentCount: getWorkspaceDeploymentCount(ws.id),
      createdAt: ws.created_at,
      updatedAt: ws.updated_at,
    }));

    return NextResponse.json({ workspaces: enriched });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}

export async function POST(request: NextRequest) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const body = await request.json();
    const { name, ownerId, ownerEmail } = body;

    if (!name) {
      return NextResponse.json({ error: 'Workspace name is required' }, { status: 400 });
    }

    // Resolve owner: either by ownerId directly or by email lookup
    let resolvedOwnerId = ownerId;
    if (!resolvedOwnerId && ownerEmail) {
      const user = getUserByEmail(ownerEmail);
      if (!user) {
        return NextResponse.json({ error: `No user found with email: ${ownerEmail}` }, { status: 404 });
      }
      resolvedOwnerId = user.id;
    }

    if (!resolvedOwnerId) {
      return NextResponse.json({ error: 'Owner is required (provide ownerId or ownerEmail)' }, { status: 400 });
    }

    const workspaceId = createWorkspace(name, resolvedOwnerId);

    // createWorkspace already inserts owner into workspace_access, but grantWorkspaceAccess
    // uses INSERT OR REPLACE so calling it again with owner role is idempotent and ensures role.
    grantWorkspaceAccess(resolvedOwnerId, workspaceId, 'owner');

    return NextResponse.json({ id: workspaceId }, { status: 201 });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
