/**
 * Admin Workspace Detail API
 * GET  /api/admin/workspaces/[id] — workspace detail with members
 * PUT  /api/admin/workspaces/[id] — update workspace (name, quotas)
 * DELETE /api/admin/workspaces/[id] — delete workspace
 */

import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import {
  getWorkspaceById,
  updateWorkspace,
  deleteWorkspace,
  getSystemDatabase,
  getWorkspaceProjectCount,
} from '@/lib/auth/system-database';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin workspace detail routes */
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

interface WorkspaceMember {
  userId: string;
  email: string;
  displayName: string | null;
  role: string;
  joinedAt: string;
}

function getWorkspaceMembers(workspaceId: string): WorkspaceMember[] {
  try {
    const sysDb = getSystemDatabase();
    const rows = sysDb.prepare(`
      SELECT wa.user_id, wa.role, wa.created_at as joined_at,
             u.email, u.display_name
      FROM workspace_access wa
      JOIN users u ON u.id = wa.user_id
      WHERE wa.workspace_id = ?
      ORDER BY wa.created_at ASC
    `).all(workspaceId) as {
      user_id: string;
      role: string;
      joined_at: string;
      email: string;
      display_name: string | null;
    }[];

    return rows.map(r => ({
      userId: r.user_id,
      email: r.email,
      displayName: r.display_name,
      role: r.role,
      joinedAt: r.joined_at,
    }));
  } catch { return []; }
}

function getOwnerEmail(ownerId: string): string | null {
  try {
    const sysDb = getSystemDatabase();
    const row = sysDb.prepare('SELECT email FROM users WHERE id = ?').get(ownerId) as { email: string } | undefined;
    return row?.email ?? null;
  } catch { return null; }
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
    const ws = getWorkspaceById(id);
    if (!ws) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    return NextResponse.json({
      id: ws.id,
      name: ws.name,
      ownerId: ws.owner_id,
      ownerEmail: getOwnerEmail(ws.owner_id),
      maxProjects: ws.max_projects,
      maxDeployments: ws.max_deployments,
      maxStorageMb: ws.max_storage_mb,
      projectCount: getWorkspaceProjectCount(ws.id),
      deploymentCount: getWorkspaceDeploymentCount(ws.id),
      createdAt: ws.created_at,
      updatedAt: ws.updated_at,
      members: getWorkspaceMembers(ws.id),
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
    const ws = getWorkspaceById(id);
    if (!ws) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    const body = await request.json();

    updateWorkspace(id, {
      name: body.name,
      max_projects: body.maxProjects,
      max_deployments: body.maxDeployments,
      max_storage_mb: body.maxStorageMb,
    });

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
    const ws = getWorkspaceById(id);
    if (!ws) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }

    deleteWorkspace(id);

    // Clean up workspace data directory
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
    const workspaceDir = path.join(dataDir, 'workspaces', id);
    try {
      if (fs.existsSync(workspaceDir)) {
        fs.rmSync(workspaceDir, { recursive: true, force: true });
      }
    } catch {
      // Filesystem cleanup failure is non-fatal
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
