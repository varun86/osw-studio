/**
 * Admin Users API
 * GET /api/admin/users - List all users (with per-user stats)
 */

import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin, verifyInstanceApiKey } from '@/lib/auth/session';
import { listUsers, listUserWorkspaces, createUser, getUserByEmail, createWorkspace, setDefaultWorkspace } from '@/lib/auth/system-database';
import { hashPassword } from '@/lib/auth/passwords';
import { validatePassword } from '@/lib/auth/password-policy';
import { internalErrorResponse } from '@/lib/security/error-response';
import { adminRateLimiter, RATE_LIMIT_CONFIG, getIdentifier } from '@/lib/analytics/rate-limiter';

/** SECURITY (Step 51): Rate limit check for admin user routes */
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
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

function getDataDir(): string {
  return process.env.DATA_DIR || path.join(process.cwd(), 'data');
}

/**
 * Aggregate project count + last active date across all of a user's workspaces.
 */
function getUserStats(userId: string): { projectCount: number; lastActive: string | null } {
  const workspaces = listUserWorkspaces(userId);
  let totalProjects = 0;
  let lastActive: string | null = null;

  for (const ws of workspaces) {
    const dbPath = path.join(getDataDir(), 'workspaces', ws.id, 'osws.sqlite');
    if (!fs.existsSync(dbPath)) continue;
    try {
      const db = new Database(dbPath, { readonly: true });
      const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'").get();
      if (tableExists) {
        totalProjects += (db.prepare('SELECT COUNT(*) as count FROM projects').get() as { count: number }).count;
        const lastProject = db.prepare('SELECT updated_at FROM projects ORDER BY updated_at DESC LIMIT 1').get() as { updated_at: string } | undefined;
        if (lastProject?.updated_at && (!lastActive || lastProject.updated_at > lastActive)) {
          lastActive = lastProject.updated_at;
        }
      }
      db.close();
    } catch { /* skip inaccessible workspace DB */ }
  }

  return { projectCount: totalProjects, lastActive };
}

/**
 * Recursively compute total size of a directory in bytes.
 */
function getDirectorySizeSync(dirPath: string): number {
  let total = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        total += getDirectorySizeSync(fullPath);
      } else if (entry.isFile()) {
        total += fs.statSync(fullPath).size;
      }
    }
  } catch { /* directory may not exist */ }
  return total;
}

/**
 * Calculate total storage for a user by summing all workspace data directories.
 */
function getUserStorageMb(userId: string): number {
  const workspaces = listUserWorkspaces(userId);
  let totalBytes = 0;

  for (const ws of workspaces) {
    const wsDir = path.join(getDataDir(), 'workspaces', ws.id);
    totalBytes += getDirectorySizeSync(wsDir);
  }

  return Math.round((totalBytes / (1024 * 1024)) * 10) / 10;
}

export async function GET(request: NextRequest) {
  const rateLimitResponse = checkRateLimit(request);
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const apiSession = verifyInstanceApiKey(request);
    const session = apiSession || await requireAdmin();

    const users = listUsers();

    // Enrich with workspace info, project stats, and storage (exclude password hash from response)
    const enriched = users.map(user => {
      const stats = getUserStats(user.id);
      return {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        isAdmin: user.is_admin === 1,
        active: user.active === 1,
        workspaces: listUserWorkspaces(user.id),
        projectCount: stats.projectCount,
        storageMb: getUserStorageMb(user.id),
        lastActive: stats.lastActive,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      };
    });

    return NextResponse.json({ users: enriched });
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
    const { email, password, displayName, workspaceAssignment, workspaceId: assignWorkspaceId, isAdmin: makeAdmin } = body;

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required' }, { status: 400 });
    }

    // Enforce password policy for admin-created users too
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return NextResponse.json({ error: passwordValidation.errors.join('. ') }, { status: 400 });
    }

    // Check for existing user
    const existing = getUserByEmail(email);
    if (existing) {
      return NextResponse.json({ error: 'A user with this email already exists' }, { status: 409 });
    }

    const passwordHash = await hashPassword(password);
    const userId = createUser(email, passwordHash, displayName || undefined);

    // Optionally promote to instance admin
    if (makeAdmin) {
      const { updateUser } = await import('@/lib/auth/system-database');
      updateUser(userId, { active: 1 }); // updateUser doesn't support is_admin directly
      const db = (await import('@/lib/auth/system-database')).getSystemDatabase();
      db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(userId);
    }

    // Workspace assignment
    let workspaceId: string | undefined;
    if (workspaceAssignment === 'existing' && assignWorkspaceId) {
      const { grantWorkspaceAccess } = await import('@/lib/auth/system-database');
      grantWorkspaceAccess(userId, assignWorkspaceId, 'editor');
      setDefaultWorkspace(userId, assignWorkspaceId);
      workspaceId = assignWorkspaceId;
    } else if (workspaceAssignment !== 'none') {
      // Default: create new workspace
      const workspaceName = displayName ? `${displayName}'s Workspace` : 'My Workspace';
      workspaceId = createWorkspace(workspaceName, userId);
      setDefaultWorkspace(userId, workspaceId);
    }

    return NextResponse.json({ id: userId, workspaceId }, { status: 201 });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.json(...internalErrorResponse(error));
  }
}
