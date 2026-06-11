/**
 * Next.js Middleware
 *
 * Handles authentication, CSRF protection, and routing for Server mode.
 * In Browser mode, server-only routes are blocked.
 * In Server mode, all data routes require authentication.
 *
 * CSRF protection:
 * - All POST/PUT/PATCH/DELETE requests to API routes are validated
 * - Origin/Referer headers must match allowed origins
 * - Exempt paths (auth, analytics, edge functions) skip validation
 *
 * Workspace authorization:
 * - /w/[workspaceId]/* pages require auth + workspace access
 * - /api/w/[workspaceId]/* routes require auth + workspace access
 * - /api/server-generate/* routes require auth
 * - Legacy /admin/{view} paths redirect to /w/{defaultWorkspaceId}/{view}
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifySession, maybeRefreshSession, verifyInstanceApiKey, SESSION_COOKIE_NAME, SESSION_DURATION } from '@/lib/auth/session';
import type { SessionData } from '@/lib/auth/session';
import { validateCsrf } from '@/lib/csrf';

async function nextWithRefreshedSession(session: SessionData): Promise<NextResponse> {
  const response = NextResponse.next();
  const refreshed = await maybeRefreshSession(session);
  if (refreshed) {
    response.cookies.set(SESSION_COOKIE_NAME, refreshed, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_DURATION / 1000,
      path: '/',
    });
  }
  return response;
}

// Views that have moved from /admin/{view} to /w/{workspaceId}/{view}
const WORKSPACE_VIEWS = ['projects', 'dashboard', 'deployments', 'settings', 'skills', 'templates', 'docs'];

function loginRedirect(request: NextRequest): NextResponse {
  // SECURITY: Use server-only GATEWAY_URL first, then fall back to NEXT_PUBLIC_ for compatibility
  const gatewayUrl = process.env.GATEWAY_URL || process.env.NEXT_PUBLIC_GATEWAY_URL;
  if (gatewayUrl) return NextResponse.redirect(gatewayUrl + '/login');
  return NextResponse.redirect(new URL('/admin/login', request.url));
}

/**
 * Check if a user has access to a workspace.
 * Uses the database to verify access, with admin bypass.
 * Returns true if access is granted, false otherwise.
 *
 * This is intentionally synchronous (uses require/import) because middleware
 * runs on the Edge Runtime in some deployments, but in this project it runs
 * on the Node.js runtime where synchronous require works.
 */
function checkWorkspaceAccess(userId: string, workspaceId: string): boolean {
  // Built-in admin accounts bypass workspace access checks
  if (userId === 'admin' || userId === 'desktop' || userId === 'instance-api') {
    return true;
  }

  try {
    // Use require for synchronous access in middleware
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { getWorkspaceAccess, getUserById } = require('@/lib/auth/system-database') as typeof import('@/lib/auth/system-database');

    // Check if user is admin (DB-verified)
    const user = getUserById(userId);
    if (user?.is_admin) return true;

    // Check workspace access
    const access = getWorkspaceAccess(userId, workspaceId);
    return !!access;
  } catch {
    // If database is unavailable, allow access (don't block on DB errors)
    return true;
  }
}

/**
 * Validate the osw_workspace cookie value against the user's authorized workspaces.
 * Returns the workspace ID if valid, null if the user doesn't have access.
 * In case of DB errors, returns the workspace ID (graceful degradation).
 */
function validateWorkspaceCookie(userId: string, workspaceId: string | undefined): string | null {
  if (!workspaceId) return null;

  // Built-in admin accounts can access any workspace
  if (userId === 'admin' || userId === 'desktop' || userId === 'instance-api') {
    return workspaceId;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { getWorkspaceAccess, getUserById, getUserDefaultWorkspace } = require('@/lib/auth/system-database') as typeof import('@/lib/auth/system-database');

    // Check if user is admin (DB-verified)
    const user = getUserById(userId);
    if (user?.is_admin) return workspaceId;

    // Check workspace access
    const access = getWorkspaceAccess(userId, workspaceId);
    if (access) return workspaceId;

    // User doesn't have access — return their default workspace instead
    const defaultWs = getUserDefaultWorkspace(userId);
    return defaultWs || null;
  } catch {
    // DB unavailable — return as-is (graceful degradation)
    return workspaceId;
  }
}

/**
 * Extract workspaceId from a URL path like /w/{workspaceId}/... or /api/w/{workspaceId}/...
 */
function extractWorkspaceId(pathname: string): string | null {
  // Match /w/{workspaceId} or /api/w/{workspaceId}
  const match = pathname.match(/^\/(?:api\/)?w\/([^/]+)/);
  return match ? match[1] : null;
}

export async function middleware(request: NextRequest) {
  const isServerMode = process.env.NEXT_PUBLIC_SERVER_MODE === 'true';
  const { pathname } = request.nextUrl;
  const isDesktop = process.env.OSW_DESKTOP === 'true';

  // ============================================
  // CSRF Protection: Validate Origin/Referer on state-changing requests
  // ============================================
  if (pathname.startsWith('/api/')) {
    const csrfResult = validateCsrf(request);
    if (!csrfResult.valid) {
      return NextResponse.json(
        { error: 'CSRF validation failed', reason: csrfResult.reason },
        { status: 403 }
      );
    }
  }

  // Desktop app: skip auth but still handle workspace routing
  if (isDesktop) {
    // Legacy redirect: /admin/{view} -> /w/{workspaceId}/{view}
    if (pathname.startsWith('/admin')) {
      for (const view of WORKSPACE_VIEWS) {
        if (pathname === `/admin/${view}` || pathname.startsWith(`/admin/${view}/`)) {
          const workspaceId = request.cookies.get('osw_workspace')?.value;
          if (workspaceId) {
            const newPath = pathname.replace(`/admin/${view}`, `/w/${workspaceId}/${view}`);
            return NextResponse.redirect(new URL(newPath, request.url));
          }
          // No workspace cookie yet — redirect to root to trigger bootstrap
          return NextResponse.redirect(new URL('/', request.url));
        }
      }
    }
    return NextResponse.next();
  }

  // ============================================
  // Workspace page routes: /w/[workspaceId]/*
  // ============================================
  if (pathname.startsWith('/w/')) {
    if (!isServerMode) {
      return NextResponse.redirect(new URL('/', request.url));
    }

    const token = request.cookies.get('osw_session')?.value;
    if (!token) {
      const response = loginRedirect(request);
      // Clear stale workspace cookie
      response.cookies.delete('osw_workspace');
      return response;
    }

    const session = await verifySession(token);
    if (!session) {
      const response = loginRedirect(request);
      // Clear stale cookies
      response.cookies.delete('osw_session');
      response.cookies.delete('osw_workspace');
      return response;
    }

    // Workspace authorization: verify user has access to this workspace
    const workspaceId = extractWorkspaceId(pathname);
    if (workspaceId && !checkWorkspaceAccess(session.userId, workspaceId)) {
      // User is authenticated but doesn't have access to this workspace
      // Validate the workspace cookie and redirect to an authorized workspace
      const cookieWorkspaceId = validateWorkspaceCookie(session.userId, request.cookies.get('osw_workspace')?.value);
      if (cookieWorkspaceId && cookieWorkspaceId !== workspaceId) {
        // Replace the workspaceId in the URL with the user's validated workspace
        const newPath = pathname.replace(`/w/${workspaceId}`, `/w/${cookieWorkspaceId}`);
        return NextResponse.redirect(new URL(newPath, request.url));
      }
      // No valid workspace — redirect to root
      return NextResponse.redirect(new URL('/', request.url));
    }

    return nextWithRefreshedSession(session);
  }

  // ============================================
  // Server-generate API routes: /api/server-generate/*
  // ============================================
  if (pathname.startsWith('/api/server-generate')) {
    if (!isServerMode) {
      return NextResponse.json({ error: 'Not available in Browser mode' }, { status: 404 });
    }

    const token = request.cookies.get('osw_session')?.value;
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const session = await verifySession(token);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    return nextWithRefreshedSession(session);
  }

  // ============================================
  // Workspace API routes: /api/w/[workspaceId]/*
  // ============================================
  if (pathname.startsWith('/api/w/')) {
    if (!isServerMode) {
      return NextResponse.json({ error: 'Not available in Browser mode' }, { status: 404 });
    }

    const token = request.cookies.get('osw_session')?.value;
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const session = await verifySession(token);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Workspace authorization: verify user has access to this workspace
    const workspaceId = extractWorkspaceId(pathname);
    if (workspaceId && !checkWorkspaceAccess(session.userId, workspaceId)) {
      return NextResponse.json({ error: 'Workspace access denied' }, { status: 403 });
    }

    return nextWithRefreshedSession(session);
  }

  // ============================================
  // Admin API routes: /api/admin/*
  // ============================================
  if (pathname.startsWith('/api/admin')) {
    if (!isServerMode) {
      return NextResponse.json({ error: 'Not available in Browser mode' }, { status: 404 });
    }
    // Defense-in-depth: verify session for admin API routes
    const token = request.cookies.get('osw_session')?.value;
    if (token) {
      const session = await verifySession(token);
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      return nextWithRefreshedSession(session);
    }
    // SECURITY (Step 37): Verify the API key in middleware, not just check its presence.
    // Previously, any value in x-instance-api-key header bypassed auth.
    // Now we actually validate it with timing-safe comparison.
    const apiSession = verifyInstanceApiKey(request);
    if (!apiSession) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.next();
  }

  // ============================================
  // Admin pages: /admin/*
  // ============================================
  if (pathname.startsWith('/admin')) {
    if (!isServerMode) {
      return NextResponse.redirect(new URL('/', request.url));
    }

    // When managed by an external auth provider, redirect login/register there
    // SECURITY: Use server-only GATEWAY_URL first, then fall back to NEXT_PUBLIC_ for compatibility
    const gatewayUrl = process.env.GATEWAY_URL || process.env.NEXT_PUBLIC_GATEWAY_URL;
    if (gatewayUrl && (pathname === '/admin/login' || pathname === '/admin/register')) {
      return NextResponse.redirect(gatewayUrl + '/login');
    }

    // Allow login and register pages without auth
    // (Register API enforces REGISTRATION_MODE + zero-users check server-side)
    if (pathname === '/admin/login' || pathname === '/admin/register') {
      return NextResponse.next();
    }

    const token = request.cookies.get('osw_session')?.value;
    if (!token) return loginRedirect(request);

    const session = await verifySession(token);
    if (!session) return loginRedirect(request);

    // Only admins can access user/workspace management
    if (!session.isAdmin && (pathname.startsWith('/admin/users') || pathname.startsWith('/admin/workspaces'))) {
      // Redirect non-admin to their default workspace
      const workspaceId = request.cookies.get('osw_workspace')?.value;
      if (workspaceId) {
        return NextResponse.redirect(new URL(`/w/${workspaceId}/projects`, request.url));
      }
      return loginRedirect(request);
    }

    // Legacy redirect: /admin/{view} -> /w/{workspaceId}/{view}
    for (const view of WORKSPACE_VIEWS) {
      if (pathname === `/admin/${view}` || pathname.startsWith(`/admin/${view}/`)) {
        const workspaceId = request.cookies.get('osw_workspace')?.value;
        if (workspaceId) {
          const newPath = pathname.replace(`/admin/${view}`, `/w/${workspaceId}/${view}`);
          return NextResponse.redirect(new URL(newPath, request.url));
        }
        // No workspace cookie — redirect to login
        return loginRedirect(request);
      }
    }

    // /admin root redirect
    if (pathname === '/admin' || pathname === '/admin/') {
      const workspaceId = request.cookies.get('osw_workspace')?.value;
      if (workspaceId) {
        return NextResponse.redirect(new URL(`/w/${workspaceId}/projects`, request.url));
      }
      return loginRedirect(request);
    }

    return nextWithRefreshedSession(session);
  }

  return NextResponse.next();
}

// Force Node.js runtime so we can use better-sqlite3 for workspace access checks
export const runtime = 'nodejs';

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|deployments/|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
