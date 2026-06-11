/**
 * Registration API Route
 *
 * Creates a new user account in the system database.
 */

import { NextRequest, NextResponse } from 'next/server';
import { createSession } from '@/lib/auth/session';
import { createUser, getUserByEmail, getUserCount, createWorkspace, setDefaultWorkspace, updateWorkspace } from '@/lib/auth/system-database';
import { hashPassword } from '@/lib/auth/passwords';
import { validatePassword } from '@/lib/auth/password-policy';
import { logger } from '@/lib/utils';
import { getSystemDatabase } from '@/lib/auth/system-database';
import { RateLimiter, getIdentifier } from '@/lib/analytics/rate-limiter';

// Rate limiting: 3 registrations per IP per hour
const registerRateLimiter = new RateLimiter();
const REGISTER_RATE_LIMIT = { limit: 3, windowMs: 60 * 60 * 1000 }; // 3 per IP per hour

export async function POST(request: NextRequest) {
  // Rate limiting check — before any registration logic
  const clientIp = getIdentifier(request);
  if (!registerRateLimiter.check(clientIp, REGISTER_RATE_LIMIT)) {
    const resetTime = registerRateLimiter.getResetTime(clientIp, REGISTER_RATE_LIMIT);
    return NextResponse.json(
      { error: 'Too many registration attempts. Please try again later.' },
      { status: 429, headers: { 'Retry-After': String(resetTime) } }
    );
  }

  try {
    const userCount = getUserCount();
    const isFirstUser = userCount === 0;
    const registrationMode = process.env.REGISTRATION_MODE || 'closed';

    // Allow registration if: open mode, OR no users exist yet (initial setup)
    if (registrationMode !== 'open' && !isFirstUser) {
      return NextResponse.json(
        { error: 'Registration is not available on this instance' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { email, password, displayName } = body;

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password required' }, { status: 400 });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json({ error: 'Invalid email format' }, { status: 400 });
    }

    // Enforce password policy: min 12 chars, max 128 chars, 3/4 complexity categories
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return NextResponse.json({ error: passwordValidation.errors.join('. ') }, { status: 400 });
    }

    const existing = getUserByEmail(email);
    if (existing) {
      // Return generic success-like message to prevent user enumeration.
      // Attackers must not be able to determine whether an email is registered.
      logger.info(`[API /api/auth/register] Duplicate registration attempt for: ${email}`);
      return NextResponse.json(
        { message: 'If this email is not already registered, an account will be created.' },
        { status: 200 }
      );
    }

    const passwordHash = await hashPassword(password);
    const userId = createUser(email, passwordHash, displayName);

    // First user becomes admin
    if (isFirstUser) {
      const db = getSystemDatabase();
      db.prepare("UPDATE users SET is_admin = 1, updated_at = datetime('now') WHERE id = ?").run(userId);
    }

    // Create default workspace
    const workspaceName = displayName ? `${displayName}'s Workspace` : 'My Workspace';
    const workspaceId = createWorkspace(workspaceName, userId);

    // First user gets unlimited workspace
    if (isFirstUser) {
      updateWorkspace(workspaceId, {
        max_projects: 9999,
        max_deployments: 9999,
        max_storage_mb: 99999,
      });
    }

    setDefaultWorkspace(userId, workspaceId);

    const token = await createSession(userId, email, isFirstUser);
    const response = NextResponse.json({ success: true, userId, defaultWorkspaceId: workspaceId, defaultWorkspaceName: workspaceName });
    response.cookies.set('osw_session', token, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60,
      path: '/',
    });
    return response;
  } catch (error) {
    logger.error('[API /api/auth/register] Error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Registration failed' },
      { status: 500 }
    );
  }
}
