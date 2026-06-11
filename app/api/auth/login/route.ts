/**
 * Login API Route
 *
 * Authenticates user against system database and creates session.
 * Falls back to ADMIN_PASSWORD env var for backward compatibility.
 */

import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';
import { createSession } from '@/lib/auth/session';
import { getUserByEmail, getUserDefaultWorkspace, getWorkspaceById, getUserCount } from '@/lib/auth/system-database';
import { ensureDefaultWorkspace } from '@/lib/auth/default-workspace';
import { verifyPassword } from '@/lib/auth/passwords';
import { logger } from '@/lib/utils';
import { RateLimiter, getIdentifier } from '@/lib/analytics/rate-limiter';

// Rate limiting: 5 attempts per email per 15 min, 20 per IP per 15 min
const emailRateLimiter = new RateLimiter();
const ipRateLimiter = new RateLimiter();
const LOGIN_RATE_LIMITS = {
  email: { limit: 5, windowMs: 15 * 60 * 1000 },   // 5 per email per 15 min
  ip: { limit: 20, windowMs: 15 * 60 * 1000 },      // 20 per IP per 15 min
};

export async function POST(request: NextRequest) {
  // Rate limiting check — before any authentication logic
  const clientIp = getIdentifier(request);
  if (!ipRateLimiter.check(clientIp, LOGIN_RATE_LIMITS.ip)) {
    const resetTime = ipRateLimiter.getResetTime(clientIp, LOGIN_RATE_LIMITS.ip);
    return NextResponse.json(
      { error: 'Too many login attempts. Please try again later.' },
      { status: 429, headers: { 'Retry-After': String(resetTime) } }
    );
  }

  try {
    const body = await request.json();
    const { email, password } = body;

    if (!password) {
      return NextResponse.json({ error: 'Password required' }, { status: 400 });
    }

    // If email provided, authenticate against system database
    if (email) {
      // Per-email rate limiting
      if (!emailRateLimiter.check(email.toLowerCase().trim(), LOGIN_RATE_LIMITS.email)) {
        const resetTime = emailRateLimiter.getResetTime(email.toLowerCase().trim(), LOGIN_RATE_LIMITS.email);
        return NextResponse.json(
          { error: 'Too many login attempts for this email. Please try again later.' },
          { status: 429, headers: { 'Retry-After': String(resetTime) } }
        );
      }

      const user = getUserByEmail(email);
      if (!user) {
        return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 });
      }

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) {
        return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 });
      }

      // Run legacy data migration if needed
      await ensureDefaultWorkspace(user.id);

      const token = await createSession(user.id, user.email, user.is_admin === 1);
      const defaultWorkspaceId = getUserDefaultWorkspace(user.id);
      const defaultWorkspaceName = defaultWorkspaceId ? getWorkspaceById(defaultWorkspaceId)?.name : undefined;
      const response = NextResponse.json({ success: true, defaultWorkspaceId, defaultWorkspaceName });
      response.cookies.set('osw_session', token, {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60,
        path: '/',
      });
      return response;
    }

    // Legacy admin password — only works when no users exist (bootstrap)
    const adminPassword = process.env.ADMIN_PASSWORD;
    const userCount = getUserCount();

    if (!adminPassword || userCount > 0) {
      return NextResponse.json(
        { error: userCount > 0 ? 'Please log in with your email and password' : 'Authentication not configured' },
        { status: userCount > 0 ? 400 : 500 }
      );
    }

    const passwordsMatch = (() => {
      try {
        const a = Buffer.from(password);
        const b = Buffer.from(adminPassword);
        if (a.length !== b.length) return false;
        return timingSafeEqual(a, b);
      } catch {
        return false;
      }
    })();
    if (!passwordsMatch) {
      return NextResponse.json({ error: 'Invalid password' }, { status: 401 });
    }

    // Bootstrap: create admin user and workspace via ensureDefaultWorkspace
    const adminWorkspaceId = await ensureDefaultWorkspace('admin');

    const token = await createSession('admin', 'admin@localhost', true);
    const adminWorkspaceName = getWorkspaceById(adminWorkspaceId)?.name;
    const response = NextResponse.json({ success: true, defaultWorkspaceId: adminWorkspaceId, defaultWorkspaceName: adminWorkspaceName });
    response.cookies.set('osw_session', token, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60,
      path: '/',
    });
    return response;
  } catch (error) {
    logger.error('[API /api/auth/login] Error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Login failed' },
      { status: 500 }
    );
  }
}
