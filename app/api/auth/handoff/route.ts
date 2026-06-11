import { NextRequest, NextResponse } from 'next/server';
import { verifyHandoffToken, createSession, SESSION_COOKIE_NAME, SESSION_DURATION } from '@/lib/auth/session';
import { getUserById, getUserDefaultWorkspace } from '@/lib/auth/system-database';
import { ensureDefaultWorkspace } from '@/lib/auth/default-workspace';
import { RateLimiter, getIdentifier } from '@/lib/analytics/rate-limiter';

// Rate limiting: 10 handoff attempts per IP per minute
const handoffRateLimiter = new RateLimiter();
const HANDOFF_RATE_LIMIT = { limit: 10, windowMs: 60 * 1000 }; // 10 per IP per minute

const UUID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

function sanitizeRedirect(redirect: string): string {
  // Only allow relative paths starting with / — block open redirects
  if (!redirect.startsWith('/') || redirect.startsWith('//')) return '/';
  return redirect;
}

/**
 * Helper to process a verified handoff token and create a session.
 * Shared between GET (legacy) and POST (secure) handlers.
 */
async function processHandoff(request: NextRequest, token: string, redirectPath: string) {
  const redirect = sanitizeRedirect(redirectPath);

  const result = await verifyHandoffToken(token);
  if (!result) {
    return null;
  }

  const user = getUserById(result.userId);
  if (!user) {
    return null;
  }

  // Ensure workspace is fully initialized (same as login flow)
  await ensureDefaultWorkspace(user.id);

  // Create a normal OSWS session for this user
  const sessionToken = await createSession(user.id, user.email, !!user.is_admin);

  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || request.url;
  const response = NextResponse.redirect(new URL(redirect, baseUrl));
  response.cookies.set(SESSION_COOKIE_NAME, sessionToken, {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DURATION / 1000,
    path: '/',
  });

  // Set osw_workspace cookie — extract workspace ID from redirect URL or use default
  const workspaceMatch = redirect.match(/\/w\/([^/]+)\//);
  const extractedId = workspaceMatch?.[1];
  const workspaceId = (extractedId && UUID_REGEX.test(extractedId)) ? extractedId : getUserDefaultWorkspace(user.id);
  if (workspaceId) {
    response.cookies.set('osw_workspace', workspaceId, {
      httpOnly: false, // Read client-side by VFS factory, workspace switcher, and tool registry
      secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 365,
      path: '/',
    });
  }

  return response;
}

/**
 * POST handler — secure handoff with token in request body (not URL).
 * This prevents token leakage via browser history, server logs, and Referer headers.
 *
 * Request body: { token: string, redirect?: string }
 * Response: Redirect to the app with session cookie set
 */
export async function POST(request: NextRequest) {
  // Rate limiting check
  const clientIp = getIdentifier(request);
  if (!handoffRateLimiter.check(clientIp, HANDOFF_RATE_LIMIT)) {
    const resetTime = handoffRateLimiter.getResetTime(clientIp, HANDOFF_RATE_LIMIT);
    return NextResponse.json(
      { error: 'Too many handoff attempts. Please try again later.' },
      { status: 429, headers: { 'Retry-After': String(resetTime) } }
    );
  }

  try {
    const body = await request.json();
    const { token, redirect } = body;

    if (!token) {
      return NextResponse.json({ error: 'Token is required' }, { status: 400 });
    }

    const result = await processHandoff(request, token, redirect || '/');
    if (!result) {
      return NextResponse.json({ error: 'Invalid or expired handoff token' }, { status: 401 });
    }

    return result;
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}

/**
 * GET handler — legacy handoff with token in URL query parameter.
 *
 * SECURITY WARNING: Tokens in URLs can leak via browser history, server logs,
 * and Referer headers. The POST handler above should be preferred.
 * This GET handler is kept for backward compatibility with external auth providers
 * that redirect users via URL.
 */
export async function GET(request: NextRequest) {
  // Rate limiting check
  const clientIp = getIdentifier(request);
  if (!handoffRateLimiter.check(clientIp, HANDOFF_RATE_LIMIT)) {
    const resetTime = handoffRateLimiter.getResetTime(clientIp, HANDOFF_RATE_LIMIT);
    return NextResponse.redirect(
      new URL(`/admin/login?error=rate_limited&retry_after=${resetTime}`, process.env.NEXT_PUBLIC_APP_URL || request.url)
    );
  }

  const token = request.nextUrl.searchParams.get('token');
  const rawRedirect = request.nextUrl.searchParams.get('redirect') || '/';

  if (!token) {
    return NextResponse.redirect(new URL('/admin/login', process.env.NEXT_PUBLIC_APP_URL || request.url));
  }

  const result = await processHandoff(request, token, rawRedirect);
  if (!result) {
    return NextResponse.redirect(new URL('/admin/login', process.env.NEXT_PUBLIC_APP_URL || request.url));
  }

  return result;
}
