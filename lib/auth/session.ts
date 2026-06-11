/**
 * Session Management for Server Mode
 *
 * Simple JWT-based session management using jose library
 */

import { SignJWT, jwtVerify } from 'jose';
import { cookies } from 'next/headers';
import { timingSafeEqual } from 'crypto';
import type { NextRequest } from 'next/server';
import { isSessionRevoked } from './session-revocation';

const SESSION_COOKIE_NAME = 'osw_session';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

function getSecretKey(): Uint8Array {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error('SESSION_SECRET environment variable not set');
  }
  return new TextEncoder().encode(secret);
}

export interface SessionData {
  userId: string;
  email: string;
  isAdmin: boolean;
  exp: number;
  /** JWT ID — unique identifier for this specific session token */
  jti: string;
  /** Issued-at timestamp (epoch seconds) */
  iat: number;
}

/**
 * Create a new session token
 */
export async function createSession(userId: string, email: string, isAdmin = false): Promise<string> {
  const secret = getSecretKey();
  const exp = Math.floor((Date.now() + SESSION_DURATION) / 1000);
  const jti = crypto.randomUUID();

  const token = await new SignJWT({
    userId,
    email,
    isAdmin,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(exp)
    .setIssuedAt()
    .setJti(jti)
    .sign(secret);

  return token;
}

/**
 * Verify and decode a session token
 */
export async function verifySession(token: string): Promise<SessionData | null> {
  try {
    const secret = getSecretKey();
    const { payload } = await jwtVerify(token, secret);

    const jti = payload.jti as string | undefined;
    const iat = payload.iat as number | undefined;

    // Sessions without a JTI are legacy tokens — allow them but they
    // cannot be individually revoked. They will naturally expire.
    // For security, we could reject them, but that would force all
    // active sessions to re-login after this update.
    if (jti && iat) {
      const userId = payload.userId as string;
      const revoked = isSessionRevoked(jti, userId, iat);
      if (revoked) return null;
    }

    return {
      userId: payload.userId as string,
      email: payload.email as string,
      isAdmin: payload.isAdmin as boolean,
      exp: payload.exp as number,
      jti: jti || '',
      iat: iat || 0,
    };
  } catch (error) {
    return null;
  }
}

/**
 * Returns a refreshed token if the session is past the halfway point of its
 * lifetime, otherwise null (keep the existing cookie).
 *
 * Used by middleware to extend active sessions without re-issuing a cookie on
 * every single request.
 */
export async function maybeRefreshSession(session: SessionData): Promise<string | null> {
  const nowSec = Math.floor(Date.now() / 1000);
  const remainingMs = (session.exp - nowSec) * 1000;
  if (remainingMs > SESSION_DURATION / 2) return null;
  // When refreshing, the old session's JTI is effectively superseded.
  // The new token gets its own JTI. The old JTI remains valid until
  // its natural expiration unless explicitly revoked.
  return createSession(session.userId, session.email, session.isAdmin);
}

export { SESSION_COOKIE_NAME, SESSION_DURATION };

/**
 * Get current session from cookies
 */
export async function getSession(): Promise<SessionData | null> {
  // Desktop app: always authenticated as local admin
  if (process.env.OSW_DESKTOP === 'true') {
    return {
      userId: 'desktop',
      email: 'desktop@localhost',
      isAdmin: true,
      exp: 253402300799,
      jti: '__desktop__',
      iat: Math.floor(Date.now() / 1000),
    };
  }

  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;

  if (!token) {
    return null;
  }

  const session = await verifySession(token);
  if (!session) return null;

  // Check user is still active (prevents deactivated users from continuing)
  if (session.userId !== 'admin' && session.userId !== 'desktop' && session.userId !== 'instance-api') {
    try {
      const { getUserById } = await import('@/lib/auth/system-database');
      const user = getUserById(session.userId);
      if (!user) return null;
    } catch {
      // System database not available (browser mode) — skip check
    }
  }

  return session;
}

/**
 * Set session cookie
 */
export async function setSessionCookie(token: string): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false' && process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DURATION / 1000,
    path: '/',
  });
}

/**
 * Clear session cookie
 */
export async function clearSessionCookie(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(SESSION_COOKIE_NAME);
}

/**
 * Check if user is authenticated
 */
export async function isAuthenticated(): Promise<boolean> {
  const session = await getSession();
  return session !== null;
}

/**
 * Require authentication (throws if not authenticated)
 */
export async function requireAuth(): Promise<SessionData> {
  const session = await getSession();
  if (!session) {
    throw new Error('Unauthorized');
  }
  return session;
}

/**
 * Require admin authentication with database-verified admin status.
 *
 * SECURITY: This verifies isAdmin from the database, not from the JWT claim.
 * The JWT claim is only used for UI rendering (show/hide admin menu).
 * All authorization decisions must use this function instead of checking session.isAdmin.
 *
 * @returns The session data if the user is a verified admin
 * @throws {Error} If not authenticated or not an admin in the database
 */
export async function requireAdmin(): Promise<SessionData> {
  const session = await getSession();
  if (!session) {
    throw new Error('Unauthorized');
  }

  // Built-in admin accounts bypass DB check
  if (session.userId === 'admin' || session.userId === 'desktop' || session.userId === 'instance-api') {
    return session;
  }

  // Verify admin status from database (not JWT claim)
  try {
    const { getUserById } = await import('@/lib/auth/system-database');
    const user = getUserById(session.userId);
    if (!user || user.is_admin !== 1) {
      throw new Error('Admin access required');
    }
  } catch (error) {
    if (error instanceof Error && error.message === 'Admin access required') {
      throw error;
    }
    // If database is unavailable (browser mode), fall back to JWT claim
    // This should not happen in server mode
    if (!session.isAdmin) {
      throw new Error('Admin access required');
    }
  }

  return session;
}

/**
 * Verify instance API key for machine-to-machine auth.
 * Returns a synthetic admin session if the key is valid.
 * When GATEWAY_IPS is set, restricts to those source IPs only.
 */
export function verifyInstanceApiKey(request: NextRequest): SessionData | null {
  const apiKey = request.headers.get('x-instance-api-key');
  const expectedKey = process.env.INSTANCE_API_KEY;

  if (!apiKey || !expectedKey) return null;
  try {
    const a = Buffer.from(apiKey);
    const b = Buffer.from(expectedKey);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  } catch {
    return null;
  }

  const allowedIps = process.env.GATEWAY_IPS;
  if (allowedIps) {
    // SECURITY: Use getIdentifier() which respects TRUSTED_PROXY_IPS
    // to prevent IP spoofing via client-controlled headers.
    // We use a synchronous require here since this function must remain synchronous.
    let clientIp: string | null = null;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { getIdentifier } = require('@/lib/analytics/rate-limiter') as typeof import('@/lib/analytics/rate-limiter');
      clientIp = getIdentifier(request);
    } catch {
      // Fallback: use direct remote address if getIdentifier is unavailable
      try {
        clientIp = (request as any).socket?.remoteAddress || null;
      } catch {}
    }
    const allowed = new Set(allowedIps.split(',').map(ip => ip.trim()));
    if (!clientIp || clientIp === 'unknown' || !allowed.has(clientIp)) return null;
  }

  return {
    userId: 'instance-api',
    email: 'api@instance',
    isAdmin: true,
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: `__instance-api__:${Date.now()}`,
    iat: Math.floor(Date.now() / 1000),
  };
}

/**
 * Create a short-lived handoff token for external auth → instance session exchange.
 * Token is a JWT valid for 30 seconds, signed with the same SESSION_SECRET.
 */
export async function createHandoffToken(userId: string): Promise<string> {
  const secret = getSecretKey();
  const token = await new SignJWT({
    userId,
    purpose: 'handoff',
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('30s')
    .setIssuedAt()
    .sign(secret);
  return token;
}

// In-memory set of consumed JTIs for replay protection (fallback when DB unavailable)
const consumedJTIs = new Map<string, number>();

/**
 * Verify a handoff token. Returns the userId if valid, null otherwise.
 * Single-use: consumed tokens are rejected.
 *
 * SECURITY: Consumed JTIs are persisted in the system database so that
 * replay attacks are prevented even after a server restart.
 * Falls back to in-memory tracking if the database is unavailable.
 */
export async function verifyHandoffToken(token: string): Promise<{ userId: string } | null> {
  try {
    const secret = getSecretKey();
    const { payload } = await jwtVerify(token, secret);

    if (payload.purpose !== 'handoff') return null;

    const jti = payload.jti;
    if (!jti) return null;

    // Check if already consumed — database-backed (persistent across restarts)
    try {
      const { isHandoffTokenConsumed, markHandoffTokenConsumed, cleanupExpiredHandoffTokens } = await import('@/lib/auth/system-database');

      if (isHandoffTokenConsumed(jti)) return null;

      // Mark as consumed in database
      if (!markHandoffTokenConsumed(jti)) return null;

      // Periodic cleanup (every verification has a ~5% chance of triggering)
      if (Math.random() < 0.05) {
        cleanupExpiredHandoffTokens();
      }
    } catch {
      // Database unavailable — fall back to in-memory tracking
      if (consumedJTIs.has(jti)) return null;
      consumedJTIs.set(jti, Date.now());

      // Cleanup old in-memory JTIs
      const cutoff = Date.now() - 60000;
      for (const [id, time] of consumedJTIs) {
        if (time < cutoff) consumedJTIs.delete(id);
      }
    }

    return { userId: payload.userId as string };
  } catch {
    return null;
  }
}
