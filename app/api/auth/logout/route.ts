/**
 * Logout API Route
 *
 * Clears session and workspace cookies, AND revokes the JWT
 * server-side so it cannot be reused even if stolen.
 */

import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookie, verifySession, SESSION_COOKIE_NAME } from '@/lib/auth/session';
import { revokeSession } from '@/lib/auth/session-revocation';
import { logger } from '@/lib/utils';

export async function POST(request: NextRequest) {
  try {
    // Before clearing the cookie, extract and revoke the JWT
    const token = request.cookies.get(SESSION_COOKIE_NAME)?.value;
    if (token) {
      try {
        const session = await verifySession(token);
        if (session && session.jti && session.iat) {
          // Revoke this specific session so the JWT cannot be reused
          revokeSession(session.jti, session.userId, session.exp, 'logout');
        }
      } catch (revokeError) {
        // Revocation failure should not prevent logout from completing.
        // The cookie will still be cleared. Log the error for investigation.
        logger.error('[API /api/auth/logout] Failed to revoke session:', revokeError);
      }
    }

    await clearSessionCookie();
    const response = NextResponse.json({ success: true });
    response.cookies.delete('osw_workspace');
    return response;
  } catch (error) {
    logger.error('[API /api/auth/logout] Error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Logout failed' },
      { status: 500 }
    );
  }
}
